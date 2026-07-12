"""
ClipSync v3.0 — Unified P2P Sync Engine
Replaces both clip_sync_windows/clip_sync.py and clip_sync_linux/clip_sync.py.
Auto-detects OS and handles WebSocket server, mDNS, clipboard, and file transfers.
"""

import asyncio
import datetime
import ipaddress
import json
import logging
import os
import socket
import ssl
import sys
import threading
import time
import uuid
from collections import defaultdict
from typing import Callable, Optional

import pyperclip
import websockets
from websockets import serve
from zeroconf import IPVersion, ServiceBrowser, ServiceInfo, Zeroconf
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from .security import SecurityManager
from .clipboard_monitor import ClipboardMonitor
from .content_filter import is_sensitive_text, sanitize_filename
from .file_transfer import FileTransferManager

logger = logging.getLogger("clipsync.engine")

SERVICE_TYPE = "_clipsync._tcp.local."

# ── Persistent Device ID ─────────────────────────────────────────────────

def _load_or_create_device_id(base_dir: str) -> str:
    """Load device ID from disk, or create and persist a new one."""
    id_file = os.path.join(base_dir, "device_id.txt")
    if os.path.exists(id_file):
        try:
            with open(id_file, "r") as f:
                device_id = f.read().strip()
                if device_id:
                    return device_id
        except Exception:
            pass
    device_id = str(uuid.uuid4())
    try:
        with open(id_file, "w") as f:
            f.write(device_id)
    except Exception as e:
        logger.warning(f"Could not persist device ID: {e}")
    return device_id


# ── Persistent Nonce Cache ───────────────────────────────────────────────

def _load_nonce_cache(base_dir: str) -> dict:
    cache_file = os.path.join(base_dir, "nonce_cache.json")
    if os.path.exists(cache_file):
        try:
            with open(cache_file, "r") as f:
                cache = json.load(f)
                now = time.time()
                return {k: v for k, v in cache.items() if now - v < 60}
        except Exception:
            pass
    return {}


def _save_nonce_cache(cache: dict, base_dir: str):
    cache_file = os.path.join(base_dir, "nonce_cache.json")
    try:
        with open(cache_file, "w") as f:
            json.dump(cache, f)
    except Exception as e:
        logger.warning(f"Could not persist nonce cache: {e}")


class ClipSyncEngine:
    """
    Unified P2P Clipboard + File Sync Engine.
    Works on both Windows and Linux — auto-detects platform.
    """

    def __init__(
        self,
        secret_key: str,
        port: int = 52300,
        sync_sensitive: bool = False,
        base_dir: Optional[str] = None,
    ):
        if not base_dir:
            base_dir = os.path.dirname(os.path.abspath(__file__))
            base_dir = os.path.dirname(base_dir)  # Go up from core/ to clip_sync_desktop/
        self.base_dir = base_dir

        self.port = port
        self.sync_sensitive = sync_sensitive
        self.device_id = _load_or_create_device_id(base_dir)
        self.security = SecurityManager(secret_key)
        self.clipboard = ClipboardMonitor()
        self.file_transfer = FileTransferManager(self.security)

        self.zeroconf: Optional[Zeroconf] = None
        self.browser: Optional[ServiceBrowser] = None
        self.connected_peers: set = set()
        self.active_websockets: set = set()
        self.seen_nonces = _load_nonce_cache(base_dir)
        self._connections_per_ip: dict = defaultdict(int)
        self._max_connections_per_ip = 5

        self.loop: Optional[asyncio.AbstractEventLoop] = None
        self._running = False

        # ── Event callbacks (for Flask GUI) ──────────────────────────────
        self.on_log: Optional[Callable[[str, str, str], None]] = None  # (level, message, timestamp)
        self.on_peer_connected: Optional[Callable[[str, str], None]] = None  # (device_id, ip)
        self.on_peer_disconnected: Optional[Callable[[str], None]] = None  # (device_id)
        self.on_clipboard_text_received: Optional[Callable[[str], None]] = None
        self.on_clipboard_image_received: Optional[Callable[[bytes, str], None]] = None
        self.on_file_received: Optional[Callable[[str, str], None]] = None

        # Wire up clipboard monitor callbacks
        self.clipboard.on_text_changed = self._on_local_text_changed
        self.clipboard.on_image_changed = self._on_local_image_changed
        self.clipboard.on_files_changed = self._on_local_files_changed

        # Wire up file transfer callbacks
        self.file_transfer.on_progress = self._on_transfer_progress
        self.file_transfer.on_file_received = self._on_file_received

        # Peer tracking
        self.peer_info: dict = {}  # device_id → {ip, connected_at, os}

        logger.info(f"ClipSync Engine initialized (Device: {self.device_id[:8]}..., Port: {port})")

    # ── Local Clipboard Events ───────────────────────────────────────────

    def _on_local_text_changed(self, text: str):
        """Called when local clipboard text changes."""
        if is_sensitive_text(text, self.sync_sensitive):
            logger.warning("Sensitive data detected. Sync blocked.")
            return
        logger.info(f"Local text copied, broadcasting: {text[:40]}...")
        if self.loop:
            asyncio.run_coroutine_threadsafe(self._broadcast_text(text), self.loop)

    def _on_local_image_changed(self, image_data: bytes, fmt: str):
        """Called when local clipboard image changes."""
        logger.info(f"Local image copied ({len(image_data)} bytes), broadcasting...")
        if self.loop:
            asyncio.run_coroutine_threadsafe(
                self._broadcast_image(image_data, fmt), self.loop
            )

    def _on_local_files_changed(self, files: list[str]):
        """Called when files are copied to clipboard."""
        for filepath in files:
            logger.info(f"Local file copied, broadcasting: {os.path.basename(filepath)}")
            if self.loop:
                asyncio.run_coroutine_threadsafe(
                    self._broadcast_file(filepath), self.loop
                )

    def _on_transfer_progress(self, transfer_id: str, progress: float, filename: str):
        """Called during file transfer progress."""
        logger.debug(f"Transfer {filename}: {progress:.1f}%")

    def _on_file_received(self, save_path: str, filename: str):
        """Called when a file transfer completes."""
        if self.on_file_received:
            self.on_file_received(save_path, filename)

    # ── Broadcasting ─────────────────────────────────────────────────────

    async def _broadcast_text(self, text: str):
        """Broadcast text clipboard to all connected peers."""
        msg = self.security.encrypt_message({"type": "clipboard", "text": text})
        await self._broadcast_raw(msg)

    async def _broadcast_image(self, image_data: bytes, fmt: str):
        """Broadcast clipboard image to all connected peers."""
        image_msg = self.file_transfer.create_image_message(image_data, fmt)
        encrypted = self.security.encrypt_message(image_msg)
        await self._broadcast_raw(encrypted)

    async def _broadcast_file(self, filepath: str):
        """Broadcast a file to all connected peers (chunked)."""
        for msg_dict in self.file_transfer.create_send_messages(filepath):
            encrypted = self.security.encrypt_message(msg_dict)
            await self._broadcast_raw(encrypted)
            # Small delay between chunks to avoid flooding
            if msg_dict.get("type") == "file_chunk":
                await asyncio.sleep(0.01)

    async def _broadcast_raw(self, encrypted_message: str):
        """Send an encrypted message to all active WebSocket peers."""
        if not self.active_websockets:
            return
        tasks = [ws.send(encrypted_message) for ws in self.active_websockets.copy()]
        await asyncio.gather(*tasks, return_exceptions=True)

    # ── Send a file manually via API ─────────────────────────────────────

    def send_file(self, filepath: str):
        """Public method to send a file (called from Flask)."""
        if self.loop:
            asyncio.run_coroutine_threadsafe(self._broadcast_file(filepath), self.loop)

    # ── WebSocket Connection Handler ─────────────────────────────────────

    async def handle_client(self, websocket):
        """Handle an incoming or outgoing WebSocket connection."""
        authenticated = False
        remote_ip = "unknown"
        peer_device_id = None

        try:
            remote_ip = websocket.remote_address[0]
        except Exception:
            pass

        # Per-IP rate limiting
        if self._connections_per_ip[remote_ip] >= self._max_connections_per_ip:
            logger.warning(f"Connection limit exceeded for {remote_ip}")
            await websocket.close()
            return

        self._connections_per_ip[remote_ip] += 1

        try:
            # Send our hello
            hello = {
                "type": "hello",
                "deviceId": self.device_id,
                "timestamp": int(time.time()),
                "nonce": str(uuid.uuid4()),
                "fingerprint": self.security.compute_network_challenge(),
            }
            await websocket.send(self.security.encrypt_message(hello))

            # Wait for peer's hello (2s timeout)
            try:
                first_msg = await asyncio.wait_for(websocket.recv(), timeout=2.0)
                data = self.security.decrypt_message(first_msg)

                if not data or data.get("type") != "hello":
                    logger.warning(f"Peer {remote_ip} failed auth: invalid payload")
                    await websocket.close()
                    return

                # Timestamp validation (30s window)
                ts = data.get("timestamp", 0)
                if abs(time.time() - ts) > 30:
                    logger.warning(f"Peer {remote_ip} failed auth: timestamp expired")
                    await websocket.close()
                    return

                # Nonce validation
                self._evict_expired_nonces()
                nonce = data.get("nonce")
                if not nonce or nonce in self.seen_nonces:
                    logger.warning(f"Peer {remote_ip} failed auth: nonce reused")
                    await websocket.close()
                    return
                self.seen_nonces[nonce] = time.time()
                _save_nonce_cache(self.seen_nonces, self.base_dir)

                # HMAC challenge verification
                if not self.security.verify_network_challenge(data.get("fingerprint", "")):
                    logger.warning(f"Peer {remote_ip} failed auth: bad challenge")
                    await websocket.close()
                    return

                peer_device_id = data.get("deviceId", "unknown")
                logger.info(f"✓ Authenticated peer: {peer_device_id[:8]}... ({remote_ip})")

            except asyncio.TimeoutError:
                logger.warning(f"Peer {remote_ip} auth handshake timed out")
                return

            # Auth passed — add to broadcast pool
            authenticated = True
            self.active_websockets.add(websocket)
            self.peer_info[peer_device_id] = {
                "ip": remote_ip,
                "connected_at": time.time(),
                "os": "unknown",
            }
            if self.on_peer_connected:
                self.on_peer_connected(peer_device_id, remote_ip)

            # Listen for messages
            async for encrypted_message in websocket:
                data = self.security.decrypt_message(encrypted_message)
                if not data:
                    continue

                msg_type = data.get("type")

                if msg_type == "clipboard":
                    text = data.get("text")
                    if text and text != self.clipboard._last_text:
                        logger.info(f"Received text from peer: {text[:40]}...")
                        self.clipboard.set_clipboard_text(text)
                        if self.on_clipboard_text_received:
                            self.on_clipboard_text_received(text)

                elif msg_type == "clipboard_image":
                    image_data = self.file_transfer.handle_clipboard_image(data)
                    if image_data:
                        logger.info(f"Received image from peer ({len(image_data)} bytes)")
                        self.clipboard.set_clipboard_image(image_data)
                        if self.on_clipboard_image_received:
                            self.on_clipboard_image_received(image_data, data.get("format", "png"))

                elif msg_type == "file_start":
                    self.file_transfer.handle_file_start(data)

                elif msg_type == "file_chunk":
                    self.file_transfer.handle_file_chunk(data)

                elif msg_type == "file_complete":
                    self.file_transfer.handle_file_complete(data)

        except websockets.exceptions.ConnectionClosed:
            pass
        except Exception as e:
            logger.error(f"Connection error with {remote_ip}: {e}")
        finally:
            if authenticated:
                self.active_websockets.discard(websocket)
                if peer_device_id and peer_device_id in self.peer_info:
                    del self.peer_info[peer_device_id]
                    if self.on_peer_disconnected:
                        self.on_peer_disconnected(peer_device_id)
            self._connections_per_ip[remote_ip] = max(
                0, self._connections_per_ip[remote_ip] - 1
            )
            if self._connections_per_ip[remote_ip] == 0:
                del self._connections_per_ip[remote_ip]

    def _evict_expired_nonces(self):
        now = time.time()
        expired = [n for n, ts in self.seen_nonces.items() if now - ts > 60]
        for n in expired:
            del self.seen_nonces[n]
        _save_nonce_cache(self.seen_nonces, self.base_dir)

    # ── Peer Discovery (mDNS) ───────────────────────────────────────────

    async def connect_to_peer(self, host: str, port: int):
        """Connect to a discovered peer via WSS."""
        uri = f"wss://{host}:{port}"
        try:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            ctx.minimum_version = ssl.TLSVersion.TLSv1_2

            async with websockets.connect(
                uri, ssl=ctx, max_size=2 * 1024 * 1024
            ) as websocket:
                logger.info(f"Connected to peer at {uri}")
                await self.handle_client(websocket)
        except Exception as e:
            logger.error(f"Failed to connect to {uri}: {e}")

    def add_service(self, zeroconf, type, name):
        info = zeroconf.get_service_info(type, name)
        if info:
            addresses = [socket.inet_ntoa(a) for a in info.addresses]
            if addresses:
                host = addresses[0]
                port = info.port
                if port == self.port and host == self._get_local_ip():
                    return
                logger.info(f"Discovered peer at {host}:{port}")
                if self.loop:
                    asyncio.run_coroutine_threadsafe(
                        self.connect_to_peer(host, port), self.loop
                    )

    def remove_service(self, zeroconf, type, name):
        logger.info(f"Service removed: {name}")

    def update_service(self, zeroconf, type, name):
        pass

    # ── TLS Certificate Management ───────────────────────────────────────

    def _ensure_cert_matches_ip(self):
        """Regenerate TLS cert if the local IP doesn't match the SAN."""
        cert_path = os.path.join(self.base_dir, "tls_cert.pem")
        key_path = os.path.join(self.base_dir, "tls_key.pem")
        local_ip = self._get_local_ip()
        regenerate = False

        if not os.path.exists(cert_path) or not os.path.exists(key_path):
            regenerate = True
        else:
            try:
                with open(cert_path, "rb") as f:
                    cert = x509.load_pem_x509_certificate(f.read())
                from cryptography.x509.oid import ExtensionOID
                san_ext = cert.extensions.get_extension_for_oid(
                    ExtensionOID.SUBJECT_ALTERNATIVE_NAME
                )
                san_ips = [
                    str(ip) for ip in san_ext.value.get_values_for_type(x509.IPAddress)
                ]
                if local_ip not in san_ips:
                    regenerate = True
                # Check expiry
                if cert.not_valid_after_utc < datetime.datetime.now(datetime.timezone.utc):
                    regenerate = True
            except Exception:
                regenerate = True

        if regenerate:
            self._generate_cert(local_ip, cert_path, key_path)

    def _generate_cert(self, local_ip: str, cert_path: str, key_path: str):
        """Generate a self-signed RSA-4096 TLS certificate with correct SANs."""
        logger.info(f"Generating TLS certificate for {local_ip}...")
        private_key = rsa.generate_private_key(
            public_exponent=65537, key_size=4096
        )
        subject = issuer = x509.Name([
            x509.NameAttribute(x509.oid.NameOID.ORGANIZATION_NAME, "ClipSync Local Mesh"),
            x509.NameAttribute(x509.oid.NameOID.COMMON_NAME, "localhost"),
        ])
        san_list = [
            x509.DNSName("localhost"),
            x509.IPAddress(ipaddress.IPv4Address("127.0.0.1")),
        ]
        if local_ip != "127.0.0.1":
            san_list.append(x509.IPAddress(ipaddress.IPv4Address(local_ip)))

        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(private_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.datetime.now(datetime.timezone.utc))
            .not_valid_after(
                datetime.datetime.now(datetime.timezone.utc)
                + datetime.timedelta(days=365)
            )
            .add_extension(
                x509.SubjectAlternativeName(san_list), critical=False
            )
            .sign(private_key, hashes.SHA256())
        )
        with open(cert_path, "wb") as f:
            f.write(cert.public_bytes(serialization.Encoding.PEM))
        with open(key_path, "wb") as f:
            f.write(
                private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.TraditionalOpenSSL,
                    encryption_algorithm=serialization.NoEncryption(),
                )
            )
        logger.info(f"TLS certificate generated (RSA-4096, 1-year validity, SAN: {local_ip})")

    # ── Utilities ────────────────────────────────────────────────────────

    def _get_local_ip(self) -> str:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except Exception:
            return "127.0.0.1"

    def get_status(self) -> dict:
        """Get current engine status (for API/GUI)."""
        return {
            "device_id": self.device_id,
            "local_ip": self._get_local_ip(),
            "port": self.port,
            "running": self._running,
            "peers_count": len(self.peer_info),
            "peers": [
                {
                    "device_id": did,
                    "ip": info["ip"],
                    "connected_at": info["connected_at"],
                }
                for did, info in self.peer_info.items()
            ],
            "active_transfers": len(self.file_transfer.active_transfers),
            "platform": sys.platform,
        }

    # ── Main Run Loop ────────────────────────────────────────────────────

    def start_mDNS(self):
        local_ip = self._get_local_ip()
        self.zeroconf = Zeroconf(ip_version=IPVersion.V4Only)
        info = ServiceInfo(
            SERVICE_TYPE,
            f"ClipSync-{self.device_id[:4]}.{SERVICE_TYPE}",
            addresses=[socket.inet_aton(local_ip)],
            port=self.port,
            properties={},
            server="clipsync-node.local.",
        )
        self.zeroconf.register_service(info)
        self.browser = ServiceBrowser(self.zeroconf, SERVICE_TYPE, self)
        logger.info(f"mDNS registered on {local_ip}:{self.port}")

    async def run(self):
        """Main async entry point — starts all services."""
        self._running = True
        self.loop = asyncio.get_event_loop()

        # Start mDNS
        self.start_mDNS()

        # Start clipboard monitor
        self.clipboard.start()

        # Ensure TLS certs match current IP
        self._ensure_cert_matches_ip()

        cert_path = os.path.join(self.base_dir, "tls_cert.pem")
        key_path = os.path.join(self.base_dir, "tls_key.pem")

        ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ssl_context.load_cert_chain(certfile=cert_path, keyfile=key_path)
        ssl_context.minimum_version = ssl.TLSVersion.TLSv1_2
        ssl_context.set_ciphers(
            "ECDHE+AESGCM:ECDHE+CHACHA20:DHE+AESGCM:!aNULL:!eNULL:!EXPORT:!DES:!RC4:!MD5"
        )

        logger.info(f"WebSocket server starting on wss://0.0.0.0:{self.port}")
        logger.info(f"Platform: {sys.platform} | Device: {self.device_id[:8]}...")
        logger.info("Waiting for peers...")

        async with serve(
            self.handle_client,
            "0.0.0.0",
            self.port,
            ssl=ssl_context,
            max_size=2 * 1024 * 1024,  # 2MB max for chunked transfers
            server_header=None,
        ):
            await asyncio.Future()  # Run forever

    def stop(self):
        """Stop all services."""
        self._running = False
        self.clipboard.stop()
        if self.zeroconf:
            self.zeroconf.close()
        logger.info("ClipSync Engine stopped.")

    def run_in_thread(self) -> threading.Thread:
        """Start the engine in a background thread (for Flask integration)."""
        def _thread_target():
            self.loop = asyncio.new_event_loop()
            asyncio.set_event_loop(self.loop)
            try:
                self.loop.run_until_complete(self.run())
            except Exception as e:
                logger.error(f"Engine thread error: {e}")

        thread = threading.Thread(target=_thread_target, daemon=True)
        thread.start()
        return thread
