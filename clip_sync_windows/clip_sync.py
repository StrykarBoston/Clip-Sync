import asyncio
import json
import logging
import socket
import threading
import time
import uuid
import os
import sys
import base64
import ipaddress
import datetime
import hmac

import pyperclip
import websockets
from websockets import serve
from zeroconf import IPVersion, ServiceBrowser, ServiceInfo, Zeroconf
from cryptography import x509
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.exceptions import InvalidTag
from dotenv import load_dotenv
import ssl
import re
import hashlib
from collections import defaultdict

load_dotenv()

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

SERVICE_TYPE = "_clipsync._tcp.local."
PORT = int(os.environ.get("PORT", 52300))
SYNC_SENSITIVE_DATA = os.environ.get("SYNC_SENSITIVE_DATA", "false").lower() == "true"
SHARED_SECRET_HEX = os.environ.get("SECRET_KEY")

if not SHARED_SECRET_HEX:
    logger.error("SECRET_KEY not found in .env file! Exiting.")
    sys.exit(1)

# --- VULN-020 FIX: Persistent device ID ---
DEVICE_ID_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "device_id.txt")

def _load_or_create_device_id():
    """Load device ID from disk, or create and persist a new one."""
    if os.path.exists(DEVICE_ID_FILE):
        try:
            with open(DEVICE_ID_FILE, 'r') as f:
                device_id = f.read().strip()
                if device_id:
                    return device_id
        except Exception:
            pass
    device_id = str(uuid.uuid4())
    try:
        with open(DEVICE_ID_FILE, 'w') as f:
            f.write(device_id)
    except Exception as e:
        logger.warning(f"Could not persist device ID: {e}")
    return device_id

DEVICE_ID = _load_or_create_device_id()

# --- VULN-008 FIX: HMAC-based time-window challenge instead of static fingerprint ---
def _compute_network_challenge():
    """Compute an HMAC-based challenge using a 5-minute time window.
    This avoids broadcasting a static fingerprint that could be used for offline brute-force."""
    time_window = int(time.time()) // 300  # 5-minute windows
    msg = f"clipsync-challenge:{time_window}".encode('utf-8')
    return hmac.new(SHARED_SECRET_HEX.encode('utf-8'), msg, hashlib.sha256).hexdigest()[:16]

def _verify_network_challenge(challenge):
    """Verify challenge against current and previous time window (to handle boundary transitions)."""
    current = _compute_network_challenge()
    if hmac.compare_digest(challenge, current):
        return True
    # Check previous window for clock skew tolerance
    prev_window = (int(time.time()) // 300) - 1
    prev_msg = f"clipsync-challenge:{prev_window}".encode('utf-8')
    prev_challenge = hmac.new(SHARED_SECRET_HEX.encode('utf-8'), prev_msg, hashlib.sha256).hexdigest()[:16]
    return hmac.compare_digest(challenge, prev_challenge)

# --- VULN-019 FIX: Expanded sensitive data filter ---
def is_sensitive(text):
    if SYNC_SENSITIVE_DATA:
        return False
    # Credit card numbers (13-19 digits with optional spaces/dashes)
    if re.search(r'\b(?:\d[ -]*?){13,19}\b', text):
        return True
    # Private key headers (PEM)
    if '-----BEGIN' in text and 'PRIVATE KEY-----' in text:
        return True
    # Social Security Numbers (SSN)
    if re.search(r'\b\d{3}-\d{2}-\d{4}\b', text):
        return True
    # AWS Access Key IDs
    if re.search(r'AKIA[0-9A-Z]{16}', text):
        return True
    # AWS Secret Access Keys (40-char base64)
    if re.search(r'(?:aws_secret_access_key|AWS_SECRET_ACCESS_KEY)\s*[:=]\s*\S{40}', text):
        return True
    # Generic API keys / tokens (common patterns)
    if re.search(r'(?:api[_-]?key|api[_-]?secret|access[_-]?token|auth[_-]?token)\s*[:=]\s*\S{16,}', text, re.IGNORECASE):
        return True
    # JSON Web Tokens (JWT)
    if re.search(r'eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}', text):
        return True
    # Password patterns in config/env
    if re.search(r'(?:password|passwd|pwd)\s*[:=]\s*\S+', text, re.IGNORECASE):
        return True
    return False


class SecurityManager:
    def __init__(self):
        # --- VULN-011 FIX: Use HKDF for key derivation ---
        raw_key = bytes.fromhex(SHARED_SECRET_HEX)
        derived_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b'clipsync-e2ee',
        ).derive(raw_key)
        self.aesgcm = AESGCM(derived_key)

    def encrypt_message(self, message_dict):
        # --- VULN-009 FIX: Add AAD (message type) to AES-GCM ---
        msg_type = message_dict.get('type', 'unknown')
        aad = f"{msg_type}".encode('utf-8')
        plaintext = json.dumps(message_dict).encode('utf-8')
        nonce = os.urandom(12)
        ciphertext = self.aesgcm.encrypt(nonce, plaintext, aad)
        return json.dumps({
            'iv': base64.b64encode(nonce).decode('utf-8'),
            'data': base64.b64encode(ciphertext).decode('utf-8'),
            'aad': msg_type
        })

    def decrypt_message(self, payload_str):
        try:
            payload = json.loads(payload_str)
            if 'iv' not in payload or 'data' not in payload:
                return None
            nonce = base64.b64decode(payload['iv'])
            ciphertext = base64.b64decode(payload['data'])
            # --- VULN-009 FIX: Verify AAD ---
            aad_str = payload.get('aad', 'unknown')
            aad = aad_str.encode('utf-8')
            plaintext = self.aesgcm.decrypt(nonce, ciphertext, aad)
            return json.loads(plaintext.decode('utf-8'))
        except (InvalidTag, json.JSONDecodeError, KeyError, ValueError) as e:
            logger.error(f"Decryption or parsing failed: {e}")
            return None


# --- VULN-016 FIX: Persistent nonce cache ---
NONCE_CACHE_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "nonce_cache.json")

def _load_nonce_cache():
    """Load nonce cache from disk."""
    if os.path.exists(NONCE_CACHE_FILE):
        try:
            with open(NONCE_CACHE_FILE, 'r') as f:
                cache = json.load(f)
                # Only keep nonces that are less than 60 seconds old
                now = time.time()
                return {k: v for k, v in cache.items() if now - v < 60}
        except Exception:
            pass
    return {}

def _save_nonce_cache(cache):
    """Persist nonce cache to disk."""
    try:
        with open(NONCE_CACHE_FILE, 'w') as f:
            json.dump(cache, f)
    except Exception as e:
        logger.warning(f"Could not persist nonce cache: {e}")


class ClipSyncWindows:
    def __init__(self):
        self.port = PORT
        self.zeroconf = Zeroconf(ip_version=IPVersion.V4Only)
        self.connected_peers = set()
        self.active_websockets = set()
        self.last_clipboard = ""
        self.loop = asyncio.get_event_loop()
        self.security = SecurityManager()
        # --- VULN-016 FIX: Load persisted nonce cache ---
        self.seen_nonces = _load_nonce_cache()
        # --- VULN-004 FIX: Per-IP connection tracking ---
        self._connections_per_ip = defaultdict(int)
        self._max_connections_per_ip = 5

    def _evict_expired_nonces(self):
        """Remove nonces older than 60 seconds from the cache."""
        now = time.time()
        expired = [n for n, ts in self.seen_nonces.items() if now - ts > 60]
        for n in expired:
            del self.seen_nonces[n]
        # Persist after eviction
        _save_nonce_cache(self.seen_nonces)

    def _get_remote_ip(self, websocket):
        """Extract remote IP from websocket connection."""
        try:
            return websocket.remote_address[0]
        except Exception:
            return "unknown"

    async def handle_client(self, websocket):
        authenticated = False
        remote_ip = self._get_remote_ip(websocket)

        # --- VULN-004 FIX: Per-IP connection limiting ---
        if self._connections_per_ip[remote_ip] >= self._max_connections_per_ip:
            logger.warning(f"Connection limit exceeded for IP {remote_ip}. Rejecting.")
            await websocket.close()
            return

        self._connections_per_ip[remote_ip] += 1

        try:
            # Send hello with timestamp, nonce, and challenge
            hello_payload = {
                'type': 'hello',
                'deviceId': DEVICE_ID,
                'timestamp': int(time.time()),
                'nonce': str(uuid.uuid4()),
                'fingerprint': _compute_network_challenge()
            }
            encrypted_hello = self.security.encrypt_message(hello_payload)
            await websocket.send(encrypted_hello)

            # Auth Handshake with 2-second timeout
            try:
                first_message = await asyncio.wait_for(websocket.recv(), timeout=2.0)
                data = self.security.decrypt_message(first_message)
                if not data or data.get('type') != 'hello':
                    logger.warning(f"Peer {remote_ip} failed auth handshake: Invalid payload")
                    # --- VULN-015 FIX: Close silently instead of sending plaintext rejection ---
                    await websocket.close()
                    return

                # Replay Protection: Timestamp check (30 seconds)
                ts = data.get('timestamp', 0)
                if abs(time.time() - ts) > 30:
                    logger.warning(f"Peer {remote_ip} failed auth handshake: Timestamp expired")
                    await websocket.close()
                    return

                # Replay Protection: Nonce cache with TTL-based eviction
                self._evict_expired_nonces()
                nonce = data.get('nonce')
                if not nonce or nonce in self.seen_nonces:
                    logger.warning(f"Peer {remote_ip} failed auth handshake: Nonce reused")
                    await websocket.close()
                    return
                self.seen_nonces[nonce] = time.time()
                _save_nonce_cache(self.seen_nonces)

                # --- VULN-008 FIX: HMAC-based challenge verification ---
                if not _verify_network_challenge(data.get('fingerprint', '')):
                    logger.warning(f"Peer {remote_ip} failed auth handshake: Invalid challenge")
                    await websocket.close()
                    return

                peer_id = data.get('deviceId')
                logger.info(f"Securely connected to peer: {peer_id}")
            except asyncio.TimeoutError:
                logger.warning(f"Peer {remote_ip} auth handshake timed out")
                return

            # === AUTH PASSED — only NOW add to broadcast pool ===
            authenticated = True
            self.active_websockets.add(websocket)

            async for encrypted_message in websocket:
                data = self.security.decrypt_message(encrypted_message)
                if not data:
                    continue  # Drop invalid/unauthenticated messages

                if data.get('type') == 'clipboard':
                    text = data.get('text')
                    if text and text != self.last_clipboard:
                        logger.info(f"Received secure clipboard from peer: {text[:20]}...")
                        self.last_clipboard = text
                        pyperclip.copy(text)
        finally:
            if authenticated:
                self.active_websockets.discard(websocket)
            # --- VULN-004 FIX: Decrement per-IP counter ---
            self._connections_per_ip[remote_ip] = max(0, self._connections_per_ip[remote_ip] - 1)
            if self._connections_per_ip[remote_ip] == 0:
                del self._connections_per_ip[remote_ip]

    async def connect_to_peer(self, host, port):
        uri = f"wss://{host}:{port}"
        try:
            client_ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            client_ssl_context.check_hostname = False
            client_ssl_context.verify_mode = ssl.CERT_NONE
            # --- VULN-001 FIX: Enforce TLS 1.2+ on client side too ---
            client_ssl_context.minimum_version = ssl.TLSVersion.TLSv1_2

            async with websockets.connect(uri, ssl=client_ssl_context) as websocket:
                logger.info(f"Connected to peer at {uri}")
                await self.handle_client(websocket)
        except Exception as e:
            logger.error(f"Failed to connect to peer at {uri}: {e}")

    def add_service(self, zeroconf, type, name):
        info = zeroconf.get_service_info(type, name)
        if info:
            addresses = [socket.inet_ntoa(a) for a in info.addresses]
            if addresses:
                host = addresses[0]
                port = info.port

                if port == self.port and host == self.get_local_ip():
                    return

                logger.info(f"Discovered peer at {host}:{port}")
                asyncio.run_coroutine_threadsafe(self.connect_to_peer(host, port), self.loop)

    def remove_service(self, zeroconf, type, name):
        logger.info(f"Service {name} removed")

    def update_service(self, zeroconf, type, name):
        pass

    def get_local_ip(self):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except Exception:
            return "127.0.0.1"

    def start_mDNS(self):
        local_ip = self.get_local_ip()
        # --- VULN-007 FIX: Generic service name without platform identifier ---
        # --- VULN-008 FIX: No fingerprint in mDNS TXT records ---
        info = ServiceInfo(
            SERVICE_TYPE,
            f"ClipSync-{DEVICE_ID[:4]}.{SERVICE_TYPE}",
            addresses=[socket.inet_aton(local_ip)],
            port=self.port,
            properties={},  # No fingerprint broadcast
            server=f"clipsync-node.local.",  # Generic hostname
        )
        self.zeroconf.register_service(info)
        self.browser = ServiceBrowser(self.zeroconf, SERVICE_TYPE, self)
        logger.info(f"mDNS Service registered on port {self.port}")

    async def broadcast_clipboard(self, text):
        encrypted_message = self.security.encrypt_message({'type': 'clipboard', 'text': text})
        if self.active_websockets:
            await asyncio.gather(*[ws.send(encrypted_message) for ws in self.active_websockets], return_exceptions=True)

    def clipboard_watcher_sync(self):
        while True:
            try:
                current_clipboard = pyperclip.paste()
                if current_clipboard != self.last_clipboard and isinstance(current_clipboard, str) and current_clipboard.strip():
                    if is_sensitive(current_clipboard):
                        logger.warning("Sensitive data detected in clipboard. Sync paused for this item.")
                        self.last_clipboard = current_clipboard
                        continue

                    self.last_clipboard = current_clipboard
                    logger.info(f"Local clipboard changed, broadcasting securely: {current_clipboard[:20]}...")
                    asyncio.run_coroutine_threadsafe(self.broadcast_clipboard(current_clipboard), self.loop)
            except Exception as e:
                pass
            time.sleep(0.5)

    def _ensure_cert_matches_ip(self):
        """Auto-regenerate TLS cert if the IP SAN doesn't match the current LAN IP."""
        cert_path = 'tls_cert.pem'
        key_path = 'tls_key.pem'
        local_ip = self.get_local_ip()

        regenerate = False
        if not os.path.exists(cert_path) or not os.path.exists(key_path):
            regenerate = True
            logger.info("TLS cert/key not found, generating...")
        else:
            try:
                from cryptography.x509 import load_pem_x509_certificate
                from cryptography.x509.oid import ExtensionOID
                with open(cert_path, 'rb') as f:
                    cert = load_pem_x509_certificate(f.read())
                san_ext = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
                san_ips = [str(ip) for ip in san_ext.value.get_values_for_type(x509.IPAddress)]
                if local_ip not in san_ips:
                    logger.warning(f"Cert SAN IPs {san_ips} don't include current IP {local_ip}. Regenerating...")
                    regenerate = True
                else:
                    logger.info(f"TLS cert SAN matches current IP {local_ip}")
            except Exception as e:
                logger.warning(f"Could not parse existing cert: {e}. Regenerating...")
                regenerate = True

        if regenerate:
            self._generate_cert(local_ip, cert_path, key_path)

    def _generate_cert(self, local_ip, cert_path, key_path):
        """Generate a self-signed TLS cert with the correct IP SAN."""
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.hazmat.primitives import serialization

        # --- VULN-014 FIX: Upgrade to RSA 4096-bit ---
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=4096)
        subject = issuer = x509.Name([
            x509.NameAttribute(x509.oid.NameOID.ORGANIZATION_NAME, u"ClipSync Local Mesh"),
            x509.NameAttribute(x509.oid.NameOID.COMMON_NAME, u"localhost"),
        ])
        san_list = [
            x509.DNSName(u"localhost"),
            x509.IPAddress(ipaddress.IPv4Address("127.0.0.1")),
        ]
        if local_ip != "127.0.0.1":
            san_list.append(x509.IPAddress(ipaddress.IPv4Address(local_ip)))

        cert = x509.CertificateBuilder().subject_name(subject).issuer_name(issuer).public_key(
            private_key.public_key()
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            datetime.datetime.now(datetime.UTC)
        ).not_valid_after(
            datetime.datetime.now(datetime.UTC) + datetime.timedelta(days=365)
        ).add_extension(
            x509.SubjectAlternativeName(san_list), critical=False,
        ).sign(private_key, hashes.SHA256())

        with open(cert_path, 'wb') as f:
            f.write(cert.public_bytes(serialization.Encoding.PEM))
        with open(key_path, 'wb') as f:
            f.write(private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption()
            ))
        logger.info(f"TLS cert generated (RSA-4096): SAN includes IP:{local_ip}, validity=1yr")

    async def main_async(self):
        self.start_mDNS()

        watcher_thread = threading.Thread(target=self.clipboard_watcher_sync, daemon=True)
        watcher_thread.start()

        # Auto-regenerate cert if SAN IP doesn't match current LAN IP
        self._ensure_cert_matches_ip()

        logger.info(f"Starting Secure WSS server on port {self.port}...")
        ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ssl_context.load_cert_chain(certfile='tls_cert.pem', keyfile='tls_key.pem')

        # --- VULN-001 FIX: Enforce TLS 1.2+ minimum ---
        ssl_context.minimum_version = ssl.TLSVersion.TLSv1_2

        # --- VULN-002 FIX: Restrict cipher suites, ban anonymous ciphers ---
        ssl_context.set_ciphers('ECDHE+AESGCM:ECDHE+CHACHA20:DHE+AESGCM:!aNULL:!eNULL:!EXPORT:!DES:!RC4:!MD5')

        # --- VULN-005 FIX: max_size limits payload size ---
        # --- VULN-006 FIX: server_header=None suppresses version info ---
        async with serve(
            self.handle_client,
            "0.0.0.0",
            self.port,
            ssl=ssl_context,
            max_size=65536,  # 64KB max payload
            server_header=None,  # Suppress Server header
        ):
            await asyncio.Future()

if __name__ == "__main__":
    sync = ClipSyncWindows()
    try:
        sync.loop.run_until_complete(sync.main_async())
    except KeyboardInterrupt:
        logger.info("Shutting down...")
    finally:
        sync.zeroconf.close()
