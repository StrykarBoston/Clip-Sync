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

import pyperclip
import websockets
from websockets import serve
from zeroconf import IPVersion, ServiceBrowser, ServiceInfo, Zeroconf
from cryptography import x509
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes
from cryptography.exceptions import InvalidTag
from dotenv import load_dotenv
import ssl
import re
import hashlib

load_dotenv()

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

SERVICE_TYPE = "_clipsync._tcp.local."
DEVICE_ID = str(uuid.uuid4())
SHARED_SECRET_HEX = os.environ.get("SECRET_KEY")
PORT = int(os.environ.get("PORT", 52300))
SYNC_SENSITIVE_DATA = os.environ.get("SYNC_SENSITIVE_DATA", "false").lower() == "true"
NETWORK_FINGERPRINT = hashlib.sha256(SHARED_SECRET_HEX.encode('utf-8')).hexdigest()[:16] if SHARED_SECRET_HEX else ""

if not SHARED_SECRET_HEX:
    logger.error("SECRET_KEY not found in .env file! Exiting.")
    sys.exit(1)

def is_sensitive(text):
    if SYNC_SENSITIVE_DATA:
        return False
    # Basic credit card regex (13-19 digits with optional spaces/dashes)
    if re.search(r'\b(?:\d[ -]*?){13,19}\b', text):
        return True
    # Private key headers
    if '-----BEGIN' in text and 'PRIVATE KEY-----' in text:
        return True
    return False

class SecurityManager:
    def __init__(self):
        self.aesgcm = AESGCM(bytes.fromhex(SHARED_SECRET_HEX))

    def encrypt_message(self, message_dict):
        plaintext = json.dumps(message_dict).encode('utf-8')
        nonce = os.urandom(12)
        ciphertext = self.aesgcm.encrypt(nonce, plaintext, None)
        return json.dumps({
            'iv': base64.b64encode(nonce).decode('utf-8'),
            'data': base64.b64encode(ciphertext).decode('utf-8')
        })

    def decrypt_message(self, payload_str):
        try:
            payload = json.loads(payload_str)
            if 'iv' not in payload or 'data' not in payload:
                return None
            nonce = base64.b64decode(payload['iv'])
            ciphertext = base64.b64decode(payload['data'])
            plaintext = self.aesgcm.decrypt(nonce, ciphertext, None)
            return json.loads(plaintext.decode('utf-8'))
        except (InvalidTag, json.JSONDecodeError, KeyError, ValueError) as e:
            logger.error(f"Decryption or parsing failed: {e}")
            return None

class ClipSyncWindows:
    def __init__(self):
        self.port = PORT
        self.zeroconf = Zeroconf(ip_version=IPVersion.V4Only)
        self.connected_peers = set()
        self.active_websockets = set()
        self.last_clipboard = ""
        self.loop = asyncio.get_event_loop()
        self.security = SecurityManager()
        self.seen_nonces = {}  # {nonce_str: timestamp} for TTL-based eviction



    def _evict_expired_nonces(self):
        """Remove nonces older than 60 seconds from the cache."""
        now = time.time()
        expired = [n for n, ts in self.seen_nonces.items() if now - ts > 60]
        for n in expired:
            del self.seen_nonces[n]

    async def handle_client(self, websocket):
        authenticated = False
        try:
            # Send hello with timestamp, nonce, and fingerprint
            hello_payload = {
                'type': 'hello', 
                'deviceId': DEVICE_ID,
                'timestamp': int(time.time()),
                'nonce': str(uuid.uuid4()),
                'fingerprint': NETWORK_FINGERPRINT
            }
            encrypted_hello = self.security.encrypt_message(hello_payload)
            await websocket.send(encrypted_hello)
            
            # Auth Handshake with 2-second timeout
            try:
                first_message = await asyncio.wait_for(websocket.recv(), timeout=2.0)
                data = self.security.decrypt_message(first_message)
                if not data or data.get('type') != 'hello':
                    logger.warning("Peer failed auth handshake: Invalid payload")
                    await websocket.send(json.dumps({"status": "rejected", "reason": "invalid_payload"}))
                    return
                
                # Replay Protection: Timestamp check (30 seconds)
                ts = data.get('timestamp', 0)
                if abs(time.time() - ts) > 30:
                    logger.warning("Peer failed auth handshake: Timestamp expired")
                    await websocket.send(json.dumps({"status": "rejected", "reason": "timestamp_expired"}))
                    return
                
                # Replay Protection: Nonce cache with TTL-based eviction
                self._evict_expired_nonces()
                nonce = data.get('nonce')
                if not nonce or nonce in self.seen_nonces:
                    logger.warning("Peer failed auth handshake: Nonce reused")
                    await websocket.send(json.dumps({"status": "rejected", "reason": "nonce_reused"}))
                    return
                self.seen_nonces[nonce] = time.time()

                # Fingerprint verification
                if data.get('fingerprint') != NETWORK_FINGERPRINT:
                    logger.warning("Peer failed auth handshake: Invalid fingerprint")
                    await websocket.send(json.dumps({"status": "rejected", "reason": "invalid_fingerprint"}))
                    return

                peer_id = data.get('deviceId')
                logger.info(f"Securely connected to peer: {peer_id}")
            except asyncio.TimeoutError:
                logger.warning("Peer auth handshake timed out")
                return
            
            # === AUTH PASSED — only NOW add to broadcast pool ===
            authenticated = True
            self.active_websockets.add(websocket)

            async for encrypted_message in websocket:
                data = self.security.decrypt_message(encrypted_message)
                if not data:
                    continue # Drop invalid/unauthenticated messages
                
                if data.get('type') == 'clipboard':
                    text = data.get('text')
                    if text and text != self.last_clipboard:
                        logger.info(f"Received secure clipboard from peer: {text[:20]}...")
                        self.last_clipboard = text
                        pyperclip.copy(text)
        finally:
            if authenticated:
                self.active_websockets.discard(websocket)

    async def connect_to_peer(self, host, port):
        uri = f"wss://{host}:{port}"
        try:
            client_ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            client_ssl_context.check_hostname = False
            client_ssl_context.verify_mode = ssl.CERT_NONE
            
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
                
                fingerprint = info.properties.get(b'fingerprint', b'').decode()
                if fingerprint != NETWORK_FINGERPRINT:
                    logger.warning(f"Discovered peer {host}:{port} with invalid fingerprint. Ignoring.")
                    return
                
                if port == self.port and host == self.get_local_ip():
                    return

                logger.info(f"Discovered trusted peer at {host}:{port}")
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
        info = ServiceInfo(
            SERVICE_TYPE,
            f"ClipSync Windows-{DEVICE_ID[:4]}.{SERVICE_TYPE}",
            addresses=[socket.inet_aton(local_ip)],
            port=self.port,
            properties={'fingerprint': NETWORK_FINGERPRINT},
            server=f"{socket.gethostname().replace('.','')}.local.",
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

        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
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
        logger.info(f"TLS cert generated: SAN includes IP:{local_ip}, validity=1yr")

    async def main_async(self):
        self.start_mDNS()
        
        watcher_thread = threading.Thread(target=self.clipboard_watcher_sync, daemon=True)
        watcher_thread.start()

        # Auto-regenerate cert if SAN IP doesn't match current LAN IP (CS-009)
        self._ensure_cert_matches_ip()

        logger.info(f"Starting Secure WSS server on port {self.port}...")
        ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ssl_context.load_cert_chain(certfile='tls_cert.pem', keyfile='tls_key.pem')
        
        async with serve(self.handle_client, "0.0.0.0", self.port, ssl=ssl_context):
            await asyncio.Future()

if __name__ == "__main__":
    sync = ClipSyncWindows()
    try:
        sync.loop.run_until_complete(sync.main_async())
    except KeyboardInterrupt:
        logger.info("Shutting down...")
    finally:
        sync.zeroconf.close()
