import asyncio
import json
import logging
import socket
import threading
import time
import uuid
import os
import base64

import pyperclip
import websockets
from websockets import serve
from zeroconf import IPVersion, ServiceBrowser, ServiceInfo, Zeroconf
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag
from dotenv import load_dotenv

load_dotenv()

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

SERVICE_TYPE = "_clipsync._tcp.local."
DEVICE_ID = str(uuid.uuid4())
SHARED_SECRET_HEX = os.environ.get("SECRET_KEY")

if not SHARED_SECRET_HEX:
    logger.error("SECRET_KEY not found in .env file! Exiting.")
    sys.exit(1)

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
        self.port = self.get_free_port()
        self.zeroconf = Zeroconf(ip_version=IPVersion.V4Only)
        self.connected_peers = set()
        self.active_websockets = set()
        self.last_clipboard = ""
        self.loop = asyncio.get_event_loop()
        self.security = SecurityManager()

    def get_free_port(self):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind(('', 0))
            return s.getsockname()[1]

    async def handle_client(self, websocket):
        self.active_websockets.add(websocket)
        try:
            # Send hello
            encrypted_hello = self.security.encrypt_message({'type': 'hello', 'deviceId': DEVICE_ID})
            await websocket.send(encrypted_hello)
            
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
                elif data.get('type') == 'hello':
                    peer_id = data.get('deviceId')
                    logger.info(f"Securely connected to peer: {peer_id}")
        finally:
            self.active_websockets.remove(websocket)

    async def connect_to_peer(self, host, port):
        uri = f"ws://{host}:{port}"
        try:
            async with websockets.connect(uri) as websocket:
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
                
                if port == self.port:
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
        info = ServiceInfo(
            SERVICE_TYPE,
            f"ClipSync Windows-{DEVICE_ID[:4]}.{SERVICE_TYPE}",
            addresses=[socket.inet_aton(local_ip)],
            port=self.port,
            properties={},
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
                    self.last_clipboard = current_clipboard
                    logger.info(f"Local clipboard changed, broadcasting securely: {current_clipboard[:20]}...")
                    asyncio.run_coroutine_threadsafe(self.broadcast_clipboard(current_clipboard), self.loop)
            except Exception as e:
                pass
            time.sleep(0.5)

    async def main_async(self):
        self.start_mDNS()
        
        watcher_thread = threading.Thread(target=self.clipboard_watcher_sync, daemon=True)
        watcher_thread.start()

        logger.info(f"Starting Secure WebSocket server on port {self.port}...")
        async with serve(self.handle_client, "0.0.0.0", self.port):
            await asyncio.Future()

if __name__ == "__main__":
    sync = ClipSyncWindows()
    try:
        sync.loop.run_until_complete(sync.main_async())
    except KeyboardInterrupt:
        logger.info("Shutting down...")
    finally:
        sync.zeroconf.close()
