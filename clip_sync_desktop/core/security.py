"""Cryptography for text clipboard synchronization."""

import base64
import hashlib
import hmac
import json
import logging
import os
import time

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

logger = logging.getLogger("clipsync.security")


class SecurityManager:
    """Encrypt text messages and authenticate LAN peers."""

    def __init__(self, shared_secret_hex: str):
        if not shared_secret_hex or len(shared_secret_hex) != 64:
            raise ValueError("SECRET_KEY must be a 64-character hex string (256 bits).")
        raw_key = bytes.fromhex(shared_secret_hex)
        derived_key = HKDF(
            algorithm=SHA256(),
            length=32,
            salt=None,
            info=b"clipsync-e2ee",
        ).derive(raw_key)
        self.aesgcm = AESGCM(derived_key)
        self._secret_hex = shared_secret_hex

    def encrypt_message(self, message_dict: dict) -> str:
        """Encrypt a JSON message with AES-256-GCM."""
        msg_type = message_dict.get("type", "unknown")
        aad = msg_type.encode("utf-8")
        plaintext = json.dumps(message_dict, separators=(",", ":")).encode("utf-8")
        nonce = os.urandom(12)
        ciphertext = self.aesgcm.encrypt(nonce, plaintext, aad)
        return json.dumps({
            "iv": base64.b64encode(nonce).decode("utf-8"),
            "data": base64.b64encode(ciphertext).decode("utf-8"),
            "aad": msg_type,
        })

    def decrypt_message(self, payload_str: str) -> dict | None:
        """Decrypt a JSON message, returning None for invalid payloads."""
        try:
            payload = json.loads(payload_str)
            if "iv" not in payload or "data" not in payload:
                return None
            nonce = base64.b64decode(payload["iv"])
            ciphertext = base64.b64decode(payload["data"])
            aad = payload.get("aad", "unknown").encode("utf-8")
            plaintext = self.aesgcm.decrypt(nonce, ciphertext, aad)
            return json.loads(plaintext.decode("utf-8"))
        except (InvalidTag, json.JSONDecodeError, KeyError, ValueError) as e:
            logger.error("Decryption failed: %s", e)
            return None

    def compute_network_challenge(self) -> str:
        """Compute an HMAC challenge for the current five-minute window."""
        time_window = int(time.time()) // 300
        msg = f"clipsync-challenge:{time_window}".encode("utf-8")
        return hmac.new(self._secret_hex.encode("utf-8"), msg, hashlib.sha256).hexdigest()[:16]

    def verify_network_challenge(self, challenge: str) -> bool:
        """Verify the current or immediately previous challenge window."""
        if hmac.compare_digest(challenge, self.compute_network_challenge()):
            return True
        previous_window = (int(time.time()) // 300) - 1
        message = f"clipsync-challenge:{previous_window}".encode("utf-8")
        expected = hmac.new(
            self._secret_hex.encode("utf-8"), message, hashlib.sha256
        ).hexdigest()[:16]
        return hmac.compare_digest(challenge, expected)
