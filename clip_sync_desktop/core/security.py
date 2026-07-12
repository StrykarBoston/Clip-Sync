"""
ClipSync v3.0 — Security Manager
AES-256-GCM encryption with HKDF key derivation, HMAC challenge auth,
and SHA-256 file integrity verification.

OWASP A04 (Cryptographic Failures) compliant.
"""

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
    """Handles all cryptographic operations for ClipSync."""

    def __init__(self, shared_secret_hex: str):
        if not shared_secret_hex or len(shared_secret_hex) != 64:
            raise ValueError("SECRET_KEY must be a 64-character hex string (256 bits).")
        raw_key = bytes.fromhex(shared_secret_hex)
        # HKDF key derivation — never use raw key directly
        derived_key = HKDF(
            algorithm=SHA256(),
            length=32,
            salt=None,
            info=b"clipsync-e2ee",
        ).derive(raw_key)
        self.aesgcm = AESGCM(derived_key)
        self._secret_hex = shared_secret_hex
        logger.info("SecurityManager initialized with HKDF-derived AES-256-GCM key.")

    # ── Encryption / Decryption ──────────────────────────────────────────

    def encrypt_message(self, message_dict: dict) -> str:
        """Encrypt a dict payload → JSON string with {iv, data, aad}."""
        msg_type = message_dict.get("type", "unknown")
        aad = msg_type.encode("utf-8")
        plaintext = json.dumps(message_dict, separators=(",", ":")).encode("utf-8")
        nonce = os.urandom(12)  # 96-bit CSPRNG nonce
        ciphertext = self.aesgcm.encrypt(nonce, plaintext, aad)
        return json.dumps({
            "iv": base64.b64encode(nonce).decode("utf-8"),
            "data": base64.b64encode(ciphertext).decode("utf-8"),
            "aad": msg_type,
        })

    def decrypt_message(self, payload_str: str) -> dict | None:
        """Decrypt a JSON payload → dict, or None on failure."""
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
            logger.error(f"Decryption failed: {e}")
            return None

    # ── Encrypt raw binary data (for images/files) ───────────────────────

    def encrypt_binary(self, data: bytes, aad_type: str = "binary") -> dict:
        """Encrypt raw binary data → dict with {iv, data, aad}."""
        aad = aad_type.encode("utf-8")
        nonce = os.urandom(12)
        ciphertext = self.aesgcm.encrypt(nonce, data, aad)
        return {
            "iv": base64.b64encode(nonce).decode("utf-8"),
            "data": base64.b64encode(ciphertext).decode("utf-8"),
            "aad": aad_type,
        }

    def decrypt_binary(self, payload: dict) -> bytes | None:
        """Decrypt binary payload → bytes, or None on failure."""
        try:
            nonce = base64.b64decode(payload["iv"])
            ciphertext = base64.b64decode(payload["data"])
            aad = payload.get("aad", "binary").encode("utf-8")
            return self.aesgcm.decrypt(nonce, ciphertext, aad)
        except (InvalidTag, KeyError, ValueError) as e:
            logger.error(f"Binary decryption failed: {e}")
            return None

    # ── HMAC Network Challenge (5-minute time windows) ───────────────────

    def compute_network_challenge(self) -> str:
        """Compute HMAC-SHA256 challenge for the current 5-minute window."""
        time_window = int(time.time()) // 300
        msg = f"clipsync-challenge:{time_window}".encode("utf-8")
        return hmac.new(
            self._secret_hex.encode("utf-8"), msg, hashlib.sha256
        ).hexdigest()[:16]

    def verify_network_challenge(self, challenge: str) -> bool:
        """Verify challenge against current and previous time window."""
        current = self.compute_network_challenge()
        if hmac.compare_digest(challenge, current):
            return True
        # Previous window for clock-skew tolerance
        prev_window = (int(time.time()) // 300) - 1
        prev_msg = f"clipsync-challenge:{prev_window}".encode("utf-8")
        prev_challenge = hmac.new(
            self._secret_hex.encode("utf-8"), prev_msg, hashlib.sha256
        ).hexdigest()[:16]
        return hmac.compare_digest(challenge, prev_challenge)

    # ── File Integrity (SHA-256) ─────────────────────────────────────────

    @staticmethod
    def compute_file_hash(filepath: str) -> str:
        """Compute SHA-256 hash of a file."""
        sha256 = hashlib.sha256()
        with open(filepath, "rb") as f:
            while True:
                chunk = f.read(65536)
                if not chunk:
                    break
                sha256.update(chunk)
        return f"sha256:{sha256.hexdigest()}"

    @staticmethod
    def compute_bytes_hash(data: bytes) -> str:
        """Compute SHA-256 hash of raw bytes."""
        return f"sha256:{hashlib.sha256(data).hexdigest()}"

    @staticmethod
    def verify_hash(data: bytes, expected_hash: str) -> bool:
        """Verify data integrity against expected SHA-256 hash."""
        actual = f"sha256:{hashlib.sha256(data).hexdigest()}"
        return hmac.compare_digest(actual, expected_hash)
