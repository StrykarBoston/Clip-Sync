"""
ClipSync v3.0 — Chunked File Transfer Protocol
Handles sending and receiving of large files in encrypted 1MB chunks.

OWASP A06 (Insecure Design) + A08 (Integrity Failures) compliant.
"""

import base64
import hashlib
import logging
import mimetypes
import os
import platform
import sys
import time
import uuid
from dataclasses import dataclass, field
from typing import Callable, Generator, Optional

from .content_filter import (
    is_blocked_file,
    sanitize_filename,
    validate_file_size,
)
from .security import SecurityManager

logger = logging.getLogger("clipsync.file_transfer")

CHUNK_SIZE = 1 * 1024 * 1024  # 1 MB per chunk


def _get_save_directory() -> str:
    """Get the platform-specific save directory for received files."""
    if sys.platform == "win32":
        # Windows → Downloads folder
        save_dir = os.path.join(os.path.expanduser("~"), "Downloads", "ClipSync")
    else:
        # Linux → Documents folder
        save_dir = os.path.join(os.path.expanduser("~"), "Documents", "ClipSync")
    os.makedirs(save_dir, exist_ok=True)
    return save_dir


def _get_mime_type(filepath: str) -> str:
    """Detect MIME type of a file."""
    mime, _ = mimetypes.guess_type(filepath)
    if mime:
        return mime
    # Fallback: try python-magic if available
    try:
        import magic
        return magic.from_file(filepath, mime=True)
    except (ImportError, Exception):
        return "application/octet-stream"


@dataclass
class TransferState:
    """Tracks the state of an in-progress file transfer."""
    transfer_id: str
    filename: str
    total_size: int
    expected_hash: str
    mime_type: str
    chunk_count: int
    received_chunks: dict = field(default_factory=dict)
    start_time: float = field(default_factory=time.time)
    completed: bool = False
    save_path: str = ""

    @property
    def received_size(self) -> int:
        return sum(len(c) for c in self.received_chunks.values())

    @property
    def progress(self) -> float:
        if self.chunk_count == 0:
            return 0.0
        return len(self.received_chunks) / self.chunk_count * 100

    @property
    def is_complete(self) -> bool:
        return len(self.received_chunks) == self.chunk_count


class FileTransferManager:
    """Manages sending and receiving of files via the ClipSync mesh."""

    def __init__(self, security: SecurityManager):
        self.security = security
        self.active_transfers: dict[str, TransferState] = {}
        self.completed_transfers: list[dict] = []
        self.on_progress: Optional[Callable[[str, float, str], None]] = None
        self.on_file_received: Optional[Callable[[str, str], None]] = None
        self.on_transfer_started: Optional[Callable[[str, str, int, str], None]] = None

    # ── Sending ──────────────────────────────────────────────────────────

    def create_send_messages(self, filepath: str) -> Generator[dict, None, None]:
        """
        Generator that yields encrypted messages for a file transfer.
        Yields: file_start, file_chunk(s), file_complete
        """
        if not os.path.exists(filepath):
            logger.error(f"File not found: {filepath}")
            return

        filename = os.path.basename(filepath)
        file_size = os.path.getsize(filepath)

        # Security checks
        if is_blocked_file(filename):
            logger.warning(f"Blocked file type: {filename}")
            return
        if not validate_file_size(file_size):
            logger.warning(f"File too large: {filename} ({file_size} bytes)")
            return

        transfer_id = str(uuid.uuid4())
        file_hash = self.security.compute_file_hash(filepath)
        mime_type = _get_mime_type(filepath)
        chunk_count = (file_size + CHUNK_SIZE - 1) // CHUNK_SIZE  # ceiling division

        # 1. file_start message
        yield {
            "type": "file_start",
            "transfer_id": transfer_id,
            "filename": sanitize_filename(filename),
            "size": file_size,
            "hash": file_hash,
            "mime_type": mime_type,
            "chunk_count": chunk_count,
        }

        # 2. file_chunk messages
        with open(filepath, "rb") as f:
            chunk_index = 0
            while True:
                chunk_data = f.read(CHUNK_SIZE)
                if not chunk_data:
                    break
                yield {
                    "type": "file_chunk",
                    "transfer_id": transfer_id,
                    "chunk_index": chunk_index,
                    "data": base64.b64encode(chunk_data).decode("utf-8"),
                }
                chunk_index += 1

        # 3. file_complete message
        yield {
            "type": "file_complete",
            "transfer_id": transfer_id,
            "hash": file_hash,
        }

        logger.info(
            f"File transfer prepared: {filename} "
            f"({file_size / 1024:.1f} KB, {chunk_count} chunks)"
        )

    def create_image_message(self, image_data: bytes, fmt: str = "png") -> dict:
        """Create a clipboard_image message from raw image bytes."""
        image_hash = self.security.compute_bytes_hash(image_data)
        return {
            "type": "clipboard_image",
            "format": fmt,
            "size": len(image_data),
            "hash": image_hash,
            "data": base64.b64encode(image_data).decode("utf-8"),
        }

    # ── Receiving ────────────────────────────────────────────────────────

    def handle_file_start(self, data: dict) -> bool:
        """Handle incoming file_start message. Returns True if accepted."""
        transfer_id = data.get("transfer_id")
        filename = sanitize_filename(data.get("filename", "unnamed"))
        total_size = data.get("size", 0)
        expected_hash = data.get("hash", "")
        mime_type = data.get("mime_type", "")
        chunk_count = data.get("chunk_count", 0)

        # Security validations
        if is_blocked_file(filename):
            logger.warning(f"Rejecting blocked file type: {filename}")
            return False
        if not validate_file_size(total_size):
            logger.warning(f"Rejecting oversized file: {filename}")
            return False

        save_dir = _get_save_directory()
        save_path = os.path.join(save_dir, filename)

        # Avoid overwriting — append number if file exists
        base, ext = os.path.splitext(save_path)
        counter = 1
        while os.path.exists(save_path):
            save_path = f"{base}_{counter}{ext}"
            counter += 1

        state = TransferState(
            transfer_id=transfer_id,
            filename=filename,
            total_size=total_size,
            expected_hash=expected_hash,
            mime_type=mime_type,
            chunk_count=chunk_count,
            save_path=save_path,
        )
        self.active_transfers[transfer_id] = state

        logger.info(
            f"File transfer started: {filename} "
            f"({total_size / 1024:.1f} KB, {chunk_count} chunks)"
        )

        if self.on_transfer_started:
            self.on_transfer_started(transfer_id, filename, total_size, "receiving")

        return True

    def handle_file_chunk(self, data: dict) -> float:
        """Handle incoming file_chunk message. Returns progress percentage."""
        transfer_id = data.get("transfer_id")
        state = self.active_transfers.get(transfer_id)
        if not state:
            logger.warning(f"Chunk for unknown transfer: {transfer_id}")
            return -1

        chunk_index = data.get("chunk_index", -1)
        chunk_data = base64.b64decode(data.get("data", ""))
        state.received_chunks[chunk_index] = chunk_data

        progress = state.progress
        if self.on_progress:
            self.on_progress(transfer_id, progress, state.filename)

        return progress

    def handle_file_complete(self, data: dict) -> Optional[str]:
        """
        Handle incoming file_complete message.
        Assembles chunks, verifies hash, saves to disk.
        Returns save path on success, None on failure.
        """
        transfer_id = data.get("transfer_id")
        state = self.active_transfers.get(transfer_id)
        if not state:
            logger.warning(f"Complete for unknown transfer: {transfer_id}")
            return None

        expected_hash = data.get("hash", state.expected_hash)

        # Assemble chunks in order
        assembled = b""
        for i in range(state.chunk_count):
            chunk = state.received_chunks.get(i)
            if chunk is None:
                logger.error(f"Missing chunk {i} for transfer {transfer_id}")
                del self.active_transfers[transfer_id]
                return None
            assembled += chunk

        # Verify integrity (SHA-256)
        if not self.security.verify_hash(assembled, expected_hash):
            logger.error(f"Hash mismatch for {state.filename}! Transfer corrupted.")
            del self.active_transfers[transfer_id]
            return None

        # Write to disk
        try:
            with open(state.save_path, "wb") as f:
                f.write(assembled)
            state.completed = True
            elapsed = time.time() - state.start_time
            logger.info(
                f"File received: {state.filename} → {state.save_path} "
                f"({len(assembled) / 1024:.1f} KB in {elapsed:.1f}s)"
            )

            # Track in history
            self.completed_transfers.append({
                "transfer_id": transfer_id,
                "filename": state.filename,
                "size": len(assembled),
                "direction": "received",
                "save_path": state.save_path,
                "timestamp": time.time(),
                "hash": expected_hash,
            })

            if self.on_file_received:
                self.on_file_received(state.save_path, state.filename)

            return state.save_path
        except Exception as e:
            logger.error(f"Failed to save file {state.filename}: {e}")
            return None
        finally:
            del self.active_transfers[transfer_id]

    def handle_clipboard_image(self, data: dict) -> Optional[bytes]:
        """
        Handle incoming clipboard_image message.
        Verifies hash and returns raw image bytes.
        Also saves to disk.
        """
        image_data = base64.b64decode(data.get("data", ""))
        expected_hash = data.get("hash", "")
        fmt = data.get("format", "png")

        if not image_data:
            return None

        # Verify integrity
        if expected_hash and not self.security.verify_hash(image_data, expected_hash):
            logger.error("Image hash mismatch! Rejecting.")
            return None

        # Save image to disk
        save_dir = _get_save_directory()
        timestamp = int(time.time())
        filename = f"clipboard_image_{timestamp}.{fmt}"
        save_path = os.path.join(save_dir, filename)
        try:
            with open(save_path, "wb") as f:
                f.write(image_data)
            logger.info(f"Clipboard image saved: {save_path} ({len(image_data)} bytes)")

            self.completed_transfers.append({
                "transfer_id": str(uuid.uuid4()),
                "filename": filename,
                "size": len(image_data),
                "direction": "received",
                "save_path": save_path,
                "timestamp": time.time(),
                "hash": expected_hash,
            })
        except Exception as e:
            logger.error(f"Failed to save clipboard image: {e}")

        return image_data

    def get_transfer_history(self) -> list[dict]:
        """Get all completed + active transfers for the GUI."""
        history = list(self.completed_transfers)
        for tid, state in self.active_transfers.items():
            history.append({
                "transfer_id": tid,
                "filename": state.filename,
                "size": state.total_size,
                "direction": "receiving",
                "progress": state.progress,
                "timestamp": state.start_time,
            })
        return sorted(history, key=lambda x: x.get("timestamp", 0), reverse=True)
