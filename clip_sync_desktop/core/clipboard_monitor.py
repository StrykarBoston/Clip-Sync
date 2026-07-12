"""
ClipSync v3.0 — Clipboard Monitor
Cross-platform clipboard monitoring for text, images, and files.
Auto-detects Windows vs Linux and uses the appropriate system APIs.
"""

import io
import logging
import os
import platform
import subprocess
import sys
import threading
import time
from typing import Callable, Optional

logger = logging.getLogger("clipsync.clipboard")

# ── Platform detection ───────────────────────────────────────────────────

IS_WINDOWS = sys.platform == "win32"
IS_LINUX = sys.platform == "linux"


class ClipboardMonitor:
    """
    Monitors the system clipboard for text, images, and file changes.
    Runs in a background daemon thread polling every 0.5s.
    """

    def __init__(self):
        self._last_text: str = ""
        self._last_image_hash: str = ""
        self._running = False
        self._thread: Optional[threading.Thread] = None

        # Callbacks
        self.on_text_changed: Optional[Callable[[str], None]] = None
        self.on_image_changed: Optional[Callable[[bytes, str], None]] = None
        self.on_files_changed: Optional[Callable[[list[str]], None]] = None

    def start(self):
        """Start the clipboard monitoring thread."""
        if self._running:
            return
        self._running = True
        self._thread = threading.Thread(target=self._poll_loop, daemon=True)
        self._thread.start()
        logger.info(f"Clipboard monitor started (platform: {platform.system()})")

    def stop(self):
        """Stop the clipboard monitoring thread."""
        self._running = False
        if self._thread:
            self._thread.join(timeout=2)
        logger.info("Clipboard monitor stopped")

    def _poll_loop(self):
        """Main polling loop — checks clipboard every 0.5 seconds."""
        while self._running:
            try:
                self._check_clipboard()
            except Exception as e:
                logger.debug(f"Clipboard poll error: {e}")
            time.sleep(0.5)

    def _check_clipboard(self):
        """Check for text, image, and file changes on clipboard."""
        # 1. Check for image first (higher priority)
        image_data = self._get_clipboard_image()
        if image_data:
            import hashlib
            img_hash = hashlib.md5(image_data).hexdigest()
            if img_hash != self._last_image_hash:
                self._last_image_hash = img_hash
                logger.info(f"Clipboard image changed ({len(image_data)} bytes)")
                if self.on_image_changed:
                    self.on_image_changed(image_data, "png")
                return

        # 2. Check for files
        files = self._get_clipboard_files()
        if files:
            # We don't track "last files" since file lists can repeat
            logger.info(f"Clipboard files detected: {len(files)} file(s)")
            if self.on_files_changed:
                self.on_files_changed(files)
            return

        # 3. Check for text
        text = self._get_clipboard_text()
        if text and text != self._last_text and text.strip():
            self._last_text = text
            if self.on_text_changed:
                self.on_text_changed(text)

    # ── Text Clipboard ───────────────────────────────────────────────────

    def _get_clipboard_text(self) -> str:
        """Get text from clipboard (cross-platform)."""
        try:
            import pyperclip
            return pyperclip.paste()
        except Exception:
            return ""

    def set_clipboard_text(self, text: str):
        """Set text to clipboard (cross-platform)."""
        try:
            import pyperclip
            self._last_text = text  # Prevent feedback loop
            pyperclip.copy(text)
        except Exception as e:
            logger.error(f"Failed to set clipboard text: {e}")

    # ── Image Clipboard ──────────────────────────────────────────────────

    def _get_clipboard_image(self) -> Optional[bytes]:
        """Get image from clipboard as PNG bytes."""
        if IS_WINDOWS:
            return self._get_clipboard_image_windows()
        elif IS_LINUX:
            return self._get_clipboard_image_linux()
        return None

    def _get_clipboard_image_windows(self) -> Optional[bytes]:
        """Get clipboard image on Windows using Pillow."""
        try:
            from PIL import ImageGrab
            img = ImageGrab.grabclipboard()
            if img is None:
                return None
            # img could be a PIL Image or a list of file paths
            if isinstance(img, list):
                return None  # File paths, not image data
            buf = io.BytesIO()
            img.save(buf, format="PNG")
            return buf.getvalue()
        except ImportError:
            logger.debug("Pillow not available for image clipboard")
            return None
        except Exception:
            return None

    def _get_clipboard_image_linux(self) -> Optional[bytes]:
        """Get clipboard image on Linux using xclip."""
        try:
            result = subprocess.run(
                ["xclip", "-selection", "clipboard", "-t", "image/png", "-o"],
                capture_output=True,
                timeout=2,
            )
            if result.returncode == 0 and result.stdout:
                return result.stdout
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass
        return None

    def set_clipboard_image(self, image_data: bytes):
        """Set image to clipboard."""
        if IS_WINDOWS:
            self._set_clipboard_image_windows(image_data)
        elif IS_LINUX:
            self._set_clipboard_image_linux(image_data)

    def _set_clipboard_image_windows(self, image_data: bytes):
        """Set clipboard image on Windows using Pillow."""
        try:
            from PIL import Image
            import hashlib
            self._last_image_hash = hashlib.md5(image_data).hexdigest()
            img = Image.open(io.BytesIO(image_data))
            # Use win32clipboard to set the image
            import ctypes
            import ctypes.wintypes
            from io import BytesIO

            output = BytesIO()
            img.convert("RGB").save(output, "BMP")
            bmp_data = output.getvalue()[14:]  # Strip BMP header

            CF_DIB = 8
            kernel32 = ctypes.windll.kernel32
            user32 = ctypes.windll.user32

            user32.OpenClipboard(0)
            user32.EmptyClipboard()
            h_mem = kernel32.GlobalAlloc(0x0042, len(bmp_data))
            ptr = kernel32.GlobalLock(h_mem)
            ctypes.memmove(ptr, bmp_data, len(bmp_data))
            kernel32.GlobalUnlock(h_mem)
            user32.SetClipboardData(CF_DIB, h_mem)
            user32.CloseClipboard()
            logger.info("Image set to Windows clipboard")
        except Exception as e:
            logger.error(f"Failed to set Windows clipboard image: {e}")

    def _set_clipboard_image_linux(self, image_data: bytes):
        """Set clipboard image on Linux using xclip."""
        try:
            import hashlib
            self._last_image_hash = hashlib.md5(image_data).hexdigest()
            process = subprocess.Popen(
                ["xclip", "-selection", "clipboard", "-t", "image/png", "-i"],
                stdin=subprocess.PIPE,
            )
            process.communicate(input=image_data, timeout=5)
            logger.info("Image set to Linux clipboard")
        except Exception as e:
            logger.error(f"Failed to set Linux clipboard image: {e}")

    # ── File Clipboard ───────────────────────────────────────────────────

    def _get_clipboard_files(self) -> list[str]:
        """Get file paths from clipboard."""
        if IS_WINDOWS:
            return self._get_clipboard_files_windows()
        elif IS_LINUX:
            return self._get_clipboard_files_linux()
        return []

    def _get_clipboard_files_windows(self) -> list[str]:
        """Get file paths from Windows clipboard."""
        try:
            import ctypes
            import ctypes.wintypes

            CF_HDROP = 15
            user32 = ctypes.windll.user32
            shell32 = ctypes.windll.shell32

            if not user32.OpenClipboard(0):
                return []
            try:
                if not user32.IsClipboardFormatAvailable(CF_HDROP):
                    return []
                h_drop = user32.GetClipboardData(CF_HDROP)
                if not h_drop:
                    return []

                file_count = shell32.DragQueryFileW(h_drop, 0xFFFFFFFF, None, 0)
                files = []
                for i in range(file_count):
                    buf_size = shell32.DragQueryFileW(h_drop, i, None, 0) + 1
                    buf = ctypes.create_unicode_buffer(buf_size)
                    shell32.DragQueryFileW(h_drop, i, buf, buf_size)
                    path = buf.value
                    if os.path.exists(path) and os.path.isfile(path):
                        files.append(path)
                return files
            finally:
                user32.CloseClipboard()
        except Exception:
            return []

    def _get_clipboard_files_linux(self) -> list[str]:
        """Get file paths from Linux clipboard (file:// URIs)."""
        try:
            result = subprocess.run(
                ["xclip", "-selection", "clipboard", "-t", "text/uri-list", "-o"],
                capture_output=True,
                text=True,
                timeout=2,
            )
            if result.returncode != 0 or not result.stdout:
                return []
            files = []
            for line in result.stdout.strip().split("\n"):
                line = line.strip()
                if line.startswith("file://"):
                    path = line[7:]  # Remove file:// prefix
                    # URL decode
                    from urllib.parse import unquote
                    path = unquote(path)
                    if os.path.exists(path) and os.path.isfile(path):
                        files.append(path)
            return files
        except Exception:
            return []
