"""Clipboard monitor for text-only clipboard sync."""

import logging
import platform
import sys
import threading
import time
from typing import Callable, Optional

logger = logging.getLogger("clipsync.clipboard")

IS_WINDOWS = sys.platform == "win32"
IS_LINUX = sys.platform == "linux"


class ClipboardMonitor:
    """Monitors the system clipboard for text changes only."""

    def __init__(self):
        self._last_text: str = ""
        self._running = False
        self._thread: Optional[threading.Thread] = None
        self.on_text_changed: Optional[Callable[[str], None]] = None

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
        """Main polling loop checks clipboard every 0.5 seconds."""
        while self._running:
            try:
                self._check_clipboard()
            except Exception as e:
                logger.debug(f"Clipboard poll error: {e}")
            time.sleep(0.5)

    def _check_clipboard(self):
        """Check for text changes on clipboard."""
        text = self._get_clipboard_text()
        if text and text != self._last_text and text.strip():
            self._last_text = text
            if self.on_text_changed:
                self.on_text_changed(text)

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
            self._last_text = text
            pyperclip.copy(text)
        except Exception as e:
            logger.error(f"Failed to set clipboard text: {e}")

