"""
ClipSync v3.0 â€” Flask-SocketIO Event Handlers
Real-time event streaming from the sync engine to the web dashboard.
"""

import logging
import time
from typing import Optional

from flask_socketio import SocketIO

logger = logging.getLogger("clipsync.web.socket")

socketio: Optional[SocketIO] = None


def init_socketio(sio: SocketIO):
    """Register the global SocketIO instance."""
    global socketio
    socketio = sio

    @sio.on("connect")
    def handle_connect():
        logger.debug("Browser client connected to SocketIO")
        emit_log("info", "Dashboard connected")

    @sio.on("disconnect")
    def handle_disconnect():
        logger.debug("Browser client disconnected from SocketIO")


# â”€â”€ Emit Functions (called from sync engine) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

def emit_log(level: str, message: str):
    """Emit a log event to the browser dashboard."""
    if socketio:
        socketio.emit("log_event", {
            "timestamp": time.strftime("%H:%M:%S"),
            "level": level,
            "message": message,
        })


def emit_peer_update(peers: list):
    """Emit updated peer list to the dashboard."""
    if socketio:
        socketio.emit("peer_update", {"peers": peers})


def emit_clipboard_update(content_type: str, content: str):
    """Emit clipboard update preview."""
    if socketio:
        socketio.emit("clipboard_update", {
            "type": content_type,
            "content": content[:200],  # Truncate for preview
            "timestamp": time.strftime("%H:%M:%S"),
        })


def emit_stats_update(peers_count: int, syncs_today: int, uptime: int):
    """Emit dashboard stats update."""
    if socketio:
        socketio.emit("stats_update", {
            "peers_count": peers_count,
            "syncs_today": syncs_today,
            "uptime": uptime,
        })


def emit_security_alert(message: str, severity: str = "warning"):
    """Emit a security alert to the dashboard."""
    if socketio:
        socketio.emit("security_alert", {
            "message": message,
            "severity": severity,
            "timestamp": time.strftime("%H:%M:%S"),
        })


# â”€â”€ Log Handler (bridges Python logging â†’ SocketIO) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

class SocketIOLogHandler(logging.Handler):
    """
    Custom logging handler that forwards all ClipSync log messages
    to the browser dashboard via SocketIO in real time.
    """

    LEVEL_MAP = {
        logging.DEBUG: "debug",
        logging.INFO: "info",
        logging.WARNING: "warning",
        logging.ERROR: "error",
        logging.CRITICAL: "critical",
    }

    def emit(self, record):
        try:
            level = self.LEVEL_MAP.get(record.levelno, "info")
            message = self.format(record)
            emit_log(level, message)
        except Exception:
            pass  # Never crash the app due to logging

