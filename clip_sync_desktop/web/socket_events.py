"""
ClipSync v3.0 — Flask-SocketIO Event Handlers
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


# ── Emit Functions (called from sync engine) ─────────────────────────────

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


def emit_transfer_progress(transfer_id: str, filename: str, progress: float, status: str, direction: str = "receiving"):
    """Emit file transfer progress."""
    if socketio:
        socketio.emit("transfer_progress", {
            "transfer_id": transfer_id,
            "filename": filename,
            "progress": progress,
            "status": status,
            "direction": direction,
        })


def emit_clipboard_update(content_type: str, content: str):
    """Emit clipboard update preview."""
    if socketio:
        socketio.emit("clipboard_update", {
            "type": content_type,
            "content": content[:200],  # Truncate for preview
            "timestamp": time.strftime("%H:%M:%S"),
        })


def emit_stats_update(peers_count: int, syncs_today: int, uptime: int, active_transfers: int):
    """Emit dashboard stats update."""
    if socketio:
        socketio.emit("stats_update", {
            "peers_count": peers_count,
            "syncs_today": syncs_today,
            "uptime": uptime,
            "active_transfers": active_transfers,
        })


def emit_security_alert(message: str, severity: str = "warning"):
    """Emit a security alert to the dashboard."""
    if socketio:
        socketio.emit("security_alert", {
            "message": message,
            "severity": severity,
            "timestamp": time.strftime("%H:%M:%S"),
        })


# ── Log Handler (bridges Python logging → SocketIO) ─────────────────────

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
