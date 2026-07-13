"""
ClipSync v3.0 — Flask App Entry Point
Initializes Flask, SocketIO, and starts the core sync engine in a background thread.
"""

import logging
import os
import sys
import time
from threading import Thread

from dotenv import load_dotenv
from flask import Flask
from flask_socketio import SocketIO

# Load environment variables
load_dotenv()

# Setup root logger (capture everything except werkzeug spam)
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(name)s - %(message)s",
)
logging.getLogger("werkzeug").setLevel(logging.WARNING)
logger = logging.getLogger("clipsync")


def create_app():
    """Create and configure the Flask application."""
    app = Flask(__name__, static_folder="static", template_folder="templates")

    # Initialize OWASP security middleware
    from web.flask_security import init_security
    init_security(app)

    # Initialize SocketIO
    socketio = SocketIO(
        app,
        cors_allowed_origins=["http://localhost:5000", "http://127.0.0.1:5000"],
        async_mode="threading",
    )
    
    from web.socket_events import init_socketio, SocketIOLogHandler
    init_socketio(socketio)

    # Bridge Python logging to SocketIO for real-time dashboard logs
    sio_handler = SocketIOLogHandler()
    sio_handler.setFormatter(logging.Formatter("%(message)s"))
    logging.getLogger("clipsync").addHandler(sio_handler)

    # Register Blueprints
    from web.routes import api, set_engine
    app.register_blueprint(api)

    # Start the core Sync Engine
    secret_key = os.environ.get("SECRET_KEY")
    if not secret_key or len(secret_key) != 64:
        logger.error("SECRET_KEY in .env must be exactly 64 hex characters!")
        sys.exit(1)

    port = int(os.environ.get("PORT", 52300))
    sync_sensitive = os.environ.get("SYNC_SENSITIVE_DATA", "false").lower() == "true"

    from core.sync_engine import ClipSyncEngine
    engine = ClipSyncEngine(
        secret_key=secret_key,
        port=port,
        sync_sensitive=sync_sensitive,
        base_dir=os.path.dirname(os.path.abspath(__file__)),
    )
    set_engine(engine)

    # Wire engine events to SocketIO emitters
    from web.socket_events import (
        emit_peer_update,
        emit_transfer_progress,
        emit_clipboard_update,
        emit_security_alert,
    )
    from web.routes import increment_sync_count

    def on_peer_connected(device_id: str, ip: str):
        emit_peer_update(engine.get_status()["peers"])

    def on_peer_disconnected(device_id: str):
        emit_peer_update(engine.get_status()["peers"])

    def on_transfer_progress(transfer_id: str, progress: float, filename: str):
        emit_transfer_progress(transfer_id, filename, progress, "receiving")

    def on_clipboard_text(text: str):
        increment_sync_count()
        emit_clipboard_update("text", text)

    def on_clipboard_image(image_data: bytes, fmt: str):
        increment_sync_count()
        emit_clipboard_update("image", f"[{fmt.upper()} Image Received - {len(image_data)} bytes]")

    def on_file_received(save_path: str, filename: str):
        increment_sync_count()
        # The transfer_progress event with 100% will trigger UI updates
        emit_transfer_progress(str(time.time()), filename, 100.0, "completed")

    engine.on_peer_connected = on_peer_connected
    engine.on_peer_disconnected = on_peer_disconnected
    engine.file_transfer.on_progress = on_transfer_progress
    engine.on_clipboard_text_received = on_clipboard_text
    engine.on_clipboard_image_received = on_clipboard_image
    engine.on_file_received = on_file_received

    # Override content filter logger to emit security alerts
    class SecurityAlertFilter(logging.Filter):
        def filter(self, record):
            if record.levelno >= logging.WARNING and "Blocked" in record.getMessage():
                emit_security_alert(record.getMessage())
            return True
    
    logging.getLogger("clipsync.content_filter").addFilter(SecurityAlertFilter())

    # Start engine in background thread
    engine.run_in_thread()

    # Background stats emitter
    def _stats_worker():
        from web.socket_events import emit_stats_update
        from web.routes import _start_time, _syncs_today
        while True:
            time.sleep(2)
            try:
                peers_count = len(engine.peer_info)
                uptime = int(time.time() - _start_time)
                active_transfers = len(engine.file_transfer.active_transfers)
                emit_stats_update(peers_count, _syncs_today, uptime, active_transfers)
            except Exception:
                pass

    Thread(target=_stats_worker, daemon=True).start()

    return app, socketio


if __name__ == "__main__":
    logger.info("Initializing ClipSync v3.0 Web Dashboard...")
    app, socketio = create_app()
    logger.info("Starting Flask server on http://127.0.0.1:5000")
    
    # Run with Werkzeug server (for local desktop usage, this is fine)
    # Using threading async_mode
    socketio.run(app, host="127.0.0.1", port=5000, debug=False, use_reloader=False, allow_unsafe_werkzeug=True)
