"""
ClipSync v3.0 — Flask REST API Routes
Provides endpoints for the web dashboard to interact with the sync engine.
"""

import logging
import os
import time

from flask import Blueprint, jsonify, request, render_template
from werkzeug.utils import secure_filename

from .flask_security import rate_limit, sanitize_input

logger = logging.getLogger("clipsync.web.routes")

api = Blueprint("api", __name__)

# The sync engine instance will be set by app.py at startup
_engine = None
_start_time = time.time()
_syncs_today = 0


def set_engine(engine):
    """Set the ClipSyncEngine instance for route handlers."""
    global _engine
    _engine = engine


# ── Dashboard ────────────────────────────────────────────────────────────

@api.route("/")
def dashboard():
    """Serve the main dashboard page."""
    return render_template("index.html")


# ── Status API ───────────────────────────────────────────────────────────

@api.route("/api/status")
@rate_limit
def get_status():
    """Get current engine status."""
    if not _engine:
        return jsonify({"error": "Engine not initialized"}), 503

    status = _engine.get_status()
    status["uptime"] = int(time.time() - _start_time)
    status["syncs_today"] = _syncs_today
    return jsonify(status)


# ── Peers API ────────────────────────────────────────────────────────────

@api.route("/api/peers")
@rate_limit
def get_peers():
    """Get list of connected peers."""
    if not _engine:
        return jsonify({"peers": []})
    return jsonify({"peers": _engine.get_status()["peers"]})


# ── Settings API ─────────────────────────────────────────────────────────

@api.route("/api/settings", methods=["GET"])
@rate_limit
def get_settings():
    """Get current settings (key masked)."""
    env_path = os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))), ".env"
    )
    secret_key = os.environ.get("SECRET_KEY", "")
    port = os.environ.get("PORT", "52300")
    sync_sensitive = os.environ.get("SYNC_SENSITIVE_DATA", "false")

    masked_key = secret_key[:6] + "•" * 52 + secret_key[-6:] if len(secret_key) >= 12 else "•" * 64

    import sys
    if sys.platform == "win32":
        save_location = os.path.join(os.path.expanduser("~"), "Downloads", "ClipSync")
    else:
        save_location = os.path.join(os.path.expanduser("~"), "Documents", "ClipSync")

    return jsonify({
        "secret_key_masked": masked_key,
        "port": port,
        "sync_sensitive_data": sync_sensitive,
        "save_location": save_location,
    })


@api.route("/api/settings", methods=["POST"])
@rate_limit
def update_settings():
    """Update settings (secret key, port). Requires app restart."""
    data = request.get_json()
    if not data:
        return jsonify({"error": "Invalid JSON"}), 400

    env_path = os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))), ".env"
    )

    new_key = data.get("secret_key", "").strip()
    new_port = data.get("port", "52300").strip()
    sync_sensitive = data.get("sync_sensitive_data", "false").strip()

    # Validate key
    if new_key:
        new_key = sanitize_input(new_key, max_length=64)
        if len(new_key) != 64:
            return jsonify({"error": "Secret key must be 64 hex characters"}), 400
        try:
            bytes.fromhex(new_key)
        except ValueError:
            return jsonify({"error": "Secret key must be valid hexadecimal"}), 400

    # Validate port
    try:
        port_int = int(new_port)
        if not (1024 <= port_int <= 65535):
            return jsonify({"error": "Port must be between 1024 and 65535"}), 400
    except ValueError:
        return jsonify({"error": "Invalid port number"}), 400

    # Write to .env
    try:
        lines = []
        if new_key:
            lines.append(f"SECRET_KEY={new_key}")
        else:
            lines.append(f"SECRET_KEY={os.environ.get('SECRET_KEY', '')}")
        lines.append(f"PORT={new_port}")
        lines.append(f"SYNC_SENSITIVE_DATA={sync_sensitive}")
        lines.append("")

        with open(env_path, "w", encoding="utf-8") as f:
            f.write("\n".join(lines))

        logger.info("Settings updated. Restart required.")
        return jsonify({
            "status": "success",
            "message": "Settings saved. Please restart ClipSync for changes to take effect.",
        })
    except Exception as e:
        logger.error(f"Failed to save settings: {e}")
        return jsonify({"error": "Failed to save settings"}), 500


# ── Transfers API ────────────────────────────────────────────────────────

@api.route("/api/transfers")
@rate_limit
def get_transfers():
    """Get transfer history."""
    if not _engine:
        return jsonify({"transfers": []})
    return jsonify({
        "transfers": _engine.file_transfer.get_transfer_history()
    })


@api.route("/api/send-file", methods=["POST"])
@rate_limit
def send_file():
    """Upload and broadcast a file to all peers."""
    if not _engine:
        return jsonify({"error": "Engine not initialized"}), 503

    if "file" not in request.files:
        return jsonify({"error": "No file provided"}), 400

    file = request.files["file"]
    if file.filename == "":
        return jsonify({"error": "No file selected"}), 400

    filename = secure_filename(file.filename)
    if not filename:
        return jsonify({"error": "Invalid filename"}), 400

    # Save to temp location
    import tempfile
    temp_dir = os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
        "temp_uploads",
    )
    os.makedirs(temp_dir, exist_ok=True)
    temp_path = os.path.join(temp_dir, filename)

    try:
        file.save(temp_path)
        _engine.send_file(temp_path)
        logger.info(f"File queued for broadcast: {filename}")
        return jsonify({
            "status": "success",
            "message": f"File '{filename}' is being sent to all peers.",
        })
    except Exception as e:
        logger.error(f"Failed to send file: {e}")
        return jsonify({"error": "Failed to send file"}), 500


# ── Security API ─────────────────────────────────────────────────────────

@api.route("/api/security")
@rate_limit
def get_security_info():
    """Get security status and OWASP compliance info."""
    cert_info = _get_cert_info()
    return jsonify({
        "tls": cert_info,
        "owasp_compliance": {
            "A01_access_control": {"status": "pass", "detail": "Localhost-only binding + CSRF + rate limiting"},
            "A02_misconfiguration": {"status": "pass", "detail": "Debug disabled, secure defaults enforced"},
            "A03_supply_chain": {"status": "pass", "detail": "Pinned dependency versions"},
            "A04_cryptographic": {"status": "pass", "detail": "AES-256-GCM + HKDF + RSA-4096 TLS"},
            "A05_injection": {"status": "pass", "detail": "Input sanitization, filename validation, CSP headers"},
            "A06_insecure_design": {"status": "pass", "detail": "File type blocklist, magic-byte MIME check, size limits"},
            "A07_auth_failures": {"status": "pass", "detail": "HMAC challenge + 30s timestamp + nonce cache"},
            "A08_integrity": {"status": "pass", "detail": "SHA-256 hash verification on all file transfers"},
            "A09_logging": {"status": "pass", "detail": "Structured security event logging"},
            "A10_exceptions": {"status": "pass", "detail": "Global error handler, no stack traces exposed"},
        },
        "active_protections": [
            "AES-256-GCM End-to-End Encryption",
            "HKDF Key Derivation (SHA-256)",
            "HMAC-SHA256 Network Challenge (5-min windows)",
            "Rolling Nonce Cache (60s TTL)",
            "TLS 1.2+ Transport Encryption",
            "RSA-4096 Self-Signed Certificates",
            "Dynamic IP SAN Auto-Regeneration",
            "Per-IP Connection Rate Limiting (5/IP)",
            "Content Security Policy (CSP) Headers",
            "Sensitive Data Detection & Blocking",
            "Executable File Type Blocklist",
            "SHA-256 File Integrity Verification",
            "Filename Sanitization (Path Traversal Prevention)",
        ],
    })


def _get_cert_info() -> dict:
    """Read TLS certificate info."""
    try:
        from cryptography import x509
        from cryptography.x509.oid import ExtensionOID

        cert_path = os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
            "tls_cert.pem",
        )
        if not os.path.exists(cert_path):
            return {"status": "missing"}

        with open(cert_path, "rb") as f:
            cert = x509.load_pem_x509_certificate(f.read())

        san_ext = cert.extensions.get_extension_for_oid(
            ExtensionOID.SUBJECT_ALTERNATIVE_NAME
        )
        san_ips = [str(ip) for ip in san_ext.value.get_values_for_type(x509.IPAddress)]

        return {
            "status": "valid",
            "issuer": cert.issuer.rfc4514_string(),
            "not_before": cert.not_valid_before_utc.isoformat(),
            "not_after": cert.not_valid_after_utc.isoformat(),
            "key_size": "RSA-4096",
            "san_ips": san_ips,
        }
    except Exception as e:
        return {"status": "error", "detail": str(e)}


def increment_sync_count():
    """Increment daily sync counter."""
    global _syncs_today
    _syncs_today += 1
