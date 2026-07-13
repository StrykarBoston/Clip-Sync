"""
ClipSync v3.0 — Flask Security Middleware
OWASP Top 10 2025 compliant security hardening for the Flask web dashboard.
"""

import logging
import os
import secrets
import time
from collections import defaultdict
from functools import wraps

from flask import Flask, request, jsonify, session, abort

logger = logging.getLogger("clipsync.web.security")


def init_security(app: Flask):
    """Apply OWASP-hardened security configuration to the Flask app."""

    # ── A02: Security Misconfiguration — Enforce secure defaults ─────────
    app.config.update(
        DEBUG=False,
        TESTING=False,
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Strict",
        SESSION_COOKIE_SECURE=False,  # Localhost only, no HTTPS needed
        PERMANENT_SESSION_LIFETIME=3600,  # 1 hour
        MAX_CONTENT_LENGTH=110 * 1024 * 1024,  # 110 MB (for file uploads)
    )

    # Ensure strong random secret key for Flask sessions
    if not app.config.get("SECRET_KEY") or app.config["SECRET_KEY"] == "dev":
        app.config["SECRET_KEY"] = secrets.token_hex(32)

    # ── A01: Broken Access Control — Security Headers ────────────────────
    @app.after_request
    def set_security_headers(response):
        # Content Security Policy — prevent XSS
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; "
            "script-src 'self' 'unsafe-inline' https://cdn.socket.io https://cdn.jsdelivr.net https://unpkg.com; "
            "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
            "font-src 'self' https://fonts.gstatic.com; "
            "img-src 'self' data: blob:; "
            "connect-src 'self' ws://localhost:* wss://localhost:* ws://127.0.0.1:* wss://127.0.0.1:*; "
        )
        # Prevent MIME type sniffing
        response.headers["X-Content-Type-Options"] = "nosniff"
        # Clickjacking protection
        response.headers["X-Frame-Options"] = "DENY"
        # XSS filter
        response.headers["X-XSS-Protection"] = "1; mode=block"
        # No referrer leakage
        response.headers["Referrer-Policy"] = "no-referrer"
        # Permissions policy
        response.headers["Permissions-Policy"] = (
            "camera=(), microphone=(), geolocation=(), payment=()"
        )
        # Remove server header
        response.headers.pop("Server", None)
        return response

    # ── A10: Exception Handling — Global error handler ───────────────────
    @app.errorhandler(400)
    def bad_request(e):
        return jsonify({"error": "Bad Request"}), 400

    @app.errorhandler(404)
    def not_found(e):
        return jsonify({"error": "Not Found"}), 404

    @app.errorhandler(413)
    def too_large(e):
        return jsonify({"error": "File too large (max 100 MB)"}), 413

    @app.errorhandler(429)
    def rate_limited(e):
        return jsonify({"error": "Rate limited. Try again later."}), 429

    @app.errorhandler(500)
    def internal_error(e):
        logger.error(f"Internal server error: {e}")
        return jsonify({"error": "Internal Server Error"}), 500

    logger.info("OWASP security middleware initialized")


# ── A01: Rate Limiting ───────────────────────────────────────────────────

class RateLimiter:
    """Simple in-memory rate limiter for API endpoints."""

    def __init__(self, max_requests: int = 30, window_seconds: int = 60):
        self.max_requests = max_requests
        self.window = window_seconds
        self._requests: dict = defaultdict(list)

    def is_allowed(self, key: str) -> bool:
        now = time.time()
        # Clean old entries
        self._requests[key] = [
            t for t in self._requests[key] if now - t < self.window
        ]
        if len(self._requests[key]) >= self.max_requests:
            return False
        self._requests[key].append(now)
        return True


# Global rate limiter instance
api_limiter = RateLimiter(max_requests=60, window_seconds=60)


def rate_limit(f):
    """Decorator to rate-limit API endpoints."""
    @wraps(f)
    def decorated(*args, **kwargs):
        client_ip = request.remote_addr or "unknown"
        if not api_limiter.is_allowed(client_ip):
            abort(429)
        return f(*args, **kwargs)
    return decorated


# ── A05: Input Sanitization ──────────────────────────────────────────────

def sanitize_input(text: str, max_length: int = 1000) -> str:
    """Sanitize user input to prevent injection attacks."""
    if not isinstance(text, str):
        return ""
    # Remove null bytes
    text = text.replace("\x00", "")
    # Remove control characters (except newline/tab)
    import re
    text = re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]", "", text)
    # Truncate
    return text[:max_length]
