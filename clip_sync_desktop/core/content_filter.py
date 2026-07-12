"""
ClipSync v3.0 — Content Filter
Detects sensitive data in text and validates file transfers.

OWASP A05 (Injection) + A06 (Insecure Design) compliant.
"""

import logging
import os
import re

logger = logging.getLogger("clipsync.content_filter")

# ── Dangerous file extensions (executables, scripts) ─────────────────────

BLOCKED_EXTENSIONS = {
    ".exe", ".bat", ".cmd", ".com", ".scr", ".pif",  # Windows executables
    ".msi", ".msp", ".mst",                          # Windows installers
    ".sh", ".bash", ".csh", ".ksh", ".zsh",          # Unix shells
    ".ps1", ".psm1", ".psd1",                         # PowerShell
    ".dll", ".so", ".dylib",                          # Libraries
    ".vbs", ".vbe", ".js", ".jse", ".wsf", ".wsh",   # Scripting
    ".reg",                                            # Registry
    ".inf", ".sct", ".hta",                           # Windows system
    ".cpl", ".sys", ".drv",                           # Windows drivers
}

# ── Allowed MIME types for file transfer ─────────────────────────────────

ALLOWED_MIME_PREFIXES = {
    "image/",           # All image types
    "application/pdf",
    "text/",            # All text types
    "application/msword",
    "application/vnd.openxmlformats-officedocument",  # DOCX, XLSX, PPTX
    "application/vnd.ms-excel",
    "application/vnd.ms-powerpoint",
    "application/zip",
    "application/x-tar",
    "application/gzip",
    "application/json",
    "application/xml",
    "application/csv",
    "video/",           # All video types
    "audio/",           # All audio types
}

MAX_FILE_SIZE = 100 * 1024 * 1024  # 100 MB
MAX_FILENAME_LENGTH = 255


def is_sensitive_text(text: str, sync_sensitive: bool = False) -> bool:
    """Check if text contains sensitive data that should not be synced."""
    if sync_sensitive:
        return False

    # Credit card numbers (13-19 digits with optional separators)
    if re.search(r"\b(?:\d[ -]*?){13,19}\b", text):
        logger.warning("Blocked: Credit card pattern detected")
        return True

    # Private keys (PEM format)
    if "-----BEGIN" in text and "PRIVATE KEY-----" in text:
        logger.warning("Blocked: Private key detected")
        return True

    # SSN (US Social Security Number)
    if re.search(r"\b\d{3}-\d{2}-\d{4}\b", text):
        logger.warning("Blocked: SSN pattern detected")
        return True

    # AWS Access Key ID
    if re.search(r"AKIA[0-9A-Z]{16}", text):
        logger.warning("Blocked: AWS Access Key ID detected")
        return True

    # AWS Secret Access Key
    if re.search(
        r"(?:aws_secret_access_key|AWS_SECRET_ACCESS_KEY)\s*[:=]\s*\S{40}", text
    ):
        logger.warning("Blocked: AWS Secret Key detected")
        return True

    # Generic API keys/tokens
    if re.search(
        r"(?:api[_-]?key|api[_-]?secret|access[_-]?token|auth[_-]?token)\s*[:=]\s*\S{16,}",
        text,
        re.IGNORECASE,
    ):
        logger.warning("Blocked: API key/token pattern detected")
        return True

    # JWT tokens
    if re.search(
        r"eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}", text
    ):
        logger.warning("Blocked: JWT token detected")
        return True

    # Passwords in config strings
    if re.search(r"(?:password|passwd|pwd)\s*[:=]\s*\S+", text, re.IGNORECASE):
        logger.warning("Blocked: Password pattern detected")
        return True

    return False


def is_blocked_file(filename: str) -> bool:
    """Check if a file has a blocked extension (executable/script)."""
    ext = os.path.splitext(filename)[1].lower()
    if ext in BLOCKED_EXTENSIONS:
        logger.warning(f"Blocked file type: {ext} ({filename})")
        return True
    return False


def is_mime_allowed(mime_type: str) -> bool:
    """Check if a MIME type is in the allow list."""
    if not mime_type:
        return False
    mime_lower = mime_type.lower()
    for prefix in ALLOWED_MIME_PREFIXES:
        if mime_lower.startswith(prefix):
            return True
    logger.warning(f"MIME type not allowed: {mime_type}")
    return False


def validate_file_size(size: int) -> bool:
    """Check if file size is within the allowed limit."""
    if size <= 0:
        return False
    if size > MAX_FILE_SIZE:
        logger.warning(f"File too large: {size / (1024*1024):.1f} MB (max {MAX_FILE_SIZE / (1024*1024):.0f} MB)")
        return False
    return True


def sanitize_filename(filename: str) -> str:
    """
    Sanitize a filename to prevent path traversal and injection attacks.
    OWASP A05 (Injection) mitigation.
    """
    # Remove path components — only keep the basename
    filename = os.path.basename(filename)

    # Remove null bytes
    filename = filename.replace("\x00", "")

    # Remove path traversal sequences
    filename = filename.replace("..", "").replace("/", "").replace("\\", "")

    # Remove control characters
    filename = re.sub(r"[\x00-\x1f\x7f]", "", filename)

    # Replace dangerous characters on Windows
    filename = re.sub(r'[<>:"|?*]', "_", filename)

    # Truncate to max length
    if len(filename) > MAX_FILENAME_LENGTH:
        name, ext = os.path.splitext(filename)
        filename = name[: MAX_FILENAME_LENGTH - len(ext)] + ext

    # Fallback if filename is empty after sanitization
    if not filename or filename.strip(".") == "":
        filename = "unnamed_file"

    return filename
