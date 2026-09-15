"""Sensitive-data filtering for clipboard text."""

import logging
import re

logger = logging.getLogger("clipsync.content_filter")


def is_sensitive_text(text: str, sync_sensitive: bool = False) -> bool:
    """Return True when clipboard text matches a sensitive-data pattern."""
    if sync_sensitive:
        return False

    patterns = (
        (r"\b(?:\d[ -]*?){13,19}\b", "credit card"),
        (r"-----BEGIN.*PRIVATE KEY-----", "private key"),
        (r"\b\d{3}-\d{2}-\d{4}\b", "SSN"),
        (r"AKIA[0-9A-Z]{16}", "AWS access key"),
        (r"(?:aws_secret_access_key|AWS_SECRET_ACCESS_KEY)\s*[:=]\s*\S{40}", "AWS secret key"),
        (r"(?:api[_-]?key|api[_-]?secret|access[_-]?token|auth[_-]?token)\s*[:=]\s*\S{16,}", "API key/token"),
        (r"eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}", "JWT"),
        (r"(?:password|passwd|pwd)\s*[:=]\s*\S+", "password"),
    )
    for pattern, label in patterns:
        if re.search(pattern, text, re.IGNORECASE):
            logger.warning("Blocked: %s pattern detected", label)
            return True
    return False
