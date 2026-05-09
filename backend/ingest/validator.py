"""
ingest/validator.py — File upload validation.

Security boundary for all uploaded log files. Validates MIME type using magic
bytes (not file extension — extensions are trivially spoofed), enforces file size
limits, and sanitizes filenames to prevent path traversal.
"""

import os
import re

from fastapi import UploadFile

from backend.config import settings
from backend.exceptions import IngestException

# Try to import libmagic — may not be available on all platforms
try:
    import magic as _magic
    _MAGIC_AVAILABLE = True
except (ImportError, OSError):
    _MAGIC_AVAILABLE = False

# MIME types accepted for log file uploads — allowlist, not blocklist
_ALLOWED_MIME_TYPES: frozenset[str] = frozenset(
    [
        "application/json",
        "text/plain",
        "text/csv",
        "application/x-ndjson",
        "application/gzip",
        "application/x-gzip",
        # Some magic libraries report these for text-based formats
        "application/octet-stream",  # Only allowed if size check passes
    ]
)

# Extensions that indicate executable content — always rejected regardless of MIME
_BLOCKED_EXTENSIONS: frozenset[str] = frozenset(
    [".exe", ".sh", ".py", ".js", ".bat", ".cmd", ".ps1", ".vbs", ".wsf", ".jar"]
)

# Maximum bytes to read for magic byte detection (libmagic needs at least 262)
_MAGIC_READ_BYTES = 8192


async def validate_upload(file: UploadFile) -> bytes:
    """Validate an uploaded file and return its full content as bytes.

    Checks (in order):
      1. File size ≤ MAX_UPLOAD_SIZE_MB
      2. Filename sanitization (no path traversal, no executable extensions)
      3. MIME type from magic bytes (not extension)

    Returns:
        File content as bytes.

    Raises:
        IngestException: On any validation failure with a safe message.
    """
    # --- Read content (needed for size check and magic byte detection) ---
    content = await file.read()

    # 1. Size check
    if len(content) > settings.max_upload_size_bytes:
        raise IngestException(
            detail=f"File exceeds maximum upload size of {settings.MAX_UPLOAD_SIZE_MB}MB.",
            internal_detail=f"Upload size {len(content)} bytes exceeds limit.",
        )

    # 2. Filename sanitization
    filename = sanitize_filename(file.filename or "upload.json")

    # 3. Magic byte MIME detection
    mime = _detect_mime(content[:_MAGIC_READ_BYTES])
    if mime not in _ALLOWED_MIME_TYPES:
        raise IngestException(
            detail=f"File type '{mime}' is not accepted. Upload JSON, NDJSON, CSV, or gzip.",
            internal_detail=f"Rejected MIME type: {mime} for file: {filename}",
        )

    return content


def sanitize_filename(filename: str) -> str:
    """Strip path components and reject dangerous filenames.

    Raises:
        IngestException: If the filename contains traversal characters or
                         executable extensions.
    """
    # Normalize all separators to forward slashes for uniform traversal detection.
    # os.path.basename("../../../etc/passwd") → "passwd", missing the traversal.
    # Checking the ORIGINAL (normalized) filename before stripping catches this.
    normalized = filename.replace("\\", "/")

    # Reject traversal sequences in the original path (before basename extraction)
    if ".." in normalized:
        raise IngestException(
            detail="Invalid filename.",
            internal_detail=f"Path traversal attempt in filename: {filename!r}",
        )

    # Reject Unix-style absolute paths — they cannot be safely stripped to a
    # meaningful filename. Windows-style absolute paths (C:/...) are fine: basename
    # strips the drive+directories and leaves just the filename.
    if normalized.startswith("/"):
        raise IngestException(
            detail="Invalid filename.",
            internal_detail=f"Absolute path not allowed: {filename!r}",
        )

    # Strip any path components — only keep the basename
    basename = os.path.basename(normalized)

    # Check for executable extensions (case-insensitive)
    _, ext = os.path.splitext(basename.lower())
    if ext in _BLOCKED_EXTENSIONS:
        raise IngestException(
            detail=f"Files with extension '{ext}' are not accepted.",
            internal_detail=f"Blocked extension '{ext}' in filename: {filename!r}",
        )

    # Restrict to alphanumeric, dots, hyphens, underscores
    safe = re.sub(r"[^\w.\-]", "_", basename)
    return safe


def _detect_mime(header_bytes: bytes) -> str:
    """Detect MIME type from magic bytes using libmagic.

    Falls back to header-byte inspection when libmagic is unavailable (e.g.,
    on Windows without the libmagic DLL). The header inspection is less precise
    but sufficient to detect the most common log file formats.
    """
    if _MAGIC_AVAILABLE:
        try:
            m = _magic.Magic(mime=True)
            return m.from_buffer(header_bytes)
        except Exception:
            pass

    # Fallback: magic byte signatures for common log formats
    return _detect_mime_fallback(header_bytes)


def _detect_mime_fallback(header_bytes: bytes) -> str:
    """Minimal magic byte detection when libmagic is unavailable."""
    if header_bytes[:2] == b"\x1f\x8b":
        return "application/gzip"
    stripped = header_bytes.lstrip(b" \t\r\n")
    if stripped.startswith(b"{") or stripped.startswith(b"["):
        return "application/json"
    if stripped.startswith(b"<"):
        return "text/plain"  # XML/HTML-ish
    # Check for printable text (CSV, NDJSON, plain text)
    try:
        header_bytes[:512].decode("utf-8")
        return "text/plain"
    except UnicodeDecodeError:
        return "application/octet-stream"
