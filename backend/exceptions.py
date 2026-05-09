"""
exceptions.py — Custom exception hierarchy for fried-plantains.

Every exception carries a safe client-facing detail and a richer internal_detail
for structured logging. Route handlers map these to HTTP status codes; the
internal_detail is never returned to the client.
"""

from typing import ClassVar


class FPBaseException(Exception):
    """Base for all fried-plantains domain exceptions."""

    status_code: ClassVar[int] = 500

    def __init__(self, detail: str, internal_detail: str = ""):
        super().__init__(detail)
        self.detail = detail
        # Full context for internal logging — never sent to the client
        self.internal_detail = internal_detail or detail


class AuthException(FPBaseException):
    """Authentication and authorization failures."""
    status_code: ClassVar[int] = 401


class ForbiddenException(FPBaseException):
    """Access to a resource is denied."""
    status_code: ClassVar[int] = 403


class IngestException(FPBaseException):
    """Log upload, parsing, or normalization failures."""
    status_code: ClassVar[int] = 422


class QueryException(FPBaseException):
    """Query parsing, transpilation, or execution failures."""
    status_code: ClassVar[int] = 400

    def __init__(
        self,
        detail: str,
        internal_detail: str = "",
        line: int | None = None,
        column: int | None = None,
    ):
        super().__init__(detail, internal_detail)
        self.line = line
        self.column = column


class DetectionException(FPBaseException):
    """Detection rule schema, storage, or execution failures."""
    status_code: ClassVar[int] = 422


class SchemaException(FPBaseException):
    """MDE schema violations — unknown table names or column names."""
    status_code: ClassVar[int] = 422


class StorageException(FPBaseException):
    """Parquet read/write or file system failures."""
    status_code: ClassVar[int] = 500


class RateLimitException(FPBaseException):
    """Request rate limit exceeded."""
    status_code: ClassVar[int] = 429
