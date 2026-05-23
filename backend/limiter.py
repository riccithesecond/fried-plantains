"""
limiter.py — Shared slowapi Limiter instance.

Imported by main.py (to wire up middleware) and by individual route modules
(to apply @limiter.limit decorators). Defined here to avoid circular imports.

Limits:
  - Query execution: 60/minute — generous for interactive use, prevents scripted abuse
  - Log ingest:      10/minute — uploads should be deliberate, not hammered
"""

from slowapi import Limiter
from slowapi.util import get_remote_address

limiter = Limiter(key_func=get_remote_address)

QUERY_LIMIT = "60/minute"
INGEST_LIMIT = "10/minute"
