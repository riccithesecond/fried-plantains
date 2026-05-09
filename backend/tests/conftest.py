"""
Test configuration and shared fixtures.

Sets up a minimal .env for tests so Settings() doesn't fail on missing vars.
Uses in-memory DuckDB and isolated temp directories for Parquet files.
"""

import os
import tempfile
from pathlib import Path

import pytest

# Set required env vars before any backend import that triggers Settings()
os.environ.setdefault("SECRET_KEY", "test-secret-key-that-is-at-least-32-characters")
os.environ.setdefault("ADMIN_USERNAME", "admin")
os.environ.setdefault("ADMIN_PASSWORD_HASH", "$2b$12$KIXqaO/IWmjc.H55p5YIKuIgHy9X6ZIiqmJN4q5IB8.a.RuBRqhYS")
os.environ.setdefault("CORS_ORIGIN", "http://localhost:5173")
os.environ.setdefault("STORAGE_ROOT", "./test_storage")


@pytest.fixture(scope="session")
def tmp_storage(tmp_path_factory) -> Path:
    """Temporary storage root for Parquet files in tests."""
    return tmp_path_factory.mktemp("storage")
