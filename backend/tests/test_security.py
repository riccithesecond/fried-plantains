"""
Security tests for fried-plantains.

Covers four attack surfaces not addressed in other test modules:
  1. SQL transpiler — DDL/DML injection, data exfiltration, unknown table refs
  2. KQL/SPL transpilers — injection guard, case-sensitivity invariants
  3. JWT — refresh token used as access token, wrong key, algorithm=none
  4. File upload — magic-byte MIME rejection, size limit enforcement

These are the tests that catch bugs which would silently pass type checkers
and unit tests but create real exposure in a deployed system.
"""

import asyncio
import os
import datetime

import pytest

# env vars must be set before any backend module is imported
os.environ.setdefault("SECRET_KEY", "test-secret-key-that-is-at-least-32-characters")
os.environ.setdefault("ADMIN_USERNAME", "testadmin")
os.environ.setdefault("ADMIN_PASSWORD_HASH", "$2b$12$KIXqaO/IWmjc.H55p5YIKuIgHy9X6ZIiqmJN4q5IB8.a.RuBRqhYS")
os.environ.setdefault("CORS_ORIGIN", "http://localhost:5173")
os.environ.setdefault("STORAGE_ROOT", "./test_storage")


# ---------------------------------------------------------------------------
# SQL Transpiler — injection surface
# ---------------------------------------------------------------------------

class TestSqlTranspilerInjection:
    """
    The SQL transpiler passes queries through to DuckDB after validation.
    It is the only place in the stack where a raw SQL string can reach the
    engine — which makes it the highest-value injection target.
    """

    def _validate(self, sql: str) -> str:
        from backend.engine.sql_transpiler import SqlValidator
        return SqlValidator.validate(sql)

    def _assert_rejected(self, sql: str) -> None:
        from backend.exceptions import QueryException
        with pytest.raises(QueryException):
            self._validate(sql)

    # --- DDL/DML rejection ---

    def test_drop_table_rejected(self):
        self._assert_rejected("DROP TABLE DeviceProcessEvents")

    def test_delete_rejected(self):
        self._assert_rejected("DELETE FROM DeviceProcessEvents WHERE 1=1")

    def test_insert_rejected(self):
        self._assert_rejected("INSERT INTO DeviceProcessEvents VALUES ('x', 'y')")

    def test_update_rejected(self):
        self._assert_rejected("UPDATE DeviceProcessEvents SET FileName='evil'")

    def test_create_table_rejected(self):
        self._assert_rejected("CREATE TABLE shadow AS SELECT * FROM DeviceProcessEvents")

    def test_alter_table_rejected(self):
        self._assert_rejected("ALTER TABLE DeviceProcessEvents ADD COLUMN Malicious TEXT")

    def test_exec_rejected(self):
        self._assert_rejected("EXEC xp_cmdshell('cmd /c whoami')")

    def test_execute_rejected(self):
        self._assert_rejected("EXECUTE sp_helpdb")

    def test_pragma_rejected(self):
        self._assert_rejected("PRAGMA database_list")

    # --- Data exfiltration pattern ---

    def test_into_outfile_rejected(self):
        self._assert_rejected(
            "SELECT * INTO OUTFILE '/etc/passwd' FROM DeviceProcessEvents"
        )

    # --- Multi-statement rejection ---

    def test_stacked_statements_rejected(self):
        self._assert_rejected(
            "SELECT * FROM DeviceProcessEvents; DROP TABLE DeviceProcessEvents"
        )

    # --- Case-insensitive keyword detection ---

    def test_lowercase_drop_rejected(self):
        self._assert_rejected("drop table DeviceProcessEvents")

    def test_mixed_case_delete_rejected(self):
        self._assert_rejected("DeLeTe FROM DeviceProcessEvents")

    # --- Unknown table reference ---

    def test_unknown_table_rejected(self):
        self._assert_rejected("SELECT * FROM SensitiveInternalTable")

    def test_nonexistent_table_rejected(self):
        self._assert_rejected("SELECT * FROM users WHERE 1=1")

    # Table name case-sensitivity: MDE table names must match exactly
    def test_lowercase_table_name_rejected(self):
        self._assert_rejected("SELECT * FROM deviceprocessevents")

    # --- Valid queries accepted ---

    def test_valid_select_accepted(self):
        sql = self._validate("SELECT Timestamp, DeviceName FROM DeviceProcessEvents LIMIT 10")
        assert "DeviceProcessEvents" in sql

    def test_cte_alias_valid_within_query(self):
        sql = self._validate(
            "WITH recent AS (SELECT * FROM DeviceProcessEvents) "
            "SELECT * FROM recent LIMIT 5"
        )
        assert sql is not None

    def test_join_across_known_tables(self):
        sql = self._validate(
            "SELECT p.DeviceName, n.RemoteIP "
            "FROM DeviceProcessEvents p "
            "JOIN DeviceNetworkEvents n ON p.DeviceId = n.DeviceId"
        )
        assert sql is not None


# ---------------------------------------------------------------------------
# KQL Transpiler — injection surface + case-sensitivity invariant
# ---------------------------------------------------------------------------

class TestKqlTranspilerSecurity:
    """
    KQL is transpiled (not passed through), so the injection risk is lower.
    The critical security property here is that malformed input raises a
    structured QueryException — never an unhandled Python exception — and
    that column name casing is preserved exactly (MDE portability requirement).
    """

    def _transpile(self, kql: str) -> str:
        from backend.engine.kql_transpiler import KqlTranspiler
        return KqlTranspiler.transpile(kql)

    def test_empty_kql_raises_query_exception(self):
        from backend.exceptions import QueryException
        with pytest.raises(QueryException):
            self._transpile("")

    def test_garbage_input_raises_query_exception(self):
        from backend.exceptions import QueryException
        with pytest.raises(QueryException):
            self._transpile("!@#$%^&*()_+{}")

    def test_no_unhandled_exceptions_on_malformed_input(self):
        """Malformed KQL must raise QueryException, not AttributeError/TypeError/etc."""
        from backend.exceptions import QueryException
        bad_inputs = [
            "| where",           # pipe with no source table
            "DeviceProcessEvents |",  # trailing pipe
            "DeviceProcessEvents | summarize",  # summarize with no body
        ]
        for kql in bad_inputs:
            try:
                self._transpile(kql)
            except QueryException:
                pass  # correct
            except Exception as exc:
                pytest.fail(
                    f"KQL '{kql}' raised {type(exc).__name__} instead of QueryException: {exc}"
                )

    def test_column_name_casing_preserved_pascalcase(self):
        """DeviceName must appear in the SQL output exactly as written — not lowercased."""
        sql = self._transpile(
            "DeviceProcessEvents | project DeviceName, FileName | limit 5"
        )
        assert "DeviceName" in sql
        assert "FileName" in sql

    def test_column_name_casing_preserved_lowercase_input(self):
        """If a query uses lowercase column refs, they must appear lowercase in SQL —
        the transpiler must NOT silently normalize to MDE casing.
        MDE will reject such queries; that's correct behaviour."""
        sql = self._transpile(
            "DeviceProcessEvents | project devicename | limit 5"
        )
        # The transpiler must preserve the casing as written, not correct it
        assert "devicename" in sql.lower()
        # And must NOT silently promote it to DeviceName
        # (that would mask a bug that would fail in real MDE)
        assert "DeviceName" not in sql

    def test_ago_transpiles_to_interval(self):
        sql = self._transpile(
            "DeviceProcessEvents | where Timestamp > ago(1h) | limit 5"
        )
        assert "INTERVAL" in sql.upper()

    def test_valid_kql_produces_select(self):
        sql = self._transpile(
            "DeviceProcessEvents | where FileName =~ 'powershell.exe' | limit 10"
        )
        assert sql.upper().startswith("SELECT")


# ---------------------------------------------------------------------------
# SPL Transpiler — injection guard
# ---------------------------------------------------------------------------

class TestSplTranspilerInjection:
    """_check_injection runs before any parsing — tests verify it fires on the
    most common SQL injection keyword payloads embedded in SPL syntax."""

    def _transpile(self, spl: str) -> str:
        from backend.engine.spl_transpiler import SplTranspiler
        return SplTranspiler.transpile(spl)

    def _assert_rejected(self, spl: str) -> None:
        from backend.exceptions import QueryException
        with pytest.raises(QueryException):
            self._transpile(spl)

    def test_drop_in_spl_rejected(self):
        self._assert_rejected("index=process | DROP TABLE DeviceProcessEvents")

    def test_delete_in_spl_rejected(self):
        self._assert_rejected("index=process | DELETE FROM DeviceProcessEvents")

    def test_insert_in_spl_rejected(self):
        self._assert_rejected("index=process | INSERT INTO results VALUES (1)")

    def test_create_in_spl_rejected(self):
        self._assert_rejected("index=process | CREATE TABLE evil AS SELECT 1")

    def test_exec_in_spl_rejected(self):
        self._assert_rejected("index=process | EXEC xp_cmdshell")

    def test_valid_spl_accepted(self):
        sql = self._transpile(
            "index=process | where FileName=\"powershell.exe\" | head 10"
        )
        assert sql is not None
        assert "SELECT" in sql.upper()


# ---------------------------------------------------------------------------
# JWT Security — token type enforcement and signature validation
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module")
def client():
    from backend.main import app
    from fastapi.testclient import TestClient
    with TestClient(app, raise_server_exceptions=False) as c:
        yield c


def _make_token(payload: dict) -> str:
    from jose import jwt
    return jwt.encode(
        payload,
        "test-secret-key-that-is-at-least-32-characters",
        algorithm="HS256",
    )


class TestJwtSecurity:
    def _auth_header(self, token: str) -> dict:
        return {"Authorization": f"Bearer {token}"}

    def test_refresh_token_rejected_as_access_token(self, client):
        """A refresh token (type=refresh) must not be accepted where an access
        token (type=access) is required — enforced by the type claim check in
        get_current_user."""
        refresh_token = _make_token({
            "sub": "testadmin",
            "type": "refresh",
            "exp": datetime.datetime(2099, 1, 1, tzinfo=datetime.timezone.utc),
            "iat": datetime.datetime.now(datetime.timezone.utc),
        })
        resp = client.get(
            "/api/v1/detections/",
            headers=self._auth_header(refresh_token),
        )
        assert resp.status_code == 401

    def test_token_with_wrong_signing_key_rejected(self, client):
        from jose import jwt
        wrong_key_token = jwt.encode(
            {
                "sub": "testadmin",
                "type": "access",
                "exp": datetime.datetime(2099, 1, 1, tzinfo=datetime.timezone.utc),
            },
            "this-is-a-completely-different-secret-key-xyz",
            algorithm="HS256",
        )
        resp = client.get(
            "/api/v1/detections/",
            headers=self._auth_header(wrong_key_token),
        )
        assert resp.status_code == 401

    def test_token_missing_type_claim_rejected(self, client):
        """Token without a 'type' claim — get_current_user checks token_type != 'access'."""
        token = _make_token({
            "sub": "testadmin",
            "exp": datetime.datetime(2099, 1, 1, tzinfo=datetime.timezone.utc),
        })
        resp = client.get(
            "/api/v1/detections/",
            headers=self._auth_header(token),
        )
        assert resp.status_code == 401

    def test_token_missing_sub_claim_rejected(self, client):
        """Token without a 'sub' claim — no subject means no user lookup."""
        token = _make_token({
            "type": "access",
            "exp": datetime.datetime(2099, 1, 1, tzinfo=datetime.timezone.utc),
        })
        resp = client.get(
            "/api/v1/detections/",
            headers=self._auth_header(token),
        )
        assert resp.status_code == 401

    def test_algorithm_none_attack_rejected(self, client):
        """'alg=none' is a known JWT attack. jose rejects it when algorithms=['HS256']
        is specified explicitly in jwt.decode()."""
        import base64, json
        header = base64.urlsafe_b64encode(
            json.dumps({"alg": "none", "typ": "JWT"}).encode()
        ).rstrip(b"=").decode()
        payload_part = base64.urlsafe_b64encode(
            json.dumps({
                "sub": "testadmin",
                "type": "access",
                "exp": 9999999999,
            }).encode()
        ).rstrip(b"=").decode()
        none_token = f"{header}.{payload_part}."  # empty signature

        resp = client.get(
            "/api/v1/detections/",
            headers=self._auth_header(none_token),
        )
        assert resp.status_code == 401

    def test_access_token_used_as_refresh_token_rejected(self, client):
        """An access token must not be accepted at the /refresh endpoint."""
        access_token = _make_token({
            "sub": "testadmin",
            "type": "access",
            "exp": datetime.datetime(2099, 1, 1, tzinfo=datetime.timezone.utc),
        })
        resp = client.post(
            "/api/v1/auth/refresh",
            cookies={"refresh_token": access_token},
        )
        assert resp.status_code == 401


# ---------------------------------------------------------------------------
# MIME detection — magic-byte validation (sync)
# ---------------------------------------------------------------------------

class TestMimeDetection:
    """
    _detect_mime_fallback is the safety net when libmagic is unavailable
    (Windows dev environments). These tests verify it correctly identifies
    binary content as non-text, preventing executable uploads disguised as
    JSON by filename extension only.
    """

    def _detect(self, header: bytes) -> str:
        from backend.ingest.validator import _detect_mime_fallback
        return _detect_mime_fallback(header)

    def test_gzip_magic_bytes(self):
        assert self._detect(b"\x1f\x8b" + b"\x00" * 100) == "application/gzip"

    def test_json_object_detected(self):
        assert self._detect(b'{"key": "value", "nested": [1, 2, 3]}') == "application/json"

    def test_json_array_detected(self):
        assert self._detect(b'[{"event": "login"}, {"event": "logout"}]') == "application/json"

    def test_pe_exe_binary_detected_as_octet_stream(self):
        # Windows PE magic bytes: MZ header
        pe_header = b"MZ" + b"\x90\x00" + b"\x00" * 100
        mime = self._detect(pe_header)
        assert mime == "application/octet-stream"

    def test_jpeg_binary_detected_as_octet_stream(self):
        # JPEG magic bytes: FF D8 FF
        jpeg_header = b"\xff\xd8\xff\xe0" + b"\x00" * 100
        mime = self._detect(jpeg_header)
        assert mime == "application/octet-stream"

    def test_elf_binary_detected_as_octet_stream(self):
        # ELF magic bytes: 7f 45 4c 46
        elf_header = b"\x7fELF" + b"\x00" * 100
        mime = self._detect(elf_header)
        assert mime == "application/octet-stream"

    def test_xml_detected_as_text(self):
        # XML starts with '<' — treated as plain text (safe to reject by MIME check)
        mime = self._detect(b"<?xml version='1.0'?><root/>")
        assert mime == "text/plain"

    def test_whitespace_prefixed_json_detected(self):
        # JSON with leading whitespace — common in pretty-printed files
        assert self._detect(b"   \n{\n  \"key\": \"value\"\n}") == "application/json"


# ---------------------------------------------------------------------------
# File upload — size limit enforcement
# ---------------------------------------------------------------------------

class TestUploadSizeLimit:
    def test_oversized_upload_rejected(self, monkeypatch):
        """Content larger than MAX_UPLOAD_SIZE_MB must be rejected before any parsing."""
        from unittest.mock import AsyncMock, MagicMock
        from backend.exceptions import IngestException
        from backend.ingest.validator import validate_upload
        from backend.config import settings

        oversized = b"x" * (settings.max_upload_size_bytes + 1)

        mock_file = MagicMock()
        mock_file.filename = "big.json"
        mock_file.read = AsyncMock(return_value=oversized)

        with pytest.raises(IngestException) as exc_info:
            asyncio.run(validate_upload(mock_file))

        assert "size" in exc_info.value.detail.lower() or "exceed" in exc_info.value.detail.lower() or "maximum" in exc_info.value.detail.lower()

    def test_valid_size_not_rejected_by_size_check(self, monkeypatch):
        """A small valid JSON payload must not be rejected by the size check."""
        from unittest.mock import AsyncMock, MagicMock
        from backend.exceptions import IngestException
        from backend.ingest.validator import validate_upload

        content = b'{"Timestamp": "2025-01-01T00:00:00Z"}'

        mock_file = MagicMock()
        mock_file.filename = "small.json"
        mock_file.read = AsyncMock(return_value=content)

        # Should not raise IngestException for size
        try:
            asyncio.run(validate_upload(mock_file))
        except IngestException as exc:
            assert "size" not in exc.detail.lower(), (
                f"Small upload incorrectly rejected for size: {exc.detail}"
            )
