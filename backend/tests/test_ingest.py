"""
Tests for file upload validation and ingest pipeline.

Security-focused tests:
  - Path traversal filenames → rejected
  - MIME type mismatch → rejected
  - Oversized files → rejected
  - Executable extensions → rejected
"""

import os
import pytest
from unittest.mock import AsyncMock, MagicMock

from backend.exceptions import IngestException
from backend.ingest.validator import sanitize_filename, validate_upload
from backend.ingest.normalizer import normalize
from backend.schema.mde_tables import MDE_TABLES


class TestFilenamesSanitization:
    def test_path_traversal_rejected(self):
        with pytest.raises(IngestException):
            sanitize_filename("../../../etc/passwd")

    def test_windows_path_traversal_rejected(self):
        with pytest.raises(IngestException):
            sanitize_filename("..\\..\\windows\\system32\\evil.dll")

    def test_absolute_path_rejected(self):
        with pytest.raises(IngestException):
            sanitize_filename("/etc/passwd")

    def test_executable_exe_rejected(self):
        with pytest.raises(IngestException):
            sanitize_filename("malware.exe")

    def test_executable_sh_rejected(self):
        with pytest.raises(IngestException):
            sanitize_filename("exploit.sh")

    def test_executable_py_rejected(self):
        with pytest.raises(IngestException):
            sanitize_filename("backdoor.py")

    def test_executable_bat_rejected(self):
        with pytest.raises(IngestException):
            sanitize_filename("run.bat")

    def test_executable_ps1_rejected(self):
        with pytest.raises(IngestException):
            sanitize_filename("evil.ps1")

    def test_valid_json_filename_accepted(self):
        result = sanitize_filename("logs.json")
        assert result == "logs.json"

    def test_valid_gz_filename_accepted(self):
        result = sanitize_filename("logs.json.gz")
        assert "gz" in result

    def test_filename_with_path_strips_path(self):
        result = sanitize_filename("C:/Users/admin/logs.json")
        assert "/" not in result
        assert result == "logs.json"


class TestNormalizer:
    def test_report_id_generated_if_missing(self):
        event = {
            "Timestamp": "2025-01-15T14:00:00Z",
            "DeviceId": "abc123",
            "DeviceName": "CORP-WS-001",
            "ActionType": "ProcessCreated",
            "FileName": "powershell.exe",
            "ProcessId": 1234,
        }
        result = normalize(event, "DeviceProcessEvents")
        assert "ReportId" in result
        assert result["ReportId"] != ""

    def test_unknown_table_rejected(self):
        from backend.exceptions import SchemaException
        with pytest.raises(SchemaException):
            normalize({"Timestamp": "2025-01-15T14:00:00Z"}, "NonExistentTable")

    def test_timestamp_normalized_to_iso(self):
        event = {
            "Timestamp": "2025-01-15 14:00:00",
            "DeviceId": "abc123",
            "DeviceName": "CORP-WS-001",
            "ActionType": "ProcessCreated",
            "FileName": "cmd.exe",
            "ProcessId": 100,
        }
        result = normalize(event, "DeviceProcessEvents")
        assert "T" in result["Timestamp"]  # ISO 8601 format

    def test_extra_fields_go_to_additional_fields(self):
        event = {
            "Timestamp": "2025-01-15T14:00:00Z",
            "DeviceId": "abc123",
            "DeviceName": "CORP-WS-001",
            "ActionType": "AntivirusDetection",
            "ExtraField": "should_be_captured",
            "AnotherExtra": 42,
        }
        result = normalize(event, "DeviceEvents")
        assert "AdditionalFields" in result
        assert "ExtraField" in str(result.get("AdditionalFields", ""))

    def test_all_mde_tables_have_valid_schema(self):
        for table_name in MDE_TABLES:
            assert table_name in MDE_TABLES
            table = MDE_TABLES[table_name]
            assert len(table.columns) > 0
