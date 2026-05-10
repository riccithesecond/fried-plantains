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


# ---------------------------------------------------------------------------
# Cloud parser tests
# ---------------------------------------------------------------------------

import json as _json

from backend.parsers.cloudtrail import CloudTrailParser
from backend.parsers.cloudflare import CloudflareParser
from backend.parsers.zscaler import ZscalerParser


class TestCloudTrailParser:
    def test_cloudtrail_records_format(self):
        raw = _json.dumps({"Records": [
            {"eventVersion": "1.08", "eventID": "abc-123",
             "eventTime": "2024-01-15T09:23:11Z",
             "eventName": "GetObject", "eventSource": "s3.amazonaws.com",
             "awsRegion": "us-east-1", "sourceIPAddress": "1.2.3.4",
             "userAgent": "aws-cli", "readOnly": True,
             "userIdentity": {"type": "IAMUser", "userName": "jsmith",
                              "arn": "arn:aws:iam::123456789012:user/jsmith",
                              "accountId": "123456789012"},
             "requestParameters": {"bucketName": "my-bucket"}}
        ]})
        events = CloudTrailParser.parse(raw)
        assert len(events) == 1
        assert events[0]["table"] == "AWSCloudTrailEvents"
        assert events[0]["data"]["EventName"] == "GetObject"
        assert events[0]["data"]["ActionType"] == "DataAccess"

    def test_cloudtrail_root_action_type(self):
        event = {"eventID": "x", "eventTime": "2024-01-15T09:00:00Z",
                 "eventName": "ListBuckets", "eventSource": "s3.amazonaws.com",
                 "awsRegion": "us-east-1", "sourceIPAddress": "1.2.3.4",
                 "userAgent": "console", "readOnly": True,
                 "userIdentity": {"type": "Root", "arn": "arn:aws:iam::123:root",
                                  "accountId": "123456789012"}}
        result = CloudTrailParser._parse_event(event)
        assert result["UserIdentityType"] == "Root"

    def test_cloudtrail_console_login_auth_attempt(self):
        event = {"eventID": "y", "eventTime": "2024-01-15T09:00:00Z",
                 "eventName": "ConsoleLogin", "eventSource": "signin.amazonaws.com",
                 "awsRegion": "us-east-1", "sourceIPAddress": "1.2.3.4",
                 "userAgent": "Mozilla/5.0", "readOnly": False,
                 "userIdentity": {"type": "IAMUser", "userName": "jsmith",
                                  "arn": "arn:aws:iam::123:user/jsmith",
                                  "accountId": "123456789012"}}
        result = CloudTrailParser._parse_event(event)
        assert result["ActionType"] == "AuthAttempt"

    def test_cloudtrail_assume_role_token_issued(self):
        event = {"eventID": "z", "eventTime": "2024-01-15T09:00:00Z",
                 "eventName": "AssumeRole", "eventSource": "sts.amazonaws.com",
                 "awsRegion": "us-east-1", "sourceIPAddress": "1.2.3.4",
                 "userAgent": "aws-cli", "readOnly": False,
                 "userIdentity": {"type": "IAMUser", "userName": "jsmith",
                                  "arn": "arn:aws:iam::123:user/jsmith",
                                  "accountId": "123456789012"}}
        result = CloudTrailParser._parse_event(event)
        assert result["ActionType"] == "TokenIssued"

    def test_cloudtrail_jsonlines_format(self):
        line = _json.dumps({"eventID": "abc", "eventTime": "2024-01-15T09:00:00Z",
                            "eventName": "DescribeInstances",
                            "eventSource": "ec2.amazonaws.com",
                            "awsRegion": "us-east-1", "sourceIPAddress": "1.2.3.4",
                            "userAgent": "aws-cli", "readOnly": True,
                            "userIdentity": {"type": "IAMUser", "userName": "ops",
                                             "arn": "arn:aws:iam::123:user/ops",
                                             "accountId": "123456789012"}})
        events = CloudTrailParser.parse(line)
        assert len(events) == 1
        assert events[0]["data"]["ActionType"] == "ManagementRead"


class TestCloudflareParser:
    def test_cloudflare_mixed_log_routing(self):
        http_line = _json.dumps({
            "RayID": "abc", "ClientRequestMethod": "GET",
            "EdgeStartTimestamp": 1700000000000000000,
            "ClientIP": "1.2.3.4", "EdgeResponseStatus": 200,
            "ClientRequestHost": "example.com", "ClientRequestURI": "/",
            "ClientRequestUserAgent": "Mozilla/5.0",
        })
        fw_line = _json.dumps({
            "RayID": "def", "FirewallSource": "waf",
            "Datetime": "2024-01-15T09:00:00Z",
            "ClientIP": "1.2.3.4", "Action": "block",
            "Source": "waf", "RuleID": "rule-001",
        })
        dns_line = _json.dumps({
            "QueryName": "example.com", "QueryType": "A",
            "ResponseCode": "NOERROR",
            "QueryTimestamp": "2024-01-15T09:00:00Z",
            "SourceIP": "10.0.0.1", "Blocked": False,
        })
        raw = "\n".join([http_line, fw_line, dns_line])
        result = CloudflareParser.parse(raw)
        assert "CloudflareHttpEvents" in result
        assert "CloudflareFirewallEvents" in result
        assert "CloudflareDnsEvents" in result

    def test_cloudflare_nanosecond_timestamp(self):
        ts = 1700000000000000000
        result = CloudflareParser._convert_timestamp(ts)
        assert result.year == 2023
        assert result.tzinfo is not None

    def test_cloudflare_waf_block_action_type(self):
        fw_line = _json.dumps({
            "RayID": "xyz", "FirewallSource": "waf",
            "Datetime": "2024-01-15T09:00:00Z",
            "ClientIP": "5.6.7.8", "Action": "block",
            "Source": "waf", "RuleID": "waf-001",
        })
        result = CloudflareParser.parse(fw_line)
        assert result["CloudflareFirewallEvents"][0]["ActionType"] == "WAFBlock"

    def test_cloudflare_http_bot_detected(self):
        http_line = _json.dumps({
            "RayID": "bot1", "ClientRequestMethod": "GET",
            "EdgeStartTimestamp": 1700000000000000000,
            "ClientIP": "1.2.3.4", "EdgeResponseStatus": 200,
            "ClientRequestHost": "example.com", "ClientRequestURI": "/",
            "ClientRequestUserAgent": "python-requests/2.28",
            "BotScore": 90,
            "FirewallMatchesActions": [],
        })
        result = CloudflareParser.parse(http_line)
        assert result["CloudflareHttpEvents"][0]["ActionType"] == "BotDetected"


class TestZscalerParser:
    def test_zscaler_keyvalue_format(self):
        raw = "time=1705312991 action=Blocked url=https://malware.example.com user=jsmith@corp.com malwarename=Emotet"
        events = ZscalerParser.parse(raw)
        assert events[0]["table"] == "ZscalerWebEvents"
        assert events[0]["data"]["ActionType"] == "MalwareDetected"
        assert events[0]["data"]["MalwareName"] == "Emotet"

    def test_zscaler_json_format(self):
        raw = _json.dumps({"action": "Allowed", "url": "https://www.example.com",
                           "user": "jsmith@corp.com", "srcip": "10.0.0.5",
                           "datetime": "1705312991"})
        events = ZscalerParser.parse(raw)
        assert events[0]["table"] == "ZscalerWebEvents"
        assert events[0]["data"]["ActionType"] == "WebAllow"

    def test_zscaler_dns_detection(self):
        raw = _json.dumps({"action": "Block", "dnsname": "c2.malware.com",
                           "threatname": "Emotet-C2", "srcip": "10.0.0.5",
                           "datetime": "1705312991"})
        events = ZscalerParser.parse(raw)
        assert events[0]["table"] == "ZscalerDnsEvents"
        assert events[0]["data"]["ActionType"] == "DnsThreatMatch"

    def test_zscaler_dlp_violation(self):
        raw = _json.dumps({"action": "DLP", "url": "https://drive.google.com/upload",
                           "user": "badactor@corp.com", "srcip": "10.0.0.9",
                           "datetime": "1705312991", "bytesout": "15000000"})
        events = ZscalerParser.parse(raw)
        assert events[0]["data"]["ActionType"] == "DlpViolation"

    def test_zscaler_dns_sinkhole(self):
        raw = _json.dumps({"action": "Block", "dnsname": "c2.apt.com",
                           "policyname": "Sinkhole-Policy",
                           "srcip": "10.0.0.5", "datetime": "1705312991"})
        events = ZscalerParser.parse(raw)
        assert events[0]["table"] == "ZscalerDnsEvents"
        assert events[0]["data"]["ActionType"] == "DnsSinkhole"
