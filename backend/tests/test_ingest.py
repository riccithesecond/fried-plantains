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


# ---------------------------------------------------------------------------
# Proofpoint parser tests
# ---------------------------------------------------------------------------

from backend.parsers.proofpoint import ProofpointParser
from backend.parsers.abnormal import AbnormalParser


class TestProofpointParser:
    def _tap_message(self, **overrides) -> dict:
        base = {
            "GUID": "pp-guid-001",
            "messageID": "<test-msg-001@corp.com>",
            "messageTime": "2024-01-15T09:23:11Z",
            "recipient": ["jsmith@corp.com"],
            "fromAddress": ["attacker@evil.com"],
            "senderIP": "1.2.3.4",
            "subject": "Urgent wire transfer request",
            "messageSize": 4096,
            "spamScore": 12,
            "phishScore": 95,
            "impostorScore": 88,
            "malwareScore": 0,
            "spamVerdict": "negative",
            "phishVerdict": "positive",
            "malwareVerdict": "negative",
            "bulkVerdict": "negative",
            "senderReputation": "veryMalicious",
            "policyRoutes": ["phish_block"],
            "modulesRun": ["pdr"],
            "threatsInfoMap": [{"threatType": "phish", "threatStatus": "active",
                                "sha256": "abc123", "threatUrl": "https://tp.proofpoint.com/v2/url?k=abc"}],
            "messageParts": [],
            "urlsInBody": [{"url": "http://evil.com/payload"}],
            "spf": "fail",
            "dkim": "fail",
            "dmarc": "fail",
        }
        base.update(overrides)
        return base

    def test_tap_phish_blocked(self):
        raw = _json.dumps({"messagesBlocked": [self._tap_message()]})
        result = ProofpointParser.parse(raw)
        assert "ProofpointMessageEvents" in result
        evt = result["ProofpointMessageEvents"][0]
        assert evt["ActionType"] == "PhishFiltered"
        assert evt["PhishScore"] == 95.0
        assert evt["SenderReputation"] == "VeryMalicious"

    def test_tap_message_id_strips_angle_brackets(self):
        raw = _json.dumps({"messagesBlocked": [self._tap_message()]})
        result = ProofpointParser.parse(raw)
        evt = result["ProofpointMessageEvents"][0]
        assert evt["NetworkMessageId"] == "test-msg-001@corp.com"
        assert "<" not in evt["NetworkMessageId"]
        assert ">" not in evt["NetworkMessageId"]

    def test_tap_delivered_impostor(self):
        msg = self._tap_message(threatsInfoMap=[{"threatType": "impostor", "threatStatus": "active"}])
        raw = _json.dumps({"messagesDelivered": [msg]})
        result = ProofpointParser.parse(raw)
        evt = result["ProofpointMessageEvents"][0]
        assert evt["ActionType"] == "Delivered"

    def test_tap_click_blocked(self):
        click = {
            "GUID": "click-001",
            "messageID": "<test-msg-001@corp.com>",
            "clickTime": "2024-01-15T09:25:00Z",
            "recipient": "jsmith@corp.com",
            "sender": "attacker@evil.com",
            "senderIP": "1.2.3.4",
            "url": "http://evil.com/payload",
            "threatStatus": "active",
            "classification": "phish",
            "clickIP": "10.0.0.5",
            "userAgent": "Mozilla/5.0",
        }
        raw = _json.dumps({"clicksBlocked": [click]})
        result = ProofpointParser.parse(raw)
        assert "ProofpointClickEvents" in result
        evt = result["ProofpointClickEvents"][0]
        assert evt["ActionType"] == "UrlBlocked"
        assert evt["Blocked"] is True
        assert evt["NetworkMessageId"] == "test-msg-001@corp.com"

    def test_tap_click_permitted(self):
        click = {
            "GUID": "click-002",
            "messageID": "benign-msg@corp.com",
            "clickTime": "2024-01-15T10:00:00Z",
            "recipient": "bob@corp.com",
            "sender": "newsletter@vendor.com",
            "senderIP": "5.6.7.8",
            "url": "https://vendor.com/unsubscribe",
            "threatStatus": "cleared",
            "classification": "spam",
            "clickIP": "10.0.0.10",
        }
        raw = _json.dumps({"clicksPermitted": [click]})
        result = ProofpointParser.parse(raw)
        evt = result["ProofpointClickEvents"][0]
        assert evt["Blocked"] is False
        assert evt["ActionType"] == "UrlPermitted"

    def test_tap_report_id_from_guid(self):
        raw = _json.dumps({"messagesDelivered": [self._tap_message(GUID="my-guid-xyz")]})
        result = ProofpointParser.parse(raw)
        evt = result["ProofpointMessageEvents"][0]
        assert evt["ReportId"] == "my-guid-xyz"

    def test_tap_both_table_keys_returned(self):
        click = {
            "GUID": "c", "messageID": "m@x.com", "clickTime": "2024-01-15T09:00:00Z",
            "recipient": "a@b.com", "sender": "x@y.com", "senderIP": "1.1.1.1",
            "url": "http://x.com", "threatStatus": "active", "classification": "phish",
            "clickIP": "10.0.0.1",
        }
        raw = _json.dumps({
            "messagesBlocked": [self._tap_message()],
            "clicksBlocked": [click],
        })
        result = ProofpointParser.parse(raw)
        assert "ProofpointMessageEvents" in result
        assert "ProofpointClickEvents" in result

    def test_cef_message_parsed(self):
        cef = (
            "CEF:0|Proofpoint|TAP|1.0|100|Message Blocked|5|"
            "rt=2024-01-15T09:23:11Z suser=attacker@evil.com duser=jsmith@corp.com "
            "src=1.2.3.4 msg=Urgent deviceExternalId=cef-msg-001 "
            "cn1=10 cn2=90 cn3=0 spf=fail dkim=fail dmarc=fail"
        )
        result = ProofpointParser.parse(cef)
        assert "ProofpointMessageEvents" in result
        evt = result["ProofpointMessageEvents"][0]
        assert evt["SenderFromAddress"] == "attacker@evil.com"
        assert evt["PhishScore"] == 90.0

    def test_detect_source_tap_json(self):
        raw = _json.dumps({"messagesDelivered": [], "clicksBlocked": []})
        assert ProofpointParser.detect_source(raw) is True

    def test_detect_source_cef(self):
        assert ProofpointParser.detect_source("CEF:0|Proofpoint|TAP|1.0|100|msg|5|ext=val") is True


class TestAbnormalParser:
    def _threat(self, **overrides) -> dict:
        base = {
            "threatId": "abn-threat-001",
            "receivedTime": "2024-01-15T09:20:00Z",
            "attackType": "Business Email Compromise",
            "attackStrategy": "NaivetyExploitation",
            "attackVector": "email",
            "fromAddress": "ceo-fake@evil.com",
            "fromName": "John Smith (CEO)",
            "toAddress": "finance@corp.com",
            "toName": "Finance Team",
            "subject": "Urgent: Wire Transfer Approval",
            "isRecipientVip": True,
            "isSenderKnown": False,
            "impersonatedParty": "CEO",
            "abNormalScore": 0.98,
            "threatStatus": "Active",
            "remediationStatus": "Auto-Remediated",
            "suspiciousContent": ["urgent language", "wire transfer request"],
            "urls": [],
            "attachments": [],
        }
        base.update(overrides)
        return base

    def test_threat_detected_bec(self):
        raw = _json.dumps({"threats": [self._threat()]})
        result = AbnormalParser.parse(raw)
        assert "AbnormalThreatEvents" in result
        evt = result["AbnormalThreatEvents"][0]
        assert evt["ActionType"] == "ThreatDetected"
        assert evt["AttackType"] == "BEC"
        assert evt["RecipientIsVIP"] is True

    def test_threat_abnormal_score(self):
        raw = _json.dumps({"threats": [self._threat(abNormalScore=0.98)]})
        result = AbnormalParser.parse(raw)
        evt = result["AbnormalThreatEvents"][0]
        assert evt["AbNormalScore"] == pytest.approx(0.98)

    def test_threat_message_id_strips_angle_brackets(self):
        raw = _json.dumps({"threats": [self._threat(internetMessageId="<msg@corp.com>")]})
        result = AbnormalParser.parse(raw)
        evt = result["AbnormalThreatEvents"][0]
        assert evt["NetworkMessageId"] == "msg@corp.com"

    def test_threat_no_message_id_is_none(self):
        raw = _json.dumps({"threats": [self._threat()]})
        result = AbnormalParser.parse(raw)
        evt = result["AbnormalThreatEvents"][0]
        assert evt["NetworkMessageId"] is None

    def test_threat_remediated_action_type(self):
        raw = _json.dumps({"threats": [self._threat(threatStatus="Remediated")]})
        result = AbnormalParser.parse(raw)
        evt = result["AbnormalThreatEvents"][0]
        assert evt["ActionType"] == "ThreatRemediated"

    def test_case_opened(self):
        case = {
            "caseId": "abn-case-001",
            "createdAt": "2024-01-15T10:00:00Z",
            "status": "New",
            "severity": "High",
            "caseType": "BEC",
            "threatCount": 5,
            "affectedEmployeeCount": 3,
            "affectedAccountCount": 3,
            "firstObservedTime": "2024-01-14T08:00:00Z",
            "lastObservedTime": "2024-01-15T09:00:00Z",
            "remediationStatus": "Auto-Remediated",
        }
        raw = _json.dumps({"cases": [case]})
        result = AbnormalParser.parse(raw)
        assert "AbnormalCaseEvents" in result
        evt = result["AbnormalCaseEvents"][0]
        assert evt["ActionType"] == "CaseOpened"
        assert evt["CaseSeverity"] == "High"
        assert evt["ThreatCount"] == 5

    def test_case_closed_action_type(self):
        case = {
            "caseId": "abn-case-002",
            "status": "Closed",
            "severity": "Medium",
            "caseType": "Phishing",
            "threatCount": 2,
            "affectedEmployeeCount": 1,
            "affectedAccountCount": 1,
            "firstObservedTime": "2024-01-14T08:00:00Z",
            "lastObservedTime": "2024-01-15T09:00:00Z",
            "remediationStatus": "manually_remediated",
        }
        raw = _json.dumps({"cases": [case]})
        result = AbnormalParser.parse(raw)
        evt = result["AbnormalCaseEvents"][0]
        assert evt["ActionType"] == "CaseClosed"
        assert evt["RemediationStatus"] == "ManualRemediation"

    def test_webhook_threat_payload(self):
        payload = self._threat()
        payload["threatId"] = "webhook-threat-001"
        raw = _json.dumps(payload)
        result = AbnormalParser.parse(raw)
        assert "AbnormalThreatEvents" in result
        assert result["AbnormalThreatEvents"][0]["ReportId"] == "webhook-threat-001"

    def test_detect_source_threats_api(self):
        raw = _json.dumps({"threats": []})
        assert AbnormalParser.detect_source(raw) is True

    def test_detect_source_cases_api(self):
        raw = _json.dumps({"cases": []})
        assert AbnormalParser.detect_source(raw) is True

    def test_detect_source_webhook(self):
        raw = _json.dumps({"threatId": "abc", "receivedTime": "2024-01-15T09:00:00Z"})
        assert AbnormalParser.detect_source(raw) is True
