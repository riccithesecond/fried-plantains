"""
abnormal.py — Parser for Abnormal Security AI email threat platform.

Handles three delivery formats:
  - REST API /threats response: {"threats": [...]}
  - REST API /cases response: {"cases": [...]}
  - Webhook payload: single threat or case object with "threatId" or "caseId" key

Returns dict[str, list[dict]] keyed by table name:
  {"AbnormalThreatEvents": [...], "AbnormalCaseEvents": [...]}

NetworkMessageId is nullable in AbnormalThreatEvents — Abnormal does not always
have the original Message-ID. Strip angle brackets when present to align with
ProofpointMessageEvents and MDO join key convention.
"""

from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone
from typing import Any

from backend.parsers.base_parser import BaseParser

# Abnormal attack type normalization — API returns various spellings
_ATTACK_TYPE_MAP: dict[str, str] = {
    "Business Email Compromise":       "BEC",
    "bec":                             "BEC",
    "Phishing":                        "Phishing",
    "phishing":                        "Phishing",
    "Malware":                         "Malware",
    "malware":                         "Malware",
    "Spam":                            "Spam",
    "spam":                            "Spam",
    "Social Engineering":              "SocialEngineering",
    "social_engineering":              "SocialEngineering",
    "Account Takeover":                "AccountTakeover",
    "account_takeover":                "AccountTakeover",
    "Reputation Hijacking":            "ReputationHijacking",
    "reputation_hijacking":            "ReputationHijacking",
}

_ATTACK_VECTOR_MAP: dict[str, str] = {
    "email":             "Email",
    "link":              "Link",
    "attachment":        "Attachment",
    "social":            "SocialEngineering",
}

_REMEDIATION_STATUS_MAP: dict[str, str] = {
    "Auto-Remediated":        "Auto-remediated",
    "auto_remediated":        "Auto-remediated",
    "Manually Remediated":    "ManualRemediation",
    "manually_remediated":    "ManualRemediation",
    "Pending Remediation":    "Pending",
    "pending":                "Pending",
    "Not Remediated":         "NotRemediated",
    "not_remediated":         "NotRemediated",
}

_CASE_TYPE_MAP: dict[str, str] = {
    "Account Takeover":   "AccountTakeover",
    "account_takeover":   "AccountTakeover",
    "bec":                "BEC",
    "BEC":                "BEC",
    "Phishing":           "Phishing",
    "Malware":            "Malware",
    "Policy":             "Policy",
}


class AbnormalParser(BaseParser):
    """Parse Abnormal Security /threats, /cases API responses and webhooks."""

    @classmethod
    def detect_source(cls, raw: str) -> bool:
        stripped = raw.strip()
        try:
            data = json.loads(stripped)
            if isinstance(data, dict):
                # REST API list responses
                if "threats" in data or "cases" in data:
                    return True
                # Webhook single-object payloads
                if "threatId" in data or "caseId" in data or "abxMessageId" in data:
                    return True
            return False
        except (json.JSONDecodeError, AttributeError):
            return False

    @classmethod
    def parse(cls, raw: str) -> dict[str, list[dict]]:
        result: dict[str, list[dict]] = {
            "AbnormalThreatEvents": [],
            "AbnormalCaseEvents": [],
        }

        try:
            data = json.loads(raw.strip())
        except json.JSONDecodeError:
            return result

        if not isinstance(data, dict):
            return result

        # REST API list responses
        for threat in data.get("threats", []):
            result["AbnormalThreatEvents"].append(cls._parse_threat(threat))

        for case in data.get("cases", []):
            result["AbnormalCaseEvents"].append(cls._parse_case(case))

        # Webhook single-object payloads
        if "threatId" in data or "abxMessageId" in data:
            result["AbnormalThreatEvents"].append(cls._parse_threat(data))

        if "caseId" in data:
            result["AbnormalCaseEvents"].append(cls._parse_case(data))

        return {k: v for k, v in result.items() if v}

    # ------------------------------------------------------------------
    # Threat parsing
    # ------------------------------------------------------------------

    @classmethod
    def _parse_threat(cls, threat: dict[str, Any]) -> dict:
        attack_type_raw = threat.get("attackType", threat.get("attack_type", ""))
        attack_type = _ATTACK_TYPE_MAP.get(attack_type_raw, attack_type_raw or "Phishing")

        attack_vector_raw = (threat.get("attackVector", threat.get("attack_vector", "email")) or "email").lower()
        attack_vector = _ATTACK_VECTOR_MAP.get(attack_vector_raw, "Email")

        remediation_raw = threat.get("remediationStatus", threat.get("remediation_status", ""))
        remediation_status = _REMEDIATION_STATUS_MAP.get(remediation_raw, remediation_raw or "NotRemediated")

        remediation_ts_raw = threat.get("remediationTimestamp", threat.get("remediation_timestamp"))
        remediation_ts = cls._parse_timestamp(remediation_ts_raw) if remediation_ts_raw else None

        # Determine ActionType from status
        threat_status = threat.get("threatStatus", threat.get("status", "Active"))
        action_type = cls._derive_threat_action_type(threat_status)

        sender = threat.get("fromAddress", threat.get("senderAddress", ""))
        sender_domain = sender.split("@")[-1] if "@" in sender else ""

        recipient = threat.get("toAddress", threat.get("recipientAddress", ""))

        attachments: list[dict] = threat.get("attachments", [])
        att_names = [a.get("filename", "") for a in attachments if a.get("filename")] or None
        att_hashes = [a.get("sha256", "") for a in attachments if a.get("sha256")] or None

        urls: list[str] = threat.get("urls", []) or []
        suspicious_urls = [u for u in urls if isinstance(u, str)] or None

        suspicious_content: list[str] = threat.get("suspiciousContent", threat.get("suspicious_content", [])) or []

        score_raw = threat.get("abNormalScore", threat.get("abnormal_score", threat.get("score", 0)))
        ab_score = float(score_raw or 0)

        return {
            "Timestamp":             cls._parse_timestamp(threat.get("receivedTime", threat.get("received_time", ""))),
            "ReportId":              str(threat.get("threatId", threat.get("abxMessageId", uuid.uuid4()))),
            "NetworkMessageId":      cls._normalize_message_id(threat.get("internetMessageId", threat.get("messageId")) or ""),
            "ActionType":            action_type,
            "AttackType":            attack_type,
            "AttackStrategy":        threat.get("attackStrategy", threat.get("attack_strategy", attack_type)),
            "AttackVector":          attack_vector,
            "ThreatStatus":          threat_status,
            "AbNormalScore":         ab_score,
            "SenderFromAddress":     sender,
            "SenderFromDomain":      sender_domain,
            "SenderDisplayName":     threat.get("fromName", threat.get("senderName", sender)),
            "SenderIP":              threat.get("senderIp", threat.get("sender_ip")) or None,
            "IsSenderKnown":         bool(threat.get("isSenderKnown", threat.get("is_sender_known", False))),
            "ReplyToAddress":        threat.get("replyToAddress", threat.get("reply_to")) or None,
            "RecipientEmailAddress": recipient,
            "RecipientName":         threat.get("toName", threat.get("recipientName", "")),
            "RecipientIsVIP":        bool(threat.get("isRecipientVip", threat.get("recipient_is_vip", False))),
            "ImpersonatedParty":     threat.get("impersonatedParty", threat.get("impersonated_party")) or None,
            "ImpersonatedEmail":     threat.get("impersonatedEmail", threat.get("impersonated_email")) or None,
            "Subject":               threat.get("subject", ""),
            "SubjectModified":       bool(threat.get("subjectModified", threat.get("subject_modified", False))),
            "SuspiciousContent":     suspicious_content,
            "RemediationStatus":     remediation_status,
            "RemediationTimestamp":  remediation_ts,
            "AttachmentCount":       len(attachments) if attachments else None,
            "AttachmentNames":       att_names,
            "AttachmentSHA256":      att_hashes,
            "UrlCount":              len(urls) if urls else None,
            "SuspiciousUrls":        suspicious_urls,
            "CampaignId":            threat.get("campaignId", threat.get("campaign_id")) or None,
            "AdditionalFields":      json.dumps(threat),
        }

    @staticmethod
    def _derive_threat_action_type(status: str) -> str:
        normalized = (status or "").lower().replace(" ", "").replace("_", "")
        if "remediat" in normalized:
            return "ThreatRemediated"
        if "released" in normalized or "release" in normalized:
            return "ThreatReleased"
        if "false" in normalized and "positive" in normalized:
            return "FalsePositive"
        return "ThreatDetected"

    # ------------------------------------------------------------------
    # Case parsing
    # ------------------------------------------------------------------

    @classmethod
    def _parse_case(cls, case: dict[str, Any]) -> dict:
        case_type_raw = case.get("caseType", case.get("case_type", ""))
        case_type = _CASE_TYPE_MAP.get(case_type_raw, case_type_raw or "Policy")

        remediation_raw = case.get("remediationStatus", case.get("remediation_status", ""))
        remediation_status = _REMEDIATION_STATUS_MAP.get(remediation_raw, remediation_raw or "NotRemediated")

        remediation_ts_raw = case.get("remediationTimestamp", case.get("remediation_timestamp"))
        remediation_ts = cls._parse_timestamp(remediation_ts_raw) if remediation_ts_raw else None

        case_status = case.get("status", "New")
        action_type = cls._derive_case_action_type(case_status)

        first_ts = cls._parse_timestamp(case.get("firstObservedTime", case.get("first_observed_time", "")))
        last_ts = cls._parse_timestamp(case.get("lastObservedTime", case.get("last_observed_time", "")))
        case_ts = case.get("timestamp", case.get("createdAt", case.get("created_at", "")))

        return {
            "Timestamp":              cls._parse_timestamp(case_ts) if case_ts else first_ts,
            "ReportId":               str(case.get("caseId", uuid.uuid4())),
            "ActionType":             action_type,
            "CaseSeverity":           case.get("severity", "Medium"),
            "CaseStatus":             case_status,
            "CaseType":               case_type,
            "ThreatCount":            int(case.get("threatCount", case.get("threat_count", 0)) or 0),
            "AffectedEmployeeCount":  int(case.get("affectedEmployeeCount", case.get("affected_employee_count", 0)) or 0),
            "AffectedAccountCount":   int(case.get("affectedAccountCount", case.get("affected_account_count", 0)) or 0),
            "FirstObservedTimestamp": first_ts,
            "LastObservedTimestamp":  last_ts,
            "RemediationStatus":      remediation_status,
            "RemediationTimestamp":   remediation_ts,
            "AnalystAssigned":        case.get("analystAssigned", case.get("analyst_assigned")) or None,
            "ResolutionReason":       case.get("resolutionReason", case.get("resolution_reason")) or None,
            "AdditionalFields":       json.dumps(case),
        }

    @staticmethod
    def _derive_case_action_type(status: str) -> str:
        normalized = (status or "").lower()
        if "closed" in normalized:
            return "CaseClosed"
        if "investig" in normalized or "open" in normalized or "new" in normalized:
            return "CaseOpened"
        return "CaseUpdated"

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _normalize_message_id(raw: str) -> str | None:
        """Strip angle brackets and return None for empty strings."""
        if not raw:
            return None
        if raw.startswith("<") and raw.endswith(">"):
            raw = raw[1:-1]
        return raw or None

    @staticmethod
    def _parse_timestamp(raw: Any) -> str:
        if not raw:
            return datetime.now(timezone.utc).isoformat()
        if isinstance(raw, (int, float)):
            return datetime.fromtimestamp(raw, tz=timezone.utc).isoformat()
        raw_str = str(raw).strip()
        for fmt in ("%Y-%m-%dT%H:%M:%S.%fZ", "%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%d %H:%M:%S"):
            try:
                return datetime.strptime(raw_str, fmt).replace(tzinfo=timezone.utc).isoformat()
            except ValueError:
                continue
        try:
            return datetime.fromisoformat(raw_str).isoformat()
        except ValueError:
            return datetime.now(timezone.utc).isoformat()
