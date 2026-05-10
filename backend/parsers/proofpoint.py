"""
proofpoint.py — Parser for Proofpoint Targeted Attack Protection (TAP) SIEM API.

Handles two delivery formats:
  - TAP SIEM API JSON: {"messagesDelivered": [...], "messagesBlocked": [...],
                        "clicksPermitted": [...], "clicksBlocked": [...]}
  - Syslog/CEF: one CEF line per message event from Proofpoint syslog forwarder

Returns dict[str, list[dict]] keyed by table name:
  {"ProofpointMessageEvents": [...], "ProofpointClickEvents": [...]}

NetworkMessageId is the cross-table join key with ProofpointClickEvents and MDO.
Proofpoint delivers it angle-bracket-wrapped (<id@domain>) — strip them at ingest.
"""

from __future__ import annotations

import json
import re
import uuid
from datetime import datetime, timezone
from typing import Any
from urllib.parse import urlparse

from backend.parsers.base_parser import BaseParser

# CEF header pattern: CEF:0|vendor|product|version|sig|name|severity|extensions
_CEF_HEADER_RE = re.compile(
    r"^CEF:0\|(?P<vendor>[^|]*)\|(?P<product>[^|]*)\|(?P<version>[^|]*)\|"
    r"(?P<sig_id>[^|]*)\|(?P<name>[^|]*)\|(?P<severity>[^|]*)\|(?P<ext>.*)$"
)
_CEF_KV_RE = re.compile(r"(\w+)=((?:[^\\=\s]|\\.)+(?:\s(?=[^=\s]+=))*)")

# Proofpoint sender reputation labels from TAP API docs
_REPUTATION_MAP = {
    "veryMalicious": "VeryMalicious",
    "malicious":     "Malicious",
    "suspicious":    "Suspicious",
    "unknown":       "Unknown",
    "neutral":       "NeutralOrGood",
    "good":          "NeutralOrGood",
}

# TAP disposition → ActionType mapping
_DISPOSITION_TO_ACTION: dict[str, str] = {
    "deliver":     "Delivered",
    "quarantine":  "Quarantined",
    "discard":     "Blocked",
}

# TAP threat type → ActionType suffix used when disposition is quarantine/discard
_THREAT_TO_ACTION: dict[str, str] = {
    "spam":      "SpamFiltered",
    "phish":     "PhishFiltered",
    "malware":   "MalwareBlocked",
    "impostor":  "ImpostorBlocked",
    "bulk":      "BulkFiltered",
    "sandbox":   "SandboxBlocked",
}


class ProofpointParser(BaseParser):
    """Parse Proofpoint TAP SIEM API JSON and syslog/CEF into MDE-aligned tables."""

    @classmethod
    def detect_source(cls, raw: str) -> bool:
        stripped = raw.strip()
        if stripped.startswith("CEF:0|Proofpoint") or stripped.startswith("CEF:0|proofpoint"):
            return True
        try:
            data = json.loads(stripped)
            tap_keys = {"messagesDelivered", "messagesBlocked", "clicksPermitted", "clicksBlocked"}
            return bool(tap_keys & set(data.keys()))
        except (json.JSONDecodeError, AttributeError):
            return False

    @classmethod
    def parse(cls, raw: str) -> dict[str, list[dict]]:
        stripped = raw.strip()
        result: dict[str, list[dict]] = {
            "ProofpointMessageEvents": [],
            "ProofpointClickEvents": [],
        }

        # CEF syslog — one event per line
        if stripped.startswith("CEF:"):
            for line in stripped.splitlines():
                line = line.strip()
                if not line:
                    continue
                event = cls._parse_cef_line(line)
                if event:
                    table, record = event
                    result.setdefault(table, []).append(record)
            return {k: v for k, v in result.items() if v}

        # TAP SIEM API JSON
        try:
            data = json.loads(stripped)
        except json.JSONDecodeError:
            return result

        for msg in data.get("messagesDelivered", []):
            record = cls._parse_tap_message(msg, delivered=True)
            result["ProofpointMessageEvents"].append(record)

        for msg in data.get("messagesBlocked", []):
            record = cls._parse_tap_message(msg, delivered=False)
            result["ProofpointMessageEvents"].append(record)

        for click in data.get("clicksPermitted", []):
            record = cls._parse_tap_click(click, blocked=False)
            result["ProofpointClickEvents"].append(record)

        for click in data.get("clicksBlocked", []):
            record = cls._parse_tap_click(click, blocked=True)
            result["ProofpointClickEvents"].append(record)

        return {k: v for k, v in result.items() if v}

    # ------------------------------------------------------------------
    # TAP SIEM API message parsing
    # ------------------------------------------------------------------

    @classmethod
    def _parse_tap_message(cls, msg: dict[str, Any], *, delivered: bool) -> dict:
        threats: list[dict] = msg.get("threatsInfoMap", [])
        action_type = cls._derive_message_action_type(msg, delivered=delivered)

        recipients: list[str] = msg.get("recipient", [])
        primary_recipient = recipients[0] if recipients else ""

        attachments: list[dict] = msg.get("messageParts", [])
        att_names = [a.get("filename", "") for a in attachments if a.get("filename")]
        att_types = [a.get("contentType", "") for a in attachments if a.get("contentType")]
        att_hashes = [a.get("sha256", "") for a in attachments if a.get("sha256")]

        urls: list[dict] = msg.get("urlsInBody", []) + msg.get("urlsInHeaders", [])

        header_from = msg.get("headerFrom", "") or ""
        from_address = msg.get("fromAddress", [])
        sender_from = from_address[0] if isinstance(from_address, list) and from_address else (from_address or "")
        sender_domain = sender_from.split("@")[-1] if "@" in sender_from else ""

        quarantine_folder = msg.get("quarantineFolder") or None
        quarantine_rule = msg.get("quarantineRule") or None

        spf_val = (msg.get("spfVerified") or msg.get("spf") or "none").lower()
        dkim_val = (msg.get("dkimVerified") or msg.get("dkim") or "none").lower()
        dmarc_val = (msg.get("dmarcVerified") or msg.get("dmarc") or "none").lower()

        return {
            "Timestamp":               cls._parse_timestamp(msg.get("messageTime", "")),
            "ReportId":                msg.get("GUID") or str(uuid.uuid4()),
            "NetworkMessageId":        cls._normalize_message_id(msg.get("messageID", "")),
            "ActionType":              action_type,
            "SenderFromAddress":       sender_from,
            "SenderFromDomain":        sender_domain,
            "SenderIP":                msg.get("senderIP", ""),
            "SenderReputation":        _REPUTATION_MAP.get(msg.get("senderReputation", ""), "Unknown"),
            "RecipientEmailAddress":   primary_recipient,
            "RecipientEmailAddresses": recipients,
            "Subject":                 msg.get("subject", ""),
            "MessageSize":             int(msg.get("messageSize", 0) or 0),
            "SpamScore":               float(msg.get("spamScore", 0) or 0),
            "PhishScore":              float(msg.get("phishScore", 0) or 0),
            "ImpostorScore":           float(msg.get("impostorScore", 0) or 0),
            "MalwareScore":            float(msg.get("malwareScore", 0) or 0),
            "SpamVerdict":             cls._verdict(msg.get("spamVerdict")),
            "PhishVerdict":            cls._verdict(msg.get("phishVerdict")),
            "MalwareVerdict":          cls._verdict(msg.get("malwareVerdict")),
            "BulkVerdict":             cls._verdict(msg.get("bulkVerdict")),
            "DispositionAction":       "deliver" if delivered else "quarantine",
            "QuarantineFolder":        quarantine_folder,
            "QuarantineRule":          quarantine_rule,
            "PolicyRoutes":            msg.get("policyRoutes", []),
            "ModulesRun":              msg.get("modulesRun", []),
            "ThreatsInfoMap":          json.dumps(threats),
            "AttachmentCount":         len(attachments),
            "AttachmentNames":         att_names or None,
            "AttachmentTypes":         att_types or None,
            "AttachmentSHA256":        att_hashes or None,
            "UrlCount":                len(urls),
            "HeaderFrom":              header_from,
            "HeaderReplyTo":           msg.get("replyToAddress") or None,
            "XOriginatingIP":          msg.get("xOriginatingIp") or None,
            "DKIM":                    dkim_val,
            "DMARC":                   dmarc_val,
            "SPF":                     spf_val,
            "AdditionalFields":        json.dumps(msg),
        }

    @classmethod
    def _derive_message_action_type(cls, msg: dict, *, delivered: bool) -> str:
        threats: list[dict] = msg.get("threatsInfoMap", [])
        if not threats:
            return "Delivered" if delivered else "Blocked"

        # Highest-priority threat type determines ActionType
        threat_types = {t.get("threatType", "").lower() for t in threats}
        for threat_key in ("malware", "impostor", "phish", "spam", "bulk", "sandbox"):
            if threat_key in threat_types:
                if not delivered:
                    return _THREAT_TO_ACTION.get(threat_key, "Blocked")
                # Delivered despite threat → note in action type
                return "Delivered"
        return "Delivered" if delivered else "Blocked"

    # ------------------------------------------------------------------
    # TAP SIEM API click parsing
    # ------------------------------------------------------------------

    @classmethod
    def _parse_tap_click(cls, click: dict[str, Any], *, blocked: bool) -> dict:
        url = click.get("url", "")
        url_domain = ""
        try:
            url_domain = urlparse(url).hostname or ""
        except Exception:
            pass

        threat_time_raw = click.get("threatTime")
        threat_time = cls._parse_timestamp(threat_time_raw) if threat_time_raw else None

        action_type = "UrlBlocked" if blocked else "UrlPermitted"
        if click.get("classification", "").lower() in ("phish", "malware", "ransomware"):
            action_type = "UrlBlocked" if blocked else "UrlClicked"

        return {
            "Timestamp":             cls._parse_timestamp(click.get("clickTime", "")),
            "ReportId":              click.get("GUID") or str(uuid.uuid4()),
            "NetworkMessageId":      cls._normalize_message_id(click.get("messageID", "")),
            "ActionType":            action_type,
            "RecipientEmailAddress": click.get("recipient", ""),
            "SenderFromAddress":     click.get("sender", ""),
            "SenderIP":              click.get("senderIP", ""),
            "Url":                   url,
            "UrlDomain":             url_domain,
            "ThreatURL":             click.get("threatURL") or None,
            "ThreatStatus":          click.get("threatStatus", "active"),
            "Classification":        click.get("classification", ""),
            "ThreatTime":            threat_time,
            "UserAgent":             click.get("userAgent") or None,
            "ClickIP":               click.get("clickIP", ""),
            "Blocked":               blocked,
            "CampaignId":            click.get("campaignId") or None,
            "AdditionalFields":      json.dumps(click),
        }

    # ------------------------------------------------------------------
    # CEF syslog parsing
    # ------------------------------------------------------------------

    @classmethod
    def _parse_cef_line(cls, line: str) -> tuple[str, dict] | None:
        m = _CEF_HEADER_RE.match(line)
        if not m:
            return None

        sig_id = m.group("sig_id")
        name_lower = m.group("name").lower()
        ext_str = m.group("ext")
        ext = {k: v.strip() for k, v in _CEF_KV_RE.findall(ext_str)}

        # Route by event name — Proofpoint uses "click" for URL click events
        if "click" in name_lower:
            return "ProofpointClickEvents", cls._cef_to_click(ext, blocked="block" in name_lower)

        return "ProofpointMessageEvents", cls._cef_to_message(ext, sig_id)

    @classmethod
    def _cef_to_message(cls, ext: dict, sig_id: str) -> dict:
        sender = ext.get("suser", ext.get("fromAddress", ""))
        sender_domain = sender.split("@")[-1] if "@" in sender else ""
        recipients_raw = ext.get("duser", "")
        recipients = [r.strip() for r in recipients_raw.split(",") if r.strip()]

        return {
            "Timestamp":               cls._parse_timestamp(ext.get("rt", "")),
            "ReportId":                ext.get("externalId") or str(uuid.uuid4()),
            "NetworkMessageId":        cls._normalize_message_id(ext.get("deviceExternalId", "")),
            "ActionType":              "Quarantined" if "quarantine" in sig_id.lower() else "Delivered",
            "SenderFromAddress":       sender,
            "SenderFromDomain":        sender_domain,
            "SenderIP":                ext.get("src", ""),
            "SenderReputation":        _REPUTATION_MAP.get(ext.get("cs1", ""), "Unknown"),
            "RecipientEmailAddress":   recipients[0] if recipients else "",
            "RecipientEmailAddresses": recipients,
            "Subject":                 ext.get("msg", ""),
            "MessageSize":             int(ext.get("fileSize", 0) or 0),
            "SpamScore":               float(ext.get("cn1", 0) or 0),
            "PhishScore":              float(ext.get("cn2", 0) or 0),
            "ImpostorScore":           0.0,
            "MalwareScore":            float(ext.get("cn3", 0) or 0),
            "SpamVerdict":             "Positive" if float(ext.get("cn1", 0) or 0) > 50 else "Negative",
            "PhishVerdict":            "Positive" if float(ext.get("cn2", 0) or 0) > 50 else "Negative",
            "MalwareVerdict":          "Positive" if float(ext.get("cn3", 0) or 0) > 50 else "Negative",
            "BulkVerdict":             "Negative",
            "DispositionAction":       "quarantine" if "quarantine" in sig_id.lower() else "deliver",
            "QuarantineFolder":        ext.get("cs2") or None,
            "QuarantineRule":          ext.get("cs3") or None,
            "PolicyRoutes":            [],
            "ModulesRun":              [],
            "ThreatsInfoMap":          "[]",
            "AttachmentCount":         int(ext.get("fileCount", 0) or 0),
            "AttachmentNames":         None,
            "AttachmentTypes":         None,
            "AttachmentSHA256":        None,
            "UrlCount":                int(ext.get("urlCount", 0) or 0),
            "HeaderFrom":              ext.get("fromAddress", ""),
            "HeaderReplyTo":           ext.get("replyTo") or None,
            "XOriginatingIP":          ext.get("cs4") or None,
            "DKIM":                    ext.get("dkim", "none"),
            "DMARC":                   ext.get("dmarc", "none"),
            "SPF":                     ext.get("spf", "none"),
            "AdditionalFields":        json.dumps(ext),
        }

    @classmethod
    def _cef_to_click(cls, ext: dict, *, blocked: bool) -> dict:
        url = ext.get("request", "")
        url_domain = ""
        try:
            url_domain = urlparse(url).hostname or ""
        except Exception:
            pass

        return {
            "Timestamp":             cls._parse_timestamp(ext.get("rt", "")),
            "ReportId":              ext.get("externalId") or str(uuid.uuid4()),
            "NetworkMessageId":      cls._normalize_message_id(ext.get("deviceExternalId", "")),
            "ActionType":            "UrlBlocked" if blocked else "UrlPermitted",
            "RecipientEmailAddress": ext.get("duser", ""),
            "SenderFromAddress":     ext.get("suser", ""),
            "SenderIP":              ext.get("src", ""),
            "Url":                   url,
            "UrlDomain":             url_domain,
            "ThreatURL":             None,
            "ThreatStatus":          "active",
            "Classification":        ext.get("cs1", "phish"),
            "ThreatTime":            None,
            "UserAgent":             ext.get("requestClientApplication") or None,
            "ClickIP":               ext.get("src", ""),
            "Blocked":               blocked,
            "CampaignId":            ext.get("cs2") or None,
            "AdditionalFields":      json.dumps(ext),
        }

    # ------------------------------------------------------------------
    # Shared helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _normalize_message_id(raw: str) -> str:
        """Strip angle brackets from Proofpoint Message-ID before storing.

        Proofpoint delivers IDs as <id@domain>; MDO stores without brackets.
        Stripping here ensures NetworkMessageId is consistent across both tables.
        """
        if raw.startswith("<") and raw.endswith(">"):
            return raw[1:-1]
        return raw

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

    @staticmethod
    def _verdict(raw: Any) -> str:
        if raw is None:
            return "Negative"
        val = str(raw).lower()
        if val in ("positive", "true", "1"):
            return "Positive"
        if val in ("neutral",):
            return "Neutral"
        return "Negative"
