"""
parsers/cloudflare.py — Cloudflare Logpush log parser.

Handles three Cloudflare log datasets from a single file or stream:
  - CloudflareHttpEvents  : HTTP Requests dataset (has RayID + ClientRequestMethod)
  - CloudflareFirewallEvents: Firewall Events dataset (has RayID + FirewallSource)
  - CloudflareDnsEvents   : Gateway DNS dataset (has QueryName + ResponseCode)

All three formats are delivered as JSON lines. A single file may mix datasets
if the caller concatenated multiple Logpush outputs — each line is routed
independently based on field presence.

Returns a dict keyed by table name rather than a flat list, because a single
parse call can produce rows for up to three distinct tables.
"""

import json
import logging
import re
import uuid
from datetime import datetime, timezone
from typing import Any

logger = logging.getLogger(__name__)


class CloudflareParser:
    """Parse Cloudflare Logpush JSON line exports."""

    @classmethod
    def detect_source(cls, raw: str) -> bool:
        for line in raw.strip().splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
                return (
                    ("RayID" in obj and ("ClientRequestMethod" in obj or "FirewallSource" in obj))
                    or ("QueryName" in obj and "ResponseCode" in obj)
                )
            except json.JSONDecodeError:
                return False
        return False

    @classmethod
    def parse(cls, raw: str) -> dict[str, list[dict]]:
        """Parse Cloudflare JSON lines.

        Returns:
            Dict keyed by table name; only tables with events are included.
            e.g. {"CloudflareHttpEvents": [...], "CloudflareFirewallEvents": [...]}
        """
        result: dict[str, list[dict]] = {}

        for line in raw.strip().splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError as exc:
                logger.debug("CloudflareParser: skipping unparseable line: %s", exc)
                continue

            table, event = cls._route(obj)
            if table and event:
                result.setdefault(table, []).append(event)

        return result

    @classmethod
    def _route(cls, obj: dict) -> tuple[str | None, dict | None]:
        """Detect which Cloudflare dataset this line belongs to and map it."""
        if "RayID" in obj and "ClientRequestMethod" in obj:
            return "CloudflareHttpEvents", cls._map_http(obj)
        if "RayID" in obj and "FirewallSource" in obj:
            return "CloudflareFirewallEvents", cls._map_firewall(obj)
        if "QueryName" in obj and "ResponseCode" in obj:
            return "CloudflareDnsEvents", cls._map_dns(obj)
        return None, None

    # ------------------------------------------------------------------
    # HTTP Events
    # ------------------------------------------------------------------

    @classmethod
    def _map_http(cls, obj: dict) -> dict[str, Any]:
        ts_raw = obj.get("EdgeStartTimestamp")
        firewall_actions: list[str] = obj.get("FirewallMatchesActions") or []
        bot_score: int | None = obj.get("BotScore")
        threat_score: int | None = obj.get("ThreatScore")

        return {
            "Timestamp": cls._convert_timestamp(ts_raw).isoformat(),
            "ReportId": obj.get("RayID", str(uuid.uuid4())),
            "ActionType": cls._http_action_type(firewall_actions, bot_score, threat_score),
            "ClientIP": obj.get("ClientIP", ""),
            "ClientPort": obj.get("ClientSrcPort"),
            "ClientCountry": obj.get("ClientCountry"),
            "ClientASN": obj.get("ClientASN"),
            "ClientASNDescription": obj.get("ClientASNDescription"),
            "ClientRequestMethod": obj.get("ClientRequestMethod", ""),
            "ClientRequestHost": obj.get("ClientRequestHost", ""),
            "ClientRequestURI": obj.get("ClientRequestURI", ""),
            "ClientRequestUserAgent": obj.get("ClientRequestUserAgent", ""),
            "ClientRequestReferer": obj.get("ClientRequestReferer"),
            "ClientRequestBytes": obj.get("ClientRequestBytes"),
            "ClientSSLProtocol": obj.get("ClientSSLProtocol"),
            "ClientSSLCipher": obj.get("ClientSSLCipher"),
            "EdgeResponseStatus": obj.get("EdgeResponseStatus", 0),
            "EdgeResponseBytes": obj.get("EdgeResponseBytes", 0),
            "EdgeColoCode": obj.get("EdgeColoCode"),
            "EdgeServerIP": obj.get("EdgeServerIP"),
            "OriginIP": obj.get("OriginIP"),
            "OriginResponseStatus": obj.get("OriginResponseStatus"),
            "OriginResponseTime": obj.get("OriginResponseTime"),
            "CacheCacheStatus": obj.get("CacheCacheStatus"),
            "CacheTieredFill": obj.get("CacheTieredFill"),
            "FirewallMatchesActions": firewall_actions or None,
            "FirewallMatchesRuleIDs": obj.get("FirewallMatchesRuleIDs") or None,
            "BotScore": bot_score,
            "BotScoreSrc": obj.get("BotScoreSrc"),
            "ThreatScore": threat_score,
            "WorkerSubrequest": obj.get("WorkerSubrequest"),
            "ZoneName": obj.get("ZoneName"),
            "AdditionalFields": obj,
        }

    @classmethod
    def _http_action_type(
        cls,
        firewall_actions: list[str],
        bot_score: int | None,
        threat_score: int | None,
    ) -> str:
        actions_lower = [a.lower() for a in firewall_actions]
        if "block" in actions_lower:
            return "HttpBlocked"
        if "managed_challenge" in actions_lower:
            return "HttpManagedChallenge"
        if "challenge" in actions_lower:
            return "HttpChallenged"
        if bot_score is not None and bot_score >= 80:
            return "BotDetected"
        if threat_score is not None and threat_score >= 50:
            return "DDoSMitigation"
        if "ratelimit" in actions_lower or "rate_limit" in actions_lower:
            return "RateLimited"
        return "HttpRequest"

    # ------------------------------------------------------------------
    # Firewall Events
    # ------------------------------------------------------------------

    @classmethod
    def _map_firewall(cls, obj: dict) -> dict[str, Any]:
        fw_action: str = obj.get("Action", "")
        fw_source: str = obj.get("Source", obj.get("FirewallSource", ""))

        return {
            "Timestamp": cls._parse_iso_or_epoch(obj.get("Datetime", "")),
            "ReportId": obj.get("RayID", str(uuid.uuid4())),
            "ActionType": cls._firewall_action_type(fw_action, fw_source),
            "ClientIP": obj.get("ClientIP", ""),
            "ClientCountry": obj.get("ClientCountry"),
            "ClientASN": obj.get("ClientASN"),
            "ClientRequestMethod": obj.get("ClientRequestMethod"),
            "ClientRequestHost": obj.get("ClientRequestHost"),
            "ClientRequestURI": obj.get("ClientRequestURI"),
            "ClientRequestUserAgent": obj.get("ClientRequestUserAgent"),
            "EdgeColoCode": obj.get("EdgeColoCode"),
            "FirewallAction": fw_action,
            "FirewallRuleID": obj.get("RuleID", obj.get("FirewallRuleID", "")),
            "FirewallRuleDescription": obj.get("Description", obj.get("FirewallRuleDescription")),
            "FirewallSource": fw_source,
            "MatchIndex": obj.get("MatchIndex"),
            "Metadata": obj.get("Metadata"),
            "OriginResponseStatus": obj.get("OriginResponseStatus"),
            "SampledRate": obj.get("SampleInterval"),
            "ZoneName": obj.get("ZoneName"),
            "AdditionalFields": obj,
        }

    @classmethod
    def _firewall_action_type(cls, action: str, source: str) -> str:
        a = action.lower()
        s = source.lower()
        if a == "block":
            if s == "waf":
                return "WAFBlock"
            if s in ("ratelimit", "rate_limit"):
                return "RateLimitBlock"
            if s == "country":
                return "CountryBlock"
            if s == "l4":
                return "L4Block"
            return "FirewallBlock"
        if a == "challenge":
            return "FirewallChallenge"
        if a == "managed_challenge":
            return "FirewallManagedChallenge"
        if a == "allow":
            return "FirewallAllow"
        if a == "log":
            return "FirewallLog"
        if a == "skip":
            return "FirewallSkip"
        return "FirewallLog"

    # ------------------------------------------------------------------
    # DNS Events
    # ------------------------------------------------------------------

    @classmethod
    def _map_dns(cls, obj: dict) -> dict[str, Any]:
        blocked: bool = bool(obj.get("Blocked", False))
        threat_cat: str = obj.get("ThreatCategory", "") or ""
        policy_name: str = obj.get("PolicyName", "") or ""
        response_code: str = obj.get("ResponseCode", "")

        resolved_raw = obj.get("ResolvedIPs") or obj.get("Answers")
        resolved_ips: list[str] | None = None
        if isinstance(resolved_raw, list):
            resolved_ips = [str(ip) for ip in resolved_raw] or None
        elif isinstance(resolved_raw, str) and resolved_raw:
            resolved_ips = [resolved_raw]

        return {
            "Timestamp": cls._parse_iso_or_epoch(obj.get("QueryTimestamp", "")),
            "ReportId": obj.get("ReportId") or str(uuid.uuid4()),
            "ActionType": cls._dns_action_type(blocked, threat_cat, response_code, policy_name),
            "SourceIP": obj.get("SourceIP", obj.get("DeviceIP", "")),
            "SourcePort": obj.get("SourcePort"),
            "DeviceID": obj.get("DeviceID"),
            "DeviceName": obj.get("DeviceName"),
            "UserID": obj.get("UserID"),
            "AccountName": obj.get("AccountName"),
            "QueryName": obj.get("QueryName", ""),
            "QueryType": obj.get("QueryType", ""),
            "QueryTypeName": obj.get("QueryTypeName"),
            "ResponseCode": response_code,
            "ResolvedIPs": resolved_ips,
            "ResolverDecision": obj.get("ResolverDecision"),
            "ThreatCategory": threat_cat or None,
            "ThreatIndicator": obj.get("ThreatIndicator"),
            "PolicyName": policy_name or None,
            "PolicyID": obj.get("PolicyID"),
            "Blocked": blocked,
            "ResponseDurationMs": obj.get("QueryDurationMs"),
            "ZoneName": obj.get("ZoneName"),
            "Location": obj.get("Location"),
            "AdditionalFields": obj,
        }

    @classmethod
    def _dns_action_type(
        cls,
        blocked: bool,
        threat_category: str,
        response_code: str,
        policy_name: str,
    ) -> str:
        if blocked and threat_category:
            return "DnsThreatMatch"
        if blocked:
            return "DnsBlock"
        if response_code == "NXDOMAIN":
            return "DnsNXDomain"
        if response_code == "SERVFAIL":
            return "DnsServFail"
        if policy_name:
            return "DnsPolicyMatch"
        return "DnsQuery"

    # ------------------------------------------------------------------
    # Timestamp helpers
    # ------------------------------------------------------------------

    @classmethod
    def _convert_timestamp(cls, ts: int | float | str | None) -> datetime:
        """Convert EdgeStartTimestamp (nanosecond epoch integer) to UTC datetime."""
        if ts is None:
            return datetime.now(timezone.utc)
        try:
            ts_int = int(ts)
            # Nanosecond epoch: divide by 1e9
            return datetime.fromtimestamp(ts_int / 1_000_000_000, tz=timezone.utc)
        except (ValueError, TypeError, OSError):
            return datetime.now(timezone.utc)

    @classmethod
    def _parse_iso_or_epoch(cls, value: str | int | None) -> str:
        """Parse an ISO 8601 string or Unix epoch seconds to a UTC ISO string."""
        if value is None or value == "":
            return datetime.now(timezone.utc).isoformat()
        if isinstance(value, (int, float)):
            try:
                return datetime.fromtimestamp(float(value), tz=timezone.utc).isoformat()
            except (ValueError, OSError):
                return datetime.now(timezone.utc).isoformat()
        value_str = str(value).strip().rstrip("Z")
        if re.fullmatch(r"\d+", value_str):
            try:
                return datetime.fromtimestamp(int(value_str), tz=timezone.utc).isoformat()
            except (ValueError, OSError):
                pass
        try:
            if "+" not in value_str and "-" not in value_str[10:]:
                value_str += "+00:00"
            return datetime.fromisoformat(value_str).isoformat()
        except ValueError:
            return datetime.now(timezone.utc).isoformat()
