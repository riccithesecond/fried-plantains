"""
parsers/zscaler.py — Zscaler NSS log parser.

Handles two Zscaler log types from NSS feeds or API exports:
  - ZscalerWebEvents : HTTP/S transactions from ZIA web proxy
  - ZscalerDnsEvents : DNS queries from Zscaler DNS Security

Two wire formats are supported:
  1. JSON lines  — detected by lines starting with '{'
  2. key=value   — NSS native format: time=... action=Allowed url=https://...

Zscaler NSS uses inconsistent field names across firmware versions. Field alias
normalisation happens in _extract() before schema mapping so the rest of the
parser only deals with canonical names.

Returns a list of {"table": <name>, "data": <dict>} records, consistent with
the CloudTrailParser interface so the ingest pipeline handles them the same way.
"""

import json
import logging
import re
import uuid
from datetime import datetime, timezone
from typing import Any
from urllib.parse import urlparse

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Field alias maps — NSS field name → canonical name
# ---------------------------------------------------------------------------

_WEB_ALIASES: dict[str, str] = {
    "url": "RequestURL",
    "requesturl": "RequestURL",
    "fullurl": "RequestURL",
    "hostname": "RequestHost",
    "requesthost": "RequestHost",
    "host": "RequestHost",
    "srcip": "ClientIP",
    "clientip": "ClientIP",
    "cip": "ClientIP",
    "user": "UserName",
    "login": "UserName",
    "username": "UserName",
    "action": "action",
    "urlaction": "action",
    "webaction": "action",
    "cat": "URLCategory",
    "urlcat": "URLCategory",
    "category": "URLCategory",
    "appname": "CloudApplicationName",
    "cloudapp": "CloudApplicationName",
    "apprisk": "CloudApplicationRisk",
    "malwareclass": "MalwareClass",
    "threatclass": "MalwareClass",
    "malwarename": "MalwareName",
    "threatname": "MalwareName",
    "fileclass": "FileType",
    "filetype": "FileType",
    "filename": "FileName",
    "sha256": "FileSHA256",
    "filesha256": "FileSHA256",
    "dept": "Department",
    "department": "Department",
    "location": "Location",
    "loc": "Location",
    "reqsize": "RequestSize",
    "requestsize": "RequestSize",
    "respsize": "ResponseSize",
    "responsesize": "ResponseSize",
    "resptime": "ResponseTime",
    "responsetime": "ResponseTime",
    "duration": "ResponseTime",
    "protocol": "Protocol",
    "method": "RequestMethod",
    "requestmethod": "RequestMethod",
    "respcode": "ResponseCode",
    "responsecode": "ResponseCode",
    "contenttype": "ContentType",
    "contenttype": "ContentType",
    "serverip": "ServerIP",
    "destip": "ServerIP",
    "serverport": "ServerPort",
    "destport": "ServerPort",
    "bytesin": "BytesIn",
    "bytesout": "BytesOut",
    "deviceowner": "DeviceOwner",
    "devicename": "DeviceName",
    "devicehostname": "DeviceName",
    "ssldecrypted": "SSLDecrypted",
    "rulelabel": "RuleLabel",
    "rulename": "RuleLabel",
    "policyname": "PolicyName",
    "policy": "PolicyName",
    "time": "_ts",
    "datetime": "_ts",
    "epochtime": "_ts",
    "timestamp": "_ts",
}

_DNS_ALIASES: dict[str, str] = {
    "dns_query": "QueryName",
    "dnsname": "QueryName",
    "queryname": "QueryName",
    "qname": "QueryName",
    "dns_type": "QueryType",
    "querytype": "QueryType",
    "qtype": "QueryType",
    "dns_response": "ResponseCode",
    "responsecode": "ResponseCode",
    "rcode": "ResponseCode",
    "srcip": "ClientIP",
    "clientip": "ClientIP",
    "resolvedips": "ResolvedIPs",
    "answers": "ResolvedIPs",
    "category": "CategoryName",
    "categoryname": "CategoryName",
    "threatname": "ThreatName",
    "threatcategory": "ThreatCategory",
    "policyname": "PolicyName",
    "action": "action",
    "devicename": "DeviceName",
    "deviceowner": "DeviceOwner",
    "dept": "Department",
    "department": "Department",
    "location": "Location",
    "user": "UserName",
    "login": "UserName",
    "username": "UserName",
    "durationms": "DnsDurationMs",
    "querydurationms": "DnsDurationMs",
    "doh": "DoHStatus",
    "time": "_ts",
    "datetime": "_ts",
    "epochtime": "_ts",
    "timestamp": "_ts",
}

# DNS-indicator field names — presence of any of these means this is a DNS log line
_DNS_INDICATOR_FIELDS = frozenset({"dns_query", "dnsname", "queryname", "qname", "dns_type"})


class ZscalerParser:
    """Parse Zscaler NSS web and DNS log exports."""

    @classmethod
    def detect_source(cls, raw: str) -> bool:
        for line in raw.strip().splitlines():
            line = line.strip()
            if not line:
                continue
            if line.startswith("{"):
                try:
                    obj = json.loads(line)
                    return (
                        "url" in obj or "requesturl" in obj or "hostname" in obj
                        or "dns_query" in obj or "dnsname" in obj or "queryname" in obj
                    )
                except json.JSONDecodeError:
                    return False
            # key=value — check for Zscaler-specific fields
            return bool(
                re.search(r"\b(action|urlaction|webaction|dns_query|dnsname)\s*=", line, re.I)
            )
        return False

    @classmethod
    def parse(cls, raw: str) -> list[dict]:
        """Parse Zscaler log lines.

        Returns:
            List of {"table": <name>, "data": <event dict>} records.
        """
        results = []
        for line in raw.strip().splitlines():
            line = line.strip()
            if not line:
                continue
            fields = cls._parse_line(line)
            if not fields:
                continue
            table, event = cls._map(fields)
            if table and event:
                results.append({"table": table, "data": event})
        return results

    # ------------------------------------------------------------------
    # Line parsing
    # ------------------------------------------------------------------

    @classmethod
    def _parse_line(cls, line: str) -> dict[str, Any] | None:
        """Parse a single line as JSON or key=value."""
        if line.startswith("{"):
            try:
                return json.loads(line)
            except json.JSONDecodeError as exc:
                logger.debug("ZscalerParser: JSON parse error: %s", exc)
                return None
        return cls._parse_kv(line)

    @classmethod
    def _parse_kv(cls, line: str) -> dict[str, str]:
        """Parse Zscaler NSS key=value format into a dict."""
        # Handles: key=value key2=value2 key3="quoted value"
        result: dict[str, str] = {}
        pattern = re.compile(r'(\w+)=("(?:[^"\\]|\\.)*"|[^=\s]+)')
        for match in pattern.finditer(line):
            key = match.group(1)
            val = match.group(2).strip('"')
            result[key] = val
        return result

    # ------------------------------------------------------------------
    # Routing and mapping
    # ------------------------------------------------------------------

    @classmethod
    def _is_dns(cls, raw_fields: dict) -> bool:
        """Return True if the fields look like a DNS log line."""
        lower_keys = {k.lower() for k in raw_fields}
        return bool(lower_keys & _DNS_INDICATOR_FIELDS)

    @classmethod
    def _map(cls, raw_fields: dict) -> tuple[str | None, dict | None]:
        """Normalise aliases and route to the correct table mapper."""
        if cls._is_dns(raw_fields):
            normalised = cls._extract(raw_fields, _DNS_ALIASES)
            return "ZscalerDnsEvents", cls._map_dns(normalised, raw_fields)
        normalised = cls._extract(raw_fields, _WEB_ALIASES)
        return "ZscalerWebEvents", cls._map_web(normalised, raw_fields)

    @classmethod
    def _extract(cls, raw: dict, alias_map: dict[str, str]) -> dict[str, Any]:
        """Translate raw field names to canonical names using the alias map."""
        out: dict[str, Any] = {}
        for raw_key, raw_val in raw.items():
            canonical = alias_map.get(raw_key.lower())
            if canonical:
                out[canonical] = raw_val
        return out

    # ------------------------------------------------------------------
    # Web event mapper
    # ------------------------------------------------------------------

    @classmethod
    def _map_web(cls, f: dict, raw: dict) -> dict[str, Any]:
        action: str = str(f.get("action", "Allowed"))
        malware_name: str = f.get("MalwareName", "") or ""
        file_type: str = f.get("FileType", "") or ""
        cloud_app: str = f.get("CloudApplicationName", "") or ""

        url: str = f.get("RequestURL", "")
        host = f.get("RequestHost") or (urlparse(url).hostname if url else "") or ""

        resp_time_raw = f.get("ResponseTime")
        resp_time: int | None = None
        if resp_time_raw is not None:
            try:
                resp_time_val = float(resp_time_raw)
                # Convert seconds to ms if the value looks like seconds (< 1000)
                resp_time = int(resp_time_val * 1000 if resp_time_val < 1000 else resp_time_val)
            except (ValueError, TypeError):
                pass

        ssl_raw = f.get("SSLDecrypted", "")
        ssl_decrypted = str(ssl_raw).lower() in ("true", "1", "yes")

        return {
            "Timestamp": cls._parse_timestamp(f.get("_ts")),
            "ReportId": str(uuid.uuid4()),
            "ActionType": cls._web_action_type(action, malware_name, file_type, cloud_app),
            "UserName": f.get("UserName", ""),
            "Department": f.get("Department"),
            "Location": f.get("Location"),
            "ClientIP": f.get("ClientIP", ""),
            "Protocol": f.get("Protocol", "HTTPS"),
            "RequestMethod": f.get("RequestMethod", "GET"),
            "RequestURL": url,
            "RequestHost": host,
            "RequestSize": cls._to_int(f.get("RequestSize")),
            "ResponseCode": cls._to_int(f.get("ResponseCode")) or 0,
            "ResponseSize": cls._to_int(f.get("ResponseSize")),
            "ResponseTime": resp_time,
            "ContentType": f.get("ContentType"),
            "FileType": file_type or None,
            "FileName": f.get("FileName"),
            "FileSHA256": f.get("FileSHA256"),
            "MalwareClass": f.get("MalwareClass") or None,
            "MalwareName": malware_name or None,
            "ThreatCategory": None,
            "PolicyName": f.get("PolicyName"),
            "RuleLabel": f.get("RuleLabel"),
            "URLCategory": f.get("URLCategory"),
            "CloudApplicationName": cloud_app or None,
            "CloudApplicationRisk": f.get("CloudApplicationRisk"),
            "SSLDecrypted": ssl_decrypted,
            "DeviceOwner": f.get("DeviceOwner"),
            "DeviceName": f.get("DeviceName"),
            "ServerIP": f.get("ServerIP"),
            "ServerPort": cls._to_int(f.get("ServerPort")),
            "BytesIn": cls._to_int(f.get("BytesIn")),
            "BytesOut": cls._to_int(f.get("BytesOut")),
            "DurationMs": cls._to_int(f.get("ResponseTime")),
            "AdditionalFields": raw,
        }

    @classmethod
    def _web_action_type(
        cls, action: str, malware_name: str, file_type: str, cloud_app: str
    ) -> str:
        a = action.strip()
        if a == "Allowed" and not malware_name:
            return "WebAllow"
        if a == "Blocked" and malware_name:
            return "MalwareDetected"
        if a == "Blocked" and file_type:
            return "FileBlocked"
        if a == "Blocked" and cloud_app:
            return "AppControlBlock"
        if a == "Blocked":
            return "WebBlock"
        if a == "Caution":
            return "WebCautioned"
        if a == "SSL_Bypass":
            return "SslBypass"
        if a == "SSL_Block":
            return "SslBlock"
        if a == "DLP":
            return "DlpViolation"
        if a == "Quarantine":
            return "QuarantinedFile"
        return "WebAllow"

    # ------------------------------------------------------------------
    # DNS event mapper
    # ------------------------------------------------------------------

    @classmethod
    def _map_dns(cls, f: dict, raw: dict) -> dict[str, Any]:
        threat_name: str = f.get("ThreatName", "") or ""
        action: str = str(f.get("action", "Allow"))
        policy_name: str = f.get("PolicyName", "") or ""
        response_code: str = f.get("ResponseCode", "NOERROR")

        resolved_raw = f.get("ResolvedIPs")
        resolved_ips: list[str] | None = None
        if isinstance(resolved_raw, list):
            resolved_ips = [str(ip) for ip in resolved_raw] or None
        elif isinstance(resolved_raw, str) and resolved_raw:
            resolved_ips = [resolved_raw]

        doh_raw = f.get("DoHStatus")
        doh: bool | None = None
        if doh_raw is not None:
            doh = str(doh_raw).lower() in ("true", "1", "yes")

        return {
            "Timestamp": cls._parse_timestamp(f.get("_ts")),
            "ReportId": str(uuid.uuid4()),
            "ActionType": cls._dns_action_type(action, threat_name, policy_name, response_code),
            "UserName": f.get("UserName"),
            "Department": f.get("Department"),
            "Location": f.get("Location"),
            "ClientIP": f.get("ClientIP", ""),
            "QueryName": f.get("QueryName", ""),
            "QueryType": f.get("QueryType", ""),
            "ResponseCode": response_code,
            "ResolvedIPs": resolved_ips,
            "CategoryName": f.get("CategoryName"),
            "ThreatName": threat_name or None,
            "ThreatCategory": f.get("ThreatCategory"),
            "PolicyName": policy_name or None,
            "DeviceName": f.get("DeviceName"),
            "DeviceOwner": f.get("DeviceOwner"),
            "DnsDurationMs": cls._to_int(f.get("DnsDurationMs")),
            "DoHStatus": doh,
            "AdditionalFields": raw,
        }

    @classmethod
    def _dns_action_type(
        cls, action: str, threat_name: str, policy_name: str, response_code: str
    ) -> str:
        if threat_name:
            return "DnsThreatMatch"
        a = action.strip()
        if a == "Block":
            if policy_name and "sinkhole" in policy_name.lower():
                return "DnsSinkhole"
            return "DnsBlock"
        if response_code == "NXDOMAIN":
            return "DnsNXDomain"
        if response_code == "SERVFAIL":
            return "DnsServFail"
        return "DnsAllow"

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @classmethod
    def _parse_timestamp(cls, value: Any) -> str:
        """Convert epoch seconds or ISO string to UTC ISO string."""
        if value is None:
            return datetime.now(timezone.utc).isoformat()
        try:
            epoch = int(str(value).strip())
            return datetime.fromtimestamp(epoch, tz=timezone.utc).isoformat()
        except (ValueError, TypeError, OSError):
            pass
        try:
            normalized = str(value).strip().rstrip("Z")
            if "+" not in normalized and "-" not in normalized[10:]:
                normalized += "+00:00"
            return datetime.fromisoformat(normalized).isoformat()
        except ValueError:
            return datetime.now(timezone.utc).isoformat()

    @classmethod
    def _to_int(cls, value: Any) -> int | None:
        if value is None:
            return None
        try:
            return int(value)
        except (ValueError, TypeError):
            return None
