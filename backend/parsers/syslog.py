"""
parsers/syslog.py — RFC 5424 syslog parser.

Parses structured and legacy syslog messages to DeviceEvents. Syslog is
heterogeneous — the ActionType is inferred from the facility/severity pair.
"""

import logging
import re
import uuid
from typing import Any

from backend.parsers.base_parser import BaseParser

logger = logging.getLogger(__name__)

_TARGET_TABLE = "DeviceEvents"

# RFC 5424 header: <PRI>VERSION TIMESTAMP HOSTNAME APP-NAME PROCID MSGID
_RFC5424 = re.compile(
    r"^<(\d+)>(\d)\s+"                   # PRI + VERSION
    r"(\S+)\s+"                           # TIMESTAMP
    r"(\S+)\s+"                           # HOSTNAME
    r"(\S+)\s+"                           # APP-NAME
    r"(\S+)\s+"                           # PROCID
    r"(\S+)\s+"                           # MSGID
    r"(.*)$",                             # MSG (may include STRUCTURED-DATA)
    re.DOTALL,
)

# Legacy (RFC 3164) syslog
_RFC3164 = re.compile(
    r"^<(\d+)>"
    r"(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+"
    r"(\S+)\s+"
    r"([^:]+):\s+"
    r"(.*)$",
    re.DOTALL,
)


class SyslogParser(BaseParser):
    """Parse RFC 5424 and RFC 3164 syslog messages."""

    @classmethod
    def detect_source(cls, raw: str) -> bool:
        first_line = raw.strip().split("\n")[0]
        return bool(_RFC5424.match(first_line) or _RFC3164.match(first_line))

    @classmethod
    def parse(cls, raw: str) -> list[dict]:
        results = []
        for line in raw.strip().splitlines():
            line = line.strip()
            if not line:
                continue
            parsed = cls._parse_line(line)
            if parsed:
                results.append(parsed)
        return results

    @classmethod
    def _parse_line(cls, line: str) -> dict[str, Any] | None:
        m5424 = _RFC5424.match(line)
        if m5424:
            pri, _, timestamp, hostname, app_name, procid, _, msg = m5424.groups()
            severity = cls._pri_to_severity(int(pri))
            return {
                "_target_table": _TARGET_TABLE,
                "Timestamp": timestamp,
                "DeviceName": hostname,
                "DeviceId": str(uuid.uuid5(uuid.NAMESPACE_DNS, hostname)),
                "ActionType": "AntivirusDetection" if "virus" in msg.lower() else "PowerShellCommand",
                "ProcessCommandLine": msg[:1024],
                "InitiatingProcessFileName": app_name,
                "InitiatingProcessCommandLine": msg[:256],
                "InitiatingProcessAccountName": "SYSTEM",
                "InitiatingProcessId": int(procid) if procid.isdigit() else 0,
                "AdditionalFields": {
                    "pri": int(pri),
                    "severity": severity,
                    "app_name": app_name,
                    "raw_message": msg[:4096],
                },
                "ReportId": str(uuid.uuid4()),
            }

        m3164 = _RFC3164.match(line)
        if m3164:
            pri, timestamp, hostname, process, msg = m3164.groups()
            return {
                "_target_table": _TARGET_TABLE,
                "Timestamp": timestamp,
                "DeviceName": hostname,
                "DeviceId": str(uuid.uuid5(uuid.NAMESPACE_DNS, hostname)),
                "ActionType": "PowerShellCommand",
                "ProcessCommandLine": msg[:1024],
                "InitiatingProcessFileName": process.split("[")[0],
                "InitiatingProcessCommandLine": msg[:256],
                "InitiatingProcessAccountName": "SYSTEM",
                "InitiatingProcessId": 0,
                "AdditionalFields": {
                    "pri": int(pri),
                    "raw_message": msg[:4096],
                },
                "ReportId": str(uuid.uuid4()),
            }

        return None

    @staticmethod
    def _pri_to_severity(pri: int) -> str:
        severity_num = pri % 8
        names = ["Emergency", "Alert", "Critical", "Error", "Warning", "Notice", "Info", "Debug"]
        return names[severity_num] if severity_num < len(names) else "Info"
