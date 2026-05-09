"""
parsers/windows_event.py — Windows Security/System/Application event parser.

Handles two formats:
  - Windows XML event log (EventData elements)
  - JSON export format (from Get-WinEvent | ConvertTo-Json or MDE raw export)

EventID → MDE table mapping:
  4624 → DeviceLogonEvents (LogonSuccess)
  4625 → DeviceLogonEvents (LogonFailed)
  4647 → DeviceLogonEvents (LogonSuccess — interactive logoff, implicit success)
  4688 → DeviceProcessEvents (ProcessCreated)
  4663 → DeviceFileEvents (FileCreated or FileModified)
  4657 → DeviceRegistryEvents (RegistryValueSet)
  4648 → DeviceLogonEvents (LogonAttempted — explicit credentials)
"""

import json
import logging
import re
import uuid
import xml.etree.ElementTree as ET
from typing import Any

from backend.parsers.base_parser import BaseParser

logger = logging.getLogger(__name__)

# EventID to (MDE table, ActionType) mapping
_EVENT_MAP: dict[int, tuple[str, str]] = {
    4624: ("DeviceLogonEvents", "LogonSuccess"),
    4625: ("DeviceLogonEvents", "LogonFailed"),
    4647: ("DeviceLogonEvents", "LogonSuccess"),
    4648: ("DeviceLogonEvents", "LogonAttempted"),
    4688: ("DeviceProcessEvents", "ProcessCreated"),
    4663: ("DeviceFileEvents", "FileCreated"),
    4657: ("DeviceRegistryEvents", "RegistryValueSet"),
    4698: ("DeviceRegistryEvents", "RegistryKeyCreated"),
}

# Logon type integer to name
_LOGON_TYPE_NAMES: dict[int, str] = {
    2: "Interactive",
    3: "Network",
    4: "Batch",
    5: "Service",
    7: "Unlock",
    8: "NetworkCleartext",
    9: "NewCredentials",
    10: "RemoteInteractive",
    11: "CachedInteractive",
}

_XML_NS = "http://schemas.microsoft.com/win/2004/08/events/event"


class WindowsEventParser(BaseParser):
    """Parse Windows event logs in XML or JSON format."""

    @classmethod
    def detect_source(cls, raw: str) -> bool:
        stripped = raw.strip()
        if stripped.startswith("<Event ") or stripped.startswith("<?xml"):
            return True
        if stripped.startswith("{") or stripped.startswith("["):
            try:
                data = json.loads(stripped)
                events = data if isinstance(data, list) else [data]
                first = events[0] if events else {}
                return "EventID" in first or "EventId" in first or "System" in first
            except (json.JSONDecodeError, IndexError, KeyError):
                pass
        return False

    @classmethod
    def parse(cls, raw: str) -> list[dict]:
        stripped = raw.strip()
        if stripped.startswith("<") or "<?xml" in stripped[:100]:
            return cls._parse_xml(stripped)
        return cls._parse_json(stripped)

    @classmethod
    def _parse_json(cls, raw: str) -> list[dict]:
        try:
            data = json.loads(raw)
        except json.JSONDecodeError as exc:
            logger.warning("WindowsEventParser: JSON parse error: %s", exc)
            return []

        events = data if isinstance(data, list) else [data]
        results = []
        for evt in events:
            parsed = cls._map_json_event(evt)
            if parsed:
                results.append(parsed)
        return results

    @classmethod
    def _map_json_event(cls, evt: dict) -> dict | None:
        try:
            event_id = int(
                evt.get("EventID")
                or evt.get("EventId")
                or (evt.get("System") or {}).get("EventID", {}).get("#text", 0)
                or 0
            )
        except (ValueError, TypeError):
            return None

        if event_id not in _EVENT_MAP:
            logger.debug("WindowsEventParser: unknown EventID %d — skipping", event_id)
            return None

        table, action_type = _EVENT_MAP[event_id]
        event_data = evt.get("EventData", {}) or {}
        system = evt.get("System", {}) or {}

        base: dict[str, Any] = {
            "_target_table": table,
            "Timestamp": evt.get("TimeCreated") or system.get("TimeCreated", {}).get("@SystemTime", ""),
            "DeviceName": system.get("Computer", evt.get("Computer", "UNKNOWN")),
            "DeviceId": evt.get("DeviceId", str(uuid.uuid4())),
            "ActionType": action_type,
            "ReportId": evt.get("EventRecordID") or str(uuid.uuid4()),
        }

        if table == "DeviceLogonEvents":
            logon_type = int(event_data.get("LogonType", 0) or 0)
            base.update({
                "AccountName": event_data.get("TargetUserName", ""),
                "AccountDomain": event_data.get("TargetDomainName", ""),
                "AccountSid": event_data.get("TargetUserSid", ""),
                "LogonType": logon_type,
                "LogonTypeName": _LOGON_TYPE_NAMES.get(logon_type, "Unknown"),
                "IsLocalAdmin": False,
                "FailureReason": event_data.get("FailureReason"),
                "RemoteIP": event_data.get("IpAddress"),
                "RemoteDeviceName": event_data.get("WorkstationName"),
            })
        elif table == "DeviceProcessEvents":
            base.update({
                "FileName": event_data.get("NewProcessName", "").split("\\")[-1],
                "FolderPath": event_data.get("NewProcessName", ""),
                "ProcessId": int(event_data.get("NewProcessId", "0") or "0", 16),
                "ProcessCommandLine": event_data.get("CommandLine", ""),
                "AccountName": event_data.get("SubjectUserName", ""),
                "AccountDomain": event_data.get("SubjectDomainName", ""),
                "AccountSid": event_data.get("SubjectUserSid", ""),
                "InitiatingProcessId": int(event_data.get("ProcessId", "0") or "0", 16),
                "InitiatingProcessFileName": event_data.get("ParentProcessName", "").split("\\")[-1],
            })
        elif table == "DeviceFileEvents":
            base.update({
                "FileName": event_data.get("ObjectName", "").split("\\")[-1],
                "FolderPath": event_data.get("ObjectName", ""),
                "InitiatingProcessFileName": event_data.get("ProcessName", "").split("\\")[-1],
            })
        elif table == "DeviceRegistryEvents":
            base.update({
                "RegistryKey": event_data.get("ObjectName", ""),
                "RegistryValueName": event_data.get("ObjectValueName", ""),
                "RegistryValueData": event_data.get("NewValue", ""),
                "InitiatingProcessFileName": event_data.get("ProcessName", "").split("\\")[-1],
            })

        return base

    @classmethod
    def _parse_xml(cls, raw: str) -> list[dict]:
        results = []
        # Support both single event and multi-event XML documents
        if "<Events>" in raw:
            root_xml = raw
        elif raw.startswith("<Event "):
            root_xml = f"<Events>{raw}</Events>"
        else:
            root_xml = raw

        try:
            root = ET.fromstring(root_xml)
        except ET.ParseError as exc:
            logger.warning("WindowsEventParser: XML parse error: %s", exc)
            return []

        events = root.findall(f"{{{_XML_NS}}}Event") or root.findall("Event") or [root]
        for event in events:
            parsed = cls._map_xml_event(event)
            if parsed:
                results.append(parsed)
        return results

    @classmethod
    def _map_xml_event(cls, event: ET.Element) -> dict | None:
        def find_text(parent: ET.Element, tag: str, ns: str = _XML_NS) -> str:
            el = parent.find(f"{{{ns}}}{tag}") or parent.find(tag)
            return el.text or "" if el is not None else ""

        system = event.find(f"{{{_XML_NS}}}System") or event.find("System")
        if system is None:
            return None

        event_id_el = system.find(f"{{{_XML_NS}}}EventID") or system.find("EventID")
        try:
            event_id = int(event_id_el.text or "0")
        except (AttributeError, ValueError):
            return None

        if event_id not in _EVENT_MAP:
            return None

        table, action_type = _EVENT_MAP[event_id]
        time_created = system.find(f"{{{_XML_NS}}}TimeCreated") or system.find("TimeCreated")
        timestamp = (time_created.get("SystemTime", "") if time_created is not None else "")
        computer = find_text(system, "Computer")

        event_data_el = event.find(f"{{{_XML_NS}}}EventData") or event.find("EventData")
        event_data: dict[str, str] = {}
        if event_data_el is not None:
            for data in event_data_el:
                name = data.get("Name", "")
                if name:
                    event_data[name] = data.text or ""

        # Re-use JSON mapper after reconstructing a dict
        synthetic = {
            "EventID": event_id,
            "TimeCreated": timestamp,
            "Computer": computer,
            "EventData": event_data,
            "EventRecordID": find_text(system, "EventRecordID"),
        }
        return cls._map_json_event(synthetic)
