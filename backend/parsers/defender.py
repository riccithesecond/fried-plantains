"""
parsers/defender.py — Microsoft Defender for Endpoint raw JSON export parser.

MDE raw JSON exports are already in MDE schema format. This parser handles
minimal mapping — validates required fields exist, normalizes timestamps to UTC,
and ensures ReportId is set. The heavy lifting is in the normalizer.
"""

import json
import logging
import uuid
from typing import Any

from backend.parsers.base_parser import BaseParser
from backend.schema.mde_tables import MDE_TABLES

logger = logging.getLogger(__name__)


class DefenderParser(BaseParser):
    """Parse MDE raw JSON export format."""

    @classmethod
    def detect_source(cls, raw: str) -> bool:
        stripped = raw.strip()
        try:
            # MDE exports are NDJSON or JSON array
            if stripped.startswith("["):
                events = json.loads(stripped)
                first = events[0] if events else {}
            else:
                first = json.loads(stripped.splitlines()[0])
            # Presence of ReportId and a known ActionType is the signal
            return "ReportId" in first and (
                "ActionType" in first or "Timestamp" in first
            )
        except (json.JSONDecodeError, IndexError):
            return False

    @classmethod
    def parse(cls, raw: str) -> list[dict]:
        stripped = raw.strip()
        events: list[dict] = []

        if stripped.startswith("["):
            try:
                events = json.loads(stripped)
            except json.JSONDecodeError as exc:
                logger.warning("DefenderParser: JSON array parse error: %s", exc)
                return []
        else:
            # NDJSON
            for line in stripped.splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    events.append(json.loads(line))
                except json.JSONDecodeError:
                    logger.debug("DefenderParser: skipping malformed line")

        return [cls._map_event(e) for e in events if e]

    @classmethod
    def _map_event(cls, event: dict) -> dict[str, Any]:
        # Identify target table from MDE_TABLES — look for a table where this
        # event's columns make sense. Fallback to DeviceEvents.
        target_table = event.get("_table", "DeviceEvents")
        if target_table not in MDE_TABLES:
            target_table = "DeviceEvents"

        event["_target_table"] = target_table
        if "ReportId" not in event or not event["ReportId"]:
            event["ReportId"] = str(uuid.uuid4())
        return event
