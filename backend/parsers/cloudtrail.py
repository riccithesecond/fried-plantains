"""
parsers/cloudtrail.py — AWS CloudTrail JSON log parser.

Maps CloudTrail Records to CloudAppEvents MDE table. CloudTrail events model
cloud API calls — each Record is one API call with source, action, and actor.
"""

import json
import logging
import uuid
from typing import Any

from backend.parsers.base_parser import BaseParser

logger = logging.getLogger(__name__)

_TARGET_TABLE = "CloudAppEvents"


class CloudTrailParser(BaseParser):
    """Parse AWS CloudTrail JSON export format."""

    @classmethod
    def detect_source(cls, raw: str) -> bool:
        stripped = raw.strip()
        try:
            data = json.loads(stripped)
            records = data.get("Records") if isinstance(data, dict) else None
            if records and isinstance(records, list) and records:
                first = records[0]
                return "eventSource" in first and "eventName" in first
        except (json.JSONDecodeError, AttributeError):
            pass
        return False

    @classmethod
    def parse(cls, raw: str) -> list[dict]:
        try:
            data = json.loads(raw.strip())
        except json.JSONDecodeError as exc:
            logger.warning("CloudTrailParser: JSON parse error: %s", exc)
            return []

        records = data.get("Records", []) if isinstance(data, dict) else []
        results = []
        for record in records:
            parsed = cls._map_record(record)
            if parsed:
                results.append(parsed)
        return results

    @classmethod
    def _map_record(cls, record: dict) -> dict[str, Any] | None:
        try:
            user_identity = record.get("userIdentity", {}) or {}
            source_ip = record.get("sourceIPAddress", "")
            geo = record.get("userAgent", "")

            event: dict[str, Any] = {
                "_target_table": _TARGET_TABLE,
                "Timestamp": record.get("eventTime", ""),
                "Application": record.get("eventSource", "aws"),
                "ActionType": record.get("eventName", "UnknownAction"),
                "AccountObjectId": user_identity.get("accountId", ""),
                "AccountDisplayName": user_identity.get("userName") or user_identity.get("arn", ""),
                "AccountDomain": "aws",
                "IPAddress": source_ip,
                "AdditionalFields": {
                    "eventSource": record.get("eventSource"),
                    "awsRegion": record.get("awsRegion"),
                    "requestParameters": record.get("requestParameters"),
                    "responseElements": record.get("responseElements"),
                    "userAgent": geo,
                },
                "ReportId": record.get("eventID") or str(uuid.uuid4()),
            }
            return event
        except Exception as exc:
            logger.debug("CloudTrailParser: failed to map record: %s", exc)
            return None
