"""
parsers/cloudtrail.py — AWS CloudTrail log parser.

Maps CloudTrail events to AWSCloudTrailEvents. Handles three delivery formats:
  1. Single event JSON object
  2. {"Records": [...]} S3 delivery wrapper
  3. JSON lines — one event per line (Firehose / streaming)

All events regardless of eventName route to AWSCloudTrailEvents. ActionType
is derived from eventName prefixes, eventCategory, and eventSource heuristics
to distinguish data-plane vs management-plane vs auth operations.
"""

import json
import logging
import uuid
from datetime import datetime, timezone
from typing import Any

from backend.parsers.base_parser import BaseParser

logger = logging.getLogger(__name__)

_TARGET_TABLE = "AWSCloudTrailEvents"

# Data-plane AWS services — events from these map to DataAccess/DataWrite rather
# than ManagementRead/ManagementWrite, because the operations touch actual data
# objects rather than control-plane resources.
_DATA_PLANE_SOURCES: frozenset[str] = frozenset({
    "s3.amazonaws.com",
    "dynamodb.amazonaws.com",
    "kinesis.amazonaws.com",
    "firehose.amazonaws.com",
    "sqs.amazonaws.com",
    "sns.amazonaws.com",
    "lambda.amazonaws.com",
    "glacier.amazonaws.com",
    "elasticmapreduce.amazonaws.com",
})

# Prefixes that indicate management read operations
_MGMT_READ_PREFIXES = ("Describe", "List", "Get", "Head", "BatchGet")

# Prefixes that indicate management write operations
_MGMT_WRITE_PREFIXES = (
    "Create", "Update", "Delete", "Modify", "Put", "Attach",
    "Detach", "Enable", "Disable", "Start", "Stop",
)

# Token-issuing operations — credential generation, not just auth attempts
_TOKEN_OPS: frozenset[str] = frozenset({
    "AssumeRole",
    "AssumeRoleWithSAML",
    "AssumeRoleWithWebIdentity",
    "GetSessionToken",
    "GetFederationToken",
})

# CloudTrail/Config/GuardDuty control-plane event names that represent config changes
_CONFIG_CHANGE_OPS: frozenset[str] = frozenset({
    "StopLogging",
    "StartLogging",
    "DeleteTrail",
    "UpdateTrail",
    "CreateTrail",
    "DeleteEventDataStore",
    "UpdateEventDataStore",
    "PutDeliveryChannel",
    "DeleteDeliveryChannel",
    "StopConfigurationRecorder",
    "StartConfigurationRecorder",
    "DeleteConfigRule",
    "PutConfigRule",
    "CreateDetector",
    "DeleteDetector",
    "UpdateDetector",
    "DisassociateFromMasterAccount",
})


class CloudTrailParser(BaseParser):
    """Parse AWS CloudTrail JSON logs in any of the three delivery formats."""

    @classmethod
    def detect_source(cls, raw: str) -> bool:
        stripped = raw.strip()
        # Try Records wrapper format first
        try:
            data = json.loads(stripped)
            if isinstance(data, dict):
                records = data.get("Records")
                if isinstance(records, list) and records:
                    first = records[0]
                    return "eventSource" in first and "eventName" in first
                # Single-event object
                return "eventSource" in data and "eventName" in data
        except json.JSONDecodeError:
            pass
        # JSON lines — check first non-empty line
        for line in stripped.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
                return "eventSource" in obj and "eventName" in obj
            except json.JSONDecodeError:
                return False
        return False

    @classmethod
    def parse(cls, raw: str) -> list[dict]:
        """Parse raw CloudTrail content.

        Returns a list of dicts, each with:
          {"table": "AWSCloudTrailEvents", "data": <event dict>}
        """
        stripped = raw.strip()
        raw_events: list[dict] = []

        # Try JSON parse of the whole string first
        try:
            data = json.loads(stripped)
            if isinstance(data, dict):
                records = data.get("Records")
                if isinstance(records, list):
                    raw_events = records
                else:
                    # Single event object
                    raw_events = [data]
            elif isinstance(data, list):
                raw_events = data
        except json.JSONDecodeError:
            # Fall back to JSON lines
            for line in stripped.splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    raw_events.append(json.loads(line))
                except json.JSONDecodeError as exc:
                    logger.debug("CloudTrailParser: skipping unparseable line: %s", exc)

        results = []
        for evt in raw_events:
            data = cls._parse_event(evt)
            if data is not None:
                results.append({"table": _TARGET_TABLE, "data": data})
        return results

    @classmethod
    def _parse_event(cls, event: dict) -> dict[str, Any] | None:
        """Map a single CloudTrail record to AWSCloudTrailEvents schema."""
        try:
            user_identity: dict = event.get("userIdentity") or {}
            return {
                "Timestamp": cls._parse_timestamp(event.get("eventTime", "")),
                "ReportId": event.get("eventID") or str(uuid.uuid4()),
                "ActionType": cls._get_action_type(event),
                "AccountId": user_identity.get("accountId", ""),
                "AccountName": None,
                "UserIdentityType": user_identity.get("type", ""),
                "UserIdentityArn": user_identity.get("arn", ""),
                "UserIdentityName": cls._get_user_identity_name(user_identity),
                "SessionName": cls._get_session_name(user_identity),
                "EventSource": event.get("eventSource", ""),
                "EventName": event.get("eventName", ""),
                "EventCategory": event.get("eventCategory", "Management"),
                "AWSRegion": event.get("awsRegion", ""),
                "SourceIPAddress": event.get("sourceIPAddress", ""),
                "UserAgent": event.get("userAgent", ""),
                "RequestParameters": event.get("requestParameters"),
                "ResponseElements": event.get("responseElements"),
                "ErrorCode": event.get("errorCode"),
                "ErrorMessage": event.get("errorMessage"),
                "ReadOnly": cls._is_read_only(event),
                "MFAAuthenticated": cls._get_mfa_authenticated(user_identity),
                "SharedEventID": event.get("sharedEventID"),
                "AdditionalFields": event,
            }
        except Exception as exc:
            logger.debug("CloudTrailParser: failed to map record: %s", exc)
            return None

    @classmethod
    def _parse_timestamp(cls, event_time: str) -> str:
        """Normalize CloudTrail ISO 8601 eventTime to UTC ISO string."""
        if not event_time:
            return datetime.now(timezone.utc).isoformat()
        try:
            normalized = event_time.rstrip("Z")
            if "+" not in normalized and "-" not in normalized[10:]:
                normalized += "+00:00"
            return datetime.fromisoformat(normalized).isoformat()
        except ValueError:
            return event_time

    @classmethod
    def _get_user_identity_name(cls, user_identity: dict) -> str | None:
        """Extract the most useful name from a userIdentity block."""
        id_type = user_identity.get("type", "")
        if id_type == "IAMUser":
            return user_identity.get("userName")
        if id_type == "AssumedRole":
            session_ctx = user_identity.get("sessionContext") or {}
            issuer = session_ctx.get("sessionIssuer") or {}
            return issuer.get("userName")
        if id_type == "Root":
            return "root"
        if id_type == "Service":
            return user_identity.get("principalId")
        arn = user_identity.get("arn", "")
        return arn.split("/")[-1] if "/" in arn else arn or None

    @classmethod
    def _get_session_name(cls, user_identity: dict) -> str | None:
        """Extract roleSessionName from AssumedRole ARN (last path component)."""
        if user_identity.get("type") != "AssumedRole":
            return None
        arn = user_identity.get("arn", "")
        parts = arn.split("/")
        return parts[-1] if len(parts) >= 3 else None

    @classmethod
    def _get_action_type(cls, event: dict) -> str:
        """Derive ActionType from eventName, eventCategory, and eventSource."""
        event_name: str = event.get("eventName", "")
        event_source: str = event.get("eventSource", "")
        event_category: str = event.get("eventCategory", "")
        read_only: bool = cls._is_read_only(event)

        # Auth operations — check before prefix rules
        if event_name == "ConsoleLogin":
            return "AuthAttempt"

        # Token issuance — session credentials created
        if event_name in _TOKEN_OPS:
            return "TokenIssued"

        # CloudTrail/Config/GuardDuty control-plane changes
        if event_name in _CONFIG_CHANGE_OPS:
            return "ConfigChange"

        # CloudTrail Insights anomaly events
        if event_category == "Insight":
            return "InsightEvent"

        # Data plane: either eventCategory says Data, or we know the service is data-plane only
        is_data_plane = event_category == "Data" or event_source in _DATA_PLANE_SOURCES
        if is_data_plane:
            return "DataAccess" if read_only else "DataWrite"

        # Management read: Describe/List/Get/Head/BatchGet prefixes
        if event_name.startswith(_MGMT_READ_PREFIXES):
            return "ManagementRead"

        # Management write: Create/Update/Delete/etc. prefixes
        if event_name.startswith(_MGMT_WRITE_PREFIXES):
            return "ManagementWrite"

        return "ApiCall"

    @classmethod
    def _is_read_only(cls, event: dict) -> bool:
        """Determine read-only status from the readOnly field or eventName heuristic."""
        read_only = event.get("readOnly")
        if isinstance(read_only, bool):
            return read_only
        if isinstance(read_only, str):
            return read_only.lower() == "true"
        # Heuristic: Describe/List/Get/Head are reads
        event_name: str = event.get("eventName", "")
        return event_name.startswith(_MGMT_READ_PREFIXES)

    @classmethod
    def _get_mfa_authenticated(cls, user_identity: dict) -> bool | None:
        """Extract MFA authentication status from sessionContext."""
        session_ctx = user_identity.get("sessionContext") or {}
        attrs = session_ctx.get("attributes") or {}
        mfa_val = attrs.get("mfaAuthenticated")
        if mfa_val is None:
            return None
        if isinstance(mfa_val, bool):
            return mfa_val
        return str(mfa_val).lower() == "true"
