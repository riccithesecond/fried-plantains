"""
ingest/normalizer.py — Normalize raw log events to MDE table schemas.

Each raw event is mapped to an MDE table's column schema. Required columns must
be present; optional (nullable) columns are filled if available. Unknown fields
go into AdditionalFields if the table defines that column, otherwise they are
dropped with a DEBUG log.

The normalizer enforces type coercions at write time, not at query time — this
keeps the Parquet files schema-valid so DuckDB reads them cleanly without runtime
type errors.
"""

import logging
import uuid
from datetime import datetime, timezone
from typing import Any

from backend.exceptions import SchemaException
from backend.schema.mde_tables import MDE_TABLES, MdeTable, get_column_names

logger = logging.getLogger(__name__)


def normalize(raw_event: dict[str, Any], target_table: str) -> dict[str, Any]:
    """Map a raw event dict to the target MDE table schema.

    Args:
        raw_event: Source event with arbitrary field names.
        target_table: MDE table name (must exist in MDE_TABLES).

    Returns:
        Dict with exactly the columns defined in the MDE table schema,
        coerced to correct types.

    Raises:
        SchemaException: If the target table is unknown or required fields
                         are missing after mapping.
    """
    table = MDE_TABLES.get(target_table)
    if table is None:
        raise SchemaException(
            detail=f"Unknown MDE table '{target_table}'.",
            internal_detail=f"normalize() called with unknown table: {target_table}",
        )

    # Start with the raw event, then coerce each defined column
    result: dict[str, Any] = {}
    extra_fields: dict[str, Any] = {}
    schema_columns = get_column_names(target_table)

    # Separate known columns from extras
    for key, value in raw_event.items():
        if key in schema_columns:
            result[key] = value
        else:
            extra_fields[key] = value

    # Fill defaults for missing required fields
    result.setdefault("ReportId", str(uuid.uuid4()))
    result.setdefault("Timestamp", datetime.now(timezone.utc).isoformat())

    # Coerce types according to schema
    result = _coerce_types(result, table)

    # Extras → AdditionalFields if the table has that column
    if extra_fields:
        if "AdditionalFields" in schema_columns:
            existing = result.get("AdditionalFields") or {}
            if isinstance(existing, str):
                import json
                try:
                    existing = json.loads(existing)
                except ValueError:
                    existing = {}
            result["AdditionalFields"] = {**existing, **extra_fields}
        else:
            logger.debug(
                "Dropping %d unknown fields for table %s: %s",
                len(extra_fields),
                target_table,
                list(extra_fields.keys()),
            )

    # Validate required columns are present
    missing = _check_required(result, table)
    if missing:
        raise SchemaException(
            detail=f"Required fields missing for table '{target_table}': {missing}",
            internal_detail=f"Missing required columns: {missing}",
        )

    # Fill nullable columns that are absent with None
    for col in table.columns:
        if col.name not in result:
            result[col.name] = None

    return result


def _coerce_types(event: dict[str, Any], table: MdeTable) -> dict[str, Any]:
    """Coerce event values to the types defined in the MDE schema."""
    for col in table.columns:
        if col.name not in event or event[col.name] is None:
            continue
        value = event[col.name]
        try:
            if col.dtype == "TIMESTAMP":
                event[col.name] = _to_timestamp(value)
            elif col.dtype in ("INT", "BIGINT"):
                event[col.name] = int(value)
            elif col.dtype == "BOOLEAN":
                event[col.name] = bool(value)
            elif col.dtype == "STRING":
                event[col.name] = str(value) if value is not None else None
            elif col.dtype == "JSON":
                if isinstance(value, (dict, list)):
                    import json
                    event[col.name] = json.dumps(value)
                else:
                    event[col.name] = str(value)
        except (ValueError, TypeError) as exc:
            logger.debug("Type coercion failed for %s.%s: %s", table.name, col.name, exc)
            if not col.nullable:
                raise SchemaException(
                    detail=f"Field '{col.name}' has invalid type for table '{table.name}'.",
                    internal_detail=str(exc),
                )
            event[col.name] = None
    return event


def _to_timestamp(value: Any) -> datetime:
    """Coerce a value to a UTC-naive datetime.

    Returning a naive datetime (not a string) ensures pyarrow writes the column
    as TIMESTAMP rather than VARCHAR, so DuckDB temporal comparisons work.
    Timezone-naive UTC avoids a pytz dependency in DuckDB's Python layer.
    """
    if isinstance(value, datetime):
        dt = value if value.tzinfo else value.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc).replace(tzinfo=None)
    if isinstance(value, (int, float)):
        return datetime.utcfromtimestamp(value)
    if isinstance(value, str):
        for fmt in (
            "%Y-%m-%dT%H:%M:%S.%fZ",
            "%Y-%m-%dT%H:%M:%SZ",
            "%Y-%m-%dT%H:%M:%S.%f+00:00",
            "%Y-%m-%dT%H:%M:%S+00:00",
            "%Y-%m-%dT%H:%M:%S",
            "%Y-%m-%d %H:%M:%S",
            "%Y-%m-%d",
        ):
            try:
                return datetime.strptime(value, fmt).replace(tzinfo=None)
            except ValueError:
                continue
        logger.warning("Could not parse timestamp %r — using current time", value)
        return datetime.utcnow()
    return datetime.utcnow()


def _check_required(event: dict[str, Any], table: MdeTable) -> list[str]:
    """Return required ingest columns that are absent from the event.

    Uses table.required_for_ingest (defined per-table in mde_tables.py) so
    device-centric defaults don't wrongly apply to identity or cloud tables.
    ReportId is excluded because normalize() generates a default value.
    """
    required = table.required_for_ingest - {"ReportId"}
    return [name for name in required if name not in event]
