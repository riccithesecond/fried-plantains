"""
api/ingest.py — Log upload and ingestion endpoint.

Pipeline:
  1. validate_upload() — size, filename, MIME type
  2. detect_and_parse() — auto-detect format, parse into raw events
  3. normalize() — map each raw event to MDE table schema
  4. write_parquet() — atomic write to hive-partitioned Parquet

Returns a structured response: table, event count, partition path, duration.
Errors return structured JSON via the exception handlers — never raw exceptions.
"""

import logging
import time
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, UploadFile

from backend.api.auth import get_current_user
from backend.ingest.normalizer import normalize
from backend.ingest.validator import validate_upload
from backend.ingest.writer import write_parquet
from backend.models.user import User
from backend.parsers import detect_and_parse
from backend.schema.mde_tables import MDE_TABLES

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/ingest", tags=["ingest"])


@router.post("/upload")
async def upload_logs(
    file: UploadFile,
    table: str | None = None,
    current_user: User = Depends(get_current_user),
) -> dict:
    """Upload and ingest a log file.

    Args:
        file: Multipart file upload (JSON, NDJSON, CSV, or gzip).
        table: Optional override for the target MDE table. If omitted, the
               parser's auto-detection determines the table per event.

    Returns:
        Ingest summary: table name, events ingested, partition path, duration.
    """
    start_ms = time.monotonic()

    # 1. Validate upload
    content = await validate_upload(file)
    raw_text = content.decode("utf-8", errors="replace")

    # 2. Parse — auto-detect or use provided table
    raw_events = detect_and_parse(raw_text)
    if not raw_events:
        # Try treating as generic JSON/NDJSON for the specified table
        import json
        try:
            parsed = json.loads(raw_text)
            raw_events = parsed if isinstance(parsed, list) else [parsed]
            if table:
                for e in raw_events:
                    e["_target_table"] = table
        except json.JSONDecodeError:
            pass

    if not raw_events:
        return {
            "table": table or "unknown",
            "events_ingested": 0,
            "partition_path": None,
            "duration_ms": int((time.monotonic() - start_ms) * 1000),
            "message": "No parseable events found in the uploaded file.",
        }

    # Group events by target table
    by_table: dict[str, list[dict]] = {}
    for event in raw_events:
        target = event.pop("_target_table", table or "DeviceEvents")
        if target not in MDE_TABLES:
            target = "DeviceEvents"
        by_table.setdefault(target, []).append(event)

    # 3. Normalize and 4. write per table
    total_ingested = 0
    last_path = None
    now = datetime.now(timezone.utc)

    for tbl, events in by_table.items():
        normalized = []
        for evt in events:
            try:
                normalized.append(normalize(evt, tbl))
            except Exception as exc:
                logger.warning("Normalization failed for table %s: %s", tbl, exc)

        if normalized:
            path = write_parquet(normalized, tbl, now)
            total_ingested += len(normalized)
            last_path = path
            logger.info("Ingested %d events into %s", len(normalized), tbl)

    duration_ms = int((time.monotonic() - start_ms) * 1000)
    return {
        "table": list(by_table.keys())[0] if len(by_table) == 1 else list(by_table.keys()),
        "events_ingested": total_ingested,
        "partition_path": last_path,
        "duration_ms": duration_ms,
    }
