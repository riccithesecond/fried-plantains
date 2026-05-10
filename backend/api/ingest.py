"""
api/ingest.py — Log upload and ingestion endpoint.

Pipeline:
  1. validate_upload() — size, filename, MIME type
  2. parse() — auto-detect format or dispatch to SOURCE_TYPES parser
  3. normalize() — map each raw event to MDE table schema
  4. write_parquet() — atomic write to hive-partitioned Parquet

Cloud parsers (CloudTrail, Cloudflare, Zscaler) may produce events for multiple
tables in a single upload. The response lists every table written and the event
count per table.
"""

import gzip
import json
import logging
import time
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, UploadFile

from backend.api.auth import get_current_user
from backend.engine.duckdb_pool import get_pool
from backend.ingest.normalizer import normalize
from backend.ingest.validator import validate_upload
from backend.ingest.writer import write_parquet
from backend.models.user import User
from backend.parsers import SOURCE_TYPES, detect_and_parse
from backend.parsers.cloudflare import CloudflareParser
from backend.schema.mde_tables import MDE_TABLES

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/ingest", tags=["ingest"])


def _coerce_to_table_dict(
    parse_result: list[dict] | dict,
    table_override: str | None,
) -> dict[str, list[dict]]:
    """Normalise the three possible parser return shapes into dict[table, list[events]].

    Shapes:
      1. list[{"table": t, "data": d}]  — CloudTrail / Zscaler
      2. dict[table_name, list[dict]]    — Cloudflare
      3. list[dict] with "_target_table" — legacy parsers (Windows, Syslog, Defender)
    """
    by_table: dict[str, list[dict]] = {}

    if isinstance(parse_result, dict):
        # Shape 2: Cloudflare
        for tbl, events in parse_result.items():
            target = tbl if tbl in MDE_TABLES else "DeviceEvents"
            by_table.setdefault(target, []).extend(events)
        return by_table

    for item in parse_result:
        if "table" in item and "data" in item:
            # Shape 1: cloud parsers
            tbl = item["table"]
            target = tbl if tbl in MDE_TABLES else (table_override or "DeviceEvents")
            by_table.setdefault(target, []).append(item["data"])
        else:
            # Shape 3: legacy parsers
            target = item.pop("_target_table", None) or table_override or "DeviceEvents"
            if target not in MDE_TABLES:
                target = "DeviceEvents"
            by_table.setdefault(target, []).append(item)

    return by_table


@router.post("/upload")
async def upload_logs(
    file: UploadFile,
    table: str | None = None,
    source: str | None = None,
    current_user: User = Depends(get_current_user),
) -> dict:
    """Upload and ingest a log file.

    Args:
        file:   Multipart file upload (JSON, NDJSON, CSV, or gzip).
        table:  Optional target MDE table override (ignored when source is set
                and the parser auto-routes per event).
        source: Optional explicit source type key from SOURCE_TYPES
                (cloudtrail | cloudflare | zscaler_web | zscaler_dns |
                 windows_event | syslog | defender). When omitted the format
                is auto-detected.

    Returns:
        Ingest summary with per-table event counts and total duration.
    """
    start_ms = time.monotonic()

    content = await validate_upload(file)

    # Decompress gzip content before parsing — magic bytes \x1f\x8b indicate gzip
    if content[:2] == b"\x1f\x8b":
        content = gzip.decompress(content)

    raw_text = content.decode("utf-8", errors="replace")

    # Parse — explicit source type wins over auto-detection
    parse_result: list[dict] | dict = []
    if source and source in SOURCE_TYPES:
        parser_cls = SOURCE_TYPES[source]
        parse_result = parser_cls.parse(raw_text)
    else:
        parse_result = detect_and_parse(raw_text)

    # Fall back to generic JSON/NDJSON if nothing matched
    if not parse_result:
        try:
            parsed = json.loads(raw_text)
            raw_events = parsed if isinstance(parsed, list) else [parsed]
            if table:
                for e in raw_events:
                    e["_target_table"] = table
            parse_result = raw_events
        except json.JSONDecodeError:
            pass

    if not parse_result:
        return {
            "tables_written": {},
            "total_events": 0,
            "duration_ms": int((time.monotonic() - start_ms) * 1000),
            "message": "No parseable events found in the uploaded file.",
        }

    by_table = _coerce_to_table_dict(parse_result, table)

    # Normalize and write per table
    tables_written: dict[str, int] = {}
    now = datetime.now(timezone.utc)

    for tbl, events in by_table.items():
        normalized = []
        for evt in events:
            try:
                normalized.append(normalize(evt, tbl))
            except Exception as exc:
                logger.warning("Normalization failed for table %s: %s", tbl, exc)

        if normalized:
            write_parquet(normalized, tbl, now)
            tables_written[tbl] = len(normalized)
            logger.info("Ingested %d events into %s", len(normalized), tbl)
            # Re-register the DuckDB view now that files exist (view may have
            # failed to register at startup before first ingest).
            get_pool().refresh_view(tbl)

    total = sum(tables_written.values())
    duration_ms = int((time.monotonic() - start_ms) * 1000)

    return {
        "tables_written": tables_written,
        "total_events": total,
        "duration_ms": duration_ms,
    }
