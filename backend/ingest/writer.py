"""
ingest/writer.py — Atomic Parquet write with hive-style partitioning.

Writes are atomic: data is written to a .tmp file first, then renamed to the
final path. This prevents DuckDB from reading a partially-written Parquet file
during concurrent ingestion — a partially-written file would cause a schema
mismatch or corrupt read. The rename is atomic at the OS level on both Linux
and Windows NTFS.

Partition layout: {STORAGE_ROOT}/{TableName}/{YYYY}/{MM}/{DD}/data.parquet
This matches DuckDB's hive partition glob pattern in the view definitions.
"""

import logging
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import pandas as pd
import pyarrow as pa
import pyarrow.parquet as pq

from backend.config import settings
from backend.exceptions import SchemaException, StorageException
from backend.schema.mde_tables import MDE_TABLES

logger = logging.getLogger(__name__)


def write_parquet(
    events: list[dict[str, Any]],
    table_name: str,
    event_timestamp: datetime | None = None,
) -> str:
    """Write normalized events to the Parquet partition for the given MDE table.

    Args:
        events: List of normalized event dicts (schema-validated).
        table_name: Target MDE table name.
        event_timestamp: Timestamp used for partition path. Defaults to now.

    Returns:
        The partition path that was written.

    Raises:
        SchemaException: If table_name is not a known MDE table.
        StorageException: On any file system or Parquet write failure.
    """
    if table_name not in MDE_TABLES:
        raise SchemaException(
            detail=f"Unknown table '{table_name}'. Cannot write Parquet.",
            internal_detail=f"write_parquet() called with unknown table: {table_name}",
        )

    if not events:
        logger.debug("write_parquet: zero events for %s — skipping", table_name)
        return ""

    ts = event_timestamp or datetime.now(timezone.utc)
    partition_dir = (
        Path(settings.STORAGE_ROOT)
        / table_name
        / f"{ts.year}"
        / f"{ts.month:02d}"
        / f"{ts.day:02d}"
    )

    try:
        partition_dir.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        raise StorageException(
            detail="Storage write failed. Contact an administrator.",
            internal_detail=f"Cannot create partition directory {partition_dir}: {exc}",
        )

    final_path = partition_dir / "data.parquet"
    tmp_path = partition_dir / "data.parquet.tmp"

    try:
        new_df = pd.DataFrame(events)

        # If a partition file already exists, merge new events with existing
        if final_path.exists():
            existing_df = pd.read_parquet(final_path)
            new_df = pd.concat([existing_df, new_df], ignore_index=True)
            logger.debug(
                "Merged %d new + %d existing events into %s",
                len(events),
                len(existing_df),
                final_path,
            )

        table_pa = pa.Table.from_pandas(new_df, preserve_index=False)
        pq.write_table(table_pa, str(tmp_path), compression="snappy")

        # Atomic rename — replaces the final file as one OS operation
        os.replace(str(tmp_path), str(final_path))
        logger.info(
            "Wrote %d events to %s (partition: %s/%02d/%02d)",
            len(events),
            table_name,
            ts.year,
            ts.month,
            ts.day,
        )
        return str(final_path)

    except Exception as exc:
        # Clean up temp file on failure
        if tmp_path.exists():
            try:
                tmp_path.unlink()
            except OSError:
                pass
        raise StorageException(
            detail="Storage write failed. Contact an administrator.",
            internal_detail=f"Parquet write error for {table_name}: {exc}",
        )
