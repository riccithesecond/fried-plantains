"""
services/alert_store.py — Dual-store alert persistence.

Alerts are written to two stores:
  1. SQLite (storage/triage.db): alert metadata + analyst triage state.
     Mutable — status transitions (open → investigating → closed) and analyst
     notes are updated in-place. Lightweight, zero-config, no daemon required.
  2. DeviceAlertEvents Parquet (immutable): one row per affected device per alert.
     Queryable via DuckDB alongside all other MDE tables for correlation hunts.
     Never updated after write — ground truth for what fired and on what device.

The two stores are keyed by AlertId (UUID). Triage state (status, notes) lives
ONLY in SQLite. The Parquet rows are the historical record.
"""

import json
import logging
import sqlite3
import uuid
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Generator

from backend.config import settings
from backend.ingest.writer import write_parquet
from backend.models.alert import Alert

logger = logging.getLogger(__name__)

_DB_PATH = Path(settings.STORAGE_ROOT) / "triage.db"

_SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS alerts (
    alert_id            TEXT PRIMARY KEY,
    rule_id             TEXT NOT NULL,
    rule_name           TEXT NOT NULL,
    severity            TEXT NOT NULL,
    triggered_at        TEXT NOT NULL,
    event_count         INTEGER NOT NULL,
    sample_event_ids    TEXT NOT NULL DEFAULT '[]',
    tags                TEXT NOT NULL DEFAULT '[]',
    status              TEXT NOT NULL DEFAULT 'open',
    notes               TEXT NOT NULL DEFAULT ''
);
"""


@contextmanager
def _get_conn() -> Generator[sqlite3.Connection, None, None]:
    """Return a WAL-mode SQLite connection scoped to a single operation."""
    _DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(_DB_PATH))
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL;")
    conn.execute(_SCHEMA_SQL)
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def _row_to_alert(row: sqlite3.Row) -> Alert:
    return Alert(
        alert_id=row["alert_id"],
        rule_id=row["rule_id"],
        rule_name=row["rule_name"],
        severity=row["severity"],
        triggered_at=datetime.fromisoformat(row["triggered_at"]),
        event_count=row["event_count"],
        sample_event_ids=json.loads(row["sample_event_ids"]),
        tags=json.loads(row["tags"]),
        status=row["status"],
        notes=row["notes"],
    )


def _build_device_alert_rows(alert: Alert, match_rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Build DeviceAlertEvents Parquet rows from detection match rows.

    One row per unique (DeviceId, DeviceName) pair. Rules that query identity or
    cloud tables produce no DeviceId — those generate a single 'unknown' sentinel
    row so the alert is still visible in DeviceAlertEvents correlation queries.
    """
    triggered_at = alert.triggered_at.replace(tzinfo=None)  # naive UTC — matches Parquet convention
    mitre_tags = [t for t in alert.tags if t.upper().startswith("T")]

    seen: set[tuple[str, str]] = set()
    out: list[dict[str, Any]] = []

    for row in match_rows:
        device_id = str(row.get("DeviceId") or "unknown")
        device_name = str(row.get("DeviceName") or "unknown")
        key = (device_id, device_name)
        if key in seen:
            continue
        seen.add(key)
        out.append({
            "Timestamp": triggered_at,
            "DeviceId": device_id,
            "DeviceName": device_name,
            "AlertId": alert.alert_id,
            "Title": alert.rule_name,
            "Severity": alert.severity.capitalize(),
            "ServiceSource": "fried-plantains",
            "DetectionSource": alert.rule_id,
            "AttackTechniques": mitre_tags,
            "ReportId": str(uuid.uuid4()),
        })

    if not out:
        out.append({
            "Timestamp": triggered_at,
            "DeviceId": "unknown",
            "DeviceName": "unknown",
            "AlertId": alert.alert_id,
            "Title": alert.rule_name,
            "Severity": alert.severity.capitalize(),
            "ServiceSource": "fried-plantains",
            "DetectionSource": alert.rule_id,
            "AttackTechniques": mitre_tags,
            "ReportId": str(uuid.uuid4()),
        })

    return out


def append_alert(
    alert: Alert,
    match_rows: list[dict[str, Any]] | None = None,
) -> None:
    """Persist a new alert to both stores.

    Args:
        alert: The alert record to persist.
        match_rows: Raw DuckDB result rows from the detection query. Used to extract
                    DeviceId/DeviceName for the DeviceAlertEvents Parquet write.
                    Pass None (or omit) for programmatic alerts with no query context.
    """
    with _get_conn() as conn:
        conn.execute(
            """
            INSERT OR IGNORE INTO alerts
                (alert_id, rule_id, rule_name, severity, triggered_at,
                 event_count, sample_event_ids, tags, status, notes)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                alert.alert_id,
                alert.rule_id,
                alert.rule_name,
                alert.severity,
                alert.triggered_at.isoformat(),
                alert.event_count,
                json.dumps(alert.sample_event_ids),
                json.dumps(alert.tags),
                alert.status,
                alert.notes,
            ),
        )

    rows = _build_device_alert_rows(alert, match_rows or [])
    try:
        write_parquet(rows, "DeviceAlertEvents", alert.triggered_at)
    except Exception as exc:
        # Parquet write failure is logged but does NOT roll back the SQLite write.
        # The alert remains in triage.db; the Parquet row can be backfilled later.
        logger.error(
            "DeviceAlertEvents Parquet write failed for alert %s: %s",
            alert.alert_id,
            exc,
        )


def load_all_alerts() -> list[Alert]:
    """Return all alerts from SQLite ordered newest-first."""
    with _get_conn() as conn:
        rows = conn.execute(
            "SELECT * FROM alerts ORDER BY triggered_at DESC"
        ).fetchall()
    return [_row_to_alert(row) for row in rows]


def get_alert(alert_id: str) -> Alert | None:
    """Return a single alert by ID, or None if not found."""
    with _get_conn() as conn:
        row = conn.execute(
            "SELECT * FROM alerts WHERE alert_id = ?", (alert_id,)
        ).fetchone()
    return _row_to_alert(row) if row else None


def update_alert(alert_id: str, patch: dict[str, Any]) -> Alert | None:
    """Apply a triage patch (status, notes) and return the updated Alert.

    Only 'status' and 'notes' are writable — all other keys in patch are ignored.
    Returns None if alert_id does not exist.
    """
    allowed_keys = {"status", "notes"}
    updates = {k: v for k, v in patch.items() if k in allowed_keys and v is not None}
    if not updates:
        return get_alert(alert_id)

    # Column names are drawn from the fixed allowed_keys set — not user input.
    set_clause = ", ".join(f"{k} = ?" for k in updates)
    values = [*updates.values(), alert_id]

    with _get_conn() as conn:
        conn.execute(f"UPDATE alerts SET {set_clause} WHERE alert_id = ?", values)

    return get_alert(alert_id)
