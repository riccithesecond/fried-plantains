"""
api/alerts.py — Alert retrieval and triage endpoints.

Alerts are stored as JSON lines in storage/alerts/alerts.jsonl. This is the
MVP storage format — simple, appendable, auditable. Production upgrade: migrate
to a database table (PostgreSQL, SQLite) for efficient filtering and indexing.

Status transitions: open → investigating → closed
"""

import json
import logging
import os
from datetime import datetime
from pathlib import Path
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, Query

from backend.api.auth import get_current_user
from backend.models.alert import Alert, AlertPatch
from backend.models.user import User

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/alerts", tags=["alerts"])

_ALERTS_FILE = Path("storage/alerts/alerts.jsonl")


def _ensure_alerts_file() -> Path:
    _ALERTS_FILE.parent.mkdir(parents=True, exist_ok=True)
    if not _ALERTS_FILE.exists():
        _ALERTS_FILE.touch()
    return _ALERTS_FILE


def _load_all_alerts() -> list[Alert]:
    path = _ensure_alerts_file()
    alerts = []
    with path.open() as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                data = json.loads(line)
                alerts.append(Alert(**data))
            except Exception as exc:
                logger.warning("Failed to parse alert line: %s", exc)
    return alerts


def _save_all_alerts(alerts: list[Alert]) -> None:
    """Rewrite the entire alerts file (used for updates).

    Production: use UPDATE query on alerts table. For MVP, full-file rewrite
    is acceptable given the expected alert volume.
    """
    path = _ensure_alerts_file()
    tmp = path.with_suffix(".jsonl.tmp")
    with tmp.open("w") as f:
        for alert in alerts:
            f.write(alert.model_dump_json() + "\n")
    os.replace(str(tmp), str(path))


def append_alert(alert: Alert) -> None:
    """Append a single alert without reading the entire file."""
    path = _ensure_alerts_file()
    with path.open("a") as f:
        f.write(alert.model_dump_json() + "\n")


@router.get("/", response_model=list[Alert])
async def list_alerts(
    severity: list[str] = Query(default=[]),
    status: str | None = Query(default=None),
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=500),
    current_user: User = Depends(get_current_user),
) -> list[Alert]:
    all_alerts = _load_all_alerts()
    all_alerts.sort(key=lambda a: a.triggered_at, reverse=True)

    if severity:
        all_alerts = [a for a in all_alerts if a.severity in severity]
    if status:
        all_alerts = [a for a in all_alerts if a.status == status]

    start = (page - 1) * page_size
    return all_alerts[start : start + page_size]


@router.get("/{alert_id}", response_model=Alert)
async def get_alert(
    alert_id: str,
    current_user: User = Depends(get_current_user),
) -> Alert:
    for alert in _load_all_alerts():
        if alert.alert_id == alert_id:
            return alert
    raise HTTPException(status_code=404, detail=f"Alert '{alert_id}' not found.")


@router.patch("/{alert_id}", response_model=Alert)
async def update_alert(
    alert_id: str,
    body: AlertPatch,
    current_user: User = Depends(get_current_user),
) -> Alert:
    """Update alert status and analyst notes for triage workflow."""
    all_alerts = _load_all_alerts()
    updated: Alert | None = None

    for i, alert in enumerate(all_alerts):
        if alert.alert_id == alert_id:
            patch = body.model_dump(exclude_none=True)
            updated = alert.model_copy(update=patch)
            all_alerts[i] = updated
            break

    if updated is None:
        raise HTTPException(status_code=404, detail=f"Alert '{alert_id}' not found.")

    _save_all_alerts(all_alerts)
    logger.info(
        "Alert %s updated by %s: status=%s",
        alert_id,
        current_user.username,
        updated.status,
    )
    return updated
