"""
api/alerts.py — Alert retrieval and triage endpoints.

Alerts are read from and written to backend.services.alert_store, which
maintains a dual-store: SQLite for mutable triage state, DeviceAlertEvents
Parquet for the immutable per-device alert record.

Status transitions: open → investigating → closed
"""

import logging

from fastapi import APIRouter, Depends, HTTPException, Query

from backend.api.auth import get_current_user
from backend.models.alert import Alert, AlertPatch
from backend.models.user import User
from backend.services.alert_store import get_alert, load_all_alerts, update_alert

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/alerts", tags=["alerts"])


@router.get("/", response_model=list[Alert])
async def list_alerts(
    severity: list[str] = Query(default=[]),
    status: str | None = Query(default=None),
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=500),
    current_user: User = Depends(get_current_user),
) -> list[Alert]:
    all_alerts = load_all_alerts()

    if severity:
        all_alerts = [a for a in all_alerts if a.severity in severity]
    if status:
        all_alerts = [a for a in all_alerts if a.status == status]

    start = (page - 1) * page_size
    return all_alerts[start : start + page_size]


@router.get("/{alert_id}", response_model=Alert)
async def get_alert_endpoint(
    alert_id: str,
    current_user: User = Depends(get_current_user),
) -> Alert:
    alert = get_alert(alert_id)
    if alert is None:
        raise HTTPException(status_code=404, detail=f"Alert '{alert_id}' not found.")
    return alert


@router.patch("/{alert_id}", response_model=Alert)
async def update_alert_endpoint(
    alert_id: str,
    body: AlertPatch,
    current_user: User = Depends(get_current_user),
) -> Alert:
    """Update alert status and analyst notes for triage workflow."""
    updated = update_alert(alert_id, body.model_dump(exclude_none=True))
    if updated is None:
        raise HTTPException(status_code=404, detail=f"Alert '{alert_id}' not found.")
    logger.info(
        "Alert %s updated by %s: status=%s",
        alert_id,
        current_user.username,
        updated.status,
    )
    return updated
