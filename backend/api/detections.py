"""
api/detections.py — Detection rule CRUD endpoints.

Rules are stored as YAML files in detections/rules/{id}.yaml. This makes them:
  - Version-controllable: git diff shows exactly what changed
  - Portable: copy the YAML to Microsoft Sentinel as an Analytic Rule
  - Inspectable: a DFIR analyst can read the rule without a GUI

Rule IDs are auto-incremented: FP-0001, FP-0002, etc.
Deletion is soft — rules are disabled (enabled: false) and marked archived.
"""

import logging
import os
import time
from datetime import datetime
from pathlib import Path

import yaml
from fastapi import APIRouter, Depends, HTTPException, Query

from backend.api.auth import get_current_user
from backend.config import settings
from backend.engine.duckdb_pool import get_pool
from backend.engine.query_router import route
from backend.models.detection import (
    DetectionRule,
    DetectionRuleCreate,
    DetectionRulePatch,
    DetectionTestResult,
)
from backend.models.user import User

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/detections", tags=["detections"])

_RULES_DIR = Path("detections/rules")


def _rules_dir() -> Path:
    _RULES_DIR.mkdir(parents=True, exist_ok=True)
    return _RULES_DIR


def _rule_path(rule_id: str) -> Path:
    return _rules_dir() / f"{rule_id}.yaml"


def _load_rule(rule_id: str) -> DetectionRule | None:
    path = _rule_path(rule_id)
    if not path.exists():
        return None
    try:
        with path.open() as f:
            data = yaml.safe_load(f)
        return DetectionRule(**data)
    except Exception as exc:
        logger.error("Failed to load rule %s: %s", rule_id, exc)
        return None


def _save_rule(rule: DetectionRule) -> None:
    path = _rule_path(rule.id)
    data = rule.model_dump(mode="json")
    # Serialize datetime fields as ISO strings
    for key in ("created_at", "updated_at"):
        if isinstance(data.get(key), datetime):
            data[key] = data[key].isoformat()
    tmp = path.with_suffix(".yaml.tmp")
    with tmp.open("w") as f:
        yaml.dump(data, f, allow_unicode=True, sort_keys=False)
    os.replace(str(tmp), str(path))


def _next_rule_id() -> str:
    existing = list(_rules_dir().glob("FP-*.yaml"))
    if not existing:
        return "FP-0001"
    ids = []
    for p in existing:
        try:
            ids.append(int(p.stem.split("-")[1]))
        except (IndexError, ValueError):
            pass
    next_num = max(ids, default=0) + 1
    return f"FP-{next_num:04d}"


def _list_all_rules() -> list[DetectionRule]:
    rules = []
    for path in sorted(_rules_dir().glob("FP-*.yaml")):
        rule = _load_rule(path.stem)
        if rule is not None:
            rules.append(rule)
    return rules


@router.get("/", response_model=list[DetectionRule])
async def list_rules(
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=500),
    current_user: User = Depends(get_current_user),
) -> list[DetectionRule]:
    all_rules = _list_all_rules()
    start = (page - 1) * page_size
    return all_rules[start : start + page_size]


@router.post("/", response_model=DetectionRule, status_code=201)
async def create_rule(
    body: DetectionRuleCreate,
    current_user: User = Depends(get_current_user),
) -> DetectionRule:
    rule_id = _next_rule_id()
    now = datetime.utcnow()
    rule = DetectionRule(
        id=rule_id,
        created_at=now,
        updated_at=now,
        **body.model_dump(),
    )
    _save_rule(rule)
    logger.info("Detection rule created: %s by %s", rule_id, current_user.username)
    return rule


@router.get("/{rule_id}", response_model=DetectionRule)
async def get_rule(
    rule_id: str,
    current_user: User = Depends(get_current_user),
) -> DetectionRule:
    rule = _load_rule(rule_id)
    if rule is None:
        raise HTTPException(status_code=404, detail=f"Rule '{rule_id}' not found.")
    return rule


@router.put("/{rule_id}", response_model=DetectionRule)
async def update_rule(
    rule_id: str,
    body: DetectionRuleCreate,
    current_user: User = Depends(get_current_user),
) -> DetectionRule:
    existing = _load_rule(rule_id)
    if existing is None:
        raise HTTPException(status_code=404, detail=f"Rule '{rule_id}' not found.")
    rule = DetectionRule(
        id=rule_id,
        created_at=existing.created_at,
        updated_at=datetime.utcnow(),
        **body.model_dump(),
    )
    _save_rule(rule)
    logger.info("Detection rule updated: %s by %s", rule_id, current_user.username)
    return rule


@router.patch("/{rule_id}", response_model=DetectionRule)
async def patch_rule(
    rule_id: str,
    body: DetectionRulePatch,
    current_user: User = Depends(get_current_user),
) -> DetectionRule:
    rule = _load_rule(rule_id)
    if rule is None:
        raise HTTPException(status_code=404, detail=f"Rule '{rule_id}' not found.")
    update_data = body.model_dump(exclude_none=True)
    updated = rule.model_copy(update={**update_data, "updated_at": datetime.utcnow()})
    _save_rule(updated)
    return updated


@router.delete("/{rule_id}", response_model=dict)
async def delete_rule(
    rule_id: str,
    current_user: User = Depends(get_current_user),
) -> dict:
    """Soft delete: disable the rule. YAML file is kept for audit trail."""
    rule = _load_rule(rule_id)
    if rule is None:
        raise HTTPException(status_code=404, detail=f"Rule '{rule_id}' not found.")
    archived = rule.model_copy(update={"enabled": False, "updated_at": datetime.utcnow()})
    _save_rule(archived)
    logger.info("Detection rule archived (soft delete): %s by %s", rule_id, current_user.username)
    return {"detail": f"Rule '{rule_id}' disabled and archived."}


@router.post("/{rule_id}/test", response_model=DetectionTestResult)
async def test_rule(
    rule_id: str,
    current_user: User = Depends(get_current_user),
) -> DetectionTestResult:
    """Run the rule against the last 24h of stored data."""
    rule = _load_rule(rule_id)
    if rule is None:
        raise HTTPException(status_code=404, detail=f"Rule '{rule_id}' not found.")

    start_ms = time.monotonic()
    try:
        sql = route(rule.query, rule.language)
    except Exception as exc:
        raise HTTPException(status_code=422, detail=f"Rule query error: {exc}")

    pool = get_pool()
    try:
        rows = await pool.execute(sql, timeout=settings.QUERY_TIMEOUT_SECONDS)
    except Exception as exc:
        raise HTTPException(status_code=400, detail=str(exc))

    duration_ms = int((time.monotonic() - start_ms) * 1000)
    sample = rows[:10]

    return DetectionTestResult(
        rule_id=rule_id,
        match_count=len(rows),
        sample_rows=sample,
        duration_ms=duration_ms,
    )
