"""
engine/detection_runner.py — Background detection rule execution loop.

Runs all enabled detection rules on a configurable interval. On match, creates
an alert record. Single rule failures are caught and logged — the loop continues.

Deduplication: if an open alert for the same rule_id already exists within the
dedup window, a new alert is NOT created. This prevents alert storms when data
accumulates between runs.

Production upgrade: replace the asyncio loop with a proper scheduler (APScheduler,
Celery Beat, or a Kubernetes CronJob) and the file-based alert store with a database.
"""

import asyncio
import logging
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

import yaml

from backend.engine.duckdb_pool import get_pool
from backend.engine.query_router import route
from backend.exceptions import QueryException
from backend.models.alert import Alert
from backend.services.alert_store import append_alert, load_all_alerts

logger = logging.getLogger(__name__)

_RULES_DIR = Path("detections/rules")
_RUN_INTERVAL_SECONDS = 300   # Run every 5 minutes
_DEDUP_WINDOW_HOURS = 1


def _load_enabled_rules() -> list[dict]:
    """Load all enabled YAML rules from disk."""
    rules = []
    if not _RULES_DIR.exists():
        return rules
    for path in sorted(_RULES_DIR.glob("FP-*.yaml")):
        try:
            with path.open() as f:
                rule = yaml.safe_load(f)
            if rule.get("enabled", True):
                rules.append(rule)
        except Exception as exc:
            logger.error("Failed to load rule %s: %s", path.name, exc)
    return rules


def _has_open_alert(rule_id: str) -> bool:
    """Return True if an open alert for this rule exists within the dedup window."""
    cutoff = datetime.now(timezone.utc) - timedelta(hours=_DEDUP_WINDOW_HOURS)
    for alert in load_all_alerts():
        if (
            alert.rule_id == rule_id
            and alert.status == "open"
            and alert.triggered_at > cutoff
        ):
            return True
    return False


async def run_detection_cycle() -> None:
    """Execute all enabled rules once and create alerts for any matches."""
    rules = _load_enabled_rules()
    if not rules:
        logger.debug("Detection cycle: no enabled rules.")
        return

    pool = get_pool()
    logger.info("Detection cycle started: %d rules", len(rules))

    for rule in rules:
        rule_id = rule.get("id", "unknown")
        try:
            sql = route(rule["query"], rule["language"])
            rows = await pool.execute(sql, timeout=30.0)

            if not rows:
                continue

            if _has_open_alert(rule_id):
                logger.debug("Detection %s: %d matches, suppressed (dedup)", rule_id, len(rows))
                continue

            sample_ids = [str(row.get("ReportId", "")) for row in rows[:10]]
            alert = Alert(
                alert_id=str(uuid.uuid4()),
                rule_id=rule_id,
                rule_name=rule.get("name", rule_id),
                severity=rule.get("severity", "medium"),
                triggered_at=datetime.now(timezone.utc),
                event_count=len(rows),
                sample_event_ids=sample_ids,
                tags=rule.get("tags", []),
                status="open",
            )
            append_alert(alert, match_rows=rows)
            logger.warning(
                "ALERT: rule=%s name=%r severity=%s matches=%d",
                rule_id,
                rule.get("name"),
                rule.get("severity"),
                len(rows),
            )

        except QueryException as exc:
            logger.error("Detection rule %s execution error: %s", rule_id, exc.internal_detail)
        except Exception as exc:
            logger.error("Detection rule %s unexpected error: %s", rule_id, exc)

    logger.info("Detection cycle complete.")


async def detection_loop() -> None:
    """Continuous background loop — runs every _RUN_INTERVAL_SECONDS."""
    logger.info("Detection runner started (interval: %ds)", _RUN_INTERVAL_SECONDS)
    while True:
        try:
            await run_detection_cycle()
        except Exception as exc:
            logger.error("Detection loop error: %s", exc)
        await asyncio.sleep(_RUN_INTERVAL_SECONDS)
