"""
Tests for services/alert_store.py — dual-store alert persistence.

Coverage:
  - append_alert: SQLite write, idempotency (INSERT OR IGNORE), Parquet call
  - load_all_alerts: returns newest-first, empty DB returns []
  - get_alert: found and not-found cases
  - update_alert: status and notes transitions; unknown keys ignored; unknown ID returns None
  - _build_device_alert_rows: device rows, dedup, unknown sentinel for identity/cloud events
  - Parquet write failure does NOT roll back the SQLite write
"""

import json
import uuid
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from backend.models.alert import Alert
from backend.services import alert_store
from backend.services.alert_store import (
    _build_device_alert_rows,
    append_alert,
    get_alert,
    load_all_alerts,
    update_alert,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture(autouse=True)
def isolated_db(tmp_path, monkeypatch):
    """Redirect the SQLite DB path to a temp directory for every test."""
    db_path = tmp_path / "triage.db"
    monkeypatch.setattr(alert_store, "_DB_PATH", db_path)


@pytest.fixture()
def mock_parquet_write():
    """Patch write_parquet so tests never touch the filesystem for Parquet."""
    with patch("backend.services.alert_store.write_parquet") as mock:
        yield mock


def _make_alert(**kwargs) -> Alert:
    defaults = dict(
        alert_id=str(uuid.uuid4()),
        rule_id="SYN-0001",
        rule_name="Test Rule",
        severity="high",
        triggered_at=datetime(2025, 6, 1, 12, 0, 0, tzinfo=timezone.utc),
        event_count=3,
        sample_event_ids=["evt-1", "evt-2"],
        tags=["T1059.001", "execution"],
        status="open",
        notes="",
    )
    defaults.update(kwargs)
    return Alert(**defaults)


def _device_match_rows() -> list[dict]:
    return [
        {"DeviceId": "dev-aaa", "DeviceName": "host-a", "FileName": "powershell.exe"},
        {"DeviceId": "dev-bbb", "DeviceName": "host-b", "FileName": "pwsh.exe"},
        {"DeviceId": "dev-aaa", "DeviceName": "host-a", "FileName": "cmd.exe"},  # duplicate
    ]


# ---------------------------------------------------------------------------
# append_alert
# ---------------------------------------------------------------------------

class TestAppendAlert:
    def test_writes_to_sqlite(self, mock_parquet_write):
        alert = _make_alert()
        append_alert(alert)

        result = get_alert(alert.alert_id)
        assert result is not None
        assert result.alert_id == alert.alert_id
        assert result.rule_id == "SYN-0001"
        assert result.severity == "high"
        assert result.status == "open"

    def test_idempotent_insert_or_ignore(self, mock_parquet_write):
        alert = _make_alert()
        append_alert(alert)
        append_alert(alert)  # second write with same alert_id

        all_alerts = load_all_alerts()
        assert len(all_alerts) == 1

    def test_tags_and_sample_ids_round_trip(self, mock_parquet_write):
        alert = _make_alert(
            tags=["T1110", "T1078"],
            sample_event_ids=["id-x", "id-y", "id-z"],
        )
        append_alert(alert)

        result = get_alert(alert.alert_id)
        assert result.tags == ["T1110", "T1078"]
        assert result.sample_event_ids == ["id-x", "id-y", "id-z"]

    def test_calls_write_parquet(self, mock_parquet_write):
        alert = _make_alert()
        append_alert(alert, match_rows=_device_match_rows())

        mock_parquet_write.assert_called_once()
        table_name_arg = mock_parquet_write.call_args[0][1]
        assert table_name_arg == "DeviceAlertEvents"

    def test_parquet_failure_does_not_roll_back_sqlite(self):
        alert = _make_alert()
        with patch(
            "backend.services.alert_store.write_parquet",
            side_effect=RuntimeError("disk full"),
        ):
            append_alert(alert)

        # Alert must still be retrievable from SQLite
        result = get_alert(alert.alert_id)
        assert result is not None
        assert result.alert_id == alert.alert_id

    def test_no_match_rows_still_writes_sentinel_parquet_row(self, mock_parquet_write):
        alert = _make_alert()
        append_alert(alert, match_rows=None)

        rows_written = mock_parquet_write.call_args[0][0]
        assert len(rows_written) == 1
        assert rows_written[0]["DeviceId"] == "unknown"
        assert rows_written[0]["DeviceName"] == "unknown"


# ---------------------------------------------------------------------------
# load_all_alerts
# ---------------------------------------------------------------------------

class TestLoadAllAlerts:
    def test_empty_db_returns_empty_list(self, mock_parquet_write):
        assert load_all_alerts() == []

    def test_returns_newest_first(self, mock_parquet_write):
        older = _make_alert(
            alert_id=str(uuid.uuid4()),
            triggered_at=datetime(2025, 1, 1, 10, 0, 0, tzinfo=timezone.utc),
        )
        newer = _make_alert(
            alert_id=str(uuid.uuid4()),
            triggered_at=datetime(2025, 1, 2, 10, 0, 0, tzinfo=timezone.utc),
        )
        append_alert(older)
        append_alert(newer)

        results = load_all_alerts()
        assert results[0].alert_id == newer.alert_id
        assert results[1].alert_id == older.alert_id

    def test_returns_all_alerts(self, mock_parquet_write):
        for _ in range(5):
            append_alert(_make_alert(alert_id=str(uuid.uuid4())))

        assert len(load_all_alerts()) == 5


# ---------------------------------------------------------------------------
# get_alert
# ---------------------------------------------------------------------------

class TestGetAlert:
    def test_returns_none_for_missing_id(self, mock_parquet_write):
        assert get_alert("does-not-exist") is None

    def test_returns_correct_alert(self, mock_parquet_write):
        alert = _make_alert()
        append_alert(alert)

        result = get_alert(alert.alert_id)
        assert result is not None
        assert result.rule_name == "Test Rule"
        assert result.event_count == 3


# ---------------------------------------------------------------------------
# update_alert
# ---------------------------------------------------------------------------

class TestUpdateAlert:
    def test_update_status(self, mock_parquet_write):
        alert = _make_alert()
        append_alert(alert)

        result = update_alert(alert.alert_id, {"status": "investigating"})
        assert result is not None
        assert result.status == "investigating"

    def test_update_notes(self, mock_parquet_write):
        alert = _make_alert()
        append_alert(alert)

        result = update_alert(alert.alert_id, {"notes": "Confirmed FP — SCCM deployment"})
        assert result is not None
        assert result.notes == "Confirmed FP — SCCM deployment"

    def test_update_status_and_notes_together(self, mock_parquet_write):
        alert = _make_alert()
        append_alert(alert)

        result = update_alert(alert.alert_id, {"status": "closed", "notes": "Closed after review"})
        assert result.status == "closed"
        assert result.notes == "Closed after review"

    def test_unknown_keys_are_ignored(self, mock_parquet_write):
        alert = _make_alert()
        append_alert(alert)

        # Injecting a key that is not in allowed_keys — must be silently dropped
        result = update_alert(alert.alert_id, {"status": "closed", "rule_id": "INJECTED"})
        assert result is not None
        assert result.rule_id == "SYN-0001"  # unchanged

    def test_empty_patch_returns_current_state(self, mock_parquet_write):
        alert = _make_alert()
        append_alert(alert)

        result = update_alert(alert.alert_id, {})
        assert result is not None
        assert result.status == "open"

    def test_returns_none_for_missing_id(self, mock_parquet_write):
        result = update_alert("ghost-id", {"status": "closed"})
        assert result is None

    def test_none_values_in_patch_are_ignored(self, mock_parquet_write):
        alert = _make_alert()
        append_alert(alert)

        result = update_alert(alert.alert_id, {"status": None, "notes": "kept"})
        assert result is not None
        assert result.status == "open"  # None value must not overwrite
        assert result.notes == "kept"


# ---------------------------------------------------------------------------
# _build_device_alert_rows
# ---------------------------------------------------------------------------

class TestBuildDeviceAlertRows:
    def _make_alert_for_build(self, **kwargs) -> Alert:
        return _make_alert(**kwargs)

    def test_deduplicates_same_device(self):
        alert = self._make_alert_for_build()
        rows = _device_match_rows()  # dev-aaa appears twice
        result = _build_device_alert_rows(alert, rows)

        device_ids = [r["DeviceId"] for r in result]
        assert device_ids.count("dev-aaa") == 1
        assert len(result) == 2

    def test_sentinel_row_when_no_match_rows(self):
        alert = self._make_alert_for_build()
        result = _build_device_alert_rows(alert, [])

        assert len(result) == 1
        assert result[0]["DeviceId"] == "unknown"
        assert result[0]["DeviceName"] == "unknown"

    def test_sentinel_row_when_no_device_fields(self):
        alert = self._make_alert_for_build()
        # Cloud/identity table rows with no DeviceId/DeviceName
        cloud_rows = [{"AccountUpn": "user@corp.com", "IPAddress": "1.2.3.4"}]
        result = _build_device_alert_rows(alert, cloud_rows)

        assert len(result) == 1
        assert result[0]["DeviceId"] == "unknown"

    def test_mitre_tags_extracted(self):
        alert = self._make_alert_for_build(tags=["T1059.001", "execution", "T1078"])
        result = _build_device_alert_rows(alert, [])

        techniques = result[0]["AttackTechniques"]
        assert "T1059.001" in techniques
        assert "T1078" in techniques
        assert "execution" not in techniques  # non-T tag filtered out

    def test_severity_capitalized(self):
        alert = self._make_alert_for_build(severity="high")
        result = _build_device_alert_rows(alert, [])
        assert result[0]["Severity"] == "High"

    def test_alert_id_and_rule_id_present(self):
        alert = self._make_alert_for_build()
        result = _build_device_alert_rows(alert, _device_match_rows())

        for row in result:
            assert row["AlertId"] == alert.alert_id
            assert row["DetectionSource"] == alert.rule_id
            assert row["ServiceSource"] == "fried-plantains"
            assert "ReportId" in row

    def test_timestamp_is_naive_utc(self):
        alert = self._make_alert_for_build(
            triggered_at=datetime(2025, 6, 1, 12, 0, 0, tzinfo=timezone.utc)
        )
        result = _build_device_alert_rows(alert, [])
        ts = result[0]["Timestamp"]
        assert ts.tzinfo is None  # naive — Parquet convention in this project
