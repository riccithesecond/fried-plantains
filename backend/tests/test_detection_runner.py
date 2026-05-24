"""
Tests for engine/detection_runner.py.

Three functions under test:
  _load_enabled_rules — YAML loading from both FP and SYN directories
  _has_open_alert     — dedup window logic against the alert store
  run_detection_cycle — full cycle: load → transpile → execute → alert

All external I/O is mocked: DuckDB pool, alert store, and the filesystem
(via tmp_path + monkeypatch). asyncio.run() is used instead of
@pytest.mark.asyncio so tests stay as plain sync functions.
"""

import asyncio
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
import yaml

from backend.engine import detection_runner
from backend.models.alert import Alert


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _write_rule(directory: Path, rule_id: str, enabled: bool = True, **overrides) -> Path:
    """Write a minimal valid rule YAML file."""
    data = {
        "id": rule_id,
        "name": f"Test rule {rule_id}",
        "description": "Test",
        "severity": "high",
        "language": "kql",
        "query": f"DeviceProcessEvents | where FileName == '{rule_id}' | limit 1",
        "tags": ["T1059.001"],
        "mde_portable": False,
        "enabled": enabled,
        "created_at": "2025-01-01T00:00:00Z",
        "updated_at": "2025-01-01T00:00:00Z",
        "author": "test",
        "false_positive_notes": "",
    }
    data.update(overrides)
    path = directory / f"{rule_id}.yaml"
    path.write_text(yaml.dump(data))
    return path


def _make_alert(rule_id: str, status: str = "open", hours_ago: float = 0.0) -> Alert:
    triggered = datetime.now(timezone.utc) - timedelta(hours=hours_ago)
    return Alert(
        alert_id=str(uuid.uuid4()),
        rule_id=rule_id,
        rule_name="Test",
        severity="high",
        triggered_at=triggered,
        event_count=1,
        status=status,
    )


# ---------------------------------------------------------------------------
# _load_enabled_rules
# ---------------------------------------------------------------------------

class TestLoadEnabledRules:
    def test_loads_fp_rules_from_root(self, tmp_path, monkeypatch):
        monkeypatch.setattr(detection_runner, "_RULES_DIR", tmp_path)
        _write_rule(tmp_path, "FP-0001")
        _write_rule(tmp_path, "FP-0002")

        rules = detection_runner._load_enabled_rules()
        ids = [r["id"] for r in rules]
        assert "FP-0001" in ids
        assert "FP-0002" in ids

    def test_loads_syn_rules_from_synthetic_subdir(self, tmp_path, monkeypatch):
        monkeypatch.setattr(detection_runner, "_RULES_DIR", tmp_path)
        synthetic = tmp_path / "synthetic"
        synthetic.mkdir()
        _write_rule(synthetic, "SYN-0001")

        rules = detection_runner._load_enabled_rules()
        assert any(r["id"] == "SYN-0001" for r in rules)

    def test_skips_disabled_rules(self, tmp_path, monkeypatch):
        monkeypatch.setattr(detection_runner, "_RULES_DIR", tmp_path)
        _write_rule(tmp_path, "FP-0001", enabled=True)
        _write_rule(tmp_path, "FP-0002", enabled=False)

        rules = detection_runner._load_enabled_rules()
        ids = [r["id"] for r in rules]
        assert "FP-0001" in ids
        assert "FP-0002" not in ids

    def test_returns_empty_list_when_directory_missing(self, tmp_path, monkeypatch):
        nonexistent = tmp_path / "nonexistent"
        monkeypatch.setattr(detection_runner, "_RULES_DIR", nonexistent)
        assert detection_runner._load_enabled_rules() == []

    def test_handles_malformed_yaml_gracefully(self, tmp_path, monkeypatch):
        monkeypatch.setattr(detection_runner, "_RULES_DIR", tmp_path)
        bad = tmp_path / "FP-0001.yaml"
        bad.write_text(": : : invalid yaml :::")
        _write_rule(tmp_path, "FP-0002")

        # Must not raise — bad rule is skipped, good rule loads
        rules = detection_runner._load_enabled_rules()
        assert any(r["id"] == "FP-0002" for r in rules)

    def test_returns_rules_in_sorted_order(self, tmp_path, monkeypatch):
        monkeypatch.setattr(detection_runner, "_RULES_DIR", tmp_path)
        _write_rule(tmp_path, "FP-0003")
        _write_rule(tmp_path, "FP-0001")
        _write_rule(tmp_path, "FP-0002")

        rules = detection_runner._load_enabled_rules()
        ids = [r["id"] for r in rules]
        assert ids == sorted(ids)

    def test_loads_both_fp_and_syn_together(self, tmp_path, monkeypatch):
        monkeypatch.setattr(detection_runner, "_RULES_DIR", tmp_path)
        _write_rule(tmp_path, "FP-0001")
        synthetic = tmp_path / "synthetic"
        synthetic.mkdir()
        _write_rule(synthetic, "SYN-0001")

        rules = detection_runner._load_enabled_rules()
        ids = [r["id"] for r in rules]
        assert "FP-0001" in ids
        assert "SYN-0001" in ids

    def test_empty_synthetic_dir_does_not_error(self, tmp_path, monkeypatch):
        monkeypatch.setattr(detection_runner, "_RULES_DIR", tmp_path)
        _write_rule(tmp_path, "FP-0001")
        (tmp_path / "synthetic").mkdir()  # empty

        rules = detection_runner._load_enabled_rules()
        assert len(rules) == 1


# ---------------------------------------------------------------------------
# _has_open_alert
# ---------------------------------------------------------------------------

class TestHasOpenAlert:
    def test_returns_false_when_no_alerts(self):
        with patch("backend.engine.detection_runner.load_all_alerts", return_value=[]):
            assert detection_runner._has_open_alert("FP-0001") is False

    def test_returns_true_for_recent_open_alert(self):
        alert = _make_alert("FP-0001", status="open", hours_ago=0.1)
        with patch("backend.engine.detection_runner.load_all_alerts", return_value=[alert]):
            assert detection_runner._has_open_alert("FP-0001") is True

    def test_returns_false_for_closed_alert(self):
        alert = _make_alert("FP-0001", status="closed", hours_ago=0.1)
        with patch("backend.engine.detection_runner.load_all_alerts", return_value=[alert]):
            assert detection_runner._has_open_alert("FP-0001") is False

    def test_returns_false_for_investigating_alert_within_window(self):
        # Only 'open' status suppresses — 'investigating' does not
        alert = _make_alert("FP-0001", status="investigating", hours_ago=0.1)
        with patch("backend.engine.detection_runner.load_all_alerts", return_value=[alert]):
            assert detection_runner._has_open_alert("FP-0001") is False

    def test_returns_false_for_alert_outside_dedup_window(self):
        # Alert is older than _DEDUP_WINDOW_HOURS (1h)
        alert = _make_alert("FP-0001", status="open", hours_ago=2.0)
        with patch("backend.engine.detection_runner.load_all_alerts", return_value=[alert]):
            assert detection_runner._has_open_alert("FP-0001") is False

    def test_returns_false_for_different_rule_id(self):
        alert = _make_alert("FP-0002", status="open", hours_ago=0.1)
        with patch("backend.engine.detection_runner.load_all_alerts", return_value=[alert]):
            assert detection_runner._has_open_alert("FP-0001") is False

    def test_returns_true_at_dedup_boundary(self):
        # Alert exactly at the boundary (just inside 1h) — should be suppressed
        alert = _make_alert("FP-0001", status="open", hours_ago=0.99)
        with patch("backend.engine.detection_runner.load_all_alerts", return_value=[alert]):
            assert detection_runner._has_open_alert("FP-0001") is True


# ---------------------------------------------------------------------------
# run_detection_cycle
# ---------------------------------------------------------------------------

class TestRunDetectionCycle:
    def _make_mock_pool(self, rows: list[dict]) -> MagicMock:
        pool = MagicMock()
        pool.execute = AsyncMock(return_value=rows)
        return pool

    def test_exits_early_when_no_rules(self, tmp_path, monkeypatch):
        monkeypatch.setattr(detection_runner, "_RULES_DIR", tmp_path)
        with patch("backend.engine.detection_runner.get_pool") as mock_get_pool:
            asyncio.run(detection_runner.run_detection_cycle())
            mock_get_pool.assert_not_called()

    def test_creates_alert_when_query_returns_rows(self, tmp_path, monkeypatch):
        monkeypatch.setattr(detection_runner, "_RULES_DIR", tmp_path)
        _write_rule(tmp_path, "FP-0001")

        match_rows = [{"DeviceId": "dev-1", "DeviceName": "host-a", "ReportId": "r1"}]
        pool = self._make_mock_pool(match_rows)

        with patch("backend.engine.detection_runner.get_pool", return_value=pool), \
             patch("backend.engine.detection_runner.load_all_alerts", return_value=[]), \
             patch("backend.engine.detection_runner.append_alert") as mock_append:
            asyncio.run(detection_runner.run_detection_cycle())
            mock_append.assert_called_once()

    def test_no_alert_when_query_returns_no_rows(self, tmp_path, monkeypatch):
        monkeypatch.setattr(detection_runner, "_RULES_DIR", tmp_path)
        _write_rule(tmp_path, "FP-0001")

        pool = self._make_mock_pool([])

        with patch("backend.engine.detection_runner.get_pool", return_value=pool), \
             patch("backend.engine.detection_runner.append_alert") as mock_append:
            asyncio.run(detection_runner.run_detection_cycle())
            mock_append.assert_not_called()

    def test_dedup_suppresses_second_alert(self, tmp_path, monkeypatch):
        monkeypatch.setattr(detection_runner, "_RULES_DIR", tmp_path)
        _write_rule(tmp_path, "FP-0001")

        match_rows = [{"DeviceId": "dev-1", "DeviceName": "host-a", "ReportId": "r1"}]
        pool = self._make_mock_pool(match_rows)
        existing_alert = _make_alert("FP-0001", status="open", hours_ago=0.1)

        with patch("backend.engine.detection_runner.get_pool", return_value=pool), \
             patch("backend.engine.detection_runner.load_all_alerts", return_value=[existing_alert]), \
             patch("backend.engine.detection_runner.append_alert") as mock_append:
            asyncio.run(detection_runner.run_detection_cycle())
            mock_append.assert_not_called()

    def test_single_rule_query_exception_does_not_break_loop(self, tmp_path, monkeypatch):
        monkeypatch.setattr(detection_runner, "_RULES_DIR", tmp_path)
        _write_rule(tmp_path, "FP-0001")
        _write_rule(tmp_path, "FP-0002")

        from backend.exceptions import QueryException

        call_count = 0

        async def mock_execute(sql, timeout):
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                raise QueryException("bad query")
            return [{"DeviceId": "x", "DeviceName": "y", "ReportId": "r"}]

        pool = MagicMock()
        pool.execute = mock_execute

        with patch("backend.engine.detection_runner.get_pool", return_value=pool), \
             patch("backend.engine.detection_runner.load_all_alerts", return_value=[]), \
             patch("backend.engine.detection_runner.append_alert") as mock_append:
            asyncio.run(detection_runner.run_detection_cycle())
            # FP-0001 failed, FP-0002 should still fire
            mock_append.assert_called_once()

    def test_unexpected_exception_does_not_break_loop(self, tmp_path, monkeypatch):
        monkeypatch.setattr(detection_runner, "_RULES_DIR", tmp_path)
        _write_rule(tmp_path, "FP-0001")
        _write_rule(tmp_path, "FP-0002")

        call_count = 0

        async def mock_execute(sql, timeout):
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                raise RuntimeError("unexpected disk error")
            return [{"DeviceId": "x", "DeviceName": "y", "ReportId": "r"}]

        pool = MagicMock()
        pool.execute = mock_execute

        with patch("backend.engine.detection_runner.get_pool", return_value=pool), \
             patch("backend.engine.detection_runner.load_all_alerts", return_value=[]), \
             patch("backend.engine.detection_runner.append_alert") as mock_append:
            asyncio.run(detection_runner.run_detection_cycle())
            mock_append.assert_called_once()

    def test_alert_contains_correct_rule_metadata(self, tmp_path, monkeypatch):
        monkeypatch.setattr(detection_runner, "_RULES_DIR", tmp_path)
        _write_rule(tmp_path, "FP-0001", name="Encoded PowerShell", severity="high",
                    tags=["T1059.001", "execution"])

        match_rows = [{"DeviceId": "dev-1", "DeviceName": "host-a", "ReportId": "r1"}]
        pool = self._make_mock_pool(match_rows)

        captured = {}

        def capture_append(alert, match_rows=None):
            captured["alert"] = alert
            captured["rows"] = match_rows

        with patch("backend.engine.detection_runner.get_pool", return_value=pool), \
             patch("backend.engine.detection_runner.load_all_alerts", return_value=[]), \
             patch("backend.engine.detection_runner.append_alert", side_effect=capture_append):
            asyncio.run(detection_runner.run_detection_cycle())

        alert = captured["alert"]
        assert alert.rule_id == "FP-0001"
        assert alert.rule_name == "Encoded PowerShell"
        assert alert.severity == "high"
        assert alert.event_count == 1
        assert "T1059.001" in alert.tags

    def test_match_rows_passed_to_append_alert(self, tmp_path, monkeypatch):
        monkeypatch.setattr(detection_runner, "_RULES_DIR", tmp_path)
        _write_rule(tmp_path, "FP-0001")

        match_rows = [
            {"DeviceId": "dev-1", "DeviceName": "host-a", "ReportId": "r1"},
            {"DeviceId": "dev-2", "DeviceName": "host-b", "ReportId": "r2"},
        ]
        pool = self._make_mock_pool(match_rows)
        captured_rows = {}

        def capture(alert, match_rows=None):
            captured_rows["rows"] = match_rows

        with patch("backend.engine.detection_runner.get_pool", return_value=pool), \
             patch("backend.engine.detection_runner.load_all_alerts", return_value=[]), \
             patch("backend.engine.detection_runner.append_alert", side_effect=capture):
            asyncio.run(detection_runner.run_detection_cycle())

        assert len(captured_rows["rows"]) == 2

    def test_multiple_rules_each_checked_independently(self, tmp_path, monkeypatch):
        monkeypatch.setattr(detection_runner, "_RULES_DIR", tmp_path)
        _write_rule(tmp_path, "FP-0001")
        _write_rule(tmp_path, "FP-0002")
        _write_rule(tmp_path, "FP-0003")

        match_rows = [{"DeviceId": "d", "DeviceName": "h", "ReportId": "r"}]
        pool = self._make_mock_pool(match_rows)

        with patch("backend.engine.detection_runner.get_pool", return_value=pool), \
             patch("backend.engine.detection_runner.load_all_alerts", return_value=[]), \
             patch("backend.engine.detection_runner.append_alert") as mock_append:
            asyncio.run(detection_runner.run_detection_cycle())
            assert mock_append.call_count == 3
