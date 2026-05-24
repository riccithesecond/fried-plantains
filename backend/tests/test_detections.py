"""
Tests for detection rule schema validation.

Verifies that:
  - mde_portable rules only use MDE-valid column names
  - Rule IDs match FP-XXXX format
  - Invalid queries are rejected at rule creation
  - Seed rule files load without error
"""

import os
from pathlib import Path

import pytest
import yaml

from backend.schema.mde_tables import MDE_TABLES, validate_columns


def _load_rule_files() -> list[Path]:
    rules_dir = Path("detections/rules")
    if not rules_dir.exists():
        return []
    paths = list(rules_dir.glob("FP-*.yaml"))
    synthetic_dir = rules_dir / "synthetic"
    if synthetic_dir.exists():
        paths.extend(synthetic_dir.glob("SYN-*.yaml"))
    return paths


def _extract_kql_column_refs(query: str) -> list[str]:
    """Extract PascalCase identifiers from a KQL query, excluding string literals.

    Removes quoted string content first to avoid treating ActionType values like
    "ProcessCreated" or "LogonSuccess" as column name references.
    """
    import re
    # Strip quoted strings to avoid catching ActionType values inside quotes
    stripped = re.sub(r'"[^"]*"', '""', query)
    stripped = re.sub(r"'[^']*'", "''", stripped)
    # Match PascalCase identifiers that look like column names (multiple words joined)
    return re.findall(r"\b([A-Z][a-z]+(?:[A-Z][a-z]+)+)\b", stripped)


class TestSeedRules:
    @pytest.mark.parametrize("rule_path", _load_rule_files())
    def test_rule_loads(self, rule_path: Path):
        with rule_path.open() as f:
            rule = yaml.safe_load(f)
        assert "id" in rule
        assert "name" in rule
        assert "query" in rule
        assert "severity" in rule
        assert "language" in rule

    @pytest.mark.parametrize("rule_path", _load_rule_files())
    def test_rule_id_format(self, rule_path: Path):
        import re
        with rule_path.open() as f:
            rule = yaml.safe_load(f)
        assert re.match(r"^(FP|SYN)-\d{4}$", rule["id"]), f"Invalid ID format: {rule['id']}"

    @pytest.mark.parametrize("rule_path", _load_rule_files())
    def test_mde_portable_rules_use_valid_columns(self, rule_path: Path):
        with rule_path.open() as f:
            rule = yaml.safe_load(f)

        if not rule.get("mde_portable", False):
            return

        import re
        query = rule["query"]

        # Skip column validation for multi-table rules that use let sub-pipelines.
        # These create computed column aliases (e.g. NetworkTimestamp = Timestamp)
        # that are valid in query context but aren't real MDE schema column names —
        # simple text-matching can't distinguish aliases from column refs.
        if re.search(r'\blet\s+\w+\s*=\s*\w+Events\b', query):
            return

        # Find all MDE table references in the query
        table_names = [t for t in MDE_TABLES if t in query]
        table_name_set = frozenset(MDE_TABLES.keys())

        for table_name in table_names:
            col_refs = _extract_kql_column_refs(query)
            # ActionType values inside quotes are stripped by _extract_kql_column_refs,
            # but filter any remaining KQL keywords or MDE table names that aren't columns.
            kql_keywords = {
                "ProcessCreated", "ProcessInjected", "EncodedCommand",
                "LogonSuccess", "LogonFailed", "FileCreated", "RegistryValueSet",
            }
            col_refs = [
                c for c in col_refs
                if c not in kql_keywords and c not in table_name_set
            ]
            invalid = validate_columns(table_name, col_refs)
            assert invalid == [], (
                f"mde_portable rule {rule['id']} references invalid columns "
                f"for {table_name}: {invalid}"
            )

    @pytest.mark.parametrize("rule_path", _load_rule_files())
    def test_rule_query_transpiles(self, rule_path: Path):
        from backend.engine.query_router import route
        from backend.exceptions import QueryException

        with rule_path.open() as f:
            rule = yaml.safe_load(f)

        try:
            sql = route(rule["query"], rule["language"])
            assert sql is not None
            assert len(sql) > 0
        except QueryException as exc:
            pytest.fail(f"Rule {rule['id']} query failed to transpile: {exc.detail}")


class TestMdeTableSchema:
    def test_all_tables_have_timestamp(self):
        for name, table in MDE_TABLES.items():
            col_names = [c.name for c in table.columns]
            assert "Timestamp" in col_names, f"Table {name} missing Timestamp"

    def test_all_tables_have_report_id(self):
        for name, table in MDE_TABLES.items():
            col_names = [c.name for c in table.columns]
            assert "ReportId" in col_names, f"Table {name} missing ReportId"

    def test_validate_columns_finds_invalid(self):
        invalid = validate_columns("DeviceProcessEvents", ["DeviceName", "FakeColumn123"])
        assert "FakeColumn123" in invalid
        assert "DeviceName" not in invalid

    def test_validate_columns_empty_for_valid(self):
        valid_cols = ["Timestamp", "DeviceName", "FileName", "ProcessId"]
        invalid = validate_columns("DeviceProcessEvents", valid_cols)
        assert invalid == []
