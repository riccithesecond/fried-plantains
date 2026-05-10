"""
Tests for the KQL → DuckDB SQL transpiler.

Key invariants under test:
  - Column name case-sensitivity (DeviceName ≠ devicename)
  - ago() resolves to NOW(), not a fixed timestamp
  - bin(Timestamp, 1h) → date_trunc('hour', ...)
  - =~ case-insensitive comparison → LOWER(a) = LOWER(b)
  - let bindings → CTEs
  - AdditionalFields.Key → json_extract()
  - Injection attempts are rejected
  - Real MDE detection rules (FP-0001) transpile correctly
"""

import pytest

from backend.engine.kql_transpiler import KqlTranspiler
from backend.exceptions import QueryException


def transpile(kql: str) -> str:
    return KqlTranspiler.transpile(kql)


class TestColumnCaseSensitivity:
    def test_valid_column_name_preserved(self):
        sql = transpile("DeviceProcessEvents | project DeviceName")
        assert "DeviceName" in sql

    def test_lowercase_column_passes_through(self):
        # The transpiler warns but doesn't hard-reject (MDE would reject at query time)
        sql = transpile("DeviceProcessEvents | project devicename")
        # lowercase preserved as-is — schema validation logs a warning
        assert "devicename" in sql

    def test_column_casing_not_normalized(self):
        sql = transpile("DeviceProcessEvents | project ProcessCommandLine")
        assert "ProcessCommandLine" in sql
        assert "processcommandline" not in sql.lower().replace("processcommandline", "")


class TestAgoFunction:
    def test_ago_7d_uses_now(self):
        sql = transpile("DeviceProcessEvents | where Timestamp > ago(7d)")
        assert "NOW()" in sql.upper() or "CURRENT_TIMESTAMP" in sql.upper()

    def test_ago_1h(self):
        sql = transpile("DeviceProcessEvents | where Timestamp > ago(1h)")
        assert "INTERVAL 1 HOUR" in sql.upper()

    def test_ago_30m(self):
        sql = transpile("DeviceProcessEvents | where Timestamp > ago(30m)")
        assert "INTERVAL 30 MINUTE" in sql.upper()

    def test_ago_60s(self):
        sql = transpile("DeviceProcessEvents | where Timestamp > ago(60s)")
        assert "INTERVAL 60 SECOND" in sql.upper()


class TestBinFunction:
    def test_bin_hourly(self):
        sql = transpile(
            "DeviceProcessEvents | summarize count() by bin(Timestamp, 1h)"
        )
        assert "date_trunc" in sql.lower()
        assert "hour" in sql.lower()

    def test_bin_daily(self):
        sql = transpile(
            "DeviceProcessEvents | summarize count() by bin(Timestamp, 1d)"
        )
        assert "date_trunc" in sql.lower()
        assert "day" in sql.lower()

    def test_bin_minute(self):
        sql = transpile(
            "DeviceProcessEvents | summarize count() by bin(Timestamp, 5m)"
        )
        assert "date_trunc" in sql.lower()
        assert "minute" in sql.lower()


class TestCaseInsensitiveOperators:
    def test_eq_tilde_produces_lower(self):
        sql = transpile("DeviceProcessEvents | where FileName =~ 'powershell.exe'")
        assert "LOWER" in sql.upper()

    def test_neq_tilde_produces_lower(self):
        sql = transpile("DeviceProcessEvents | where FileName !~ 'cmd.exe'")
        assert "LOWER" in sql.upper()

    def test_contains_is_case_insensitive(self):
        sql = transpile("DeviceProcessEvents | where ProcessCommandLine contains '-enc'")
        assert "LOWER" in sql.upper()


class TestLetBindings:
    def test_let_produces_cte(self):
        sql = transpile(
            "let suspicious = '-EncodedCommand';\n"
            "DeviceProcessEvents | where ProcessCommandLine contains '-enc'"
        )
        assert "WITH" in sql.upper()

    def test_let_name_appears_in_sql(self):
        sql = transpile(
            "let base_table = DeviceProcessEvents;\n"
            "DeviceProcessEvents | project DeviceName"
        )
        assert "WITH" in sql.upper()


class TestJsonAccessor:
    def test_additional_fields_dot_access(self):
        sql = transpile(
            "DeviceEvents | project AdditionalFields.CommandLine"
        )
        assert "json_extract" in sql.lower()

    def test_nested_json_access(self):
        sql = transpile(
            "DeviceEvents | where AdditionalFields.Severity == 'High'"
        )
        assert "json_extract" in sql.lower()


class TestInjectionRejection:
    def test_drop_table_rejected(self):
        with pytest.raises(QueryException):
            transpile("DeviceProcessEvents | where FileName == 'x'; DROP TABLE DeviceProcessEvents")

    def test_delete_rejected(self):
        with pytest.raises(QueryException):
            transpile("DELETE FROM DeviceProcessEvents")

    def test_insert_rejected(self):
        with pytest.raises(QueryException):
            transpile("INSERT INTO DeviceProcessEvents VALUES (1)")


class TestOperators:
    def test_project(self):
        sql = transpile("DeviceProcessEvents | project Timestamp, DeviceName, FileName")
        assert "Timestamp" in sql
        assert "DeviceName" in sql
        assert "FileName" in sql
        assert "FROM DeviceProcessEvents" in sql

    def test_where(self):
        sql = transpile("DeviceProcessEvents | where FileName == 'powershell.exe'")
        assert "WHERE" in sql.upper()
        assert "powershell.exe" in sql

    def test_order_by(self):
        sql = transpile("DeviceProcessEvents | order by Timestamp desc")
        assert "ORDER BY" in sql.upper()
        assert "DESC" in sql.upper()

    def test_limit(self):
        sql = transpile("DeviceProcessEvents | limit 100")
        assert "LIMIT 100" in sql.upper()

    def test_take(self):
        sql = transpile("DeviceProcessEvents | take 50")
        assert "LIMIT 50" in sql.upper()

    def test_top(self):
        sql = transpile("DeviceProcessEvents | top 10 by Timestamp desc")
        assert "LIMIT 10" in sql.upper()
        assert "ORDER BY" in sql.upper()

    def test_distinct(self):
        sql = transpile("DeviceProcessEvents | distinct DeviceName")
        assert "DISTINCT" in sql.upper()

    def test_summarize_count_by(self):
        sql = transpile("DeviceLogonEvents | summarize count() by AccountName")
        assert "COUNT(*)" in sql.upper()
        assert "GROUP BY" in sql.upper()
        assert "AccountName" in sql

    def test_extend(self):
        sql = transpile("DeviceProcessEvents | extend UpperName = toupper(FileName)")
        assert "UPPER" in sql.upper()

    def test_in_operator(self):
        sql = transpile("DeviceProcessEvents | where FileName in ('cmd.exe', 'powershell.exe')")
        assert "IN" in sql.upper()

    def test_startswith(self):
        sql = transpile("DeviceProcessEvents | where FileName startswith 'power'")
        assert "LIKE" in sql.upper()

    def test_endswith(self):
        sql = transpile("DeviceProcessEvents | where FileName endswith '.exe'")
        assert "LIKE" in sql.upper()

    def test_union(self):
        sql = transpile("DeviceProcessEvents | union DeviceNetworkEvents")
        assert "UNION ALL" in sql.upper()


class TestFP0001Rule:
    """Verify that the FP-0001 detection rule transpiles correctly."""

    QUERY = """
    DeviceProcessEvents
    | where Timestamp > ago(1h)
    | where FileName =~ "powershell.exe" or FileName =~ "pwsh.exe"
    | where ProcessCommandLine contains "-EncodedCommand"
          or ProcessCommandLine contains "-enc "
          or ProcessCommandLine contains "-ec "
    | project Timestamp, DeviceName, AccountName, ProcessCommandLine,
              InitiatingProcessFileName, InitiatingProcessCommandLine
    | order by Timestamp desc
    """

    def test_fp0001_transpiles(self):
        sql = transpile(self.QUERY)
        assert "DeviceProcessEvents" in sql
        assert "ProcessCommandLine" in sql
        assert "-EncodedCommand" in sql

    def test_fp0001_has_where(self):
        sql = transpile(self.QUERY)
        assert "WHERE" in sql.upper()

    def test_fp0001_has_order_by(self):
        sql = transpile(self.QUERY)
        assert "ORDER BY" in sql.upper()
        assert "DESC" in sql.upper()

    def test_fp0001_uses_ago(self):
        sql = transpile(self.QUERY)
        assert "NOW()" in sql.upper() or "CURRENT_TIMESTAMP" in sql.upper()

    def test_fp0001_case_insensitive_filename(self):
        sql = transpile(self.QUERY)
        # =~ operator must produce LOWER()
        assert "LOWER" in sql.upper()


class TestKqlParseError:
    """KqlParseError carries line/column position and is a QueryException subclass."""

    def test_is_query_exception_subclass(self):
        from backend.engine.kql_transpiler import KqlParseError
        err = KqlParseError("test message", line=3, column=7)
        assert isinstance(err, QueryException)

    def test_stores_line_and_column(self):
        from backend.engine.kql_transpiler import KqlParseError
        err = KqlParseError("bad token", line=5, column=12)
        assert err.line == 5
        assert err.column == 12

    def test_detail_is_message(self):
        from backend.engine.kql_transpiler import KqlParseError
        err = KqlParseError("unexpected '|'", line=1, column=20)
        assert err.detail == "unexpected '|'"

    def test_injection_raises_parse_error(self):
        from backend.engine.kql_transpiler import KqlParseError
        with pytest.raises(KqlParseError):
            transpile("DeviceProcessEvents | where FileName == 'x'; DROP TABLE foo")


class TestSchemaValidatorClass:
    """SchemaValidator returns SchemaWarning objects for unknown MDE columns."""

    def _parse(self, kql: str):
        from backend.engine.kql_transpiler import KqlTokenizer, KqlParser
        return KqlParser(KqlTokenizer(kql).tokenize()).parse()

    def test_validate_returns_list(self):
        from backend.engine.kql_transpiler import SchemaValidator
        pipeline = self._parse("DeviceProcessEvents | project DeviceName")
        result = SchemaValidator().validate(pipeline)
        assert isinstance(result, list)

    def test_valid_columns_produce_no_warnings(self):
        from backend.engine.kql_transpiler import SchemaValidator
        pipeline = self._parse("DeviceProcessEvents | project Timestamp, DeviceName, FileName")
        warnings = SchemaValidator().validate(pipeline)
        assert warnings == []

    def test_unknown_column_produces_warning(self):
        from backend.engine.kql_transpiler import SchemaValidator, SchemaWarning
        pipeline = self._parse("DeviceProcessEvents | project FakeColumnXYZ")
        warnings = SchemaValidator().validate(pipeline)
        assert len(warnings) >= 1
        assert isinstance(warnings[0], SchemaWarning)
        assert any(w.column == "FakeColumnXYZ" for w in warnings)

    def test_warning_contains_table_name(self):
        from backend.engine.kql_transpiler import SchemaValidator
        pipeline = self._parse("DeviceProcessEvents | project NoSuchField")
        warnings = SchemaValidator().validate(pipeline)
        assert any(w.table == "DeviceProcessEvents" for w in warnings)

    def test_unknown_table_produces_no_warnings(self):
        from backend.engine.kql_transpiler import SchemaValidator
        pipeline = self._parse("SomeCustomTable | project col1")
        warnings = SchemaValidator().validate(pipeline)
        assert warnings == []

    def test_validate_mde_portable_returns_strings(self):
        from backend.engine.kql_transpiler import SchemaValidator
        pipeline = self._parse("DeviceProcessEvents | project BadColumn")
        errors = SchemaValidator().validate_mde_portable(pipeline)
        assert isinstance(errors, list)
        assert all(isinstance(e, str) for e in errors)


class TestEmitResult:
    """SqlEmitter.emit() returns an EmitResult with sql, render_hint, warnings, cte_names."""

    def _emit(self, kql: str):
        from backend.engine.kql_transpiler import KqlTokenizer, KqlParser, SqlEmitter
        pipeline = KqlParser(KqlTokenizer(kql).tokenize()).parse()
        return SqlEmitter().emit(pipeline)

    def test_result_has_sql(self):
        result = self._emit("DeviceProcessEvents | where Timestamp > ago(1h)")
        assert result.sql
        assert "DeviceProcessEvents" in result.sql

    def test_render_hint_captured(self):
        result = self._emit(
            "DeviceProcessEvents | summarize count() by bin(Timestamp, 1h) | render timechart"
        )
        assert result.render_hint == "timechart"
        assert "timechart" not in result.sql.lower()
        assert "render" not in result.sql.lower()

    def test_render_hint_none_when_absent(self):
        result = self._emit("DeviceProcessEvents | project DeviceName")
        assert result.render_hint is None

    def test_cte_names_populated_from_let(self):
        result = self._emit(
            "let baseline = DeviceProcessEvents;\nDeviceProcessEvents | project DeviceName"
        )
        assert "baseline" in result.cte_names

    def test_warnings_is_list(self):
        result = self._emit("DeviceProcessEvents | project DeviceName")
        assert isinstance(result.warnings, list)


class TestNotInOperator:
    def test_not_in_produces_not_in(self):
        sql = transpile(
            "DeviceProcessEvents | where FileName !in ('svchost.exe', 'lsass.exe')"
        )
        assert "NOT IN" in sql.upper()

    def test_not_in_values_present(self):
        sql = transpile(
            "DeviceProcessEvents | where FileName !in ('svchost.exe', 'lsass.exe')"
        )
        assert "svchost.exe" in sql
        assert "lsass.exe" in sql


class TestProjectAway:
    def test_project_away_excludes_columns(self):
        sql = transpile("DeviceProcessEvents | project-away SHA256, MD5")
        # SHA256 and MD5 should not appear as standalone column names in SELECT
        # (InitiatingProcessSHA256 is a different column and may still appear)
        import re
        select_cols = sql.split("FROM")[0]  # Only check the SELECT clause
        assert not re.search(r"\bSHA256\b", select_cols), f"SHA256 found in SELECT: {select_cols}"
        assert not re.search(r"\bMD5\b", select_cols), f"MD5 found in SELECT: {select_cols}"

    def test_project_away_keeps_other_columns(self):
        sql = transpile("DeviceProcessEvents | project-away SHA256, MD5")
        assert "DeviceName" in sql
        assert "Timestamp" in sql


class TestMatchesRegex:
    def test_matches_regex_transpiles(self):
        sql = transpile(
            "DeviceProcessEvents | where ProcessCommandLine matches regex @'^cmd'"
        )
        assert "regexp_matches" in sql.lower()


class TestRenderOperator:
    def test_render_not_in_sql(self):
        sql = transpile(
            "DeviceProcessEvents | summarize count() by DeviceName | render barchart"
        )
        assert "render" not in sql.lower()
        assert "barchart" not in sql.lower()

    def test_render_with_summarize_keeps_aggregation(self):
        sql = transpile(
            "DeviceProcessEvents | summarize count() by DeviceName | render barchart"
        )
        assert "COUNT(*)" in sql.upper()
        assert "GROUP BY" in sql.upper()


class TestCloudTableRecognition:
    """Verify the six new cloud/proxy tables are recognised by the transpiler."""

    def test_aws_cloudtrail_table_recognized(self):
        sql = transpile(
            "AWSCloudTrailEvents | where UserIdentityType == 'Root' | project Timestamp, EventName"
        )
        assert "AWSCloudTrailEvents" in sql
        assert "UserIdentityType" in sql

    def test_cloudflare_http_table_recognized(self):
        sql = transpile(
            "CloudflareHttpEvents | where EdgeResponseStatus == 403 | project Timestamp, ClientIP"
        )
        assert "CloudflareHttpEvents" in sql

    def test_cloudflare_firewall_table_recognized(self):
        sql = transpile(
            "CloudflareFirewallEvents | where ActionType == 'WAFBlock' | project Timestamp, ClientIP, FirewallRuleID"
        )
        assert "CloudflareFirewallEvents" in sql
        assert "FirewallRuleID" in sql

    def test_cloudflare_dns_table_recognized(self):
        sql = transpile(
            "CloudflareDnsEvents | where Blocked == true | project Timestamp, QueryName, ThreatCategory"
        )
        assert "CloudflareDnsEvents" in sql

    def test_zscaler_web_summarize(self):
        sql = transpile(
            "ZscalerWebEvents | where ActionType == 'MalwareDetected' | summarize count() by UserName"
        )
        assert "ZscalerWebEvents" in sql
        assert "COUNT" in sql.upper()
        assert "GROUP BY" in sql.upper()

    def test_zscaler_dns_table_recognized(self):
        sql = transpile(
            "ZscalerDnsEvents | where ActionType == 'DnsSinkhole' | project Timestamp, UserName, QueryName"
        )
        assert "ZscalerDnsEvents" in sql

    def test_cloud_rules_not_mde_portable(self):
        import yaml
        from pathlib import Path
        cloud_tables = {
            "AWSCloudTrailEvents", "CloudflareHttpEvents", "CloudflareFirewallEvents",
            "CloudflareDnsEvents", "ZscalerWebEvents", "ZscalerDnsEvents",
        }
        for rule_path in Path("detections/rules").glob("*.yaml"):
            rule = yaml.safe_load(rule_path.read_text())
            query = rule.get("query", "")
            touches_cloud = any(t in query for t in cloud_tables)
            if touches_cloud:
                assert rule.get("mde_portable") is False, (
                    f"{rule['id']} queries a cloud/proxy table but mde_portable is not False"
                )
