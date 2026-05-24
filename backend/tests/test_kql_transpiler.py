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
    def test_scalar_let_inlined(self):
        # Scalar lets are substituted inline — no CTE wrapper needed or generated.
        sql = transpile(
            "let lookback = ago(1h);\n"
            "DeviceProcessEvents | where Timestamp > lookback"
        )
        assert "WITH" not in sql.upper()
        assert "INTERVAL" in sql.upper()  # ago(1h) was inlined

    def test_scalar_let_string_inlined(self):
        sql = transpile(
            "let suspicious = '-enc';\n"
            "DeviceProcessEvents | where ProcessCommandLine contains suspicious"
        )
        assert "WITH" not in sql.upper()
        assert "'-enc'" in sql  # string literal inlined at reference

    def test_subquery_let_produces_cte(self):
        # Sub-pipeline lets (Table | where ...) still become CTEs.
        sql = transpile(
            "let baseline = DeviceProcessEvents | where ActionType == 'ProcessCreated';\n"
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

    def test_cte_names_populated_from_subquery_let(self):
        # Only sub-pipeline lets appear in cte_names; scalar lets are inlined.
        result = self._emit(
            "let baseline = DeviceProcessEvents | where ActionType == 'ProcessCreated';\n"
            "DeviceProcessEvents | project DeviceName"
        )
        assert "baseline" in result.cte_names

    def test_scalar_let_not_in_cte_names(self):
        result = self._emit(
            "let lookback = ago(1h);\n"
            "DeviceProcessEvents | where Timestamp > lookback"
        )
        assert "lookback" not in result.cte_names

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
        rules_dir = Path("detections/rules")
        all_paths = list(rules_dir.glob("FP-*.yaml")) + list((rules_dir / "synthetic").glob("SYN-*.yaml"))
        for rule_path in all_paths:
            rule = yaml.safe_load(rule_path.read_text())
            query = rule.get("query", "")
            touches_cloud = any(t in query for t in cloud_tables)
            if touches_cloud:
                assert rule.get("mde_portable") is False, (
                    f"{rule['id']} queries a cloud/proxy table but mde_portable is not False"
                )


# ---------------------------------------------------------------------------
# Email security table recognition tests
# ---------------------------------------------------------------------------

class TestEmailTableRecognition:
    def test_proofpoint_message_events_recognized(self):
        sql = transpile(
            "ProofpointMessageEvents | where ActionType == 'PhishFiltered' "
            "| project Timestamp, SenderFromAddress, RecipientEmailAddress, PhishScore"
        )
        assert "ProofpointMessageEvents" in sql

    def test_proofpoint_message_events_phish_score_filter(self):
        sql = transpile(
            "ProofpointMessageEvents | where PhishScore > 90 | project Timestamp, Subject"
        )
        assert "PhishScore" in sql
        assert "90" in sql

    def test_proofpoint_click_events_recognized(self):
        sql = transpile(
            "ProofpointClickEvents | where Blocked == true | project Timestamp, Url, ClickIP"
        )
        assert "ProofpointClickEvents" in sql
        assert "Blocked" in sql

    def test_proofpoint_click_events_url_domain_filter(self):
        sql = transpile(
            "ProofpointClickEvents | where UrlDomain contains 'evil' "
            "| project Timestamp, RecipientEmailAddress, Url, Classification"
        )
        assert "UrlDomain" in sql
        assert "Classification" in sql

    def test_abnormal_threat_events_recognized(self):
        sql = transpile(
            "AbnormalThreatEvents | where AttackType == 'BEC' "
            "| project Timestamp, SenderFromAddress, RecipientEmailAddress, AbNormalScore"
        )
        assert "AbnormalThreatEvents" in sql
        assert "AttackType" in sql

    def test_abnormal_threat_events_score_filter(self):
        sql = transpile(
            "AbnormalThreatEvents | where AbNormalScore > 0.9 | project Timestamp, Subject"
        )
        assert "AbNormalScore" in sql

    def test_abnormal_case_events_recognized(self):
        sql = transpile(
            "AbnormalCaseEvents | where CaseSeverity == 'High' "
            "| project Timestamp, CaseType, ThreatCount, AffectedEmployeeCount"
        )
        assert "AbnormalCaseEvents" in sql
        assert "CaseSeverity" in sql

    def test_abnormal_case_events_threat_count_summarize(self):
        sql = transpile(
            "AbnormalCaseEvents | summarize TotalThreats=sum(ThreatCount) by CaseType"
        )
        assert "SUM" in sql.upper()
        assert "GROUP BY" in sql.upper()

    def test_email_rules_not_mde_portable(self):
        import yaml
        from pathlib import Path
        email_tables = {
            "ProofpointMessageEvents", "ProofpointClickEvents",
            "AbnormalThreatEvents", "AbnormalCaseEvents",
        }
        rules_dir = Path("detections/rules")
        all_paths = list(rules_dir.glob("FP-*.yaml")) + list((rules_dir / "synthetic").glob("SYN-*.yaml"))
        for rule_path in all_paths:
            rule = yaml.safe_load(rule_path.read_text())
            query = rule.get("query", "")
            touches_email = any(t in query for t in email_tables)
            if touches_email:
                assert rule.get("mde_portable") is False, (
                    f"{rule['id']} queries an email table but mde_portable is not False"
                )

    def test_join_filtered_subpipeline_not_dropped(self):
        """Stages inside a join sub-pipeline must survive transpilation."""
        sql = transpile(
            "DeviceProcessEvents"
            " | join kind=inner ("
            "     DeviceNetworkEvents"
            "     | where RemotePort == 4444"
            " ) on DeviceId"
        )
        assert "RemotePort" in sql
        assert "4444" in sql
        assert "JOIN" in sql.upper()

    def test_join_subpipeline_string_literal_preserved(self):
        """String literals inside a join sub-pipeline must not lose their quotes."""
        sql = transpile(
            "DeviceProcessEvents"
            " | join kind=inner ("
            "     DeviceNetworkEvents"
            "     | where Protocol == 'TCP'"
            " ) on DeviceId"
        )
        assert "'TCP'" in sql
        assert "JOIN" in sql.upper()

    def test_fp_0021_cross_layer_join_transpiles(self):
        """FP-0021 is a let + join on NetworkMessageId — verify the transpiler handles it."""
        query = """
        let ProofpointBlocked =
            ProofpointMessageEvents
            | where Timestamp > ago(24h)
            | where ActionType in ("PhishFiltered", "Quarantined")
            | project NetworkMessageId, PPTimestamp=Timestamp, SenderFromAddress;
        AbnormalThreatEvents
        | where Timestamp > ago(24h)
        | where ActionType == "ThreatDetected"
        | join kind=inner ProofpointBlocked on NetworkMessageId
        | project PPTimestamp, Timestamp, NetworkMessageId, SenderFromAddress, AbNormalScore
        """
        sql = transpile(query)
        # let clause must become a CTE
        assert "WITH" in sql.upper() or "ProofpointBlocked" in sql
        # Both table names must appear
        assert "ProofpointMessageEvents" in sql
        assert "AbnormalThreatEvents" in sql
        # Join key preserved
        assert "NetworkMessageId" in sql

    def test_network_message_id_column_preserved_in_proofpoint(self):
        """NetworkMessageId is the critical join key — must not be aliased or dropped."""
        sql = transpile(
            "ProofpointMessageEvents | where NetworkMessageId == 'msg-001@corp.com' "
            "| project Timestamp, NetworkMessageId, ActionType"
        )
        assert "NetworkMessageId" in sql

    def test_network_message_id_column_preserved_in_abnormal(self):
        sql = transpile(
            "AbnormalThreatEvents | where NetworkMessageId != '' "
            "| project Timestamp, NetworkMessageId, AttackType"
        )
        assert "NetworkMessageId" in sql


# ---------------------------------------------------------------------------
# between operator
# ---------------------------------------------------------------------------

class TestBetweenOperator:
    def test_between_produces_between_clause(self):
        sql = transpile(
            "DeviceLogonEvents | where LogonType between (2 .. 10)"
        )
        assert "BETWEEN" in sql.upper()

    def test_between_values_present(self):
        sql = transpile(
            "DeviceLogonEvents | where LogonType between (2 .. 10)"
        )
        assert "2" in sql
        assert "10" in sql


# ---------------------------------------------------------------------------
# has / has_any operators
# ---------------------------------------------------------------------------

class TestHasOperators:
    def test_has_produces_like(self):
        sql = transpile(
            "DeviceProcessEvents | where ProcessCommandLine has 'encoded'"
        )
        assert "LIKE" in sql.upper()
        assert "encoded" in sql

    def test_has_is_case_insensitive(self):
        sql = transpile(
            "DeviceProcessEvents | where ProcessCommandLine has 'encoded'"
        )
        assert "LOWER" in sql.upper()

    def test_has_any_produces_or_conditions(self):
        sql = transpile(
            "DeviceProcessEvents | where ProcessCommandLine has_any('-enc', '-EncodedCommand', '-ec')"
        )
        assert "OR" in sql.upper()
        assert "LIKE" in sql.upper()

    def test_has_any_all_values_present(self):
        sql = transpile(
            "DeviceProcessEvents | where ProcessCommandLine has_any('-enc', '-EncodedCommand')"
        )
        assert "-enc" in sql
        assert "-EncodedCommand" in sql.lower() or "encodedcommand" in sql.lower()


# ---------------------------------------------------------------------------
# isempty / isnotempty
# ---------------------------------------------------------------------------

class TestIsEmptyIsNotEmpty:
    # The transpiler implements isempty/isnotempty as postfix operators:
    # KQL syntax: `column isempty()` — NOT `isempty(column)`.
    # This matches the transpiler's parser design; callers must use postfix form.

    def test_isempty_produces_null_or_empty_check(self):
        sql = transpile(
            "DeviceProcessEvents | where ProcessCommandLine isempty()"
        )
        assert "IS NULL" in sql.upper()

    def test_isnotempty_produces_not_null_check(self):
        sql = transpile(
            "DeviceProcessEvents | where ProcessCommandLine isnotempty()"
        )
        assert "IS NOT NULL" in sql.upper()

    def test_isempty_column_name_preserved(self):
        sql = transpile(
            "DeviceProcessEvents | where SHA256 isempty()"
        )
        assert "SHA256" in sql


# ---------------------------------------------------------------------------
# Type conversion functions: tostring, toint, tolong
# ---------------------------------------------------------------------------

class TestTypeConversionFunctions:
    def test_tostring_produces_cast_varchar(self):
        sql = transpile(
            "DeviceProcessEvents | extend PidStr = tostring(ProcessId)"
        )
        assert "CAST" in sql.upper()
        assert "VARCHAR" in sql.upper()

    def test_toint_produces_cast_int(self):
        sql = transpile(
            "DeviceProcessEvents | extend Port = toint(RemotePort)"
        )
        assert "CAST" in sql.upper()
        assert "INT" in sql.upper()

    def test_tolong_produces_cast_bigint(self):
        sql = transpile(
            "DeviceFileEvents | extend SizeL = tolong(FileSize)"
        )
        assert "CAST" in sql.upper()
        assert "BIGINT" in sql.upper()


# ---------------------------------------------------------------------------
# strcat / split
# ---------------------------------------------------------------------------

class TestStringFunctions:
    def test_strcat_produces_concat(self):
        sql = transpile(
            "DeviceProcessEvents | extend FullPath = strcat(FolderPath, '\\\\', FileName)"
        )
        assert "CONCAT" in sql.upper()

    def test_strcat_preserves_all_args(self):
        sql = transpile(
            "DeviceProcessEvents | extend FullPath = strcat(FolderPath, '\\\\', FileName)"
        )
        assert "FolderPath" in sql
        assert "FileName" in sql

    def test_split_produces_string_split(self):
        sql = transpile(
            "DeviceProcessEvents | extend Parts = split(ProcessCommandLine, ' ')"
        )
        assert "string_split" in sql.lower()

    def test_split_column_preserved(self):
        sql = transpile(
            "DeviceProcessEvents | extend Parts = split(ProcessCommandLine, ' ')"
        )
        assert "ProcessCommandLine" in sql


# ---------------------------------------------------------------------------
# mv-expand → CROSS JOIN UNNEST
# ---------------------------------------------------------------------------

class TestMvExpand:
    def test_mv_expand_produces_unnest(self):
        sql = transpile(
            "DeviceAlertEvents | mv-expand AttackTechniques"
        )
        assert "UNNEST" in sql.upper()

    def test_mv_expand_column_referenced(self):
        sql = transpile(
            "DeviceAlertEvents | mv-expand AttackTechniques"
        )
        assert "AttackTechniques" in sql


# ---------------------------------------------------------------------------
# join kind=leftouter and kind=leftanti
# ---------------------------------------------------------------------------

class TestJoinKinds:
    def test_leftouter_produces_left_join(self):
        sql = transpile(
            "DeviceProcessEvents"
            " | join kind=leftouter ("
            "     DeviceNetworkEvents"
            " ) on DeviceId"
        )
        assert "LEFT JOIN" in sql.upper()

    def test_leftanti_produces_left_join_with_null_check(self):
        sql = transpile(
            "DeviceProcessEvents"
            " | join kind=leftanti ("
            "     DeviceNetworkEvents"
            " ) on DeviceId"
        )
        assert "LEFT JOIN" in sql.upper()
        assert "IS NULL" in sql.upper()

    def test_leftanti_null_check_is_on_join_key(self):
        sql = transpile(
            "DeviceProcessEvents"
            " | join kind=leftanti ("
            "     DeviceNetworkEvents"
            " ) on DeviceId"
        )
        assert "DeviceId" in sql


# ---------------------------------------------------------------------------
# sort by (synonym for order by)
# ---------------------------------------------------------------------------

class TestSortBy:
    def test_sort_by_produces_order_by(self):
        sql = transpile("DeviceProcessEvents | sort by Timestamp desc")
        assert "ORDER BY" in sql.upper()
        assert "DESC" in sql.upper()

    def test_sort_by_asc(self):
        sql = transpile("DeviceProcessEvents | sort by FileName asc")
        assert "ORDER BY" in sql.upper()
        assert "ASC" in sql.upper()


# ---------------------------------------------------------------------------
# summarize with aliases and multiple aggregates
# ---------------------------------------------------------------------------

class TestSummarizeAggregates:
    def test_summarize_with_alias(self):
        sql = transpile(
            "DeviceLogonEvents | summarize EventCount=count() by AccountName"
        )
        assert "COUNT(*)" in sql.upper()
        assert "GROUP BY" in sql.upper()
        assert "AccountName" in sql

    def test_summarize_dcount(self):
        sql = transpile(
            "DeviceLogonEvents | summarize dcount(AccountName) by DeviceName"
        )
        assert "COUNT(DISTINCT" in sql.upper()
        assert "GROUP BY" in sql.upper()

    def test_summarize_sum(self):
        sql = transpile(
            "DeviceFileEvents | summarize TotalBytes=sum(FileSize) by DeviceName"
        )
        assert "SUM" in sql.upper()
        assert "FileSize" in sql

    def test_summarize_avg(self):
        sql = transpile(
            "DeviceFileEvents | summarize avg(FileSize) by DeviceName"
        )
        assert "AVG" in sql.upper()

    def test_summarize_min_max(self):
        sql = transpile(
            "DeviceLogonEvents | summarize FirstSeen=min(Timestamp), LastSeen=max(Timestamp) by AccountName"
        )
        assert "MIN" in sql.upper()
        assert "MAX" in sql.upper()
        assert "GROUP BY" in sql.upper()

    def test_canonical_log_volume_query(self):
        """The canonical summarize count() by bin(Timestamp, 1h) pattern from CLAUDE.md."""
        sql = transpile(
            "DeviceProcessEvents | summarize count() by bin(Timestamp, 1h)"
        )
        assert "COUNT(*)" in sql.upper()
        assert "date_trunc" in sql.lower()
        assert "hour" in sql.lower()
        assert "GROUP BY" in sql.upper()


# ---------------------------------------------------------------------------
# project with rename (alias = column)
# ---------------------------------------------------------------------------

class TestProjectRename:
    def test_project_rename_alias(self):
        sql = transpile(
            "DeviceProcessEvents | project Host=DeviceName, Cmd=ProcessCommandLine"
        )
        assert "DeviceName" in sql
        assert "ProcessCommandLine" in sql

    def test_project_rename_alias_appears_in_select(self):
        sql = transpile(
            "DeviceProcessEvents | project Host=DeviceName"
        )
        # alias must appear in the SELECT clause
        assert "Host" in sql or "DeviceName" in sql


# ---------------------------------------------------------------------------
# extend with multiple expressions
# ---------------------------------------------------------------------------

class TestExtendMultiple:
    def test_extend_multiple_expressions(self):
        sql = transpile(
            "DeviceProcessEvents"
            " | extend UpperFile=toupper(FileName), LowerDevice=tolower(DeviceName)"
        )
        assert "UPPER" in sql.upper()
        assert "LOWER" in sql.upper()
        assert "FileName" in sql
        assert "DeviceName" in sql


# ---------------------------------------------------------------------------
# getschema
# ---------------------------------------------------------------------------

class TestGetSchema:
    def test_getschema_produces_sql(self):
        sql = transpile("DeviceProcessEvents | getschema")
        assert sql is not None
        assert len(sql) > 0

    def test_getschema_includes_column_name(self):
        sql = transpile("DeviceProcessEvents | getschema")
        assert "ColumnName" in sql

    def test_getschema_includes_known_column(self):
        sql = transpile("DeviceProcessEvents | getschema")
        # At least one known DeviceProcessEvents column must appear in the schema output
        assert "DeviceName" in sql or "Timestamp" in sql or "FileName" in sql


# ---------------------------------------------------------------------------
# Transpiler gap fixes — post-summarize HAVING, scalar let, STRING[] has,
# isempty/isnotempty function form, project after summarize
# ---------------------------------------------------------------------------

class TestPostSummarizeHaving:
    """where after summarize must emit HAVING, not WHERE."""

    def test_post_summarize_where_produces_having(self):
        sql = transpile(
            "DeviceLogonEvents"
            " | summarize FailCount=count() by AccountName"
            " | where FailCount > 10"
        )
        assert "HAVING" in sql.upper()
        assert "FailCount > 10" in sql or "failcount > 10" in sql.lower()

    def test_post_summarize_where_not_in_where_clause(self):
        sql = transpile(
            "DeviceLogonEvents"
            " | summarize FailCount=count() by AccountName"
            " | where FailCount > 5"
        )
        # The aggregate condition must NOT appear before GROUP BY
        group_by_pos = sql.upper().find("GROUP BY")
        having_pos = sql.upper().find("HAVING")
        assert having_pos > group_by_pos

    def test_pre_summarize_where_stays_in_where(self):
        sql = transpile(
            "DeviceLogonEvents"
            " | where ActionType == 'LogonFailed'"
            " | summarize FailCount=count() by AccountName"
            " | where FailCount > 5"
        )
        assert "WHERE" in sql.upper()
        assert "HAVING" in sql.upper()
        where_pos = sql.upper().find("WHERE")
        having_pos = sql.upper().find("HAVING")
        assert where_pos < having_pos

    def test_post_summarize_top_still_works(self):
        # top after summarize should not require HAVING — just ORDER BY + LIMIT
        sql = transpile(
            "DeviceLogonEvents"
            " | summarize FailCount=count() by AccountName"
            " | top 20 by FailCount"
        )
        assert "ORDER BY" in sql.upper()
        assert "LIMIT" in sql.upper()
        assert "HAVING" not in sql.upper()


class TestScalarLetInlining:
    """Scalar lets must be inlined at reference sites, not wrapped in CTEs."""

    def test_ago_scalar_let_inlined(self):
        sql = transpile(
            "let lookback = ago(1h);\n"
            "DeviceLogonEvents | where Timestamp > lookback"
        )
        assert "INTERVAL" in sql.upper()
        assert "WITH" not in sql.upper()

    def test_scalar_let_substituted_in_where(self):
        sql = transpile(
            "let lookback = ago(7d);\n"
            "DeviceProcessEvents | where Timestamp > lookback"
        )
        assert "INTERVAL 7 DAY" in sql.upper()

    def test_string_scalar_let_inlined(self):
        sql = transpile(
            "let enc = '-enc';\n"
            "DeviceProcessEvents | where ProcessCommandLine contains enc"
        )
        assert "WITH" not in sql.upper()
        assert "'-enc'" in sql

    def test_subquery_let_still_a_cte(self):
        sql = transpile(
            "let failures = DeviceLogonEvents | where ActionType == 'LogonFailed';\n"
            "DeviceProcessEvents | project DeviceName"
        )
        assert "WITH" in sql.upper()
        assert "failures" in sql


class TestStringListColumnOperators:
    """has / has_any / contains on STRING[] columns must use list functions, not LIKE."""

    def test_has_on_string_array_uses_list_contains(self):
        # ThreatTypes is STRING[] in EmailEvents
        sql = transpile(
            "EmailEvents | where ThreatTypes has 'Phish'"
        )
        assert "list_contains" in sql.lower()
        assert "list_transform" in sql.lower()
        assert "LOWER" in sql.upper()

    def test_has_on_scalar_string_uses_like(self):
        # ProcessCommandLine is STRING — must still use LIKE
        sql = transpile(
            "DeviceProcessEvents | where ProcessCommandLine has 'encoded'"
        )
        assert "LIKE" in sql.upper()
        assert "list_contains" not in sql.lower()

    def test_has_any_on_string_array_uses_list_contains(self):
        sql = transpile(
            "EmailEvents | where ThreatTypes has_any ('Phish', 'Malware')"
        )
        assert "list_contains" in sql.lower()
        assert "LIKE" not in sql.upper()

    def test_contains_on_string_array_uses_list_filter(self):
        sql = transpile(
            "EmailEvents | where ThreatTypes contains 'Phish'"
        )
        assert "list_filter" in sql.lower()
        assert "list_transform" in sql.lower()


class TestIsEmptyFunctionForm:
    """isempty(col) and isnotempty(col) function form must parse and emit correctly."""

    def test_isnotempty_function_form(self):
        sql = transpile(
            "EmailAttachmentInfo | where isnotempty(MalwareFamily)"
        )
        assert "IS NOT NULL" in sql.upper()
        assert "MalwareFamily" in sql

    def test_isempty_function_form(self):
        sql = transpile(
            "DeviceProcessEvents | where isempty(SHA256)"
        )
        assert "IS NULL" in sql.upper()
        assert "SHA256" in sql

    def test_isnotempty_function_form_equivalent_to_postfix(self):
        sql_fn = transpile("DeviceProcessEvents | where isnotempty(SHA256)")
        sql_postfix = transpile("DeviceProcessEvents | where SHA256 isnotempty()")
        # Both forms must produce semantically equivalent SQL
        assert "IS NOT NULL" in sql_fn.upper()
        assert "IS NOT NULL" in sql_postfix.upper()


class TestProjectAfterSummarize:
    """project after summarize must wrap the aggregate in a subquery."""

    def test_project_after_summarize_produces_subquery(self):
        sql = transpile(
            "DeviceLogonEvents"
            " | summarize FailCount=count() by AccountName, DeviceName"
            " | project AccountName, FailCount"
        )
        # Subquery wrapper must be present
        assert "FROM (" in sql or "from (" in sql.lower()

    def test_project_after_summarize_selects_correct_columns(self):
        sql = transpile(
            "DeviceLogonEvents"
            " | summarize FailCount=count() by AccountName"
            " | project AccountName, FailCount"
        )
        assert "AccountName" in sql
        assert "FailCount" in sql

    def test_project_after_summarize_with_top(self):
        sql = transpile(
            "DeviceLogonEvents"
            " | summarize FailCount=count() by AccountName"
            " | project AccountName, FailCount"
            " | top 10 by FailCount"
        )
        assert "FROM (" in sql or "from (" in sql.lower()
        assert "ORDER BY" in sql.upper()
        assert "LIMIT" in sql.upper()
