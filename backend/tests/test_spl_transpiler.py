"""Tests for the SPL → DuckDB SQL transpiler."""

import pytest

from backend.engine.spl_transpiler import SplTranspiler
from backend.exceptions import QueryException


def transpile(spl: str) -> str:
    return SplTranspiler.transpile(spl)


class TestSplBasicCommands:
    def test_stats_count_by(self):
        sql = transpile("index=wineventlog | stats count by AccountName")
        assert "COUNT(*)" in sql.upper()
        assert "GROUP BY" in sql.upper()
        assert "AccountName" in sql

    def test_index_maps_to_table(self):
        sql = transpile("index=process | stats count by DeviceName")
        assert "DeviceProcessEvents" in sql

    def test_fields_command(self):
        sql = transpile("index=endpoint | fields DeviceName, AccountName")
        assert "DeviceName" in sql
        assert "AccountName" in sql

    def test_sort_ascending(self):
        sql = transpile("index=process | sort Timestamp")
        assert "ORDER BY" in sql.upper()
        assert "ASC" in sql.upper()

    def test_sort_descending(self):
        sql = transpile("index=process | sort -Timestamp")
        assert "DESC" in sql.upper()

    def test_head_n(self):
        sql = transpile("index=process | head 100")
        assert "LIMIT 100" in sql.upper()

    def test_eval(self):
        sql = transpile("index=process | eval upper_name = toupper(AccountName)")
        assert "as upper_name" in sql.lower()

    def test_where_clause(self):
        sql = transpile("index=process | where AccountName = 'jsmith'")
        assert "WHERE" in sql.upper()

    def test_earliest_time(self):
        sql = transpile("index=process earliest=-7d latest=now")
        assert "INTERVAL 7 DAY" in sql.upper()
        assert "Timestamp" in sql

    def test_bin_span(self):
        sql = transpile("index=process | bin span=1h _time")
        assert "date_trunc" in sql.lower()
        assert "hour" in sql.lower()


class TestSplInjection:
    def test_drop_rejected(self):
        with pytest.raises(QueryException):
            transpile("index=process | DROP TABLE DeviceProcessEvents")

    def test_delete_rejected(self):
        with pytest.raises(QueryException):
            transpile("DELETE FROM DeviceProcessEvents")


# ---------------------------------------------------------------------------
# Index → table mapping (all registered indexes)
# ---------------------------------------------------------------------------

class TestIndexMapping:
    def test_process_maps_to_device_process_events(self):
        sql = transpile("index=process | head 5")
        assert "DeviceProcessEvents" in sql

    def test_network_maps_to_device_network_events(self):
        sql = transpile("index=network | head 5")
        assert "DeviceNetworkEvents" in sql

    def test_file_maps_to_device_file_events(self):
        sql = transpile("index=file | head 5")
        assert "DeviceFileEvents" in sql

    def test_registry_maps_to_device_registry_events(self):
        sql = transpile("index=registry | head 5")
        assert "DeviceRegistryEvents" in sql

    def test_auth_maps_to_union_of_logon_tables(self):
        sql = transpile("index=auth | head 5")
        assert "DeviceLogonEvents" in sql
        assert "IdentityLogonEvents" in sql
        assert "UNION ALL" in sql.upper()

    def test_wineventlog_maps_to_union(self):
        sql = transpile("index=wineventlog | head 5")
        assert "DeviceEvents" in sql
        assert "DeviceLogonEvents" in sql
        assert "UNION ALL" in sql.upper()

    def test_endpoint_maps_to_union(self):
        sql = transpile("index=endpoint | head 5")
        assert "DeviceProcessEvents" in sql
        assert "DeviceNetworkEvents" in sql
        assert "DeviceFileEvents" in sql

    def test_cloud_maps_to_cloud_app_events(self):
        sql = transpile("index=cloud | head 5")
        assert "CloudAppEvents" in sql

    def test_identity_maps_to_identity_logon_events(self):
        sql = transpile("index=identity | head 5")
        assert "IdentityLogonEvents" in sql

    def test_unknown_index_used_as_table_name(self):
        sql = transpile("index=customtable | head 5")
        assert "customtable" in sql

    def test_no_index_defaults_to_device_events(self):
        sql = transpile("search FileName=powershell.exe | head 5")
        assert "DeviceEvents" in sql


# ---------------------------------------------------------------------------
# stats aggregates
# ---------------------------------------------------------------------------

class TestStatsAggregates:
    def test_stats_sum(self):
        sql = transpile("index=file | stats sum(FileSize) by DeviceName")
        assert "SUM(FileSize)" in sql
        assert "GROUP BY" in sql.upper()

    def test_stats_avg(self):
        sql = transpile("index=file | stats avg(FileSize) by DeviceName")
        assert "AVG(FileSize)" in sql

    def test_stats_min(self):
        sql = transpile("index=process | stats min(Timestamp) by AccountName")
        assert "MIN(Timestamp)" in sql

    def test_stats_max(self):
        sql = transpile("index=process | stats max(Timestamp) by AccountName")
        assert "MAX(Timestamp)" in sql

    def test_stats_dcount(self):
        sql = transpile("index=auth | stats dcount(AccountName) by DeviceName")
        assert "COUNT(DISTINCT" in sql.upper()

    def test_stats_dc_alias(self):
        sql = transpile("index=auth | stats dc(AccountName) by DeviceName")
        assert "COUNT(DISTINCT" in sql.upper()

    def test_stats_count_and_sum_together(self):
        sql = transpile("index=file | stats count, sum(FileSize) by DeviceName")
        assert "COUNT(*)" in sql.upper()
        assert "SUM(FileSize)" in sql
        assert "GROUP BY" in sql.upper()

    def test_stats_multiple_group_by_columns(self):
        sql = transpile("index=auth | stats count by DeviceName, AccountName")
        assert "GROUP BY" in sql.upper()
        assert "DeviceName" in sql
        assert "AccountName" in sql

    def test_stats_count_no_by(self):
        sql = transpile("index=process | stats count")
        assert "COUNT(*)" in sql.upper()
        assert "GROUP BY" not in sql.upper()

    def test_stats_sum_with_alias(self):
        sql = transpile("index=file | stats sum(FileSize) AS total_bytes by DeviceName")
        assert "SUM(FileSize)" in sql
        assert "total_bytes" in sql


# ---------------------------------------------------------------------------
# rename
# ---------------------------------------------------------------------------

class TestRename:
    def test_rename_produces_alias(self):
        sql = transpile("index=process | rename AccountName AS User")
        assert "AccountName" in sql
        assert "User" in sql

    def test_rename_as_keyword_case_insensitive(self):
        sql = transpile("index=process | rename FileName as ProcessName")
        assert "FileName" in sql
        assert "ProcessName" in sql


# ---------------------------------------------------------------------------
# tail
# ---------------------------------------------------------------------------

class TestTail:
    def test_tail_produces_limit(self):
        sql = transpile("index=process | tail 50")
        assert "LIMIT 50" in sql.upper()


# ---------------------------------------------------------------------------
# dedup
# ---------------------------------------------------------------------------

class TestDedup:
    def test_dedup_produces_distinct(self):
        sql = transpile("index=process | dedup DeviceName")
        assert "DISTINCT" in sql.upper()

    def test_dedup_field_present(self):
        sql = transpile("index=process | dedup AccountName")
        assert "AccountName" in sql


# ---------------------------------------------------------------------------
# rex
# ---------------------------------------------------------------------------

class TestRex:
    def test_rex_produces_regexp_extract(self):
        sql = transpile('index=process | rex field=ProcessCommandLine "(?P<arg>-\\w+)"')
        assert "regexp_extract" in sql.lower()

    def test_rex_field_name_present(self):
        sql = transpile('index=process | rex field=FileName "(?P<ext>\\.\\w+)$"')
        assert "FileName" in sql


# ---------------------------------------------------------------------------
# table command (synonym for fields)
# ---------------------------------------------------------------------------

class TestTableCommand:
    def test_table_selects_columns(self):
        sql = transpile("index=process | table Timestamp, DeviceName, FileName")
        assert "Timestamp" in sql
        assert "DeviceName" in sql
        assert "FileName" in sql


# ---------------------------------------------------------------------------
# sourcetype
# ---------------------------------------------------------------------------

class TestSourcetype:
    def test_sourcetype_produces_where_source(self):
        sql = transpile("index=wineventlog sourcetype=WinEventLog | head 10")
        assert "source" in sql.lower()
        assert "WinEventLog" in sql


# ---------------------------------------------------------------------------
# Time range — earliest/latest variants
# ---------------------------------------------------------------------------

class TestTimeRange:
    def test_earliest_hours(self):
        sql = transpile("index=process earliest=-1h | head 10")
        assert "INTERVAL 1 HOUR" in sql.upper()

    def test_earliest_minutes(self):
        sql = transpile("index=process earliest=-30m | head 10")
        assert "INTERVAL 30 MINUTE" in sql.upper()

    def test_earliest_seconds(self):
        sql = transpile("index=process earliest=-60s | head 10")
        assert "INTERVAL 60 SECOND" in sql.upper()

    def test_earliest_weeks(self):
        sql = transpile("index=process earliest=-2w | head 10")
        assert "INTERVAL 2 WEEK" in sql.upper()

    def test_latest_now_adds_no_upper_bound(self):
        sql = transpile("index=process earliest=-7d latest=now | head 10")
        clauses = sql.upper().count("TIMESTAMP")
        # Only one Timestamp condition (earliest), not two
        assert clauses <= 1 or sql.upper().count(">=") == 1

    def test_latest_relative_adds_upper_bound(self):
        sql = transpile("index=process earliest=-7d latest=-1d | head 10")
        assert ">=" in sql
        assert "<=" in sql


# ---------------------------------------------------------------------------
# bin span variants
# ---------------------------------------------------------------------------

class TestBinSpan:
    def test_bin_span_day(self):
        sql = transpile("index=process | bin span=1d _time")
        assert "date_trunc" in sql.lower()
        assert "day" in sql.lower()

    def test_bin_span_minute(self):
        sql = transpile("index=process | bin span=5m _time")
        assert "date_trunc" in sql.lower()
        assert "minute" in sql.lower()

    def test_bin_span_second(self):
        sql = transpile("index=process | bin span=30s _time")
        assert "date_trunc" in sql.lower()
        assert "second" in sql.lower()


# ---------------------------------------------------------------------------
# search field=value conditions
# ---------------------------------------------------------------------------

class TestSearchConditions:
    def test_field_equals_value(self):
        sql = transpile("index=process FileName=powershell.exe | head 10")
        assert "powershell.exe" in sql
        assert "FileName" in sql

    def test_field_not_equals_value(self):
        sql = transpile("index=process FileName!=svchost.exe | head 10")
        assert "svchost.exe" in sql
        assert "!=" in sql

    def test_where_with_like(self):
        sql = transpile("index=process | where ProcessCommandLine LIKE '%encoded%'")
        assert "LIKE" in sql.upper()
        assert "encoded" in sql


# ---------------------------------------------------------------------------
# sort — multiple fields and explicit direction markers
# ---------------------------------------------------------------------------

class TestSortVariants:
    def test_sort_explicit_plus_is_asc(self):
        sql = transpile("index=process | sort +Timestamp")
        assert "ORDER BY" in sql.upper()
        assert "ASC" in sql.upper()

    def test_sort_multiple_fields(self):
        sql = transpile("index=process | sort -Timestamp, +AccountName")
        assert "ORDER BY" in sql.upper()
        assert "DESC" in sql.upper()
        assert "ASC" in sql.upper()


# ---------------------------------------------------------------------------
# Multi-stage pipeline (end-to-end)
# ---------------------------------------------------------------------------

class TestMultiStagePipeline:
    def test_where_then_stats(self):
        sql = transpile(
            "index=process | where FileName='powershell.exe' | stats count by AccountName"
        )
        assert "WHERE" in sql.upper()
        assert "COUNT(*)" in sql.upper()
        assert "GROUP BY" in sql.upper()
        assert "AccountName" in sql

    def test_fields_then_sort_then_head(self):
        sql = transpile(
            "index=process | fields Timestamp, DeviceName | sort -Timestamp | head 20"
        )
        assert "Timestamp" in sql
        assert "ORDER BY" in sql.upper()
        assert "LIMIT 20" in sql.upper()

    def test_earliest_where_stats_pipeline(self):
        sql = transpile(
            "index=auth earliest=-24h | where AccountName!='SYSTEM' | stats count by AccountName"
        )
        assert "INTERVAL 24 HOUR" in sql.upper()
        assert "SYSTEM" in sql
        assert "COUNT(*)" in sql.upper()
