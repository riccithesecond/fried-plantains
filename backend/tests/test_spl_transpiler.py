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
