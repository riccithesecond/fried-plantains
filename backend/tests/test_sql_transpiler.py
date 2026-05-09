"""Tests for the SQL passthrough validator."""

import pytest

from backend.engine.sql_transpiler import SqlValidator
from backend.exceptions import QueryException


class TestSqlValidation:
    def test_valid_select_passes(self):
        sql = SqlValidator.validate("SELECT DeviceName FROM DeviceProcessEvents LIMIT 10")
        assert "DeviceName" in sql

    def test_drop_rejected(self):
        with pytest.raises(QueryException):
            SqlValidator.validate("DROP TABLE DeviceProcessEvents")

    def test_delete_rejected(self):
        with pytest.raises(QueryException):
            SqlValidator.validate("DELETE FROM DeviceProcessEvents")

    def test_insert_rejected(self):
        with pytest.raises(QueryException):
            SqlValidator.validate("INSERT INTO DeviceProcessEvents VALUES ('x')")

    def test_update_rejected(self):
        with pytest.raises(QueryException):
            SqlValidator.validate("UPDATE DeviceProcessEvents SET DeviceName = 'evil'")

    def test_create_rejected(self):
        with pytest.raises(QueryException):
            SqlValidator.validate("CREATE TABLE evil AS SELECT * FROM DeviceProcessEvents")

    def test_unknown_table_rejected(self):
        with pytest.raises(QueryException):
            SqlValidator.validate("SELECT * FROM nonexistent_table")

    def test_cte_select_passes(self):
        sql = SqlValidator.validate(
            "WITH base AS (SELECT * FROM DeviceProcessEvents) "
            "SELECT DeviceName FROM base"
        )
        assert "DeviceName" in sql

    def test_window_function_passes(self):
        sql = SqlValidator.validate(
            "SELECT DeviceName, ROW_NUMBER() OVER (PARTITION BY DeviceName ORDER BY Timestamp) "
            "FROM DeviceProcessEvents"
        )
        assert sql is not None
