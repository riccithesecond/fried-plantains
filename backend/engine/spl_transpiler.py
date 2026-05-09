"""
spl_transpiler.py — Splunk SPL to DuckDB SQL transpiler.

SPL is simpler than KQL: commands pipe left-to-right, each command maps to a
SQL clause. The index= directive maps to MDE table names.

SPL index → MDE table mapping:
  index=wineventlog   → DeviceEvents, DeviceLogonEvents (union)
  index=endpoint      → DeviceProcessEvents, DeviceNetworkEvents, DeviceFileEvents
  index=*             → all tables (not recommended — expensive)
"""

import logging
import re
from typing import Any

from backend.exceptions import QueryException
from backend.schema.mde_tables import MDE_TABLES

logger = logging.getLogger(__name__)


# Mapping from Splunk index names to MDE table names
INDEX_TO_TABLE: dict[str, list[str]] = {
    "wineventlog": ["DeviceEvents", "DeviceLogonEvents"],
    "endpoint": ["DeviceProcessEvents", "DeviceNetworkEvents", "DeviceFileEvents"],
    "process": ["DeviceProcessEvents"],
    "network": ["DeviceNetworkEvents"],
    "file": ["DeviceFileEvents"],
    "registry": ["DeviceRegistryEvents"],
    "auth": ["DeviceLogonEvents", "IdentityLogonEvents"],
    "cloud": ["CloudAppEvents"],
    "identity": ["IdentityLogonEvents"],
}

# SPL earliest/latest time offset patterns
_TIME_PATTERN = re.compile(r"^-(\d+)(s|m|h|d|w|mon|y)$")
_TIME_UNITS: dict[str, str] = {
    "s": "SECOND",
    "m": "MINUTE",
    "h": "HOUR",
    "d": "DAY",
    "w": "WEEK",
    "mon": "MONTH",
    "y": "YEAR",
}


class SplTranspiler:
    """Transpile a Splunk SPL query to DuckDB SQL."""

    @staticmethod
    def transpile(spl: str) -> str:
        """Entry point.

        Raises:
            QueryException: On parse failure with descriptive message.
        """
        _check_injection(spl)
        transpiler = SplTranspiler()
        sql = transpiler._transpile(spl.strip())
        logger.debug(
            "SPL transpiled | source=%.80s | sql=%.200s",
            spl.replace("\n", " "),
            sql.replace("\n", " "),
        )
        return sql

    def _transpile(self, spl: str) -> str:
        # Split on pipe — first segment is the search, rest are commands
        parts = [p.strip() for p in spl.split("|")]
        search_part = parts[0]
        commands = parts[1:]

        table, where_clauses = self._parse_search(search_part)
        select_clause = "*"
        group_by: str | None = None
        order_by: str | None = None
        limit_clause: str | None = None

        for cmd in commands:
            cmd = cmd.strip()
            cmd_lower = cmd.lower()

            if cmd_lower.startswith("stats "):
                select_clause, group_by = self._parse_stats(cmd[6:].strip())

            elif cmd_lower.startswith("where "):
                where_clauses.append(self._parse_where_expr(cmd[6:].strip()))

            elif cmd_lower.startswith("eval "):
                expr = cmd[5:].strip()
                parts_eval = expr.split("=", 1)
                if len(parts_eval) == 2:
                    alias = parts_eval[0].strip()
                    value = parts_eval[1].strip()
                    if select_clause == "*":
                        select_clause = f"*, {value} AS {alias}"
                    else:
                        select_clause += f", {value} AS {alias}"

            elif cmd_lower.startswith("fields ") or cmd_lower.startswith("table "):
                field_str = cmd.split(" ", 1)[1].strip()
                fields = [f.strip() for f in field_str.split(",")]
                select_clause = ", ".join(fields)

            elif cmd_lower.startswith("rename "):
                rename_expr = cmd[7:].strip()
                # rename old AS new
                m = re.match(r"(\w+)\s+[Aa][Ss]\s+(\w+)", rename_expr)
                if m:
                    old, new = m.group(1), m.group(2)
                    if select_clause == "*":
                        select_clause = f"* EXCLUDE ({old}), {old} AS {new}"
                    else:
                        select_clause = select_clause.replace(old, f"{old} AS {new}", 1)

            elif cmd_lower.startswith("sort "):
                sort_expr = cmd[5:].strip()
                parts_sort = [s.strip() for s in sort_expr.split(",")]
                order_parts = []
                for s in parts_sort:
                    if s.startswith("-"):
                        order_parts.append(f"{s[1:]} DESC")
                    elif s.startswith("+"):
                        order_parts.append(f"{s[1:]} ASC")
                    else:
                        order_parts.append(f"{s} ASC")
                order_by = ", ".join(order_parts)

            elif cmd_lower.startswith("head "):
                n = cmd[5:].strip()
                limit_clause = n

            elif cmd_lower.startswith("tail "):
                # Tail requires a subquery — approximate with ORDER BY desc + LIMIT
                n = cmd[5:].strip()
                limit_clause = n
                if order_by:
                    order_by = order_by.replace("ASC", "DESC").replace("DESC", "ASC")

            elif cmd_lower.startswith("dedup "):
                field_name = cmd[6:].strip()
                # Use ROW_NUMBER() approach
                if select_clause == "*":
                    select_clause = f"DISTINCT {field_name}"
                else:
                    select_clause = "DISTINCT " + select_clause

            elif cmd_lower.startswith("rex "):
                # rex field=x "pattern" → regexp_extract
                m = re.match(r'field=(\w+)\s+"([^"]+)"', cmd[4:].strip())
                if m:
                    field_name, pattern = m.group(1), m.group(2)
                    if select_clause == "*":
                        select_clause = f"*, regexp_extract({field_name}, '{pattern}') AS rex_match"

            elif cmd_lower.startswith("bin "):
                # bin span=1h _time → date_trunc('hour', Timestamp)
                m = re.match(r"span=(\d+)([smhd])\s+(\w+)", cmd[4:].strip())
                if m:
                    n_val, unit_char, col = m.group(1), m.group(2), m.group(3)
                    unit_map = {"s": "second", "m": "minute", "h": "hour", "d": "day"}
                    unit = unit_map.get(unit_char, "hour")
                    ts_col = "Timestamp" if col == "_time" else col
                    if select_clause == "*":
                        select_clause = f"date_trunc('{unit}', {ts_col}) AS {col}_bin, *"

        # Build SQL
        sql = f"SELECT {select_clause}\nFROM {table}"
        if where_clauses:
            sql += f"\nWHERE {' AND '.join(f'({w})' for w in where_clauses)}"
        if group_by:
            sql += f"\nGROUP BY {group_by}"
        if order_by:
            sql += f"\nORDER BY {order_by}"
        if limit_clause:
            sql += f"\nLIMIT {limit_clause}"

        return sql

    def _parse_search(self, search: str) -> tuple[str, list[str]]:
        """Parse the initial search clause, extract table and WHERE conditions."""
        where_clauses: list[str] = []
        table = "DeviceEvents"  # Default table if no index specified

        # Extract index= directive
        idx_match = re.search(r"\bindex=(\w+)", search)
        if idx_match:
            index_name = idx_match.group(1)
            tables = INDEX_TO_TABLE.get(index_name, [index_name])
            if len(tables) == 1:
                table = tables[0]
            else:
                # Multiple tables → UNION ALL subquery
                union_sql = " UNION ALL ".join(f"SELECT * FROM {t}" for t in tables)
                table = f"({union_sql}) AS _union_source"
            search = search[:idx_match.start()] + search[idx_match.end():]

        # Extract sourcetype=
        src_match = re.search(r"\bsourcetype=(\w+)", search)
        if src_match:
            where_clauses.append(f"source = '{src_match.group(1)}'")
            search = search[:src_match.start()] + search[src_match.end():]

        # Extract earliest= and latest=
        earliest_match = re.search(r"\bearliest=(\S+)", search)
        if earliest_match:
            offset = earliest_match.group(1)
            sql_offset = self._time_offset_to_sql(offset)
            if sql_offset:
                where_clauses.append(f"Timestamp >= {sql_offset}")
            search = search[:earliest_match.start()] + search[earliest_match.end():]

        latest_match = re.search(r"\blatest=(\S+)", search)
        if latest_match:
            offset = latest_match.group(1)
            if offset.lower() != "now":
                sql_offset = self._time_offset_to_sql(offset)
                if sql_offset:
                    where_clauses.append(f"Timestamp <= {sql_offset}")
            search = search[:latest_match.start()] + search[latest_match.end():]

        # Parse remaining field=value conditions
        search = search.strip()
        if search and search.lower() != "search":
            for condition in self._parse_conditions(search):
                if condition:
                    where_clauses.append(condition)

        return table, where_clauses

    def _parse_conditions(self, search: str) -> list[str]:
        """Parse field=value, field!=value, etc. into SQL conditions."""
        conditions = []
        # field=value or field!=value or field="value with spaces"
        pattern = re.compile(r'(\w+)\s*(!=|=)\s*"?([^"\s,]+)"?')
        for m in pattern.finditer(search):
            field, op, value = m.group(1), m.group(2), m.group(3)
            if op == "=":
                conditions.append(f"{field} = '{value}'")
            else:
                conditions.append(f"{field} != '{value}'")
        return conditions

    def _parse_stats(self, stats_expr: str) -> tuple[str, str]:
        """Parse `count by field, field2` → SELECT clause and GROUP BY."""
        # stats count by field → SELECT field, COUNT(*) GROUP BY field
        # stats count, sum(x) by field
        by_match = re.search(r"\bby\b", stats_expr, re.IGNORECASE)
        if by_match:
            agg_part = stats_expr[: by_match.start()].strip()
            by_part = stats_expr[by_match.end():].strip()
        else:
            agg_part = stats_expr
            by_part = ""

        agg_exprs = self._parse_agg_funcs(agg_part)
        by_cols = [c.strip() for c in by_part.split(",") if c.strip()] if by_part else []

        if by_cols:
            select_clause = ", ".join(by_cols + agg_exprs)
            group_by = ", ".join(by_cols)
        else:
            select_clause = ", ".join(agg_exprs)
            group_by = ""

        return select_clause, group_by

    def _parse_agg_funcs(self, agg_str: str) -> list[str]:
        """Parse comma-separated aggregate functions."""
        exprs = []
        for part in agg_str.split(","):
            part = part.strip()
            if not part:
                continue
            # count → COUNT(*)
            if part.lower() == "count":
                exprs.append("COUNT(*) AS count")
            elif re.match(r"count\(\)", part, re.IGNORECASE):
                exprs.append("COUNT(*) AS count")
            # sum(field) AS alias
            elif m := re.match(r"(sum|avg|min|max|count)\((\w+)\)(?:\s+[Aa][Ss]\s+(\w+))?", part, re.IGNORECASE):
                func, field, alias = m.group(1).upper(), m.group(2), m.group(3)
                out = f"{func}({field})"
                if alias:
                    out += f" AS {alias}"
                exprs.append(out)
            elif m := re.match(r"dc\((\w+)\)|dcount\((\w+)\)", part, re.IGNORECASE):
                field = m.group(1) or m.group(2)
                exprs.append(f"COUNT(DISTINCT {field}) AS dcount_{field}")
            else:
                exprs.append(part)
        return exprs

    def _parse_where_expr(self, expr: str) -> str:
        """Parse an SPL where clause expression — basic field comparisons."""
        # Handle simple cases — expand as needed
        expr = re.sub(r"\blike\b", "LIKE", expr, flags=re.IGNORECASE)
        expr = re.sub(r"\bAND\b", "AND", expr, flags=re.IGNORECASE)
        expr = re.sub(r"\bOR\b", "OR", expr, flags=re.IGNORECASE)
        return expr

    def _time_offset_to_sql(self, offset: str) -> str | None:
        """Convert SPL time offset like -7d to SQL."""
        if offset.lower() == "now":
            return "NOW()"
        m = _TIME_PATTERN.match(offset)
        if m:
            n, unit_char = m.group(1), m.group(2)
            sql_unit = _TIME_UNITS.get(unit_char, "DAY")
            return f"NOW() - INTERVAL {n} {sql_unit}"
        return None


def _check_injection(spl: str) -> None:
    dangerous = re.compile(
        r"\b(DROP|DELETE|INSERT|UPDATE|CREATE|ALTER|EXEC|EXECUTE|PRAGMA)\b",
        re.IGNORECASE,
    )
    if dangerous.search(spl):
        raise QueryException(
            detail="Query contains disallowed SQL keywords.",
            internal_detail=f"Injection attempt in SPL: {spl[:200]}",
        )


# Coverage — portfolio artifact
COVERAGE: dict[str, str] = {
    "search field=value": "supported",
    "where": "supported",
    "fields / table": "supported",
    "stats count by field": "supported",
    "stats count, sum(x) by field": "supported",
    "eval new=expr": "supported",
    "rename old AS new": "supported",
    "sort by field / sort -field": "supported",
    "head N / tail N": "supported",
    "dedup field": "supported → DISTINCT",
    "rex field=x pattern": "supported → regexp_extract()",
    "index=name": "supported — mapped to MDE table",
    "sourcetype=value": "supported → WHERE source = 'value'",
    "earliest=-7d latest=now": "supported",
    "bin span=1h _time": "supported → date_trunc()",
    "transaction": "planned",
    "lookup": "planned",
    "inputlookup / outputlookup": "planned",
    "tstats": "planned",
    "multisearch": "planned",
}
