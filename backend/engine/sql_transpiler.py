"""
sql_transpiler.py — SQL passthrough validator.

SQL is not transpiled — it is validated then executed as-is against DuckDB.
Validation enforces that:
  1. The statement is a SELECT (no DDL/DML)
  2. All table references exist as registered DuckDB views
  3. The query does not contain data exfiltration patterns

This gives power users full access to DuckDB's capabilities (window functions,
CTEs, lateral joins, json_extract) while maintaining the security boundary.
"""

import logging

import sqlglot
import sqlglot.expressions as exp

from backend.exceptions import QueryException
from backend.schema.mde_tables import MDE_TABLES

logger = logging.getLogger(__name__)

# All valid table names are the registered MDE views
_VALID_TABLES: frozenset[str] = frozenset(MDE_TABLES.keys())


class SqlValidator:
    """Validate and pass through SQL to DuckDB."""

    @staticmethod
    def validate(sql: str) -> str:
        """Parse and validate a SQL statement.

        Args:
            sql: User-provided SQL string.

        Returns:
            The original SQL string unchanged (no transpilation).

        Raises:
            QueryException: If the SQL is invalid, non-SELECT, or references
                            unknown tables.
        """
        _check_dangerous_patterns(sql)

        try:
            statements = sqlglot.parse(sql, dialect="duckdb")
        except sqlglot.errors.ParseError as exc:
            raise QueryException(
                detail=f"SQL parse error: {exc}",
                internal_detail=str(exc),
            )

        if not statements:
            raise QueryException(detail="Empty SQL statement.")

        if len(statements) > 1:
            raise QueryException(
                detail="Only a single SELECT statement is allowed.",
                internal_detail=f"Received {len(statements)} statements.",
            )

        stmt = statements[0]
        if not isinstance(stmt, exp.Select):
            raise QueryException(
                detail=f"Only SELECT statements are allowed. Got: {type(stmt).__name__}.",
            )

        # Validate all table references
        _validate_table_references(stmt)

        logger.debug("SQL validated: %.200s", sql)
        return sql


def _check_dangerous_patterns(sql: str) -> None:
    """Fast pre-parse check for obviously dangerous patterns.

    sqlglot catches most cases, but this guard runs before parse to reject
    the most blatant injection attempts without the overhead of parsing.
    """
    import re
    dangerous = re.compile(
        r"\b(DROP|DELETE|INSERT|UPDATE|CREATE|ALTER|EXEC|EXECUTE|PRAGMA|INTO\s+OUTFILE)\b",
        re.IGNORECASE,
    )
    if dangerous.search(sql):
        raise QueryException(
            detail="Only SELECT statements are allowed.",
            internal_detail=f"Dangerous keyword in SQL: {sql[:200]}",
        )


def _validate_table_references(stmt: exp.Expression) -> None:
    """Ensure all table references in the AST exist as registered DuckDB views.

    CTE names defined in a WITH clause are valid table references within the same
    query — they are extracted first, then excluded from the validation check.
    """
    # Collect CTE names defined in this statement (valid within-query aliases)
    cte_names: set[str] = set()
    with_clause = stmt.find(exp.With)
    if with_clause:
        for cte in with_clause.find_all(exp.CTE):
            if cte.alias:
                cte_names.add(cte.alias)

    for table_expr in stmt.find_all(exp.Table):
        table_name = table_expr.name
        if not table_name:
            continue
        # CTE aliases and subquery aliases are valid
        if table_name in cte_names:
            continue
        if table_name not in _VALID_TABLES:
            raise QueryException(
                detail=f"Unknown table '{table_name}'. Valid tables: {sorted(_VALID_TABLES)}",
                internal_detail=f"SQL references unknown table: {table_name}",
            )
