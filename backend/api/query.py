"""
api/query.py — Query execution endpoint.

Accepts KQL, SPL, or SQL queries, routes through the transpiler, and executes
against DuckDB. The transpiled SQL is never returned to the client — it is an
internal implementation detail and may contain information about the schema.

Row limit: max 10,000, default 1,000. This is enforced at the SQL level by
appending LIMIT to the transpiled query.
"""

import logging
import time

from fastapi import APIRouter, Depends, Request
from pydantic import BaseModel, Field

from backend.api.auth import get_current_user
from backend.config import settings
from backend.engine.duckdb_pool import get_pool
from backend.engine.query_router import route
from backend.exceptions import QueryException
from backend.limiter import QUERY_LIMIT, limiter
from backend.models.user import User

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/query", tags=["query"])

_MAX_ROWS = 10_000
_DEFAULT_ROWS = 1_000


class QueryRequest(BaseModel):
    query: str = Field(min_length=1, max_length=50_000)
    language: str = Field(pattern=r"^(kql|spl|sql)$")
    limit: int = Field(default=_DEFAULT_ROWS, ge=1, le=_MAX_ROWS)


class ColumnMeta(BaseModel):
    name: str
    type: str


class QueryResponse(BaseModel):
    columns: list[ColumnMeta]
    rows: list[list]
    count: int
    duration_ms: int
    render_hint: str | None = None  # For KQL render operator


@router.post("/execute", response_model=QueryResponse)
@limiter.limit(QUERY_LIMIT)
async def execute_query(
    request: Request,
    body: QueryRequest,
    current_user: User = Depends(get_current_user),
) -> QueryResponse:
    """Execute a KQL, SPL, or SQL query and return results.

    The transpiled SQL is an internal artifact — it is never included in the
    response. If you need to debug transpilation, use server-side DEBUG logging.
    """
    start_ms = time.monotonic()

    # Transpile / validate
    sql = route(body.query, body.language)

    # Inject LIMIT — ensure user-provided limit is respected
    sql_with_limit = _apply_limit(sql, body.limit)

    # Execute via pool
    pool = get_pool()
    rows_dicts = await pool.execute(
        sql_with_limit,
        timeout=settings.QUERY_TIMEOUT_SECONDS,
    )

    duration_ms = int((time.monotonic() - start_ms) * 1000)

    if not rows_dicts:
        return QueryResponse(columns=[], rows=[], count=0, duration_ms=duration_ms)

    # Build column metadata from first row keys
    columns = [ColumnMeta(name=k, type=_infer_type(v)) for k, v in rows_dicts[0].items()]
    col_names = [c.name for c in columns]
    rows = [[row.get(col) for col in col_names] for row in rows_dicts]

    logger.info(
        "Query executed: user=%s lang=%s rows=%d duration=%dms",
        current_user.username,
        body.language,
        len(rows),
        duration_ms,
    )
    return QueryResponse(
        columns=columns,
        rows=rows,
        count=len(rows),
        duration_ms=duration_ms,
    )


def _apply_limit(sql: str, limit: int) -> str:
    """Inject a LIMIT clause if the SQL doesn't already have one."""
    sql_upper = sql.upper()
    if "LIMIT" in sql_upper:
        return sql
    return f"{sql}\nLIMIT {limit}"


def _infer_type(value: object) -> str:
    if isinstance(value, bool):
        return "boolean"
    if isinstance(value, int):
        return "integer"
    if isinstance(value, float):
        return "float"
    if isinstance(value, str):
        return "string"
    return "unknown"
