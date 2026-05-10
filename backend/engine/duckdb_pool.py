"""
duckdb_pool.py — Serialized async DuckDB connection manager.

Concurrency model: DuckDB's in-process engine is not safe for concurrent writes
from multiple threads or coroutines. Rather than opening multiple connections
(which requires DuckDB's multi-reader/single-writer mode and adds complexity),
we serialize all operations through a single asyncio.Lock.

In a production scale-out scenario this single connection becomes the bottleneck.
The upgrade path: replace this pool with DuckDB's native connection pool API
(planned for DuckDB 2.x) or migrate heavy query workloads to MotherDuck /
ClickHouse with the same Parquet files read over an object store.

The DuckDB connection is opened once at startup via init_pool() from FastAPI's
lifespan handler, and closed via close_pool() on shutdown.
"""

import asyncio
import logging
from typing import Any

import duckdb

from backend.exceptions import QueryException
from backend.schema.mde_tables import get_duckdb_view_sql

logger = logging.getLogger(__name__)


class DuckDbPool:
    """Single-connection async-safe DuckDB pool with timeout enforcement."""

    def __init__(self, storage_root: str) -> None:
        self._lock = asyncio.Lock()
        # read_only=False so we can CREATE OR REPLACE VIEW at startup
        self._conn = duckdb.connect(database=":memory:")
        self._storage_root = storage_root
        self._register_views()

    def _register_views(self) -> None:
        """Create DuckDB views over the Parquet storage layer.

        Views are registered at startup. They are virtual — no data is loaded
        into memory. Each SELECT against a view triggers DuckDB's Parquet reader,
        which applies predicate pushdown and projection pruning automatically.
        Views over empty partitions fail at creation time in DuckDB — they are
        re-registered after first write via refresh_view().
        """
        for sql in get_duckdb_view_sql(self._storage_root):
            try:
                self._conn.execute(sql)
                table_name = sql.split("VIEW ")[1].split(" AS")[0]
                logger.debug("Registered DuckDB view: %s", table_name)
            except duckdb.Error as exc:
                # View creation fails when no parquet files exist yet — normal at
                # startup before first ingest. refresh_view() registers it later.
                logger.debug("View registration deferred (no data yet): %s", exc)

    def refresh_view(self, table_name: str) -> None:
        """Register or re-register the DuckDB view for a single table.

        Called after write_parquet() succeeds so that queries against the table
        work immediately — even if the view failed to register at startup because
        no parquet files existed yet.
        """
        sqls = get_duckdb_view_sql(self._storage_root)
        for sql in sqls:
            if f"VIEW {table_name} AS" in sql:
                try:
                    self._conn.execute(sql)
                    logger.debug("Refreshed DuckDB view: %s", table_name)
                except duckdb.Error as exc:
                    logger.warning("Failed to refresh view %s: %s", table_name, exc)
                return

    async def execute(
        self,
        sql: str,
        params: list[Any] | None = None,
        timeout: float = 30.0,
    ) -> list[dict[str, Any]]:
        """Execute a SQL statement and return results as a list of row dicts.

        Acquires the serialization lock before touching the connection. The
        asyncio.wait_for() timeout fires if the query takes longer than `timeout`
        seconds — DuckDB does not natively support async cancellation, so we
        raise immediately and let the connection recover on the next call.

        Args:
            sql: Validated DuckDB SQL (already transpiled from KQL/SPL).
            params: Positional parameters for parameterized queries.
            timeout: Per-query timeout in seconds.

        Returns:
            List of dicts mapping column name → value.

        Raises:
            QueryException: On timeout or DuckDB execution error.
        """
        async with self._lock:
            try:
                result = await asyncio.wait_for(
                    asyncio.get_event_loop().run_in_executor(
                        None, self._execute_sync, sql, params or []
                    ),
                    timeout=timeout,
                )
                return result
            except asyncio.TimeoutError:
                raise QueryException(
                    detail="Query timed out. Reduce the time range or add more filters.",
                    internal_detail=f"Query exceeded {timeout}s timeout. SQL: {sql[:200]}",
                )
            except duckdb.Error as exc:
                logger.error("DuckDB execution error: %s | SQL: %.200s", exc, sql)
                raise QueryException(
                    detail="Query execution failed. Check syntax and column names.",
                    internal_detail=str(exc),
                )

    def _execute_sync(self, sql: str, params: list[Any]) -> list[dict[str, Any]]:
        """Synchronous DuckDB execution, called from the thread executor."""
        if params:
            relation = self._conn.execute(sql, params)
        else:
            relation = self._conn.execute(sql)
        columns = [desc[0] for desc in relation.description]
        return [dict(zip(columns, row)) for row in relation.fetchall()]

    async def close(self) -> None:
        """Close the DuckDB connection. Called from FastAPI lifespan shutdown."""
        async with self._lock:
            self._conn.close()
            logger.info("DuckDB connection closed.")


# ---------------------------------------------------------------------------
# Module-level singleton — initialized by FastAPI lifespan, used everywhere
# ---------------------------------------------------------------------------

_pool: DuckDbPool | None = None


async def init_pool(storage_root: str) -> None:
    """Initialize the global pool. Called once from FastAPI lifespan startup."""
    global _pool
    _pool = DuckDbPool(storage_root)
    logger.info("DuckDB pool initialized with storage root: %s", storage_root)


async def close_pool() -> None:
    """Close the global pool. Called from FastAPI lifespan shutdown."""
    global _pool
    if _pool is not None:
        await _pool.close()
        _pool = None


def get_pool() -> DuckDbPool:
    """Return the initialized pool. Raises if init_pool() was not called."""
    if _pool is None:
        raise RuntimeError("DuckDB pool is not initialized. Call init_pool() first.")
    return _pool
