"""
main.py — FastAPI application entrypoint.

Startup sequence:
  1. Load and validate configuration (pydantic-settings)
  2. Initialize DuckDB pool and register MDE table views
  3. Start detection runner background task
  4. Mount all API routers under /api/v1/

Security middleware:
  - CORS: locked to CORS_ORIGIN, never wildcard
  - CSP headers: report-only on first deploy, switch to enforcing once validated
  - Request logging: method, path, status, duration — no request bodies ever

Run with: uvicorn backend.main:app --reload
"""

import asyncio
import logging
import time
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from slowapi import _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from slowapi.middleware import SlowAPIMiddleware

from backend.api import alerts, auth, detections, ingest, query
from backend.config import settings
from backend.engine.detection_runner import detection_loop
from backend.engine.duckdb_pool import close_pool, init_pool
from backend.exceptions import FPBaseException
from backend.limiter import limiter

logging.basicConfig(
    level=getattr(logging, settings.LOG_LEVEL, logging.INFO),
    format="%(asctime)s %(levelname)s %(name)s: %(message)s",
)
logger = logging.getLogger(__name__)

_detection_task: asyncio.Task | None = None


@asynccontextmanager
async def lifespan(app: FastAPI):
    """FastAPI lifespan: initialize on startup, clean up on shutdown."""
    global _detection_task

    logger.info("Starting fried-plantains SIEM backend")
    await init_pool(settings.STORAGE_ROOT)

    _detection_task = asyncio.create_task(detection_loop())
    logger.info("Detection runner started")

    yield

    logger.info("Shutting down fried-plantains backend")
    if _detection_task:
        _detection_task.cancel()
        try:
            await _detection_task
        except asyncio.CancelledError:
            pass

    await close_pool()
    logger.info("Shutdown complete")


app = FastAPI(
    title="fried-plantains SIEM",
    description="Custom SIEM and threat hunting platform — MDE-compatible KQL/SPL/SQL",
    version="0.1.0",
    lifespan=lifespan,
    # Disable automatic /docs redirect — clients must use /api/v1/docs
    docs_url="/api/v1/docs",
    redoc_url="/api/v1/redoc",
    openapi_url="/api/v1/openapi.json",
)

# Rate limiting — slowapi middleware must be added before CORS
app.state.limiter = limiter
app.add_middleware(SlowAPIMiddleware)
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# CORS — exact origin only, never wildcard
app.add_middleware(
    CORSMiddleware,
    allow_origins=[settings.CORS_ORIGIN],
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE"],
    allow_headers=["Authorization", "Content-Type"],
)


@app.middleware("http")
async def request_logging_middleware(request: Request, call_next) -> Response:
    """Log each request: method, path, status, duration. Never log body."""
    start = time.monotonic()
    response = await call_next(request)
    duration_ms = int((time.monotonic() - start) * 1000)
    logger.info(
        "%s %s → %d (%dms)",
        request.method,
        request.url.path,
        response.status_code,
        duration_ms,
    )
    return response


@app.middleware("http")
async def csp_header_middleware(request: Request, call_next) -> Response:
    """Inject Content-Security-Policy-Report-Only header.

    Report-only mode: violations are reported but not blocked. Switch to
    Content-Security-Policy (enforcing) after validating no legitimate content
    is blocked in your deployment.
    """
    response = await call_next(request)
    response.headers["Content-Security-Policy-Report-Only"] = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline'; "  # Monaco requires inline scripts
        "style-src 'self' 'unsafe-inline'; "
        "img-src 'self' data:; "
        "font-src 'self'; "
        "connect-src 'self'"
    )
    return response


# ---------------------------------------------------------------------------
# Exception handlers — convert domain exceptions to structured HTTP responses.
# Internal details are logged but never returned to the client.
# ---------------------------------------------------------------------------

@app.exception_handler(FPBaseException)
async def fp_exception_handler(request: Request, exc: FPBaseException) -> JSONResponse:
    logger.error(
        "Domain exception [%s]: %s | internal: %s | path: %s",
        type(exc).__name__,
        exc.detail,
        exc.internal_detail,
        request.url.path,
    )
    return JSONResponse(
        status_code=exc.status_code,
        content={"detail": exc.detail},
    )


@app.exception_handler(Exception)
async def generic_exception_handler(request: Request, exc: Exception) -> JSONResponse:
    logger.exception("Unhandled exception at %s: %s", request.url.path, exc)
    return JSONResponse(
        status_code=500,
        content={"detail": "An internal error occurred."},
    )


# ---------------------------------------------------------------------------
# Route mounting
# ---------------------------------------------------------------------------

api_prefix = "/api/v1"

app.include_router(auth.router, prefix=api_prefix)
app.include_router(ingest.router, prefix=api_prefix)
app.include_router(query.router, prefix=api_prefix)
app.include_router(detections.router, prefix=api_prefix)
app.include_router(alerts.router, prefix=api_prefix)


@app.get("/api/v1/health", tags=["health"])
async def health() -> dict:
    return {"status": "ok", "service": "fried-plantains"}
