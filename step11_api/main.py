"""
main.py — FastAPI application factory for the SBOM POC Tool API.

Session: SBOM-20260409-sb01
Generated: Step 11 — FastAPI API Generation

Architecture:
  POST /api/v1/scans          -> routers/scans.py  (ScanOrchestrator)
  GET  /api/v1/scans/{id}     -> routers/scans.py  (in-memory store)
  POST /api/v1/sync           -> routers/sync.py   (NVDSyncOrchestrator)
  GET  /api/v1/cache/status   -> routers/cache.py  (NVDCacheManager)
  GET  /api/v1/health         -> routers/health.py (liveness probe)

Run with:
  uvicorn step11_api.main:app --reload --host 0.0.0.0 --port 8000

Or from within the session root directory:
  uvicorn step11_api.main:app --reload
"""

from __future__ import annotations

import logging
import os
import sys
from contextlib import asynccontextmanager
from typing import AsyncGenerator

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

# Ensure the session root is on sys.path before any local imports so that
# step6_tdd_green_phase and step9_tdd_green_phase_orchestration are importable.
_SESSION_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if _SESSION_ROOT not in sys.path:
    sys.path.insert(0, _SESSION_ROOT)

from .config import settings  # noqa: E402
from .routers import cache, health, scans, sync  # noqa: E402

# ---------------------------------------------------------------------------
# Logging setup
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=getattr(logging, settings.LOG_LEVEL, logging.INFO),
    format="%(asctime)s %(levelname)s %(name)s %(message)s",
)
logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Lifespan context manager (replaces deprecated on_event)
# ---------------------------------------------------------------------------

@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    """Application startup and shutdown lifecycle."""
    logger.info(
        "SBOM POC Tool API starting — version=%s host=%s port=%s",
        settings.VERSION,
        settings.HOST,
        settings.PORT,
    )
    yield
    logger.info("SBOM POC Tool API shutting down")


# ---------------------------------------------------------------------------
# Application factory
# ---------------------------------------------------------------------------

def create_app() -> FastAPI:
    """
    Construct and configure the FastAPI application.

    Returns a fully configured app instance.  The module-level `app` variable
    is the instance used by uvicorn; call `create_app()` directly in tests to
    get a fresh app instance.
    """
    application = FastAPI(
        title=settings.APP_NAME,
        description=(
            "REST API for the Software Bill of Materials (SBOM) POC Tool.\n\n"
            "Exposes scan and NVD sync operations implemented in the orchestration "
            "layer (ScanOrchestrator, NVDSyncOrchestrator). All vulnerability "
            "lookups use the local NVD SQLite cache — no live NVD API calls are "
            "made at scan time.\n\n"
            "**Session**: SBOM-20260409-sb01  \n"
            "**Traceability**: Business logic from step6_tdd_green_phase.py; "
            "Orchestration from step9_tdd_green_phase_orchestration.py; "
            "Schemas from step7_5_pydantic_models.py."
        ),
        version=settings.VERSION,
        docs_url="/docs",
        redoc_url="/redoc",
        openapi_url="/openapi.json",
        lifespan=lifespan,
    )

    # ------------------------------------------------------------------
    # CORS middleware
    # ------------------------------------------------------------------
    application.add_middleware(
        CORSMiddleware,
        allow_origins=settings.ALLOWED_ORIGINS,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # ------------------------------------------------------------------
    # Routers
    # ------------------------------------------------------------------
    application.include_router(
        scans.router,
        prefix="/api/v1/scans",
        tags=["business-logic"],
    )
    application.include_router(
        sync.router,
        prefix="/api/v1/sync",
        tags=["orchestration"],
    )
    application.include_router(
        cache.router,
        prefix="/api/v1/cache",
        tags=["workflow-state"],
    )
    application.include_router(
        health.router,
        prefix="/api/v1/health",
        tags=["workflow-state"],
    )

    # ------------------------------------------------------------------
    # Global exception handler — prevents raw stack traces leaking to clients
    # ------------------------------------------------------------------
    @application.exception_handler(Exception)
    async def global_exception_handler(request: Request, exc: Exception) -> JSONResponse:
        logger.exception("Unhandled exception on %s %s", request.method, request.url.path)
        return JSONResponse(
            status_code=500,
            content={
                "error": "INTERNAL_ERROR",
                "message": "An unexpected internal error occurred",
                "details": None,
            },
        )

    return application


# Module-level app instance — used by uvicorn directly.
app = create_app()


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(
        "step11_api.main:app",
        host=settings.HOST,
        port=settings.PORT,
        reload=settings.RELOAD,
        log_level=settings.LOG_LEVEL.lower(),
    )
