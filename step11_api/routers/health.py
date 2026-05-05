"""
routers/health.py — Service liveness/readiness probe endpoint.

Endpoint:
  GET /api/v1/health  — return service status, version, and NVD cache health

Health status logic:
  "ok"       — service running and NVD cache is fresh (not stale)
  "degraded" — service running but NVD cache is stale (age > 7 days or never synced)
  "down"     — should never be returned by this endpoint; exists for future use

Session: SBOM-20260409-sb01
Generated: Step 11 — FastAPI API Generation
"""

from __future__ import annotations

import logging
import os
import sys

from fastapi import APIRouter
from fastapi.responses import JSONResponse

_SESSION_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "../.."))
if _SESSION_ROOT not in sys.path:
    sys.path.insert(0, _SESSION_ROOT)

from step7_5_pydantic_models import (  # noqa: E402
    CacheStatusResponse,
    ErrorResponse,
    HealthResponse,
    HealthStatus,
)

from ..config import settings  # noqa: E402
from ..dependencies import get_cache_status_dict  # noqa: E402

logger = logging.getLogger(__name__)

router = APIRouter()


@router.get(
    "",
    response_model=HealthResponse,
    status_code=200,
    summary="Service liveness and readiness probe",
    description=(
        "Returns service health, deployed version, and **NVD** "
        "(National Vulnerability Database) cache status. Returns `degraded` "
        "(not `down`) when the cache is stale — the service is still "
        "operational and able to serve scans, just with stale-data warnings. "
        "Suitable for Kubernetes liveness/readiness probe targets and CI/CD "
        "smoke tests before a deployment is considered live."
    ),
    responses={
        500: {
            "model": ErrorResponse,
            "description": "Service is unhealthy",
        },
    },
)
async def get_health() -> HealthResponse:
    """
    Liveness and readiness probe for the SBOM POC Tool API.

    status is derived from NVD cache state:
      - "ok"       → cache is fresh
      - "degraded" → cache is stale (scan will still complete with warnings)
    """
    try:
        cache_dict = get_cache_status_dict()
    except Exception as exc:
        logger.exception("Failed to query NVD cache during health check")
        return JSONResponse(
            status_code=500,
            content=ErrorResponse(
                error="HEALTH_CHECK_FAILED",
                message="Service health check failed",
                details=None,
            ).model_dump(),
        )

    cache_status = CacheStatusResponse(
        last_synced_at=cache_dict["last_synced_at"],
        age_days=cache_dict["age_days"],
        is_stale=cache_dict["is_stale"],
        record_count=cache_dict["record_count"],
    )

    health_status = HealthStatus.degraded if cache_dict["is_stale"] else HealthStatus.ok

    return HealthResponse(
        status=health_status,
        version=settings.VERSION,
        cache_status=cache_status,
    )
