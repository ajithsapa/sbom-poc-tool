"""
routers/cache.py — NVD cache status endpoint.

Endpoint:
  GET /api/v1/cache/status  — return NVD cache staleness and record count

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

from step7_5_pydantic_models import CacheStatusResponse, ErrorResponse  # noqa: E402

from ..dependencies import get_cache_status_dict  # noqa: E402

logger = logging.getLogger(__name__)

router = APIRouter()


@router.get(
    "/status",
    response_model=CacheStatusResponse,
    status_code=200,
    summary="Get NVD cache staleness and record count",
    description=(
        "Returns the current state of the local NVD SQLite cache: "
        "last sync timestamp, age in days, staleness flag (> 7 days = stale), "
        "and total number of vulnerability records."
    ),
    responses={
        500: {
            "model": ErrorResponse,
            "description": "Internal error while querying the NVD cache",
        },
    },
)
async def get_cache_status() -> CacheStatusResponse:
    """
    Query the shared NVDCacheManager singleton and return its current state.

    is_stale is True when:
      - The cache has never been synced (last_synced_at is null), OR
      - The cache age exceeds the 7-day staleness threshold.
    """
    try:
        status = get_cache_status_dict()
    except Exception as exc:
        logger.exception("Failed to query NVD cache status")
        return JSONResponse(
            status_code=500,
            content=ErrorResponse(
                error="CACHE_STATUS_ERROR",
                message="Internal error while querying the NVD cache",
                details=None,
            ).model_dump(),
        )

    return CacheStatusResponse(
        last_synced_at=status["last_synced_at"],
        age_days=status["age_days"],
        is_stale=status["is_stale"],
        record_count=status["record_count"],
    )
