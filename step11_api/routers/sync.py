"""
routers/sync.py — NVD cache synchronization endpoint.

Endpoint:
  POST /api/v1/sync  — trigger NVDSyncOrchestrator against a local Grype DB

Maps to:  step9.NVDSyncOrchestrator.run(source_path)
Error mapping:
  NVDSyncError      → HTTP 404  (source_path not found)
  other Exception   → HTTP 500

Session: SBOM-20260409-sb01
Generated: Step 11 — FastAPI API Generation
"""

from __future__ import annotations

import logging
import os
import sys

from fastapi import APIRouter, Depends
from fastapi.responses import JSONResponse

_SESSION_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "../.."))
if _SESSION_ROOT not in sys.path:
    sys.path.insert(0, _SESSION_ROOT)

from step6_tdd_green_phase import NVDSyncError  # noqa: E402
from step7_5_pydantic_models import ErrorResponse, SyncRequest, SyncResponse  # noqa: E402
from step9_tdd_green_phase_orchestration import NVDSyncOrchestrator, SyncResult  # noqa: E402

from ..dependencies import get_sync_orchestrator  # noqa: E402

logger = logging.getLogger(__name__)

router = APIRouter()


@router.post(
    "",
    response_model=SyncResponse,
    status_code=200,
    summary="Refresh the local NVD vulnerability cache (POC Req 7)",
    description=(
        "Performs an on-demand refresh of the local **NVD** "
        "(National Vulnerability Database, NIST) cache from a local feed file. "
        "Satisfies the 'periodic NVD sync, no live API call at scan time' "
        "requirement — the cache is the only source of truth for vulnerability "
        "lookup during a scan. The cache becomes stale after 7 days; this "
        "endpoint resets the staleness clock and reports the count of records "
        "added vs. updated. Equivalent to the `sbom-tool sync` CLI command."
    ),
    responses={
        404: {
            "model": ErrorResponse,
            "description": "source_path not found on the server filesystem",
        },
        500: {
            "model": ErrorResponse,
            "description": "Unexpected error during NVD sync",
        },
    },
)
async def sync_nvd_cache(
    request: SyncRequest,
    orchestrator: NVDSyncOrchestrator = Depends(get_sync_orchestrator),
) -> SyncResponse:
    """
    Execute NVD sync by delegating to NVDSyncOrchestrator.run(source_path).

    On success, the shared NVDCacheManager is updated and subsequent scans
    will use the freshly synced cache.

    Returns HTTP 404 if source_path does not exist on the server filesystem.
    """
    try:
        result: SyncResult = orchestrator.run(source_path=request.source_path)
    except NVDSyncError as exc:
        logger.warning("NVD sync failed — source not found: %s", exc)
        return JSONResponse(
            status_code=404,
            content=ErrorResponse(
                error="NVD_SOURCE_NOT_FOUND",
                message=f"NVD source database not found: {request.source_path}",
                details={"source_path": request.source_path},
            ).model_dump(),
        )
    except Exception as exc:
        logger.exception("Unexpected error during NVD sync")
        return JSONResponse(
            status_code=500,
            content=ErrorResponse(
                error="NVD_SYNC_FAILED",
                message="NVD sync encountered an unexpected error",
                details=None,
            ).model_dump(),
        )

    logger.info(
        "NVD sync completed: source=%s added=%d updated=%d",
        result.source_path,
        result.records_added,
        result.records_updated,
    )

    return SyncResponse(
        records_added=result.records_added,
        records_updated=result.records_updated,
        synced_at=result.synced_at or "",
        source_path=result.source_path,
        sync_log=result.sync_log,
    )
