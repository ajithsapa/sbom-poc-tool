"""
routers/repos.py — Manage the workspace of cloned git repositories.

Endpoints:
  GET    /api/v1/repos          — list all clones in the workspace
  DELETE /api/v1/repos/{name}   — wipe the named clone from disk

Repos appear in this workspace when a caller invokes `POST /api/v1/scans` with
a `repo_url`. Once cloned they persist until explicitly deleted via this router.
"""

from __future__ import annotations

import logging
import os
import sys
from typing import Any, Dict

from fastapi import APIRouter, Depends, Path
from fastapi.responses import JSONResponse

_SESSION_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "../.."))
if _SESSION_ROOT not in sys.path:
    sys.path.insert(0, _SESSION_ROOT)

from git_cloner import CloneManager, GitCloneError  # noqa: E402
from step7_5_pydantic_models import (  # noqa: E402
    ClonedRepoListResponse,
    ClonedRepoRecord,
    ErrorResponse,
)

from ..dependencies import get_clone_manager  # noqa: E402

logger = logging.getLogger(__name__)

router = APIRouter()


def _clone_to_record(clone) -> ClonedRepoRecord:
    return ClonedRepoRecord(
        name=clone.name,
        url=clone.url or "",
        path=clone.path,
        cloned_at=clone.cloned_at or "",
        size_bytes=clone.size_bytes,
    )


@router.get(
    "",
    response_model=ClonedRepoListResponse,
    status_code=200,
    summary="List cloned repositories in the workspace",
    description=(
        "Returns the inventory of repositories that have been cloned into the "
        "server's workspace via `POST /api/v1/scans` with `repo_url`. Each "
        "entry includes the workspace name, original URL, on-disk path, "
        "clone timestamp, and size. Use the returned `name` to delete a clone "
        "via `DELETE /api/v1/repos/{name}`."
    ),
    responses={
        401: {"model": ErrorResponse, "description": "INVALID_API_KEY — missing or wrong X-API-Key header"},
    },
)
async def list_repos(
    clone_manager: CloneManager = Depends(get_clone_manager),
) -> ClonedRepoListResponse:
    repos = [_clone_to_record(c) for c in clone_manager.list_repos()]
    return ClonedRepoListResponse(repos=repos)


def _delete_handler(name: str, clone_manager: CloneManager):
    try:
        clone_manager.delete(name)
    except GitCloneError as exc:
        msg = str(exc)
        status = 404 if msg.startswith("No clone named") else 422
        return JSONResponse(
            status_code=status,
            content=ErrorResponse(
                error="REPO_NOT_FOUND" if status == 404 else "INVALID_REPO_NAME",
                message=msg,
                details={"name": name},
            ).model_dump(),
        )
    except OSError as exc:
        logger.exception("Failed to delete clone %s", name)
        return JSONResponse(
            status_code=500,
            content=ErrorResponse(
                error="REPO_DELETE_FAILED",
                message=f"Failed to delete clone {name!r}: {exc}",
                details={"name": name},
            ).model_dump(),
        )
    logger.info("Deleted clone: name=%s", name)
    return JSONResponse(
        status_code=200,
        content={"deleted": True, "name": name},
    )


@router.delete(
    "/{name}",
    status_code=200,
    summary="Delete a cloned repository from the workspace",
    description=(
        "Removes the named clone from disk. The `name` must match an entry "
        "returned by `GET /api/v1/repos`. Returns 404 if no such clone exists."
    ),
    responses={
        401: {"model": ErrorResponse, "description": "INVALID_API_KEY — missing or wrong X-API-Key header"},
        404: {"model": ErrorResponse, "description": "REPO_NOT_FOUND — no clone with the given name"},
        422: {"model": ErrorResponse, "description": "INVALID_REPO_NAME — invalid clone name (e.g. path traversal attempt)"},
        500: {"model": ErrorResponse, "description": "REPO_DELETE_FAILED — filesystem error while deleting"},
    },
)
async def delete_repo(
    name: str = Path(..., description="Workspace name of the clone (from GET /repos).", examples=["syft"]),
    clone_manager: CloneManager = Depends(get_clone_manager),
):
    return _delete_handler(name, clone_manager)
