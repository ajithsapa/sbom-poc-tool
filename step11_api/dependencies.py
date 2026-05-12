"""
dependencies.py — FastAPI dependency-injection providers for the SBOM POC Tool API.

Holds module-level singletons (NVDCacheManager, orchestrators, scan store) so
that all requests share the same NVD cache state within a process.  The step6
and step9 modules live one directory above; their parent path is added to
sys.path here.

Session: SBOM-20260409-sb01
Generated: Step 11 — FastAPI API Generation
"""

from __future__ import annotations

import logging
import os
import sqlite3
import sys
from datetime import datetime, timezone
from typing import Any, Dict, Generator, Optional

from fastapi import HTTPException, Security
from fastapi.security import APIKeyHeader

# ---------------------------------------------------------------------------
# Ensure session root is on sys.path so step6/step9 can be imported as plain
# module names (they live adjacent to this package, not inside it).
# ---------------------------------------------------------------------------
_SESSION_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if _SESSION_ROOT not in sys.path:
    sys.path.insert(0, _SESSION_ROOT)

# ---------------------------------------------------------------------------
# Business + orchestration imports (resolved via sys.path above)
# ---------------------------------------------------------------------------
from git_cloner import CloneManager  # noqa: E402
from step6_tdd_green_phase import NVDCacheManager, NVDSyncError  # noqa: E402
from step9_tdd_green_phase_orchestration import (  # noqa: E402
    NVDSyncOrchestrator,
    ScanOrchestrator,
    ScanResult,
    SyncResult,
)


# ---------------------------------------------------------------------------
# Module-level singletons
# ---------------------------------------------------------------------------

def _make_nvd_cache_manager() -> NVDCacheManager:
    """
    Construct an NVDCacheManager backed by the configured DB path with a
    thread-safe SQLite connection (check_same_thread=False).
    """
    from step11_api.config import settings

    db_path = settings.NVD_CACHE_DB_PATH
    manager = NVDCacheManager(db_path=db_path)
    # Replace the default connection with a thread-safe one against the same path
    if manager._conn is not None:
        try:
            manager._conn.close()
        except Exception:
            pass
    manager._conn = sqlite3.connect(db_path, check_same_thread=False)
    manager._setup_schema()

    # If the DB is pre-seeded, hydrate _last_synced_at so /health and
    # /cache/status reflect the actual sync state on cold start.
    try:
        cur = manager._conn.cursor()
        cur.execute("SELECT MAX(synced_at) FROM sync_log")
        row = cur.fetchone()
        if row and row[0]:
            manager._last_synced_at = datetime.fromisoformat(row[0])
    except Exception:
        pass

    return manager


# Shared NVDCacheManager — one SQLite connection per process.
# Uses check_same_thread=False so it is safe across FastAPI worker threads.
_nvd_cache_manager: NVDCacheManager = _make_nvd_cache_manager()

# In-memory NVD cache dict consumed by ScanOrchestrator.run().
# Hydrated from the seeded DB at startup so /scans returns CVEs without
# requiring a /sync call first. POST /sync refreshes both the DB and dict.
_nvd_cache_dict: Dict[str, Any] = {}


def _hydrate_cache_dict_from_db(manager: NVDCacheManager, target: Dict[str, Any]) -> None:
    """Load all rows from the cache DB into the dict expected by ScanOrchestrator."""
    target.clear()
    try:
        cur = manager._conn.cursor()
        rows = cur.execute(
            "SELECT cve_id, purl, cpe, cvss_score, severity, fixed_version, advisory_url "
            "FROM vulnerabilities"
        ).fetchall()
    except Exception:
        return
    for cve_id, purl, cpe, cvss_score, severity, fixed_version, advisory_url in rows:
        entry = {
            "cve_id": cve_id,
            "cvss_score": cvss_score,
            "severity": severity,
            "fixed_version": fixed_version,
            "advisory_url": advisory_url,
        }
        if purl:
            target[purl] = entry
            target[purl.lower()] = entry  # case-insensitive PyPI PURLs
        if cpe:
            target[cpe] = entry

# Hydrate the in-memory cache dict from the seeded DB at startup.
_hydrate_cache_dict_from_db(_nvd_cache_manager, _nvd_cache_dict)

# In-memory scan result store keyed by scan_id UUID string.
# A production deployment would replace this with a persistent database.
_scan_store: Dict[str, Any] = {}


def _make_clone_manager() -> CloneManager:
    """Construct the CloneManager from settings, defaulting to <session_root>/clones."""
    from step11_api.config import settings

    workspace = settings.SBOM_CLONES_DIR or os.path.join(_SESSION_ROOT, "clones")
    return CloneManager(
        workspace_dir=workspace,
        clone_timeout_seconds=settings.SBOM_CLONE_TIMEOUT_SECONDS,
        max_bytes=settings.SBOM_MAX_CLONE_BYTES,
    )


# Shared CloneManager — manages all repos cloned via POST /scans (repo_url)
# and exposed/managed via /api/v1/repos.
_clone_manager: CloneManager = _make_clone_manager()


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def get_cache_status_dict() -> Dict[str, Any]:
    """
    Query the shared NVDCacheManager and return a plain dict matching the
    CacheStatusResponse schema.  Used by both the /cache/status and /health
    endpoints.
    """
    last: Optional[datetime] = _nvd_cache_manager._last_synced_at

    if last is None:
        last_synced_at_str: Optional[str] = None
        age_days: Optional[float] = None
        is_stale: bool = True
    else:
        last_synced_at_str = last.isoformat()
        now = datetime.now(timezone.utc)
        delta = now - last
        age_days = round(delta.total_seconds() / 86400, 2)
        is_stale = _nvd_cache_manager.is_stale(last)

    # Query total record count from the SQLite connection.
    try:
        cur = _nvd_cache_manager._conn.cursor()
        cur.execute("SELECT COUNT(*) FROM vulnerabilities")
        row = cur.fetchone()
        record_count: int = row[0] if row else 0
    except Exception:
        record_count = 0

    return {
        "last_synced_at": last_synced_at_str,
        "age_days": age_days,
        "is_stale": is_stale,
        "record_count": record_count,
    }


# ---------------------------------------------------------------------------
# Dependency-injection providers (used with FastAPI Depends())
# ---------------------------------------------------------------------------

def get_scan_orchestrator() -> Generator[ScanOrchestrator, None, None]:
    """
    Yields a ScanOrchestrator wired to the shared NVDCacheManager.
    A new orchestrator is created per-request so that state machines are
    fresh, but the underlying NVDCacheManager is shared.
    """
    orchestrator = ScanOrchestrator(nvd_cache_manager=_nvd_cache_manager)
    yield orchestrator


def get_sync_orchestrator() -> Generator[NVDSyncOrchestrator, None, None]:
    """
    Yields an NVDSyncOrchestrator backed by the shared NVDCacheManager.
    Calling run() on this orchestrator updates the shared manager's
    _last_synced_at and SQLite DB.
    """
    orchestrator = NVDSyncOrchestrator(cache_manager=_nvd_cache_manager)
    yield orchestrator


def get_nvd_cache_manager() -> Generator[NVDCacheManager, None, None]:
    """Yields the shared NVDCacheManager singleton."""
    yield _nvd_cache_manager


def get_nvd_cache_dict() -> Dict[str, Any]:
    """
    Returns the current in-memory NVD cache dict.
    This dict is populated by the /sync endpoint after a successful sync.
    For the POC, an empty dict means vulnerability lookup returns no matches.
    """
    return _nvd_cache_dict


def get_scan_store() -> Dict[str, Any]:
    """Returns the module-level scan result store (keyed by scan_id)."""
    return _scan_store


def get_clone_manager() -> CloneManager:
    """Returns the shared CloneManager singleton."""
    return _clone_manager


# ---------------------------------------------------------------------------
# API-key authentication
# ---------------------------------------------------------------------------

# Registered as a security scheme so FastAPI shows the "Authorize" button in
# Swagger and the lock icon on guarded routes. auto_error=False lets us
# implement the env-gated bypass (POC dev mode when API_KEY is unset).
_api_key_header = APIKeyHeader(
    name="X-API-Key",
    auto_error=False,
    description=(
        "Static shared API key. When the server is configured with an API_KEY "
        "env var, every endpoint except /health requires this header to match."
    ),
)

_auth_logger = logging.getLogger(__name__)


def require_api_key(provided_key: Optional[str] = Security(_api_key_header)) -> None:
    """
    FastAPI dependency: enforce X-API-Key header against settings.API_KEY.

    If API_KEY is unset/empty, auth is bypassed (POC dev mode) — a warning is
    emitted at first bypass so this isn't silently insecure in production.
    """
    from step11_api.config import settings

    expected = (settings.API_KEY or "").strip()
    if not expected:
        if not getattr(require_api_key, "_warned", False):
            _auth_logger.warning(
                "API_KEY is not set — all endpoints are unauthenticated. "
                "Set API_KEY in the environment to require X-API-Key."
            )
            require_api_key._warned = True  # type: ignore[attr-defined]
        return

    if not provided_key or provided_key != expected:
        raise HTTPException(
            status_code=401,
            detail={
                "error": "INVALID_API_KEY",
                "message": "Missing or invalid X-API-Key header.",
            },
        )
