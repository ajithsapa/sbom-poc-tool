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

import os
import sqlite3
import sys
from datetime import datetime, timezone
from typing import Any, Dict, Generator, Optional

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
    Construct an NVDCacheManager whose SQLite connection allows cross-thread
    access (check_same_thread=False).

    FastAPI route handlers run in worker threads while the TestClient (and
    some production async setups) may create the singleton in a different
    thread.  Replacing the default in-memory connection with one created using
    check_same_thread=False resolves the sqlite3.ProgrammingError that would
    otherwise surface in multi-threaded environments.

    We replace ._conn AFTER construction so that _setup_schema() has already
    created the nvd_cache table on the original connection; we then recreate
    it on the thread-safe connection.
    """
    manager = NVDCacheManager()
    # Replace the default connection with a thread-safe one
    if manager._conn is not None:
        try:
            manager._conn.close()
        except Exception:
            pass
    manager._conn = sqlite3.connect(":memory:", check_same_thread=False)
    # Re-create the schema on the new connection
    cur = manager._conn.cursor()
    cur.execute("""
        CREATE TABLE IF NOT EXISTS nvd_cache (
            cve_id TEXT NOT NULL,
            purl   TEXT NOT NULL,
            cvss_score REAL,
            PRIMARY KEY (cve_id, purl)
        )
    """)
    manager._conn.commit()
    return manager


# Shared NVDCacheManager — one SQLite connection per process.
# Uses check_same_thread=False so it is safe across FastAPI worker threads.
_nvd_cache_manager: NVDCacheManager = _make_nvd_cache_manager()

# In-memory NVD cache dict consumed by ScanOrchestrator.run().
# ScanOrchestrator.run() accepts a pre-built dict; for the POC an empty dict
# means vulnerability lookups return no matches until POST /sync is called.
_nvd_cache_dict: Dict[str, Any] = {}

# In-memory scan result store keyed by scan_id UUID string.
# A production deployment would replace this with a persistent database.
_scan_store: Dict[str, Any] = {}


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
        cur.execute("SELECT COUNT(*) FROM nvd_cache")
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
