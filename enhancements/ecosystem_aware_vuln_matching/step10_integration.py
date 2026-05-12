"""
Step 10 integration module for the `ecosystem_aware_vuln_matching` enhancement.

Public entry point: `get_enhanced_components()` returns a dict of all enhancement
classes/functions wired in a way that callers can drop into existing parent
workflows without modifying any parent session file.

Loading strategy: each module is loaded explicitly via
`importlib.util.spec_from_file_location`. This avoids the module-name shadowing
risk that `sys.path.insert` would create (e.g. the enhancement and parent both
have a file called `step9_tdd_green_phase_orchestration.py` — a path-based
import would resolve to whichever appears first on `sys.path`).
"""

from __future__ import annotations

import importlib.util
import pathlib
import sys
from types import ModuleType
from typing import Any

ENHANCEMENT_DIR = pathlib.Path(__file__).resolve().parent
PARENT_DIR = ENHANCEMENT_DIR.parent.parent

_MODULE_CACHE: dict[str, ModuleType] = {}


def _load_module(name: str, path: pathlib.Path) -> ModuleType:
    """Load a Python source file as a uniquely-named module, cached by `name`."""
    if name in _MODULE_CACHE:
        return _MODULE_CACHE[name]
    if not path.is_file():
        raise FileNotFoundError(f"Cannot load {name}: {path} does not exist")
    spec = importlib.util.spec_from_file_location(name, str(path))
    if spec is None or spec.loader is None:
        raise ImportError(f"Cannot create spec for {name} at {path}")
    module = importlib.util.module_from_spec(spec)
    # Register in sys.modules BEFORE exec — @dataclass and other decorators
    # introspect `sys.modules[cls.__module__]` during class definition.
    sys.modules[name] = module
    try:
        spec.loader.exec_module(module)
    except Exception:
        sys.modules.pop(name, None)
        raise
    _MODULE_CACHE[name] = module
    return module


def _load_parent_business() -> ModuleType:
    return _load_module(
        "_sbom_parent_business",
        PARENT_DIR / "step6_tdd_green_phase.py",
    )


def _load_parent_orchestration() -> ModuleType:
    return _load_module(
        "_sbom_parent_orchestration",
        PARENT_DIR / "step9_tdd_green_phase_orchestration.py",
    )


def _load_enhancement_business() -> ModuleType:
    return _load_module(
        "_sbom_enhancement_business",
        ENHANCEMENT_DIR / "step6_tdd_green_phase_business.py",
    )


def _load_enhancement_orchestration() -> ModuleType:
    return _load_module(
        "_sbom_enhancement_orchestration",
        ENHANCEMENT_DIR / "step9_tdd_green_phase_orchestration.py",
    )


def get_enhanced_components() -> dict[str, Any]:
    """
    Return a dict of all enhancement classes, exceptions, and helpers a caller
    needs to wire ecosystem-aware vulnerability matching into a scan workflow.

    Returned keys:
        # New business classes
        "EcosystemVulnerabilityMapper"
        "OSVCache"
        "GHSACache"
        "CPESanitizer"
        "OSVSyncResult"
        "OSVCacheNotSyncedError"
        "GHSACacheNotSyncedError"

        # Sanitizing serializers (subclasses of parent serializers)
        "CycloneDXSerializer"   # cpe_sanitize=True-capable
        "SPDXSerializer"        # cpe_sanitize=True-capable

        # New orchestrator (composition over parent ScanOrchestrator)
        "EcosystemScanOrchestrator"

        # Parent components re-exported for caller convenience
        "ParentScanOrchestrator"
        "ParentCycloneDXSerializer"
        "ParentSPDXSerializer"
        "WorkflowStateMachine"
        "ScanResult"
    """
    business = _load_enhancement_business()
    orchestration = _load_enhancement_orchestration()
    parent_business = _load_parent_business()
    parent_orchestration = _load_parent_orchestration()

    components: dict[str, Any] = {
        "EcosystemVulnerabilityMapper": business.EcosystemVulnerabilityMapper,
        "OSVCache": business.OSVCache,
        "GHSACache": business.GHSACache,
        "CPESanitizer": business.CPESanitizer,
        "OSVSyncResult": business.OSVSyncResult,
        "OSVCacheNotSyncedError": business.OSVCacheNotSyncedError,
        "GHSACacheNotSyncedError": business.GHSACacheNotSyncedError,
        "CycloneDXSerializer": business.CycloneDXSerializer,
        "SPDXSerializer": business.SPDXSerializer,
        "EcosystemScanOrchestrator": orchestration.EcosystemScanOrchestrator,
        "ParentScanOrchestrator": parent_orchestration.ScanOrchestrator,
        "ParentCycloneDXSerializer": parent_business.CycloneDXSerializer,
        "ParentSPDXSerializer": parent_business.SPDXSerializer,
        "WorkflowStateMachine": parent_orchestration.WorkflowStateMachine,
        "ScanResult": parent_orchestration.ScanResult,
    }
    return components


def build_default_orchestrator(
    nvd_cache: dict | None = None,
    osv_cache_path: str | None = None,
    ghsa_cache_path: str | None = None,
):
    """
    Convenience factory: build an `EcosystemScanOrchestrator` with sensible
    defaults. Caller still needs to call `.sync(source_path)` on the returned
    OSV/GHSA caches before the first `run_scan()` if they want those backends
    active (per the cache-sync-required-before-lookup business rule).

    Returns a tuple `(orchestrator, caches)` where `caches` is the dict
    `{"nvd": nvd_cache, "osv": OSVCache, "ghsa": GHSACache}` so the caller can
    `caches["osv"].sync("path/to/osv.json")` before invoking the orchestrator.
    """
    components = get_enhanced_components()

    osv_cache = components["OSVCache"](cache_path=osv_cache_path)
    ghsa_cache = components["GHSACache"](cache_path=ghsa_cache_path)
    caches = {
        "nvd": nvd_cache if nvd_cache is not None else {},
        "osv": osv_cache,
        "ghsa": ghsa_cache,
    }

    serializers = {
        "cyclonedx": components["CycloneDXSerializer"](cpe_sanitize=True),
        "spdx": components["SPDXSerializer"](cpe_sanitize=True),
    }
    orchestrator = components["EcosystemScanOrchestrator"](
        ecosystem_mapper=components["EcosystemVulnerabilityMapper"](),
        caches=caches,
        serializers=serializers,
    )
    return orchestrator, caches


__all__ = [
    "ENHANCEMENT_DIR",
    "PARENT_DIR",
    "get_enhanced_components",
    "build_default_orchestrator",
]
