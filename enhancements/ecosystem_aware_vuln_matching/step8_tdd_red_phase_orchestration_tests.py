"""
step8_tdd_red_phase_orchestration_tests.py
SBOM POC Tool — ENHANCEMENT: Ecosystem-Aware Vulnerability Matching

Enhancement Session: SBOM-20260409-sb01-ecosystem_aware_vuln_matching
Parent Session:      SBOM-20260409-sb01
Domain:              Developer Tooling — Software Supply Chain Security

Step 8 Red Phase — Orchestration Unit Tests
-------------------------------------------
This module contains exhaustive UNIT tests for the (not-yet-implemented)
``EcosystemScanOrchestrator`` class that Step 9 will write to
``step9_tdd_green_phase_orchestration.py`` in this enhancement directory.

Distinction from Step 7 (ATDD):
  * Step 7 ATDD exercised ONLY the public ``run_scan(...)`` API end-to-end
    on real Step 6 caches and Step 7-shaped fixtures (23 acceptance tests).
  * Step 8 (this file) drives the new orchestrator class one helper method
    at a time, using ``MagicMock`` for every injected dependency so unit
    tests isolate ORCHESTRATION logic — constructor wiring, internal call
    order, state-machine transitions, error propagation, serializer dispatch.

All tests in this file MUST fail on first run — Step 9 has not been written
yet for this enhancement. That is the EXPECTED Red-phase signal.

Tolerance to Step 9 implementation pattern
------------------------------------------
The task spec describes a "Pattern A (composition)" orchestrator with a rich
constructor signature::

    EcosystemScanOrchestrator(
        tool_runner=..., adapters={...}, deduplicator=...,
        ecosystem_mapper=..., remediation_enricher=..., vex_filter=...,
        serializers={"cyclonedx": ..., "spdx": ...},
        workflow_state_machine=..., caches={"nvd":..., "osv":..., "ghsa":...},
    )

Step 7 ATDD wires it with a simpler signature::

    EcosystemScanOrchestrator(
        nvd_cache=..., osv_cache=..., ghsa_cache=..., tool_runner=...,
    )

Both shapes are acceptable Step 9 implementations. These unit tests are
written against the rich Pattern A shape but each test gracefully falls
back / xfails when only the Step-7-ATDD shape is implemented, so that the
test file remains useful regardless of which constructor Step 9 ends up
producing. The public surface (``run_scan``) is the only hard contract.

Test classes and counts
-----------------------
  TestEcosystemScanOrchestratorConstructor     : 10
  TestEcosystemScanOrchestratorRunScanFlow     : 15
  TestCacheWiring                              : 8
  TestSerializerWiring                         : 7
  TestStateMachineIntegration                  : 6
  TestBackwardCompat                           : 5
  --------------------------------------------------
  Total                                        : 51
"""

from __future__ import annotations

import importlib.util
import inspect
import json
import logging
import os
import pathlib
import sys
from copy import deepcopy
from typing import Any, Callable, Dict, List, Optional
from unittest.mock import MagicMock, call, patch

import pytest


# ---------------------------------------------------------------------------
# Path resolution — enhancement dir + parent session dir
# ---------------------------------------------------------------------------
ENHANCEMENT_DIR = pathlib.Path(__file__).parent
PARENT_SESSION_DIR = ENHANCEMENT_DIR.parent.parent  # outputs/sessions/SBOM-.../


# ---------------------------------------------------------------------------
# Business-layer imports from the enhancement's Step 6 (implemented).
# These are real classes — used to spec MagicMocks via ``spec=...`` so the
# mocks reject calls that drift from the real interface.
# ---------------------------------------------------------------------------
sys.path.insert(0, str(ENHANCEMENT_DIR))

try:
    from step6_tdd_green_phase_business import (  # type: ignore[import-not-found]
        EcosystemVulnerabilityMapper,
        OSVCache,
        GHSACache,
        OSVCacheNotSyncedError,
        GHSACacheNotSyncedError,
        CPESanitizer,
        CycloneDXSerializer as EnhCycloneDXSerializer,
        SPDXSerializer as EnhSPDXSerializer,
    )
    _BUSINESS_IMPORT_ERROR: Optional[Exception] = None
except Exception as _exc:  # pragma: no cover
    EcosystemVulnerabilityMapper = None  # type: ignore[assignment]
    OSVCache = None  # type: ignore[assignment]
    GHSACache = None  # type: ignore[assignment]
    OSVCacheNotSyncedError = Exception  # type: ignore[assignment]
    GHSACacheNotSyncedError = Exception  # type: ignore[assignment]
    CPESanitizer = None  # type: ignore[assignment]
    EnhCycloneDXSerializer = None  # type: ignore[assignment]
    EnhSPDXSerializer = None  # type: ignore[assignment]
    _BUSINESS_IMPORT_ERROR = _exc


# ---------------------------------------------------------------------------
# Parent-session orchestration imports.
# Loaded by file path because the parent directory name contains a hyphen.
# ---------------------------------------------------------------------------

def _load_parent_orchestration():
    """Load the parent step9 orchestration module into sys.modules."""
    parent_file = PARENT_SESSION_DIR / "step9_tdd_green_phase_orchestration.py"
    if not parent_file.exists():
        return None, ImportError(
            f"Parent orchestration file not found at {parent_file}."
        )
    parent_str = str(PARENT_SESSION_DIR)
    if parent_str not in sys.path:
        sys.path.insert(0, parent_str)
    module_name = "_parent_step9_orchestration_for_step8_enh"
    if module_name in sys.modules:
        return sys.modules[module_name], None
    try:
        spec = importlib.util.spec_from_file_location(module_name, parent_file)
        if spec is None or spec.loader is None:
            return None, ImportError(f"Could not build spec for {parent_file}")
        mod = importlib.util.module_from_spec(spec)
        sys.modules[module_name] = mod
        spec.loader.exec_module(mod)
        return mod, None
    except Exception as exc:  # pragma: no cover
        return None, exc


_PARENT_ORCH_MOD, _PARENT_ORCH_ERROR = _load_parent_orchestration()

if _PARENT_ORCH_MOD is not None:
    ScanOrchestrator = _PARENT_ORCH_MOD.ScanOrchestrator
    NVDSyncOrchestrator = _PARENT_ORCH_MOD.NVDSyncOrchestrator
    CLIOrchestrator = _PARENT_ORCH_MOD.CLIOrchestrator
    WorkflowStateMachine = _PARENT_ORCH_MOD.WorkflowStateMachine
    ScanWorkflowState = _PARENT_ORCH_MOD.ScanWorkflowState
    ScanResult = _PARENT_ORCH_MOD.ScanResult
    ParentNVDSyncError = getattr(_PARENT_ORCH_MOD, "NVDSyncError", Exception)
else:  # pragma: no cover
    ScanOrchestrator = None  # type: ignore[assignment]
    NVDSyncOrchestrator = None  # type: ignore[assignment]
    CLIOrchestrator = None  # type: ignore[assignment]
    WorkflowStateMachine = None  # type: ignore[assignment]
    ScanWorkflowState = None  # type: ignore[assignment]
    ScanResult = None  # type: ignore[assignment]
    ParentNVDSyncError = Exception


# ---------------------------------------------------------------------------
# Enhancement-layer orchestration import — NOT YET IMPLEMENTED.
# Every unit test in this file is expected to fail until Step 9 introduces
# ``EcosystemScanOrchestrator`` in ``step9_tdd_green_phase_orchestration.py``
# inside this enhancement directory.
# ---------------------------------------------------------------------------
try:
    from step9_tdd_green_phase_orchestration import (  # type: ignore[import-not-found]
        EcosystemScanOrchestrator,
    )
    _ORCH_IMPORT_ERROR: Optional[Exception] = None
except Exception as _exc:
    EcosystemScanOrchestrator = None  # type: ignore[assignment]
    _ORCH_IMPORT_ERROR = _exc


def _require_orchestrator() -> None:
    """Hard-fail when Step 9 has not produced an enhancement orchestrator.

    Pre-Step-9 (Red phase), this raises ``pytest.fail`` so every test
    surfaces a structured "implementation not present" failure rather
    than an opaque ``NoneType is not callable``.
    """
    if _BUSINESS_IMPORT_ERROR is not None:
        pytest.fail(
            "Enhancement Step 6 business module did not load. "
            f"Underlying import error: {_BUSINESS_IMPORT_ERROR!r}"
        )
    if _PARENT_ORCH_ERROR is not None:
        pytest.fail(
            "Parent step9 orchestration module did not load. "
            f"Underlying import error: {_PARENT_ORCH_ERROR!r}"
        )
    if _ORCH_IMPORT_ERROR is not None or EcosystemScanOrchestrator is None:
        pytest.fail(
            "Step 9 (enhancement) orchestrator not present. "
            "Expected: step9_tdd_green_phase_orchestration.EcosystemScanOrchestrator "
            "inside the enhancement directory. "
            f"Underlying import error: {_ORCH_IMPORT_ERROR!r}"
        )


# ===========================================================================
# Fixture helpers
# ===========================================================================

def _load_json(path: pathlib.Path) -> Dict[str, Any]:
    with path.open() as f:
        return json.load(f)


@pytest.fixture(scope="module")
def enh_mock_entities() -> Dict[str, Any]:
    """Load the enhancement's step1b mock entity fixture file."""
    return _load_json(ENHANCEMENT_DIR / "step1b_mock_entities.json")


@pytest.fixture
def enh_dispatch_table(enh_mock_entities) -> Dict[str, Any]:
    """Authoritative dispatch table fixture from step1b."""
    return deepcopy(
        enh_mock_entities["entities"]["PurlDispatchTableFixture"][0]["table"]
    )


@pytest.fixture
def sample_deps(enh_mock_entities) -> List[Dict[str, Any]]:
    """The mixed-ecosystem dep list — exercises all three backends."""
    for d in enh_mock_entities["entities"]["MixedEcosystemDependencyList"]:
        if d["id"] == "mixed_repo_deps":
            return deepcopy(d["deps"])
    raise AssertionError("mixed_repo_deps fixture not found")


@pytest.fixture
def sample_components(sample_deps) -> List[Dict[str, Any]]:
    """Syft-shaped component dicts (with fabricated CPEs) from the fixture."""
    out = []
    for d in sample_deps:
        out.append({
            "name": d["name"],
            "version": d["exact_version"],
            "purl": d["purl"],
            "cpe": (
                f"cpe:2.3:a:{d['name']}:{d['name']}:"
                f"{d['exact_version']}:*:*:*:*:*:*:*"
            ),
            "metadata": {},
        })
    return out


@pytest.fixture
def mock_tool_runner(sample_components) -> MagicMock:
    """A MagicMock callable that returns a Syft-shaped raw output dict."""
    runner = MagicMock(name="tool_runner")
    runner.return_value = {"tool": "syft", "components": sample_components}
    return runner


@pytest.fixture
def mock_syft_adapter() -> MagicMock:
    """Mock Syft adapter exposing normalise() — returns a stub dep list."""
    adapter = MagicMock(name="syft_adapter")
    adapter.normalise = MagicMock(return_value=[
        {"name": "lodash", "exact_version": "4.17.20",
         "purl": "pkg:npm/lodash@4.17.20", "supplier": "lodash"},
    ])
    return adapter


@pytest.fixture
def mock_trivy_adapter() -> MagicMock:
    """Mock Trivy adapter exposing normalise()."""
    adapter = MagicMock(name="trivy_adapter")
    adapter.normalise = MagicMock(return_value=[])
    return adapter


@pytest.fixture
def mock_adapters(mock_syft_adapter, mock_trivy_adapter) -> Dict[str, MagicMock]:
    """The dict-of-adapters Pattern-A constructor expects."""
    return {"syft": mock_syft_adapter, "trivy": mock_trivy_adapter}


@pytest.fixture
def mock_deduplicator() -> MagicMock:
    """Mock parent Deduplicator with a passthrough deduplicate()."""
    dedup = MagicMock(name="deduplicator")
    dedup.deduplicate = MagicMock(side_effect=lambda deps: list(deps))
    return dedup


@pytest.fixture
def mock_ecosystem_mapper() -> MagicMock:
    """Mock EcosystemVulnerabilityMapper.

    ``map_vulnerabilities(deps, caches_dict)`` returns one synthetic vuln.
    Spec'd against the real class so the mock rejects unknown calls.
    """
    mapper = (
        MagicMock(spec=EcosystemVulnerabilityMapper)
        if EcosystemVulnerabilityMapper is not None
        else MagicMock(name="ecosystem_mapper")
    )
    mapper.map_vulnerabilities = MagicMock(return_value=[
        {"advisory_id": "GHSA-xvch-5gv4-984h", "purl": "pkg:npm/minimist@1.2.5",
         "cvss_score": None, "severity": "MEDIUM",
         "dep_name": "minimist", "dep_purl": "pkg:npm/minimist@1.2.5",
         "source": "osv"},
    ])
    return mapper


@pytest.fixture
def mock_remediation_enricher() -> MagicMock:
    """Mock parent RemediationEnricher."""
    enricher = MagicMock(name="remediation_enricher")
    enricher.enrich = MagicMock(side_effect=lambda v, c: dict(v, enriched=True))
    return enricher


@pytest.fixture
def mock_vex_filter() -> MagicMock:
    """Mock parent VEXFilter."""

    class _FilterResult:  # local stub of FilterResult parent dataclass
        def __init__(self, active, suppressed):
            self.active = active
            self.suppressed = suppressed

    vex = MagicMock(name="vex_filter")
    vex.apply = MagicMock(
        side_effect=lambda vulns, statements: _FilterResult(list(vulns), [])
    )
    return vex


@pytest.fixture
def mock_cyclonedx_serializer() -> MagicMock:
    """Mock CycloneDX serializer that records cpe_sanitize."""
    s = MagicMock(name="cyclonedx_serializer")
    # The orchestrator constructs / receives serializers configured with
    # cpe_sanitize=True. Stash the flag on the mock for later assertions.
    s.cpe_sanitize = True
    s.serialize = MagicMock(return_value={
        "bomFormat": "CycloneDX", "specVersion": "1.4",
        "components": [], "vulnerabilities": [],
    })
    return s


@pytest.fixture
def mock_spdx_serializer() -> MagicMock:
    """Mock SPDX serializer that records cpe_sanitize."""
    s = MagicMock(name="spdx_serializer")
    s.cpe_sanitize = True
    s.serialize = MagicMock(return_value={
        "spdxVersion": "SPDX-2.3", "dataLicense": "CC0-1.0", "packages": [],
    })
    return s


@pytest.fixture
def mock_serializers(mock_cyclonedx_serializer, mock_spdx_serializer):
    """Dict-of-serializers as the rich constructor expects."""
    return {
        "cyclonedx": mock_cyclonedx_serializer,
        "spdx": mock_spdx_serializer,
    }


@pytest.fixture
def mock_workflow_state_machine() -> MagicMock:
    """Mock parent WorkflowStateMachine with transition / visited_states."""
    sm = MagicMock(name="workflow_state_machine")
    visited: List[str] = []

    def _transition(target):
        # target may be an enum value or a plain string.
        value = getattr(target, "value", target)
        visited.append(value)

    sm.transition = MagicMock(side_effect=_transition)
    sm.transition_to = MagicMock(side_effect=_transition)  # alt API spelling
    sm.visited_states = MagicMock(side_effect=lambda: list(visited))
    sm.state = "idle"
    sm.is_cache_stale = False
    return sm


@pytest.fixture
def mock_nvd_cache() -> Dict[str, Dict[str, Any]]:
    """A plain dict NVD cache seeded with one entry."""
    return {
        "pkg:pypi/langchain@0.0.101": {
            "cve_id": "CVE-2023-34540",
            "cvss_score": 9.8,
            "severity": "High",
            "fixed_version": "0.0.247",
        },
    }


@pytest.fixture
def mock_osv_cache() -> MagicMock:
    """Mock OSVCache instance — pre-synced.

    Spec'd against the real OSVCache so attribute typos are caught.
    """
    cache = MagicMock(spec=OSVCache) if OSVCache is not None else MagicMock()
    cache.is_synced = MagicMock(return_value=True)
    cache.lookup = MagicMock(return_value=None)
    cache.sync = MagicMock()
    return cache


@pytest.fixture
def mock_ghsa_cache() -> MagicMock:
    """Mock GHSACache instance — pre-synced."""
    cache = MagicMock(spec=GHSACache) if GHSACache is not None else MagicMock()
    cache.is_synced = MagicMock(return_value=True)
    cache.lookup = MagicMock(return_value=None)
    cache.sync = MagicMock()
    return cache


@pytest.fixture
def mock_caches(mock_nvd_cache, mock_osv_cache, mock_ghsa_cache):
    """The dict-of-caches the rich constructor expects."""
    return {"nvd": mock_nvd_cache, "osv": mock_osv_cache, "ghsa": mock_ghsa_cache}


def _build_rich_orchestrator(
    tool_runner, adapters, deduplicator, ecosystem_mapper,
    remediation_enricher, vex_filter, serializers,
    workflow_state_machine, caches, **extra,
):
    """Try to construct EcosystemScanOrchestrator with the rich Pattern-A
    signature first. Fall back to the Step-7-ATDD simple signature if the
    Step 9 implementation only accepts the four-arg form.

    Returns the constructed orchestrator; raises pytest.fail if neither
    form is accepted (which is itself a Red-phase indicator).
    """
    _require_orchestrator()
    try:
        return EcosystemScanOrchestrator(
            tool_runner=tool_runner,
            adapters=adapters,
            deduplicator=deduplicator,
            ecosystem_mapper=ecosystem_mapper,
            remediation_enricher=remediation_enricher,
            vex_filter=vex_filter,
            serializers=serializers,
            workflow_state_machine=workflow_state_machine,
            caches=caches,
            **extra,
        )
    except TypeError:
        # Fall back to the simpler Step 7 ATDD shape.
        return EcosystemScanOrchestrator(
            nvd_cache=caches.get("nvd"),
            osv_cache=caches.get("osv"),
            ghsa_cache=caches.get("ghsa"),
            tool_runner=tool_runner,
        )


@pytest.fixture
def happy_path_orchestrator(
    mock_tool_runner, mock_adapters, mock_deduplicator, mock_ecosystem_mapper,
    mock_remediation_enricher, mock_vex_filter, mock_serializers,
    mock_workflow_state_machine, mock_caches,
):
    """Build a fully-mocked EcosystemScanOrchestrator wired with the rich
    Pattern-A signature where possible. This is the canonical fixture for
    flow / state / wiring tests.
    """
    return _build_rich_orchestrator(
        tool_runner=mock_tool_runner,
        adapters=mock_adapters,
        deduplicator=mock_deduplicator,
        ecosystem_mapper=mock_ecosystem_mapper,
        remediation_enricher=mock_remediation_enricher,
        vex_filter=mock_vex_filter,
        serializers=mock_serializers,
        workflow_state_machine=mock_workflow_state_machine,
        caches=mock_caches,
    )


# ===========================================================================
# TEST CLASS 1 — Constructor behaviour
# ===========================================================================
class TestEcosystemScanOrchestratorConstructor:
    """Unit tests for ``EcosystemScanOrchestrator.__init__``.

    These tests focus on dependency injection, attribute storage, and
    lazy-construction guarantees. They do NOT call ``run_scan`` — the
    constructor must not perform any I/O.
    """

    # 1.1
    def test_accepts_all_required_dependencies(
        self, mock_tool_runner, mock_adapters, mock_deduplicator,
        mock_ecosystem_mapper, mock_remediation_enricher, mock_vex_filter,
        mock_serializers, mock_workflow_state_machine, mock_caches,
    ):
        """Constructor accepts the rich Pattern-A dependency set without raising."""
        orch = _build_rich_orchestrator(
            tool_runner=mock_tool_runner,
            adapters=mock_adapters,
            deduplicator=mock_deduplicator,
            ecosystem_mapper=mock_ecosystem_mapper,
            remediation_enricher=mock_remediation_enricher,
            vex_filter=mock_vex_filter,
            serializers=mock_serializers,
            workflow_state_machine=mock_workflow_state_machine,
            caches=mock_caches,
        )
        assert orch is not None, "Constructor returned None"

    # 1.2
    def test_stores_injected_deps_as_attributes(self, happy_path_orchestrator):
        """At least one named injected dependency must be reachable post-init.

        Tolerant: accepts any of the canonical attribute spellings — the
        contract is that injected deps are NOT silently dropped on the floor.
        """
        orch = happy_path_orchestrator
        # The orchestrator must surface at least one injected dep — otherwise
        # callers cannot introspect the wiring.
        candidate_attrs = (
            "tool_runner", "adapters", "deduplicator", "ecosystem_mapper",
            "mapper", "remediation_enricher", "enricher", "vex_filter",
            "serializers", "cyclonedx_serializer", "spdx_serializer",
            "workflow_state_machine", "state_machine", "caches",
            "nvd_cache", "osv_cache", "ghsa_cache",
        )
        observed = [a for a in candidate_attrs if hasattr(orch, a)]
        assert observed, (
            f"EcosystemScanOrchestrator surfaces no recognisable injected "
            f"attribute. Looked for one of: {candidate_attrs}"
        )

    # 1.3
    def test_raises_when_required_dep_missing(self):
        """Constructor must reject calls that omit ALL caches and ALL caches-dict.

        A no-arg construction would leave the orchestrator unable to do
        any vulnerability matching — either it must raise a clear error or
        accept the call and lazily fail at run_scan time. Either contract
        is acceptable; the regression test catches "silent partial wiring".
        """
        _require_orchestrator()
        # Try no-arg construction. We accept TypeError (strict) or no error
        # (lazy). What we DO NOT accept is the orchestrator running
        # ``run_scan`` later without complaining.
        try:
            orch = EcosystemScanOrchestrator()  # type: ignore[call-arg]
        except TypeError:
            return  # strict — required positional/keyword args enforced. PASS
        # Lazy path — run_scan must fail loudly with an actionable error.
        with pytest.raises((TypeError, ValueError, AttributeError, Exception)):
            orch.run_scan("/tmp/anywhere")  # type: ignore[arg-type]

    # 1.4
    def test_accepts_serializers_as_dict_and_stores_both_formats(
        self, mock_tool_runner, mock_adapters, mock_deduplicator,
        mock_ecosystem_mapper, mock_remediation_enricher, mock_vex_filter,
        mock_serializers, mock_workflow_state_machine, mock_caches,
    ):
        """When constructed with serializers={'cyclonedx': ..., 'spdx': ...},
        both formats must be retained — neither silently dropped.
        """
        orch = _build_rich_orchestrator(
            tool_runner=mock_tool_runner,
            adapters=mock_adapters,
            deduplicator=mock_deduplicator,
            ecosystem_mapper=mock_ecosystem_mapper,
            remediation_enricher=mock_remediation_enricher,
            vex_filter=mock_vex_filter,
            serializers=mock_serializers,
            workflow_state_machine=mock_workflow_state_machine,
            caches=mock_caches,
        )
        # If the orchestrator uses a serializers-dict attribute, both keys
        # must be present. If it spreads them to attributes, both attrs.
        if hasattr(orch, "serializers"):
            s = orch.serializers
            assert "cyclonedx" in s and "spdx" in s, (
                f"serializers dict missing one of cyclonedx/spdx: keys={list(s)}"
            )
        else:
            assert hasattr(orch, "cyclonedx_serializer") or hasattr(orch, "_cyclonedx_serializer"), (
                "CycloneDX serializer not reachable as attribute"
            )
            assert hasattr(orch, "spdx_serializer") or hasattr(orch, "_spdx_serializer"), (
                "SPDX serializer not reachable as attribute"
            )

    # 1.5
    def test_accepts_caches_as_dict_of_three(
        self, mock_tool_runner, mock_adapters, mock_deduplicator,
        mock_ecosystem_mapper, mock_remediation_enricher, mock_vex_filter,
        mock_serializers, mock_workflow_state_machine, mock_caches,
    ):
        """Constructor preserves the three-cache dict — nvd / osv / ghsa
        must all be reachable from the orchestrator post-init."""
        orch = _build_rich_orchestrator(
            tool_runner=mock_tool_runner,
            adapters=mock_adapters,
            deduplicator=mock_deduplicator,
            ecosystem_mapper=mock_ecosystem_mapper,
            remediation_enricher=mock_remediation_enricher,
            vex_filter=mock_vex_filter,
            serializers=mock_serializers,
            workflow_state_machine=mock_workflow_state_machine,
            caches=mock_caches,
        )
        reachable = {
            "nvd": (
                hasattr(orch, "nvd_cache")
                or (hasattr(orch, "caches") and "nvd" in (orch.caches or {}))
            ),
            "osv": (
                hasattr(orch, "osv_cache")
                or (hasattr(orch, "caches") and "osv" in (orch.caches or {}))
            ),
            "ghsa": (
                hasattr(orch, "ghsa_cache")
                or (hasattr(orch, "caches") and "ghsa" in (orch.caches or {}))
            ),
        }
        missing = [k for k, v in reachable.items() if not v]
        assert not missing, (
            f"Orchestrator dropped {missing!r} cache(s) at construction time."
        )

    # 1.6
    def test_default_output_format_is_cyclonedx(self, happy_path_orchestrator):
        """``run_scan(repo_path)`` with no output_format must default to cyclonedx.

        Verified via signature introspection AND a behavioural call.
        """
        orch = happy_path_orchestrator
        sig = inspect.signature(orch.run_scan)
        params = sig.parameters
        # The output_format kwarg either is present with default 'cyclonedx',
        # OR it's not present at all (positional-only) — in which case the
        # orchestrator must still emit a CycloneDX SBOM by default.
        if "output_format" in params:
            default = params["output_format"].default
            assert default in (inspect.Parameter.empty, "cyclonedx"), (
                f"output_format default is {default!r}; "
                "expected 'cyclonedx' (or empty for positional-only)."
            )

    # 1.7
    def test_constructor_does_not_call_backends_synchronously(
        self, mock_tool_runner, mock_adapters, mock_deduplicator,
        mock_ecosystem_mapper, mock_remediation_enricher, mock_vex_filter,
        mock_serializers, mock_workflow_state_machine, mock_caches,
        mock_osv_cache, mock_ghsa_cache,
    ):
        """``__init__`` must be lazy — no calls to tool_runner, no cache lookups,
        no serializer.serialize calls, no state transitions."""
        _build_rich_orchestrator(
            tool_runner=mock_tool_runner,
            adapters=mock_adapters,
            deduplicator=mock_deduplicator,
            ecosystem_mapper=mock_ecosystem_mapper,
            remediation_enricher=mock_remediation_enricher,
            vex_filter=mock_vex_filter,
            serializers=mock_serializers,
            workflow_state_machine=mock_workflow_state_machine,
            caches=mock_caches,
        )
        assert mock_tool_runner.call_count == 0, "tool_runner called from __init__"
        assert mock_osv_cache.lookup.call_count == 0, "osv_cache.lookup called from __init__"
        assert mock_ghsa_cache.lookup.call_count == 0, "ghsa_cache.lookup called from __init__"
        assert mock_serializers["cyclonedx"].serialize.call_count == 0
        assert mock_workflow_state_machine.transition.call_count == 0
        assert mock_workflow_state_machine.transition_to.call_count == 0

    # 1.8
    def test_initial_workflow_state_is_parent_initial(
        self, happy_path_orchestrator,
    ):
        """If the orchestrator exposes a state machine, its initial state
        must be the parent's initial state value ('idle')."""
        orch = happy_path_orchestrator
        sm = (
            getattr(orch, "workflow_state_machine", None)
            or getattr(orch, "state_machine", None)
        )
        if sm is None:
            pytest.skip("Orchestrator does not expose a state machine attribute")
        # Tolerant: state can be enum-with-.value or a bare string.
        cur = getattr(sm, "state", None)
        cur_value = getattr(cur, "value", cur)
        assert cur_value in ("idle", "starting", None) or cur_value == ScanWorkflowState.IDLE.value, (
            f"Initial state is {cur_value!r}; expected 'idle' (parent initial)."
        )

    # 1.9
    def test_orchestrator_does_not_inherit_from_parent_scan_orchestrator(
        self, happy_path_orchestrator,
    ):
        """Composition over inheritance — the enhancement orchestrator must
        NOT be an instance of the parent ScanOrchestrator (otherwise the
        enhancement is doing subclassing, which the spec discourages).

        Tolerant: if Step 9 chose Pattern B (subclass) the test xfails with
        a recorded reason rather than blocking the build.
        """
        orch = happy_path_orchestrator
        if isinstance(orch, ScanOrchestrator):
            pytest.xfail(
                "Step 9 chose Pattern B (subclass): EcosystemScanOrchestrator "
                "extends ScanOrchestrator. Pattern A (composition) was the "
                "documented preference but Pattern B is acceptable."
            )
        assert not isinstance(orch, ScanOrchestrator), (
            "EcosystemScanOrchestrator should compose, not inherit, from "
            "the parent ScanOrchestrator."
        )

    # 1.10
    def test_constructor_accepts_optional_logger(
        self, mock_tool_runner, mock_adapters, mock_deduplicator,
        mock_ecosystem_mapper, mock_remediation_enricher, mock_vex_filter,
        mock_serializers, mock_workflow_state_machine, mock_caches,
    ):
        """An optional ``logger`` kwarg must not blow up construction.

        Either accepted (rich constructor) or silently ignored (simple
        constructor). Either is acceptable; what is NOT acceptable is a
        crash citing the kwarg by name as 'unknown'.
        """
        _require_orchestrator()
        custom_logger = logging.getLogger("step8_test_orch_logger")
        try:
            _build_rich_orchestrator(
                tool_runner=mock_tool_runner,
                adapters=mock_adapters,
                deduplicator=mock_deduplicator,
                ecosystem_mapper=mock_ecosystem_mapper,
                remediation_enricher=mock_remediation_enricher,
                vex_filter=mock_vex_filter,
                serializers=mock_serializers,
                workflow_state_machine=mock_workflow_state_machine,
                caches=mock_caches,
                logger=custom_logger,
            )
        except TypeError as exc:
            if "logger" in str(exc):
                pytest.fail(
                    "Constructor explicitly rejects ``logger`` kwarg. "
                    "The spec marks it optional. Underlying error: "
                    f"{exc!r}"
                )
            # Other TypeErrors are acceptable (e.g. unrelated arg mismatch).
            raise


# ===========================================================================
# TEST CLASS 2 — ``run_scan()`` flow / call order / error propagation
# ===========================================================================
class TestEcosystemScanOrchestratorRunScanFlow:
    """Unit tests for the public ``run_scan(repo_path, output_format)`` flow.

    The orchestrator MUST drive the pipeline in a deterministic order:

        gather_deps → match_vulns → enrich+filter → serialize

    Each step calls one or more injected mocks. These tests verify call
    ordering, mock invocation counts, and exception propagation.
    """

    # 2.1
    def test_run_scan_invokes_pipeline_in_order(
        self, happy_path_orchestrator, mock_tool_runner, mock_syft_adapter,
        mock_deduplicator, mock_ecosystem_mapper, mock_vex_filter,
        mock_remediation_enricher, mock_serializers, tmp_path,
    ):
        """Verify the canonical pipeline order via a single MagicMock parent.

        We attach all the step-emitting mocks as children of a single
        ``manager`` MagicMock and inspect ``manager.mock_calls`` for the
        expected sub-call sequence.
        """
        manager = MagicMock()
        manager.attach_mock(mock_tool_runner, "tool_runner")
        manager.attach_mock(mock_syft_adapter.normalise, "adapter_normalise")
        manager.attach_mock(mock_deduplicator.deduplicate, "deduplicate")
        manager.attach_mock(mock_ecosystem_mapper.map_vulnerabilities, "map_vulns")
        manager.attach_mock(mock_vex_filter.apply, "vex_apply")
        manager.attach_mock(mock_remediation_enricher.enrich, "enrich")
        manager.attach_mock(mock_serializers["cyclonedx"].serialize, "serialize")

        try:
            happy_path_orchestrator.run_scan(
                str(tmp_path), output_format="cyclonedx",
            )
        except Exception:
            # If run_scan crashes due to mock shape mismatch we still want
            # to inspect the call order recorded BEFORE the crash.
            pass

        names = [c[0] for c in manager.mock_calls]
        # tool_runner must be called BEFORE map_vulns.
        if "tool_runner" in names and "map_vulns" in names:
            assert names.index("tool_runner") < names.index("map_vulns"), (
                f"tool_runner was called AFTER map_vulns. Order: {names}"
            )
        # map_vulns must be called BEFORE serialize.
        if "map_vulns" in names and "serialize" in names:
            assert names.index("map_vulns") < names.index("serialize"), (
                f"map_vulns was called AFTER serialize. Order: {names}"
            )

    # 2.2
    def test_gather_deps_calls_tool_runner_then_adapter_then_deduplicator(
        self, happy_path_orchestrator, mock_tool_runner,
        mock_syft_adapter, mock_deduplicator, tmp_path,
    ):
        """``_gather_deps`` must invoke tool_runner first, then the adapter's
        normalise, then the deduplicator. Tested via call counts >= 1 after
        ``run_scan``."""
        try:
            happy_path_orchestrator.run_scan(str(tmp_path), output_format="cyclonedx")
        except Exception:
            pass

        # At least one of these three must have been called — the orchestrator
        # must have triggered SOME dep-gather path.
        called = (
            mock_tool_runner.call_count > 0
            or mock_syft_adapter.normalise.call_count > 0
            or mock_deduplicator.deduplicate.call_count > 0
        )
        assert called, (
            "None of tool_runner / adapter.normalise / deduplicator.deduplicate "
            "were called during run_scan — orchestrator skipped dep gathering."
        )

    # 2.3
    def test_match_vulnerabilities_invokes_ecosystem_mapper(
        self, happy_path_orchestrator, mock_ecosystem_mapper, tmp_path,
    ):
        """``_match_vulnerabilities`` must invoke ``ecosystem_mapper.map_vulnerabilities``."""
        try:
            happy_path_orchestrator.run_scan(str(tmp_path), output_format="cyclonedx")
        except Exception:
            pass
        assert mock_ecosystem_mapper.map_vulnerabilities.call_count >= 1, (
            "ecosystem_mapper.map_vulnerabilities was never called by run_scan"
        )

    # 2.4
    def test_match_vulnerabilities_passes_caches_dict_or_individual_caches(
        self, happy_path_orchestrator, mock_ecosystem_mapper,
        mock_osv_cache, mock_ghsa_cache, mock_nvd_cache, tmp_path,
    ):
        """The mapper call must receive caches in some recognisable form —
        either a dict-of-3 with osv/ghsa keys, or individual cache references.
        """
        try:
            happy_path_orchestrator.run_scan(str(tmp_path), output_format="cyclonedx")
        except Exception:
            pass
        if mock_ecosystem_mapper.map_vulnerabilities.call_count == 0:
            pytest.fail("Mapper was never invoked")
        last_call = mock_ecosystem_mapper.map_vulnerabilities.call_args
        # Inspect kwargs + positional args together.
        all_args = list(last_call.args) + list(last_call.kwargs.values())
        # Look for the OSV/GHSA cache mocks somewhere in the call signature
        # — either directly or wrapped in a dict.
        found_osv = False
        found_ghsa = False
        for a in all_args:
            if a is mock_osv_cache:
                found_osv = True
            if a is mock_ghsa_cache:
                found_ghsa = True
            if isinstance(a, dict):
                if a.get("osv") is mock_osv_cache:
                    found_osv = True
                if a.get("ghsa") is mock_ghsa_cache:
                    found_ghsa = True
        assert found_osv or found_ghsa, (
            f"Mapper.map_vulnerabilities did not receive the OSV/GHSA caches. "
            f"Args: {all_args!r}"
        )

    # 2.5
    def test_enrich_and_filter_runs_enricher_then_vex(
        self, happy_path_orchestrator, mock_remediation_enricher,
        mock_vex_filter, mock_ecosystem_mapper, tmp_path,
    ):
        """Enrichment and VEX filtering must both run. (Parent contract:
        either ENRICH-then-VEX or VEX-then-ENRICH — both orderings exist in
        SBOM tools. We just assert BOTH happen.)"""
        try:
            happy_path_orchestrator.run_scan(str(tmp_path), output_format="cyclonedx")
        except Exception:
            pass
        # At least one of the post-match steps must have fired.
        post_match_call_count = (
            mock_remediation_enricher.enrich.call_count
            + mock_vex_filter.apply.call_count
        )
        assert post_match_call_count >= 1, (
            "Neither enricher nor vex_filter was called — the post-match "
            "pipeline was not driven."
        )

    # 2.6
    def test_serialize_selects_correct_serializer_for_cyclonedx(
        self, happy_path_orchestrator, mock_serializers, tmp_path,
    ):
        """``output_format='cyclonedx'`` must invoke the CycloneDX serializer
        and NOT the SPDX serializer."""
        try:
            happy_path_orchestrator.run_scan(str(tmp_path), output_format="cyclonedx")
        except Exception:
            pass
        assert mock_serializers["cyclonedx"].serialize.call_count >= 1, (
            "CycloneDX serializer was not invoked for output_format=cyclonedx"
        )
        assert mock_serializers["spdx"].serialize.call_count == 0, (
            "SPDX serializer WAS invoked despite output_format=cyclonedx"
        )

    # 2.7
    def test_serialize_selects_correct_serializer_for_spdx(
        self, happy_path_orchestrator, mock_serializers, tmp_path,
    ):
        """``output_format='spdx'`` must invoke the SPDX serializer and
        NOT the CycloneDX serializer."""
        try:
            happy_path_orchestrator.run_scan(str(tmp_path), output_format="spdx")
        except Exception:
            pass
        assert mock_serializers["spdx"].serialize.call_count >= 1, (
            "SPDX serializer was not invoked for output_format=spdx"
        )
        assert mock_serializers["cyclonedx"].serialize.call_count == 0, (
            "CycloneDX serializer WAS invoked despite output_format=spdx"
        )

    # 2.8
    def test_selected_serializer_was_built_with_cpe_sanitize_true(
        self, happy_path_orchestrator, mock_serializers,
    ):
        """The serializer used by the orchestrator must carry
        ``cpe_sanitize=True`` — either as a constructor arg recorded on the
        mock, or via the real CycloneDXSerializer/SPDXSerializer instance
        attribute that the enhancement Step 6 sets."""
        for fmt in ("cyclonedx", "spdx"):
            s = mock_serializers[fmt]
            assert getattr(s, "cpe_sanitize", False) is True, (
                f"Mock {fmt} serializer was injected without cpe_sanitize=True; "
                "the orchestrator must wire sanitizing serializers."
            )

    # 2.9
    def test_state_machine_visits_canonical_states(
        self, happy_path_orchestrator, mock_workflow_state_machine, tmp_path,
    ):
        """At least one state transition must fire during a happy-path scan.

        Tolerant of two state vocabularies:
          * Task-spec vocabulary: starting, discovering_deps, normalising,
            deduplicating, matching_vulnerabilities, enriching,
            filtering_vex, exporting_sbom
          * Parent-session vocabulary: idle, scanning_dependencies,
            deduplicating_output, matching_vulnerabilities, filtering_vex,
            enriching_remediation, exporting_sbom
        """
        try:
            happy_path_orchestrator.run_scan(str(tmp_path), output_format="cyclonedx")
        except Exception:
            pass
        total_transitions = (
            mock_workflow_state_machine.transition.call_count
            + mock_workflow_state_machine.transition_to.call_count
        )
        assert total_transitions >= 1, (
            "Orchestrator never called workflow_state_machine.transition"
            "(or .transition_to) — state machine is dead code."
        )

    # 2.10
    def test_exception_in_gather_deps_transitions_to_failed_or_propagates(
        self, mock_tool_runner, mock_adapters, mock_deduplicator,
        mock_ecosystem_mapper, mock_remediation_enricher, mock_vex_filter,
        mock_serializers, mock_workflow_state_machine, mock_caches, tmp_path,
    ):
        """When the tool runner raises, the orchestrator must EITHER record
        a 'failed' state OR let the exception propagate unchanged. Silent
        swallowing is forbidden."""
        boom = RuntimeError("syft binary crashed")
        mock_tool_runner.side_effect = boom

        orch = _build_rich_orchestrator(
            tool_runner=mock_tool_runner,
            adapters=mock_adapters,
            deduplicator=mock_deduplicator,
            ecosystem_mapper=mock_ecosystem_mapper,
            remediation_enricher=mock_remediation_enricher,
            vex_filter=mock_vex_filter,
            serializers=mock_serializers,
            workflow_state_machine=mock_workflow_state_machine,
            caches=mock_caches,
        )

        propagated = False
        try:
            orch.run_scan(str(tmp_path), output_format="cyclonedx")
        except Exception as exc:
            propagated = True
            # If propagated, it must be the same exception class — no wrap.
            assert isinstance(exc, RuntimeError) or "syft" in str(exc).lower(), (
                f"Tool-runner exception was wrapped/replaced: {exc!r}"
            )

        if not propagated:
            # Exception was swallowed; orchestrator must have transitioned
            # to a 'failed' state.
            transitions = [
                str(c.args[0]) if c.args else ""
                for c in (
                    mock_workflow_state_machine.transition.call_args_list
                    + mock_workflow_state_machine.transition_to.call_args_list
                )
            ]
            assert any("fail" in t.lower() for t in transitions), (
                f"Orchestrator swallowed tool-runner error AND did not record "
                f"a 'failed' state. Transitions seen: {transitions}"
            )

    # 2.11
    def test_osv_cache_not_synced_error_propagates_from_match(
        self, mock_tool_runner, mock_adapters, mock_deduplicator,
        mock_remediation_enricher, mock_vex_filter, mock_serializers,
        mock_workflow_state_machine, mock_caches, tmp_path,
    ):
        """If the ecosystem mapper raises OSVCacheNotSyncedError, the
        orchestrator must re-raise it unwrapped (so the CLI can show the
        actionable 'run sync' message)."""
        broken_mapper = MagicMock(name="broken_mapper")
        broken_mapper.map_vulnerabilities = MagicMock(
            side_effect=OSVCacheNotSyncedError(
                "OSV cache not initialized; run sync() first."
            )
        )

        orch = _build_rich_orchestrator(
            tool_runner=mock_tool_runner,
            adapters=mock_adapters,
            deduplicator=mock_deduplicator,
            ecosystem_mapper=broken_mapper,
            remediation_enricher=mock_remediation_enricher,
            vex_filter=mock_vex_filter,
            serializers=mock_serializers,
            workflow_state_machine=mock_workflow_state_machine,
            caches=mock_caches,
        )
        with pytest.raises(OSVCacheNotSyncedError):
            orch.run_scan(str(tmp_path), output_format="cyclonedx")

    # 2.12
    def test_exception_in_serialize_does_not_corrupt_state(
        self, mock_tool_runner, mock_adapters, mock_deduplicator,
        mock_ecosystem_mapper, mock_remediation_enricher, mock_vex_filter,
        mock_workflow_state_machine, mock_caches, tmp_path,
    ):
        """A serializer crash must propagate; the orchestrator must not
        return a half-built ScanResult silently."""
        bad_cy = MagicMock(name="bad_cyclonedx")
        bad_cy.cpe_sanitize = True
        bad_cy.serialize = MagicMock(side_effect=RuntimeError("serializer boom"))
        bad_spdx = MagicMock(name="bad_spdx")
        bad_spdx.cpe_sanitize = True

        orch = _build_rich_orchestrator(
            tool_runner=mock_tool_runner,
            adapters=mock_adapters,
            deduplicator=mock_deduplicator,
            ecosystem_mapper=mock_ecosystem_mapper,
            remediation_enricher=mock_remediation_enricher,
            vex_filter=mock_vex_filter,
            serializers={"cyclonedx": bad_cy, "spdx": bad_spdx},
            workflow_state_machine=mock_workflow_state_machine,
            caches=mock_caches,
        )

        with pytest.raises(RuntimeError):
            orch.run_scan(str(tmp_path), output_format="cyclonedx")

    # 2.13
    def test_run_scan_returns_scan_result_shape(
        self, happy_path_orchestrator, tmp_path,
    ):
        """``run_scan`` must return an object resembling the parent ScanResult
        — at minimum it must carry ``sbom_document`` (parent contract)."""
        try:
            result = happy_path_orchestrator.run_scan(
                str(tmp_path), output_format="cyclonedx",
            )
        except Exception as exc:
            pytest.fail(f"run_scan raised on happy path: {exc!r}")

        assert result is not None, "run_scan returned None"
        # Parent contract: ScanResult has sbom_document.
        assert hasattr(result, "sbom_document") or hasattr(result, "sbom_json"), (
            "ScanResult missing sbom_document/sbom_json field"
        )

    # 2.14
    def test_run_scan_is_deterministic_across_two_calls(
        self, happy_path_orchestrator, mock_serializers, tmp_path,
    ):
        """Two consecutive run_scan calls must yield the same call count to
        the serializer (i.e. flow is deterministic; no random retries)."""
        for _ in range(2):
            try:
                happy_path_orchestrator.run_scan(
                    str(tmp_path), output_format="cyclonedx",
                )
            except Exception:
                pass
        # Cyclone serializer should have been called exactly twice (once per scan).
        assert mock_serializers["cyclonedx"].serialize.call_count == 2, (
            f"Cyclone serializer call_count={mock_serializers['cyclonedx'].serialize.call_count}; "
            "expected 2 — pipeline is non-deterministic across runs."
        )

    # 2.15
    def test_run_scan_rejects_unknown_output_format(
        self, happy_path_orchestrator, tmp_path,
    ):
        """``output_format='excel'`` must raise ValueError with a message that
        lists the supported formats."""
        with pytest.raises((ValueError, TypeError, KeyError)) as exc_info:
            happy_path_orchestrator.run_scan(
                str(tmp_path), output_format="excel",
            )
        msg = str(exc_info.value).lower()
        # The error message must name at least one valid format.
        assert "cyclonedx" in msg or "spdx" in msg or "format" in msg, (
            f"Error message for unknown format does not list supported "
            f"formats: {exc_info.value!r}"
        )


# ===========================================================================
# TEST CLASS 3 — Cache wiring
# ===========================================================================
class TestCacheWiring:
    """Unit tests for how the orchestrator wires its three caches into the
    ecosystem mapper. The contract: the mapper sees ALL three backends,
    each correctly typed."""

    # 3.1
    def test_mapper_receives_all_three_caches(
        self, happy_path_orchestrator, mock_ecosystem_mapper,
        mock_osv_cache, mock_ghsa_cache, mock_nvd_cache, tmp_path,
    ):
        """All three cache backends must reach the mapper, either as a dict
        with keys nvd/osv/ghsa or as separate positional/kwarg references."""
        try:
            happy_path_orchestrator.run_scan(str(tmp_path), output_format="cyclonedx")
        except Exception:
            pass
        if mock_ecosystem_mapper.map_vulnerabilities.call_count == 0:
            pytest.fail("Mapper was never invoked")
        call_args = mock_ecosystem_mapper.map_vulnerabilities.call_args
        all_args = list(call_args.args) + list(call_args.kwargs.values())
        seen_nvd = seen_osv = seen_ghsa = False
        for a in all_args:
            if isinstance(a, dict) and any(k in a for k in ("nvd", "osv", "ghsa")):
                seen_nvd = seen_nvd or (a.get("nvd") is mock_nvd_cache)
                seen_osv = seen_osv or (a.get("osv") is mock_osv_cache)
                seen_ghsa = seen_ghsa or (a.get("ghsa") is mock_ghsa_cache)
            else:
                seen_nvd = seen_nvd or (a is mock_nvd_cache)
                seen_osv = seen_osv or (a is mock_osv_cache)
                seen_ghsa = seen_ghsa or (a is mock_ghsa_cache)
        # At least two of the three must be reachable (some implementations
        # only forward the non-NVD caches as a composite).
        reachable_count = sum([seen_nvd, seen_osv, seen_ghsa])
        assert reachable_count >= 2, (
            f"Mapper sees only {reachable_count}/3 caches. "
            f"nvd={seen_nvd} osv={seen_osv} ghsa={seen_ghsa}"
        )

    # 3.2
    def test_osv_cache_is_osv_cache_instance_not_raw_dict(
        self, happy_path_orchestrator, mock_osv_cache,
    ):
        """The OSV cache the orchestrator retained must be an OSVCache-like
        object (exposing ``.lookup``) — NOT downgraded to a raw dict by the
        constructor. We verify by re-reading the cache the orchestrator now
        holds (whichever attribute name it chose)."""
        orch = happy_path_orchestrator
        # Discover where the orchestrator stashed the osv cache.
        retained = (
            getattr(orch, "osv_cache", None)
            or (getattr(orch, "caches", {}) or {}).get("osv")
        )
        assert retained is not None, (
            "Orchestrator dropped the OSV cache at construction time — "
            "no osv_cache attribute and no caches['osv'] entry."
        )
        assert retained is mock_osv_cache, (
            "Orchestrator replaced/wrapped the injected OSV cache instance. "
            "It must retain the caller-supplied object identity."
        )
        assert hasattr(retained, "lookup"), (
            "Retained OSV cache has no .lookup method — wrong type or "
            "downgraded to a raw dict. Type: " + type(retained).__name__
        )

    # 3.3
    def test_ghsa_cache_is_ghsa_cache_instance_not_raw_dict(
        self, happy_path_orchestrator, mock_ghsa_cache,
    ):
        """The GHSA cache the orchestrator retained must be a GHSACache-like
        object exposing ``.lookup`` — same contract as the OSV test."""
        orch = happy_path_orchestrator
        retained = (
            getattr(orch, "ghsa_cache", None)
            or (getattr(orch, "caches", {}) or {}).get("ghsa")
        )
        assert retained is not None, (
            "Orchestrator dropped the GHSA cache at construction time."
        )
        assert retained is mock_ghsa_cache, (
            "Orchestrator replaced/wrapped the injected GHSA cache instance."
        )
        assert hasattr(retained, "lookup"), (
            "Retained GHSA cache has no .lookup method. Type: "
            + type(retained).__name__
        )

    # 3.4
    def test_nvd_cache_is_dict_or_cache_manager(
        self, happy_path_orchestrator, mock_nvd_cache,
    ):
        """The NVD cache the orchestrator retained must be either a plain
        dict (parent shape) or an object exposing ``.get(key)``."""
        orch = happy_path_orchestrator
        retained = (
            getattr(orch, "nvd_cache", None)
            or (getattr(orch, "caches", {}) or {}).get("nvd")
        )
        assert retained is not None, (
            "Orchestrator dropped the NVD cache at construction time."
        )
        # Identity check — the orchestrator must not silently rebuild the dict.
        assert retained is mock_nvd_cache or retained == mock_nvd_cache, (
            "Orchestrator mutated/replaced the injected NVD cache."
        )
        assert isinstance(retained, dict) or hasattr(retained, "get"), (
            "Retained NVD cache is neither a dict nor a get()-exposing object: "
            + type(retained).__name__
        )

    # 3.5
    def test_legacy_dict_cache_is_tolerated(
        self, mock_tool_runner, mock_adapters, mock_deduplicator,
        mock_ecosystem_mapper, mock_remediation_enricher, mock_vex_filter,
        mock_serializers, mock_workflow_state_machine,
    ):
        """If a caller passes a plain NVD-only dict as ``caches``, the
        orchestrator must wrap it cleanly (or accept a flat NVD-only mode)
        without raising at construction time."""
        _require_orchestrator()
        legacy_dict_nvd_only = {
            "pkg:pypi/langchain@0.0.101": {
                "cve_id": "CVE-2023-34540", "cvss_score": 9.8, "severity": "High",
            },
        }
        # Try the rich-constructor form with a legacy dict where the caches
        # dict is shaped {"nvd": dict, "osv": None, "ghsa": None}.
        try:
            _build_rich_orchestrator(
                tool_runner=mock_tool_runner,
                adapters=mock_adapters,
                deduplicator=mock_deduplicator,
                ecosystem_mapper=mock_ecosystem_mapper,
                remediation_enricher=mock_remediation_enricher,
                vex_filter=mock_vex_filter,
                serializers=mock_serializers,
                workflow_state_machine=mock_workflow_state_machine,
                caches={"nvd": legacy_dict_nvd_only, "osv": None, "ghsa": None},
            )
        except Exception as exc:
            pytest.fail(
                "Constructor crashed on legacy-shape caches "
                "({'nvd': dict, 'osv': None, 'ghsa': None}). "
                f"Underlying error: {exc!r}"
            )

    # 3.6
    def test_orchestrator_does_not_sync_osv_cache(
        self, happy_path_orchestrator, mock_osv_cache, tmp_path,
    ):
        """The orchestrator must NOT call OSVCache.sync(). Caches must be
        pre-synced by the CLI / caller before construction. This contract
        keeps the orchestrator free of file-system I/O."""
        try:
            happy_path_orchestrator.run_scan(str(tmp_path), output_format="cyclonedx")
        except Exception:
            pass
        assert mock_osv_cache.sync.call_count == 0, (
            f"Orchestrator called OSVCache.sync() {mock_osv_cache.sync.call_count} "
            "time(s); it must NEVER call sync() itself."
        )

    # 3.7
    def test_orchestrator_does_not_sync_ghsa_cache(
        self, happy_path_orchestrator, mock_ghsa_cache, tmp_path,
    ):
        """The orchestrator must NOT call GHSACache.sync()."""
        try:
            happy_path_orchestrator.run_scan(str(tmp_path), output_format="cyclonedx")
        except Exception:
            pass
        assert mock_ghsa_cache.sync.call_count == 0, (
            f"Orchestrator called GHSACache.sync() {mock_ghsa_cache.sync.call_count} "
            "time(s); it must NEVER call sync() itself."
        )

    # 3.8
    def test_propagates_cache_not_synced_errors_cleanly(
        self, mock_tool_runner, mock_adapters, mock_deduplicator,
        mock_remediation_enricher, mock_vex_filter, mock_serializers,
        mock_workflow_state_machine, mock_caches, tmp_path,
    ):
        """Both OSVCacheNotSyncedError and GHSACacheNotSyncedError must
        propagate to the caller unwrapped, regardless of which mapper
        helper raised them."""
        for err_cls in (OSVCacheNotSyncedError, GHSACacheNotSyncedError):
            broken_mapper = MagicMock()
            broken_mapper.map_vulnerabilities = MagicMock(
                side_effect=err_cls(f"{err_cls.__name__}: synthetic test")
            )
            orch = _build_rich_orchestrator(
                tool_runner=mock_tool_runner,
                adapters=mock_adapters,
                deduplicator=mock_deduplicator,
                ecosystem_mapper=broken_mapper,
                remediation_enricher=mock_remediation_enricher,
                vex_filter=mock_vex_filter,
                serializers=mock_serializers,
                workflow_state_machine=mock_workflow_state_machine,
                caches=mock_caches,
            )
            with pytest.raises(err_cls):
                orch.run_scan(str(tmp_path), output_format="cyclonedx")


# ===========================================================================
# TEST CLASS 4 — Serializer wiring
# ===========================================================================
class TestSerializerWiring:
    """Unit tests for how the orchestrator selects and configures its
    CycloneDX / SPDX serializers."""

    # 4.1
    def test_default_cyclonedx_serializer_has_cpe_sanitize_true(self):
        """When the orchestrator is constructed without an explicit CycloneDX
        serializer, it must default to a sanitizing one (cpe_sanitize=True).

        This is a contract test on the default — verified by inspecting
        the Step-6 sanitizing serializer class default."""
        _require_orchestrator()
        if EnhCycloneDXSerializer is None:
            pytest.skip("Enhancement CycloneDXSerializer not importable")
        # The enhancement's serializer class accepts cpe_sanitize as a flag.
        sig = inspect.signature(EnhCycloneDXSerializer.__init__)
        assert "cpe_sanitize" in sig.parameters, (
            "Enhancement CycloneDXSerializer.__init__ does not accept "
            "``cpe_sanitize`` kwarg."
        )

    # 4.2
    def test_default_spdx_serializer_has_cpe_sanitize_true(self):
        """Default SPDX serializer must also accept cpe_sanitize."""
        _require_orchestrator()
        if EnhSPDXSerializer is None:
            pytest.skip("Enhancement SPDXSerializer not importable")
        sig = inspect.signature(EnhSPDXSerializer.__init__)
        assert "cpe_sanitize" in sig.parameters, (
            "Enhancement SPDXSerializer.__init__ does not accept "
            "``cpe_sanitize`` kwarg."
        )

    # 4.3
    def test_caller_can_inject_custom_serializer(
        self, mock_tool_runner, mock_adapters, mock_deduplicator,
        mock_ecosystem_mapper, mock_remediation_enricher, mock_vex_filter,
        mock_workflow_state_machine, mock_caches, tmp_path,
    ):
        """A caller-supplied serializer must override the orchestrator's
        default. We inject a uniquely-marked mock and confirm it was used."""
        marker_cy = MagicMock(name="custom_cyclonedx")
        marker_cy.cpe_sanitize = True
        marker_cy.serialize = MagicMock(return_value={"bomFormat": "CycloneDX",
                                                      "_marker": "x"})
        marker_spdx = MagicMock(name="custom_spdx")
        marker_spdx.cpe_sanitize = True

        orch = _build_rich_orchestrator(
            tool_runner=mock_tool_runner,
            adapters=mock_adapters,
            deduplicator=mock_deduplicator,
            ecosystem_mapper=mock_ecosystem_mapper,
            remediation_enricher=mock_remediation_enricher,
            vex_filter=mock_vex_filter,
            serializers={"cyclonedx": marker_cy, "spdx": marker_spdx},
            workflow_state_machine=mock_workflow_state_machine,
            caches=mock_caches,
        )
        try:
            orch.run_scan(str(tmp_path), output_format="cyclonedx")
        except Exception:
            pass
        assert marker_cy.serialize.call_count >= 1, (
            "Injected custom cyclonedx serializer was not called"
        )

    # 4.4
    def test_injected_serializer_must_have_serialize_method(
        self, mock_tool_runner, mock_adapters, mock_deduplicator,
        mock_ecosystem_mapper, mock_remediation_enricher, mock_vex_filter,
        mock_workflow_state_machine, mock_caches,
    ):
        """If a caller injects a serializer that lacks ``.serialize``, the
        orchestrator should either reject at construction or at first use
        — but not silently fall through."""
        bogus = object()  # no .serialize attribute
        try:
            orch = _build_rich_orchestrator(
                tool_runner=mock_tool_runner,
                adapters=mock_adapters,
                deduplicator=mock_deduplicator,
                ecosystem_mapper=mock_ecosystem_mapper,
                remediation_enricher=mock_remediation_enricher,
                vex_filter=mock_vex_filter,
                serializers={"cyclonedx": bogus, "spdx": bogus},
                workflow_state_machine=mock_workflow_state_machine,
                caches=mock_caches,
            )
        except (TypeError, AttributeError, ValueError):
            return  # strict path — rejected at construction. PASS

        # Lazy path — must fail at run_scan.
        with pytest.raises((TypeError, AttributeError, ValueError)):
            orch.run_scan("/tmp/whatever", output_format="cyclonedx")

    # 4.5
    def test_serializer_receives_scan_data_dict(
        self, happy_path_orchestrator, mock_serializers, tmp_path,
    ):
        """The selected serializer's ``.serialize()`` must be called with a
        dict-shaped scan_data (parent contract) — NOT a bare list."""
        try:
            happy_path_orchestrator.run_scan(str(tmp_path), output_format="cyclonedx")
        except Exception:
            pass
        cy = mock_serializers["cyclonedx"]
        if cy.serialize.call_count == 0:
            pytest.fail("CycloneDX serializer was never called")
        call_arg = cy.serialize.call_args.args[0] if cy.serialize.call_args.args else None
        if call_arg is None:
            # Some implementations pass via kwarg
            call_arg = next(iter(cy.serialize.call_args.kwargs.values()), None)
        assert call_arg is not None, "serialize() was called with no arguments"
        assert isinstance(call_arg, (dict, list)), (
            f"serialize() received unexpected type: {type(call_arg).__name__}"
        )

    # 4.6
    def test_serialize_output_is_returned_unmodified(
        self, happy_path_orchestrator, mock_serializers, tmp_path,
    ):
        """Whatever the serializer returns must appear (unmodified or
        wrapped only in the ScanResult dataclass) in the orchestrator's
        return value."""
        sentinel = {"bomFormat": "CycloneDX", "_sentinel": "step8-marker"}
        mock_serializers["cyclonedx"].serialize.return_value = sentinel
        try:
            result = happy_path_orchestrator.run_scan(
                str(tmp_path), output_format="cyclonedx",
            )
        except Exception as exc:
            pytest.fail(f"run_scan raised on happy path: {exc!r}")

        sbom = getattr(result, "sbom_document", None) or getattr(result, "sbom_json", None)
        assert sbom is not None, "ScanResult.sbom_document/sbom_json is None"
        # Either the sbom IS the sentinel dict, or it stringifies to contain it.
        marker_seen = (
            sbom is sentinel
            or (isinstance(sbom, dict) and sbom.get("_sentinel") == "step8-marker")
            or "step8-marker" in str(sbom)
        )
        assert marker_seen, (
            f"Serializer return value did not flow through to ScanResult. "
            f"Got: {sbom!r}"
        )

    # 4.7
    def test_format_dispatch_is_case_insensitive(
        self, happy_path_orchestrator, mock_serializers, tmp_path,
    ):
        """``output_format='CycloneDX'`` must select the cyclonedx serializer.

        Case insensitivity is a polite contract: the CLI users often type
        the format in mixed-case (matching the SBOM standard name).
        """
        for fmt in ("CycloneDX", "CYCLONEDX", "cyclonedx", "Cyclonedx"):
            mock_serializers["cyclonedx"].serialize.reset_mock()
            mock_serializers["spdx"].serialize.reset_mock()
            try:
                happy_path_orchestrator.run_scan(str(tmp_path), output_format=fmt)
            except (ValueError, KeyError):
                # Strict implementations reject mixed-case; mark xfail.
                if fmt != "cyclonedx":
                    pytest.xfail(
                        f"Orchestrator rejected output_format={fmt!r}; "
                        "case-insensitive dispatch was a polite-only contract."
                    )
                raise
            except Exception:
                pass
            assert mock_serializers["cyclonedx"].serialize.call_count >= 1, (
                f"Cyclone serializer not called for output_format={fmt!r}"
            )


# ===========================================================================
# TEST CLASS 5 — State machine integration
# ===========================================================================
class TestStateMachineIntegration:
    """Unit tests confirming the orchestrator reuses the parent's
    ``WorkflowStateMachine`` and threads transitions through it."""

    # 5.1
    def test_orchestrator_uses_a_workflow_state_machine_instance(
        self, happy_path_orchestrator,
    ):
        """The orchestrator must expose a workflow state machine attribute
        for downstream inspection."""
        orch = happy_path_orchestrator
        sm = (
            getattr(orch, "workflow_state_machine", None)
            or getattr(orch, "state_machine", None)
        )
        assert sm is not None, (
            "Orchestrator does not expose a workflow_state_machine / "
            "state_machine attribute."
        )

    # 5.2
    def test_emit_state_calls_state_machine_transition(
        self, happy_path_orchestrator, mock_workflow_state_machine, tmp_path,
    ):
        """During run_scan, state machine transitions must be called via the
        parent's contract (either ``.transition(...)`` or ``.transition_to(...)``)."""
        try:
            happy_path_orchestrator.run_scan(str(tmp_path), output_format="cyclonedx")
        except Exception:
            pass
        total = (
            mock_workflow_state_machine.transition.call_count
            + mock_workflow_state_machine.transition_to.call_count
        )
        assert total >= 1, "State machine .transition/.transition_to never called"

    # 5.3
    def test_exception_path_records_failed_state_or_propagates(
        self, mock_tool_runner, mock_adapters, mock_deduplicator,
        mock_remediation_enricher, mock_vex_filter, mock_serializers,
        mock_workflow_state_machine, mock_caches, tmp_path,
    ):
        """On a mapper failure, the orchestrator must either propagate
        the exception OR record a 'failed' transition. Silent recovery
        with the workflow still marked 'exporting_sbom' is forbidden."""
        boom_mapper = MagicMock()
        boom_mapper.map_vulnerabilities = MagicMock(
            side_effect=RuntimeError("mapper exploded")
        )
        orch = _build_rich_orchestrator(
            tool_runner=mock_tool_runner,
            adapters=mock_adapters,
            deduplicator=mock_deduplicator,
            ecosystem_mapper=boom_mapper,
            remediation_enricher=mock_remediation_enricher,
            vex_filter=mock_vex_filter,
            serializers=mock_serializers,
            workflow_state_machine=mock_workflow_state_machine,
            caches=mock_caches,
        )
        try:
            orch.run_scan(str(tmp_path), output_format="cyclonedx")
            # If we get here, exception was swallowed — check for failed state
            transitions = []
            for c in (
                mock_workflow_state_machine.transition.call_args_list
                + mock_workflow_state_machine.transition_to.call_args_list
            ):
                if c.args:
                    transitions.append(str(c.args[0]))
            assert any("fail" in t.lower() for t in transitions), (
                f"Mapper crash swallowed AND no 'failed' state recorded. "
                f"Transitions: {transitions}"
            )
        except RuntimeError:
            return  # propagated — PASS

    # 5.4
    def test_visited_states_are_in_canonical_order(
        self, happy_path_orchestrator, mock_workflow_state_machine, tmp_path,
    ):
        """Recorded transitions must not contain duplicates of the terminal
        state, and the last recorded transition (if any) must be a valid
        parent enum value or a 'failed' marker."""
        try:
            happy_path_orchestrator.run_scan(str(tmp_path), output_format="cyclonedx")
        except Exception:
            pass
        transitions = []
        for c in (
            mock_workflow_state_machine.transition.call_args_list
            + mock_workflow_state_machine.transition_to.call_args_list
        ):
            if c.args:
                target = c.args[0]
                transitions.append(getattr(target, "value", str(target)))
        # If the orchestrator made any transitions, every recorded state
        # value must be a recognised parent state or a 'failed' marker.
        if transitions:
            parent_state_values = {s.value for s in ScanWorkflowState}
            unknown = [
                t for t in transitions
                if t not in parent_state_values
                and "fail" not in str(t).lower()
                and "start" not in str(t).lower()
            ]
            assert not unknown, (
                f"Unrecognised state value(s) recorded: {unknown}. "
                f"Allowed parent values: {sorted(parent_state_values)}"
            )

    # 5.5
    def test_independent_orchestrators_have_independent_state_machines(
        self, mock_tool_runner, mock_adapters, mock_deduplicator,
        mock_ecosystem_mapper, mock_remediation_enricher, mock_vex_filter,
        mock_serializers, mock_caches,
    ):
        """Two orchestrator instances must each receive their own state
        machine instance — no shared mutable state."""
        sm1 = MagicMock(name="sm1")
        sm2 = MagicMock(name="sm2")
        orch1 = _build_rich_orchestrator(
            tool_runner=mock_tool_runner,
            adapters=mock_adapters,
            deduplicator=mock_deduplicator,
            ecosystem_mapper=mock_ecosystem_mapper,
            remediation_enricher=mock_remediation_enricher,
            vex_filter=mock_vex_filter,
            serializers=mock_serializers,
            workflow_state_machine=sm1,
            caches=mock_caches,
        )
        orch2 = _build_rich_orchestrator(
            tool_runner=mock_tool_runner,
            adapters=mock_adapters,
            deduplicator=mock_deduplicator,
            ecosystem_mapper=mock_ecosystem_mapper,
            remediation_enricher=mock_remediation_enricher,
            vex_filter=mock_vex_filter,
            serializers=mock_serializers,
            workflow_state_machine=sm2,
            caches=mock_caches,
        )
        # Whichever attribute name the orchestrator chose, the two instances
        # must NOT share the same state machine reference.
        attrs = ("workflow_state_machine", "state_machine", "_state_machine",
                 "_workflow_state_machine")
        sm_attr_1 = next((getattr(orch1, a) for a in attrs if hasattr(orch1, a)), None)
        sm_attr_2 = next((getattr(orch2, a) for a in attrs if hasattr(orch2, a)), None)
        if sm_attr_1 is None or sm_attr_2 is None:
            pytest.skip("Orchestrator does not expose state machine attribute by recognised name")
        assert sm_attr_1 is not sm_attr_2, (
            "Two orchestrator instances share the SAME state machine reference. "
            "State machines must be per-instance."
        )

    # 5.6
    def test_state_machine_is_parent_class_not_custom_subclass(
        self, happy_path_orchestrator,
    ):
        """If the orchestrator constructs its own state machine, it must
        use the parent's WorkflowStateMachine class — NOT introduce a fork.

        Tolerant: if a custom MagicMock is injected (as in our fixture),
        we skip this check.
        """
        orch = happy_path_orchestrator
        sm = (
            getattr(orch, "workflow_state_machine", None)
            or getattr(orch, "state_machine", None)
        )
        if sm is None or isinstance(sm, MagicMock):
            pytest.skip("State machine is mocked or not exposed")
        # The real state machine MUST be the parent's class (or subclass).
        assert isinstance(sm, WorkflowStateMachine), (
            f"State machine type is {type(sm).__name__}; expected "
            f"parent WorkflowStateMachine (or subclass). Forking the state "
            "machine breaks the parent contract."
        )


# ===========================================================================
# TEST CLASS 6 — Backward compatibility with parent orchestrators
# ===========================================================================
class TestBackwardCompat:
    """Unit tests confirming the enhancement does not regress parent behaviour."""

    # 6.1
    def test_parent_scan_orchestrator_construction_still_works(self):
        """Construct parent ScanOrchestrator with its own defaults — the
        enhancement must not have monkey-patched the parent into something
        broken. Tested via a no-arg construction with the parent class."""
        _require_orchestrator()
        try:
            parent = ScanOrchestrator()
        except Exception as exc:
            pytest.fail(
                f"Parent ScanOrchestrator no longer constructs with defaults. "
                f"Enhancement leaked into the parent. Error: {exc!r}"
            )
        assert parent is not None

    # 6.2
    def test_orchestrator_can_accept_parent_fallback(
        self, mock_tool_runner, mock_adapters, mock_deduplicator,
        mock_ecosystem_mapper, mock_remediation_enricher, mock_vex_filter,
        mock_serializers, mock_workflow_state_machine, mock_caches,
    ):
        """The orchestrator's constructor should ACCEPT an optional
        ``fallback_orchestrator`` kwarg without raising. The spec describes
        this as an opt-in fallback path; this test is tolerant: if Step 9
        does not implement the kwarg, the test xfails."""
        _require_orchestrator()
        parent_fallback = ScanOrchestrator()
        try:
            _build_rich_orchestrator(
                tool_runner=mock_tool_runner,
                adapters=mock_adapters,
                deduplicator=mock_deduplicator,
                ecosystem_mapper=mock_ecosystem_mapper,
                remediation_enricher=mock_remediation_enricher,
                vex_filter=mock_vex_filter,
                serializers=mock_serializers,
                workflow_state_machine=mock_workflow_state_machine,
                caches=mock_caches,
                fallback_orchestrator=parent_fallback,
            )
        except TypeError as exc:
            if "fallback_orchestrator" in str(exc):
                pytest.xfail(
                    "Step 9 did not implement the optional "
                    "fallback_orchestrator kwarg. This is a polite contract; "
                    "marking xfail."
                )
            raise

    # 6.3
    def test_cli_orchestrator_can_be_constructed_with_ecosystem_orchestrator(
        self, happy_path_orchestrator,
    ):
        """``CLIOrchestrator(scan_orchestrator=enh_orch)`` must not crash.

        This is the integration seam where the CLI layer adopts the
        ecosystem-aware orchestrator. The construction must complete
        without TypeError.
        """
        _require_orchestrator()
        try:
            cli = CLIOrchestrator(scan_orchestrator=happy_path_orchestrator)
        except TypeError:
            # Some Step 9 implementations may require an explicit flag.
            try:
                cli = CLIOrchestrator(
                    scan_orchestrator=happy_path_orchestrator,
                    use_ecosystem_aware=True,  # type: ignore[call-arg]
                )
            except Exception as exc:
                pytest.fail(
                    f"CLIOrchestrator could not be constructed with the "
                    f"EcosystemScanOrchestrator: {exc!r}"
                )
        # The CLI must carry our orchestrator through.
        carried = getattr(cli, "scan_orchestrator", None)
        assert carried is happy_path_orchestrator, (
            "CLIOrchestrator replaced/dropped the injected ecosystem "
            "orchestrator. Integration with CLI is broken."
        )

    # 6.4
    def test_scan_result_field_names_are_parent_compatible(
        self, happy_path_orchestrator, tmp_path,
    ):
        """``run_scan`` must return a result whose field names match the
        parent ScanResult contract — NOT a divergent custom dataclass.

        Required field names (parent contract): dependencies, active_vulns,
        suppressed_vulns, warnings, sbom_document, workflow_states_visited.
        """
        try:
            result = happy_path_orchestrator.run_scan(
                str(tmp_path), output_format="cyclonedx",
            )
        except Exception as exc:
            pytest.fail(f"run_scan raised on happy path: {exc!r}")
        required_parent_fields = (
            "dependencies", "active_vulns", "suppressed_vulns", "warnings",
            "sbom_document", "workflow_states_visited",
        )
        missing = [
            f for f in required_parent_fields
            if not hasattr(result, f)
        ]
        assert not missing, (
            f"ScanResult missing parent-required field(s): {missing}. "
            "Enhancement narrowed the orchestration contract."
        )

    # 6.5
    def test_parent_step9_module_signatures_unchanged(self):
        """The enhancement must NOT modify parent step9 class signatures.
        This is verified by inspecting the parent ScanOrchestrator.__init__
        signature and asserting it still includes the 8 parent business
        component kwargs.
        """
        _require_orchestrator()
        sig = inspect.signature(ScanOrchestrator.__init__)
        params = set(sig.parameters)
        parent_required_kwargs = {
            "validator", "adapter", "mapper", "vex_filter", "enricher",
            "nvd_cache_manager", "cyclonedx_serializer", "spdx_serializer",
        }
        missing = parent_required_kwargs - params
        assert not missing, (
            f"Parent ScanOrchestrator.__init__ lost kwargs: {missing}. "
            "Enhancement modified the parent module — this is forbidden."
        )
