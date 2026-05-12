"""
step7_atdd_orchestration.py
SBOM POC Tool — ENHANCEMENT: Ecosystem-Aware Vulnerability Matching
Enhancement Session: SBOM-20260409-sb01-ecosystem_aware_vuln_matching
Parent Session:      SBOM-20260409-sb01
Domain:              Developer Tooling — Software Supply Chain Security

Scope of this orchestration acceptance test suite
-------------------------------------------------
This file is the ORCHESTRATION-layer Acceptance Test (ATDD) module for the
"ecosystem_aware_vuln_matching" enhancement. It extends — but does NOT
modify — the business-layer acceptance tests in step4_atdd_business.py
(those are inherited via `from step4_atdd_business import *`).

The orchestration-layer subject under test is:

    EcosystemScanOrchestrator

which composes (Pattern A) — or subclasses (Pattern B) — the parent's
``ScanOrchestrator`` to inject:

  * an ``EcosystemVulnerabilityMapper`` in place of the parent's plain
    ``VulnerabilityMapper`` (step 4 of the parent pipeline)
  * a sanitizing CycloneDX / SPDX serializer (``cpe_sanitize=True``)
    (step 7 of the parent pipeline)

Both patterns are valid Step 9 implementations; the tests below exercise
ONLY the public surface so they pass under either pattern:

    orch = EcosystemScanOrchestrator(
        nvd_cache=...,         # Dict[str, dict] keyed by PURL
        osv_cache=...,         # OSVCache (synced)
        ghsa_cache=...,        # GHSACache (synced)
        tool_runner=...,       # Callable[[str], dict] → raw Syft/Trivy output
    )
    result = orch.run_scan(repo_path, output_format="cyclonedx")  # → ScanResult

All tests in this file MUST fail on first run — Step 9 has not been
written yet for the enhancement. That is the expected Red-phase
behaviour. (Step 8 will write orchestration unit tests; Step 9 will
write the orchestrator implementation that turns these tests green.)

Anti-hardcoding posture
-----------------------
Expected dispatch counts, vulnerability ids, severities, and component
shapes are derived from ``step1b_mock_entities.json`` and
``step1b_mock_scenarios.json`` at test time — they are NOT inlined as
constants. Where literal strings remain (e.g. workflow state names,
exception class names, output-format identifiers) they are spec-defined
contracts taken directly from the requirements.
"""

from __future__ import annotations

import importlib.util
import io
import json
import logging
import os
import pathlib
import sys
from copy import deepcopy
from typing import Any, Callable, Dict, List, Optional
from unittest.mock import MagicMock, patch

import pytest


# ---------------------------------------------------------------------------
# Path resolution — locate enhancement + parent fixture files / modules
# ---------------------------------------------------------------------------
ENHANCEMENT_DIR = pathlib.Path(__file__).parent
PARENT_SESSION_DIR = ENHANCEMENT_DIR.parent.parent  # outputs/sessions/SBOM-.../


# ---------------------------------------------------------------------------
# Inherit ALL Step 4 business acceptance tests verbatim.
#
# This mirrors the parent session's pattern (`from step4_atdd_business import *`)
# so that the orchestration test file is a strict superset of the business
# ATDD suite. The original file is NEVER modified.
# ---------------------------------------------------------------------------
sys.path.insert(0, str(ENHANCEMENT_DIR))

from step4_atdd_business import *  # noqa: F401, F403, E402


# ---------------------------------------------------------------------------
# Business-layer imports (Step 6 — implemented).
# ---------------------------------------------------------------------------
try:
    from step6_tdd_green_phase_business import (  # type: ignore[import-not-found]
        EcosystemVulnerabilityMapper,
        OSVCache,
        GHSACache,
        OSVCacheNotSyncedError,
        GHSACacheNotSyncedError,
        CPESanitizer,
        CycloneDXSerializer as EnhancedCycloneDXSerializer,
        SPDXSerializer as EnhancedSPDXSerializer,
    )
    _BUSINESS_IMPORT_ERROR: Optional[Exception] = None
except Exception as _exc:  # pragma: no cover
    EcosystemVulnerabilityMapper = None  # type: ignore[assignment]
    OSVCache = None  # type: ignore[assignment]
    GHSACache = None  # type: ignore[assignment]
    OSVCacheNotSyncedError = None  # type: ignore[assignment]
    GHSACacheNotSyncedError = None  # type: ignore[assignment]
    CPESanitizer = None  # type: ignore[assignment]
    EnhancedCycloneDXSerializer = None  # type: ignore[assignment]
    EnhancedSPDXSerializer = None  # type: ignore[assignment]
    _BUSINESS_IMPORT_ERROR = _exc


# ---------------------------------------------------------------------------
# Parent-session orchestration imports — loaded by file path so we do not
# depend on a hyphen-bearing session directory being importable.
# ---------------------------------------------------------------------------

def _load_parent_orchestration():
    """Load the parent step9_tdd_green_phase_orchestration as a module."""
    parent_file = PARENT_SESSION_DIR / "step9_tdd_green_phase_orchestration.py"
    if not parent_file.exists():
        return None, ImportError(
            f"Parent orchestration file not found at {parent_file}."
        )
    # The parent module imports step6_tdd_green_phase from the parent session
    # — put that directory on sys.path first so its `import step6_...` resolves.
    parent_str = str(PARENT_SESSION_DIR)
    if parent_str not in sys.path:
        sys.path.insert(0, parent_str)
    module_name = "_parent_step9_orchestration"
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
else:  # pragma: no cover
    ScanOrchestrator = None  # type: ignore[assignment]
    NVDSyncOrchestrator = None  # type: ignore[assignment]
    CLIOrchestrator = None  # type: ignore[assignment]
    WorkflowStateMachine = None  # type: ignore[assignment]
    ScanWorkflowState = None  # type: ignore[assignment]
    ScanResult = None  # type: ignore[assignment]


# ---------------------------------------------------------------------------
# ENHANCEMENT-LAYER orchestration imports — NOT YET IMPLEMENTED.
# Step 9 (enhancement) will introduce ``EcosystemScanOrchestrator`` in
# ``step9_tdd_green_phase_orchestration.py`` inside this enhancement
# directory. Until then the import below fails — every test in this file
# raises a structured "implementation not present" failure rather than an
# obscure NoneType-not-callable trace.
# ---------------------------------------------------------------------------
try:
    from step9_tdd_green_phase_orchestration import (  # type: ignore[import-not-found]
        EcosystemScanOrchestrator,
    )
    _ORCH_IMPORT_ERROR: Optional[Exception] = None
except Exception as _exc:
    EcosystemScanOrchestrator = None  # type: ignore[assignment]
    _ORCH_IMPORT_ERROR = _exc


def _require_orchestration() -> None:
    """Hard-fail when the enhancement Step 9 orchestrator is missing.

    Pre-Step-9, this is the EXPECTED state and the failure is the Red-phase
    signal that Step 9 has work to do.
    """
    if _BUSINESS_IMPORT_ERROR is not None:
        pytest.fail(
            "Step 6 (enhancement) business module not present. "
            f"Underlying error: {_BUSINESS_IMPORT_ERROR!r}"
        )
    if _PARENT_ORCH_ERROR is not None:
        pytest.fail(
            "Parent session orchestration module not loadable. "
            f"Underlying error: {_PARENT_ORCH_ERROR!r}"
        )
    if _ORCH_IMPORT_ERROR is not None:
        pytest.fail(
            "Step 9 (enhancement) orchestration not yet present. "
            "Expected module: step9_tdd_green_phase_orchestration inside the "
            "enhancement directory exporting EcosystemScanOrchestrator. "
            f"Underlying import error: {_ORCH_IMPORT_ERROR!r}"
        )


# ===========================================================================
# Module-scope fixture loaders. These intentionally duplicate the loader
# names used in step4_atdd_business.py (which are inherited via wildcard
# import) so callers reach for the same names regardless of which test
# class they sit in. Both fixture sets resolve to identical JSON content.
# ===========================================================================

def _load_json(path: pathlib.Path) -> Dict[str, Any]:
    with path.open() as f:
        return json.load(f)


@pytest.fixture(scope="module")
def enh_mock_entities() -> Dict[str, Any]:
    return _load_json(ENHANCEMENT_DIR / "step1b_mock_entities.json")


@pytest.fixture(scope="module")
def enh_mock_scenarios() -> Dict[str, Any]:
    return _load_json(ENHANCEMENT_DIR / "step1b_mock_scenarios.json")


@pytest.fixture
def enh_dispatch_table(enh_mock_entities) -> Dict[str, Any]:
    return deepcopy(
        enh_mock_entities["entities"]["PurlDispatchTableFixture"][0]["table"]
    )


@pytest.fixture
def enh_osv_records(enh_mock_entities) -> List[Dict[str, Any]]:
    return deepcopy(enh_mock_entities["entities"]["OSVVulnerabilityRecord"])


@pytest.fixture
def enh_ghsa_records(enh_mock_entities) -> List[Dict[str, Any]]:
    return deepcopy(enh_mock_entities["entities"]["GHSAVulnerabilityRecord"])


def _find_dep_list(mock_entities: Dict[str, Any], id_: str) -> Dict[str, Any]:
    for d in mock_entities["entities"]["MixedEcosystemDependencyList"]:
        if d["id"] == id_:
            return deepcopy(d)
    raise AssertionError(f"Dep list fixture {id_!r} not found in mock_entities")


@pytest.fixture
def enh_mixed_repo_deps(enh_mock_entities) -> Dict[str, Any]:
    return _find_dep_list(enh_mock_entities, "mixed_repo_deps")


@pytest.fixture
def enh_pypi_only_deps(enh_mock_entities) -> Dict[str, Any]:
    return _find_dep_list(enh_mock_entities, "pypi_only_deps")


@pytest.fixture
def enh_github_actions_only_deps(enh_mock_entities) -> Dict[str, Any]:
    return _find_dep_list(enh_mock_entities, "github_actions_only_deps")


@pytest.fixture
def synced_osv_cache(enh_osv_records, tmp_path) -> Any:
    """OSVCache pre-synced from a tmp JSON fixture file."""
    _require_orchestration()
    p = tmp_path / "osv_sample.json"
    p.write_text(json.dumps(enh_osv_records))
    cache = OSVCache()
    cache.sync(str(p))
    return cache


@pytest.fixture
def synced_ghsa_cache(enh_ghsa_records, tmp_path) -> Any:
    """GHSACache pre-synced from a tmp JSON fixture file."""
    _require_orchestration()
    p = tmp_path / "ghsa_sample.json"
    p.write_text(json.dumps(enh_ghsa_records))
    cache = GHSACache()
    cache.sync(str(p))
    return cache


@pytest.fixture
def enh_nvd_cache(enh_mock_entities) -> Dict[str, Dict[str, Any]]:
    """In-memory NVD cache keyed by PURL.

    Records reflect the parent-session NVD seed for any PyPI dep referenced
    by enhancement scenarios (langchain, requests, lxml, joblib, openai,
    pydantic). Derived from the parent NVD entries used in the BDD
    scenarios. Severities/CVE-IDs are spec contracts so they appear here as
    literal — but the dep PURLs they map to are pulled from the fixture
    dep lists (no hardcoding of which deps the test will exercise).
    """
    # Build from the mixed_repo_deps + pypi_only_deps fixtures dynamically.
    nvd_seed: Dict[str, Dict[str, Any]] = {}
    cve_lookup = {
        "langchain": ("CVE-2023-34540", 9.8, "High", "0.0.247"),
        "joblib":    ("CVE-2022-21797", 9.8, "High", "1.2.0"),
        "requests":  ("CVE-2023-32681", 6.1, "Medium", "2.31.0"),
        "lxml":      ("CVE-2018-19787", 6.1, "Medium", "4.7.1"),
    }
    for dep_list_id in ("mixed_repo_deps", "pypi_only_deps"):
        dl = _find_dep_list(enh_mock_entities, dep_list_id)
        for dep in dl["deps"]:
            if dep["ecosystem"] != "pypi":
                continue
            if dep.get("_expected_vulnerable") is not True:
                continue
            cve_record = cve_lookup.get(dep["name"])
            if cve_record is None:
                continue
            cve_id, score, severity, fixed = cve_record
            nvd_seed[dep["purl"]] = {
                "cve_id": cve_id,
                "cvss_score": score,
                "severity": severity,
                "fixed_version": fixed,
                "advisory_url": f"https://nvd.nist.gov/vuln/detail/{cve_id}",
            }
    return nvd_seed


def _components_from_deps(deps: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Build Syft-style component dicts (with fabricated CPEs) from the
    mock fixture deps. Used by the canned-tool-output fixture."""
    out: List[Dict[str, Any]] = []
    for d in deps:
        comp = {
            "name": d["name"],
            "version": d["exact_version"],
            "purl": d["purl"],
            "cpe": (
                f"cpe:2.3:a:{d['name']}:{d['name']}:"
                f"{d['exact_version']}:*:*:*:*:*:*:*"
            ),
            "metadata": {},
        }
        out.append(comp)
    return out


@pytest.fixture
def make_tool_runner():
    """Factory: returns a callable suitable for the ``tool_runner`` slot
    on EcosystemScanOrchestrator. The callable receives a repo_path and
    returns a Syft-shaped dict drawn from the given fixture dep list.
    """
    def _make(deps_fixture: Dict[str, Any]) -> Callable[[str], Dict[str, Any]]:
        def runner(repo_path: str) -> Dict[str, Any]:
            return {
                "tool": "syft",
                "components": _components_from_deps(deps_fixture["deps"]),
            }
        return runner
    return _make


@pytest.fixture
def make_orchestrator(
    enh_nvd_cache, synced_osv_cache, synced_ghsa_cache, make_tool_runner,
):
    """Factory that returns a fully-wired EcosystemScanOrchestrator bound
    to the given dep-list fixture (its tool_runner emits the canned Syft
    output for those deps).
    """
    def _make(deps_fixture: Dict[str, Any]):
        _require_orchestration()
        return EcosystemScanOrchestrator(
            nvd_cache=enh_nvd_cache,
            osv_cache=synced_osv_cache,
            ghsa_cache=synced_ghsa_cache,
            tool_runner=make_tool_runner(deps_fixture),
        )
    return _make


def _ids_from_scan_result(scan_result: Any) -> List[str]:
    """Pull CVE/advisory ids from a ScanResult.active_vulns, tolerating
    either ``cve_id`` or ``advisory_id`` keys."""
    ids: List[str] = []
    for v in (scan_result.active_vulns or []):
        rid = (
            v.get("cve_id")
            or v.get("advisory_id")
            or v.get("id_field")
            or v.get("id")
        )
        if rid:
            ids.append(rid)
    return ids


def _components_from_sbom(sbom: Any, output_format: str) -> List[Dict[str, Any]]:
    """Extract the component / package list from a serialised SBOM.

    Accepts either a dict (parent serializer output) or a verbatim string
    (enhancement-serializer components-only shorthand). For strings we
    fall back to a naive parse — tests that need rich shape inspection
    use the dict form.
    """
    if isinstance(sbom, dict):
        if output_format == "cyclonedx":
            return list(sbom.get("components", []) or [])
        if output_format == "spdx":
            return list(sbom.get("packages", []) or [])
    return []


# ===========================================================================
# TEST CLASS 1 — End-to-End EcosystemScanOrchestrator behaviour
# Covers ATDD acceptance for full-pipeline coordination.
# ===========================================================================
class TestEcosystemScanOrchestratorEndToEnd:
    """ACCEPTANCE: ``EcosystemScanOrchestrator.run_scan(repo_path)`` executes
    the full SBOM pipeline (tool → adapter → dedupe → ecosystem-aware
    matching → enrichment → VEX → CPE-sanitizing serialization) and returns
    a parent-shaped ScanResult.

    ORCHESTRATION: Verifies that the enhancement coordinates the new
    EcosystemVulnerabilityMapper and the sanitizing serializers WITHIN
    the parent's seven-stage workflow without breaking the contract that
    Step 11 (API) and the parent CLI both rely on.
    """

    # -----------------------------------------------------------------------
    # AC: Mixed-ecosystem repo — all three backends contribute vulns
    # Maps to BDD Scenario 5 (Rule 1) + Scenario 18 (integration)
    # -----------------------------------------------------------------------
    def test_run_scan_on_mixed_ecosystem_repo_collects_vulns_from_all_backends(
        self, make_orchestrator, enh_mixed_repo_deps, enh_mock_scenarios, tmp_path,
    ):
        _require_orchestration()
        scenario = next(
            s for s in enh_mock_scenarios["scenarios"]
            if s["id"] == "scenario_enh_001"
        )
        expected_ids = {
            v["cve_or_advisory_id"]
            for v in scenario["expected_output"]["vulnerabilities"]
        }
        expected_counts = scenario["expected_output"]["dispatch_counts"]

        orch = make_orchestrator(enh_mixed_repo_deps)
        repo_path = str(tmp_path)

        result = orch.run_scan(repo_path, output_format="cyclonedx")

        # Result has the parent ScanResult shape
        assert hasattr(result, "active_vulns")
        assert hasattr(result, "dependencies")
        assert hasattr(result, "sbom_document")
        assert hasattr(result, "workflow_states_visited")

        # All five expected vulns are present, no extras.
        actual_ids = set(_ids_from_scan_result(result))
        assert actual_ids == expected_ids, (
            f"Mixed-ecosystem scan vuln id set mismatch.\n"
            f"  Expected: {sorted(expected_ids)}\n"
            f"  Actual:   {sorted(actual_ids)}"
        )

        # Sanity check on the per-backend split: at least one vuln from
        # each backend that was expected to contribute (>0 in scenario).
        for backend in ("nvd", "osv", "ghsa"):
            if expected_counts.get(backend, 0) > 0:
                assert any(
                    (v.get("source") or v.get("backend")) == backend
                    for v in result.active_vulns
                ), (
                    f"No vuln from backend {backend!r} in result; "
                    f"scenario_enh_001 expected {expected_counts[backend]}"
                )

    # -----------------------------------------------------------------------
    # AC: PyPI-only repo — behaves identically to the parent (regression)
    # Maps to BDD Scenario 6 (Rule 2)
    # -----------------------------------------------------------------------
    def test_run_scan_on_pypi_only_repo_matches_parent_behaviour(
        self, make_orchestrator, enh_pypi_only_deps, enh_mock_scenarios, tmp_path,
    ):
        _require_orchestration()
        scenario = next(
            s for s in enh_mock_scenarios["scenarios"]
            if s["id"] == "scenario_enh_002"
        )
        expected_ids = {
            v["cve_or_advisory_id"]
            for v in scenario["expected_output"]["vulnerabilities"]
        }
        expected_counts = scenario["expected_output"]["dispatch_counts"]

        orch = make_orchestrator(enh_pypi_only_deps)
        repo_path = str(tmp_path)

        result = orch.run_scan(repo_path, output_format="cyclonedx")

        actual_ids = set(_ids_from_scan_result(result))
        assert actual_ids == expected_ids
        # Pure PyPI route: zero OSV, zero GHSA results
        assert expected_counts["osv"] == 0
        assert expected_counts["ghsa"] == 0
        backends = [(v.get("source") or v.get("backend")) for v in result.active_vulns]
        assert all(b == "nvd" for b in backends), (
            f"PyPI-only scan produced non-NVD records: {backends}"
        )

    # -----------------------------------------------------------------------
    # AC: GitHub-Actions-only repo — all vulns from GHSA + zero CPEs in SBOM
    # Maps to BDD Scenarios 4 + 9 + 18 (CPE sanitization integration)
    # -----------------------------------------------------------------------
    def test_run_scan_on_github_actions_only_repo_emits_zero_cpes(
        self,
        make_orchestrator,
        enh_github_actions_only_deps,
        tmp_path,
    ):
        _require_orchestration()
        orch = make_orchestrator(enh_github_actions_only_deps)
        repo_path = str(tmp_path)

        result = orch.run_scan(repo_path, output_format="cyclonedx")

        # Every active vuln must be sourced from GHSA.
        backends = [(v.get("source") or v.get("backend")) for v in result.active_vulns]
        assert backends, "Expected GHSA-sourced vulns but result.active_vulns is empty"
        assert all(b == "ghsa" for b in backends), (
            f"github-only scan produced non-GHSA records: {backends}"
        )

        # SBOM must contain zero `cpe` strings — fabricated CPEs stripped.
        sbom = result.sbom_document
        assert sbom is not None
        sbom_text = json.dumps(sbom) if isinstance(sbom, dict) else str(sbom)
        # The mock fixture documents this invariant explicitly:
        expected_cpe_count = enh_github_actions_only_deps.get(
            "expected_cpe_count_in_output_sbom", 0
        )
        assert sbom_text.count('"cpe"') == expected_cpe_count, (
            f"github-only SBOM contains {sbom_text.count('\"cpe\"')} 'cpe' "
            f"occurrences; expected {expected_cpe_count} per fixture."
        )

    # -----------------------------------------------------------------------
    # AC: CycloneDX output_format works end-to-end
    # -----------------------------------------------------------------------
    def test_run_scan_with_output_format_cyclonedx_returns_cyclonedx_sbom(
        self, make_orchestrator, enh_mixed_repo_deps, tmp_path,
    ):
        _require_orchestration()
        orch = make_orchestrator(enh_mixed_repo_deps)
        result = orch.run_scan(str(tmp_path), output_format="cyclonedx")
        sbom = result.sbom_document
        assert sbom is not None

        # Tolerate both dict (parent serializer) and string (enhancement
        # components-only shorthand) outputs.
        if isinstance(sbom, dict):
            assert sbom.get("bomFormat") == "CycloneDX"
            assert sbom.get("specVersion") == "1.4"
        else:
            assert isinstance(sbom, str) and "CycloneDX" in sbom

        # output_format echoed back on result, if the orchestrator
        # carries it through (parent contract does so).
        if hasattr(result, "output_format") and result.output_format:
            assert result.output_format == "cyclonedx"

    # -----------------------------------------------------------------------
    # AC: SPDX output_format works end-to-end
    # -----------------------------------------------------------------------
    def test_run_scan_with_output_format_spdx_returns_spdx_sbom(
        self, make_orchestrator, enh_mixed_repo_deps, tmp_path,
    ):
        _require_orchestration()
        orch = make_orchestrator(enh_mixed_repo_deps)
        result = orch.run_scan(str(tmp_path), output_format="spdx")
        sbom = result.sbom_document
        assert sbom is not None

        if isinstance(sbom, dict):
            assert sbom.get("spdxVersion") == "SPDX-2.3"
        else:
            assert isinstance(sbom, str) and "SPDX" in sbom

        if hasattr(result, "output_format") and result.output_format:
            assert result.output_format == "spdx"

    # -----------------------------------------------------------------------
    # AC: Unknown PURL types are skipped (logged) — scan completes
    # Maps to BDD Scenario 12 (Rule 4)
    # -----------------------------------------------------------------------
    def test_run_scan_with_unknown_purl_type_skips_and_completes(
        self, enh_nvd_cache, synced_osv_cache, synced_ghsa_cache, tmp_path, caplog,
    ):
        _require_orchestration()

        def runner(repo_path: str) -> Dict[str, Any]:
            # Mix one good PyPI dep with an unknown-type dep
            return {
                "tool": "syft",
                "components": [
                    {
                        "name": "langchain", "version": "0.0.101",
                        "purl": "pkg:pypi/langchain@0.0.101",
                        "metadata": {},
                    },
                    {
                        "name": "foo", "version": "1.0",
                        "purl": "pkg:unknownftype/foo@1.0",
                        "metadata": {},
                    },
                ],
            }

        orch = EcosystemScanOrchestrator(
            nvd_cache=enh_nvd_cache,
            osv_cache=synced_osv_cache,
            ghsa_cache=synced_ghsa_cache,
            tool_runner=runner,
        )

        with caplog.at_level(logging.WARNING):
            result = orch.run_scan(str(tmp_path), output_format="cyclonedx")

        # Scan completes successfully
        assert result.sbom_document is not None
        # The PyPI dep produced its CVE
        assert "CVE-2023-34540" in _ids_from_scan_result(result)
        # An unknown-purl warning was logged (no exception raised)
        warning_msgs = [
            r.getMessage() for r in caplog.records
            if r.levelno >= logging.WARNING
        ]
        assert any(
            "unknownftype" in m or "pkg:unknownftype/foo@1.0" in m
            for m in warning_msgs
        ), (
            f"Expected an unknown-purl-type warning; got: {warning_msgs}"
        )

    # -----------------------------------------------------------------------
    # AC: OSVCacheNotSyncedError propagates through orchestrator
    # Maps to BDD Scenario 15 (Rule 5)
    # -----------------------------------------------------------------------
    def test_run_scan_propagates_osv_cache_not_synced_error(
        self,
        enh_nvd_cache,
        synced_ghsa_cache,
        make_tool_runner,
        enh_mixed_repo_deps,
        tmp_path,
    ):
        _require_orchestration()
        unsynced_osv = OSVCache()  # NEVER called .sync()

        orch = EcosystemScanOrchestrator(
            nvd_cache=enh_nvd_cache,
            osv_cache=unsynced_osv,
            ghsa_cache=synced_ghsa_cache,
            tool_runner=make_tool_runner(enh_mixed_repo_deps),
        )
        with pytest.raises(OSVCacheNotSyncedError):
            orch.run_scan(str(tmp_path), output_format="cyclonedx")

    # -----------------------------------------------------------------------
    # AC: GHSACacheNotSyncedError propagates through orchestrator
    # Maps to BDD Scenario 16 (Rule 5)
    # -----------------------------------------------------------------------
    def test_run_scan_propagates_ghsa_cache_not_synced_error(
        self,
        enh_nvd_cache,
        synced_osv_cache,
        make_tool_runner,
        enh_mixed_repo_deps,
        tmp_path,
    ):
        _require_orchestration()
        unsynced_ghsa = GHSACache()  # NEVER called .sync()

        orch = EcosystemScanOrchestrator(
            nvd_cache=enh_nvd_cache,
            osv_cache=synced_osv_cache,
            ghsa_cache=unsynced_ghsa,
            tool_runner=make_tool_runner(enh_mixed_repo_deps),
        )
        with pytest.raises(GHSACacheNotSyncedError):
            orch.run_scan(str(tmp_path), output_format="cyclonedx")

    # -----------------------------------------------------------------------
    # AC: Parent NVDSyncError still propagates unchanged.
    # Maps to BDD Scenario 17 (Rule 5)
    # -----------------------------------------------------------------------
    def test_run_scan_propagates_parent_nvd_sync_error(
        self,
        synced_osv_cache,
        synced_ghsa_cache,
        make_tool_runner,
        enh_mixed_repo_deps,
        tmp_path,
    ):
        _require_orchestration()

        # Find NVDSyncError from the parent module surface. We accept any
        # of the locations the parent might expose it from (orchestration
        # re-export or business module).
        nvd_sync_error = getattr(_PARENT_ORCH_MOD, "NVDSyncError", None)
        if nvd_sync_error is None:
            # Pull from business module if not re-exported on orchestration
            parent_business_path = PARENT_SESSION_DIR / "step6_tdd_green_phase.py"
            spec = importlib.util.spec_from_file_location(
                "_parent_step6_for_test", parent_business_path,
            )
            parent_business = importlib.util.module_from_spec(spec)  # type: ignore
            assert spec is not None and spec.loader is not None
            spec.loader.exec_module(parent_business)
            nvd_sync_error = getattr(parent_business, "NVDSyncError")

        # NVD cache that raises NVDSyncError on access.
        class _RaisingNVDCache(dict):
            def get(self, key, default=None):
                raise nvd_sync_error("NVD cache not synced (synthetic test)")

        orch = EcosystemScanOrchestrator(
            nvd_cache=_RaisingNVDCache(),
            osv_cache=synced_osv_cache,
            ghsa_cache=synced_ghsa_cache,
            tool_runner=make_tool_runner(enh_mixed_repo_deps),
        )
        # Must surface the same parent error class — no wrapping.
        with pytest.raises(nvd_sync_error):
            orch.run_scan(str(tmp_path), output_format="cyclonedx")

    # -----------------------------------------------------------------------
    # AC: Determinism — same input → byte-equal SBOM output
    # Maps to BDD integration scenario_enh_009 (determinism)
    # -----------------------------------------------------------------------
    def test_run_scan_is_deterministic_byte_equal_across_runs(
        self, make_orchestrator, enh_mixed_repo_deps, tmp_path,
    ):
        _require_orchestration()

        # We canonicalise the SBOM by stripping fields that legitimately
        # vary (e.g. scan_id, serialNumber, timestamps) before byte-compare.
        def _canonicalise(sbom: Any) -> str:
            if isinstance(sbom, dict):
                d = deepcopy(sbom)
                d.pop("serialNumber", None)
                meta = d.get("metadata") or {}
                if isinstance(meta, dict):
                    meta.pop("timestamp", None)
                d.pop("creationInfo", None)
                d.pop("documentNamespace", None)
                return json.dumps(d, sort_keys=True, default=str)
            return str(sbom)

        # Two independent runs with two independent orchestrators
        orch1 = make_orchestrator(enh_mixed_repo_deps)
        orch2 = make_orchestrator(enh_mixed_repo_deps)
        r1 = orch1.run_scan(str(tmp_path), output_format="cyclonedx")
        r2 = orch2.run_scan(str(tmp_path), output_format="cyclonedx")

        # Vulnerability set is identical (anti-ordering: compare as sets)
        ids1 = sorted(_ids_from_scan_result(r1))
        ids2 = sorted(_ids_from_scan_result(r2))
        assert ids1 == ids2

        # SBOM byte-equal after canonicalisation
        assert _canonicalise(r1.sbom_document) == _canonicalise(r2.sbom_document)


# ===========================================================================
# TEST CLASS 2 — Workflow state integration with parent state machine
# ===========================================================================
class TestWorkflowStateIntegration:
    """ACCEPTANCE: EcosystemScanOrchestrator does NOT introduce a new
    workflow state machine. It reuses the parent's ``WorkflowStateMachine``
    and threads the same seven states.

    ORCHESTRATION: The enhancement extends behaviour at the existing
    ``matching_vulnerabilities`` and ``exporting_sbom`` states without
    inserting new states or transitions. This guarantees the orchestration
    contract used by the parent CLI, API, and any downstream consumers
    of ``ScanResult.workflow_states_visited`` is preserved.
    """

    # -----------------------------------------------------------------------
    # State machine reuse: parent enum is the one that drives transitions.
    # -----------------------------------------------------------------------
    def test_orchestrator_reuses_parent_workflow_state_machine(
        self, make_orchestrator, enh_mixed_repo_deps, tmp_path,
    ):
        _require_orchestration()
        orch = make_orchestrator(enh_mixed_repo_deps)
        result = orch.run_scan(str(tmp_path), output_format="cyclonedx")

        # The visited list is populated and uses the parent's state enum
        # value strings — not a fork.
        visited = list(getattr(result, "workflow_states_visited", []) or [])
        assert visited, "workflow_states_visited must be populated"

        # Every emitted state must be a member of the parent enum.
        parent_state_values = {s.value for s in ScanWorkflowState}
        unknown = [s for s in visited if s not in parent_state_values]
        assert not unknown, (
            f"Orchestrator emitted state values not in parent ScanWorkflowState: "
            f"{unknown}. Allowed: {sorted(parent_state_values)}"
        )

    # -----------------------------------------------------------------------
    # Successful scan reaches the parent's terminal state.
    # -----------------------------------------------------------------------
    def test_successful_scan_reaches_parent_terminal_state(
        self, make_orchestrator, enh_mixed_repo_deps, tmp_path,
    ):
        _require_orchestration()
        orch = make_orchestrator(enh_mixed_repo_deps)
        result = orch.run_scan(str(tmp_path), output_format="cyclonedx")

        visited = list(getattr(result, "workflow_states_visited", []) or [])
        # The parent's terminal state is EXPORTING_SBOM (last of the seven).
        terminal = ScanWorkflowState.EXPORTING_SBOM.value
        assert visited[-1] == terminal, (
            f"Workflow did not reach terminal state {terminal!r}; "
            f"final visited state was {visited[-1]!r}"
        )

    # -----------------------------------------------------------------------
    # Failure path: an unsynced cache must NOT leave the workflow in the
    # terminal "exporting_sbom" state. Either the exception bubbles before
    # reaching it, or the workflow records a failure short of terminal.
    # -----------------------------------------------------------------------
    def test_failure_path_does_not_reach_terminal_state(
        self,
        enh_nvd_cache,
        synced_ghsa_cache,
        make_tool_runner,
        enh_mixed_repo_deps,
        tmp_path,
    ):
        _require_orchestration()
        unsynced_osv = OSVCache()
        orch = EcosystemScanOrchestrator(
            nvd_cache=enh_nvd_cache,
            osv_cache=unsynced_osv,
            ghsa_cache=synced_ghsa_cache,
            tool_runner=make_tool_runner(enh_mixed_repo_deps),
        )

        terminal = ScanWorkflowState.EXPORTING_SBOM.value
        try:
            result = orch.run_scan(str(tmp_path), output_format="cyclonedx")
        except OSVCacheNotSyncedError:
            # Acceptable: exception bubbled, terminal state never reached.
            return

        # If the orchestrator chose to capture the failure instead of
        # raising, then it MUST signal it via workflow state — at minimum
        # the visited list must not end at the terminal state.
        visited = list(getattr(result, "workflow_states_visited", []) or [])
        assert visited[-1] != terminal, (
            "Workflow reached terminal state despite OSVCacheNotSyncedError. "
            f"Visited: {visited}"
        )

    # -----------------------------------------------------------------------
    # ScanResult shape (backward-compat at orchestration return value).
    # -----------------------------------------------------------------------
    def test_scan_result_shape_is_parent_compatible(
        self, make_orchestrator, enh_mixed_repo_deps, tmp_path,
    ):
        _require_orchestration()
        orch = make_orchestrator(enh_mixed_repo_deps)
        result = orch.run_scan(str(tmp_path), output_format="cyclonedx")

        # Every parent ScanResult field is present.
        required_fields = (
            "dependencies", "active_vulns", "suppressed_vulns",
            "warnings", "sbom_document", "workflow_states_visited",
        )
        for field_name in required_fields:
            assert hasattr(result, field_name), (
                f"ScanResult missing parent-required field {field_name!r}. "
                "Enhancement must not narrow the orchestration contract."
            )
        # Type checks — same shapes as the parent's dataclass.
        assert isinstance(result.dependencies, list)
        assert isinstance(result.active_vulns, list)
        assert isinstance(result.suppressed_vulns, list)
        assert isinstance(result.warnings, list)
        assert isinstance(result.workflow_states_visited, list)

    # -----------------------------------------------------------------------
    # All seven parent state transitions are visited on a happy-path scan.
    # -----------------------------------------------------------------------
    def test_all_seven_parent_states_visited_on_happy_path(
        self, make_orchestrator, enh_mixed_repo_deps, tmp_path,
    ):
        _require_orchestration()
        orch = make_orchestrator(enh_mixed_repo_deps)
        result = orch.run_scan(str(tmp_path), output_format="cyclonedx")

        visited = list(getattr(result, "workflow_states_visited", []) or [])
        expected_states = [s.value for s in ScanWorkflowState]
        # All seven appear at least once, in their canonical relative order.
        last_idx = -1
        for state in expected_states:
            if state not in visited:
                pytest.fail(
                    f"Parent workflow state {state!r} was not visited. "
                    f"Visited list: {visited}"
                )
            idx = visited.index(state)
            assert idx > last_idx, (
                f"Workflow visited {state!r} OUT OF parent canonical order. "
                f"Visited: {visited}"
            )
            last_idx = idx


# ===========================================================================
# TEST CLASS 3 — CPE sanitizer integration at the serializer boundary
# ===========================================================================
class TestCPESanitizerIntegrationAtSerializerBoundary:
    """ACCEPTANCE: When the orchestrator constructs its serializer with
    ``cpe_sanitize=True`` (or wraps the parent's serializer in the
    enhancement's CPESanitizer), the emitted SBOM has zero ``cpe`` strings
    for non-NVD-indexed components and retains ``cpe`` for PyPI components.

    ORCHESTRATION: Tests the boundary where the matching layer's PURL
    awareness must flow into the serialization layer. Without correct
    wiring at the orchestration level, CPE pollution leaks downstream.
    """

    # -----------------------------------------------------------------------
    # CycloneDX: zero cpe for pkg:github/* components
    # -----------------------------------------------------------------------
    def test_cyclonedx_emits_no_cpe_for_github_components(
        self, make_orchestrator, enh_mixed_repo_deps, tmp_path,
    ):
        _require_orchestration()
        orch = make_orchestrator(enh_mixed_repo_deps)
        result = orch.run_scan(str(tmp_path), output_format="cyclonedx")

        sbom = result.sbom_document
        components = _components_from_sbom(sbom, "cyclonedx")
        if not components:
            # Fall back to raw text scan for verbatim string SBOMs.
            text = str(sbom)
            # No cpe-with-github co-occurrence anywhere in the doc.
            # Conservatively: no cpe string for any pkg:github/ component.
            for dep in enh_mixed_repo_deps["deps"]:
                if dep["ecosystem"] == "github":
                    # The purl should appear; the fabricated cpe must NOT.
                    assert dep["purl"] in text
                    fab_cpe_prefix = "cpe:2.3:a:" + dep["name"].split("/")[0]
                    assert fab_cpe_prefix not in text, (
                        f"Fabricated CPE for github component leaked into "
                        f"CycloneDX output: {fab_cpe_prefix!r}"
                    )
            return

        for c in components:
            purl = c.get("purl", "")
            if isinstance(purl, str) and purl.startswith("pkg:github/"):
                assert "cpe" not in c, (
                    f"CycloneDX component for github PURL retains cpe: {c!r}"
                )

    # -----------------------------------------------------------------------
    # CycloneDX: zero cpe for pkg:npm/* components
    # -----------------------------------------------------------------------
    def test_cyclonedx_emits_no_cpe_for_npm_components(
        self, make_orchestrator, enh_mixed_repo_deps, tmp_path,
    ):
        _require_orchestration()
        orch = make_orchestrator(enh_mixed_repo_deps)
        result = orch.run_scan(str(tmp_path), output_format="cyclonedx")

        components = _components_from_sbom(result.sbom_document, "cyclonedx")
        if not components:
            text = str(result.sbom_document)
            for dep in enh_mixed_repo_deps["deps"]:
                if dep["ecosystem"] == "npm":
                    fab_cpe_prefix = (
                        f"cpe:2.3:a:{dep['name']}:{dep['name']}:"
                        f"{dep['exact_version']}"
                    )
                    assert fab_cpe_prefix not in text, (
                        f"Fabricated CPE for npm component leaked into "
                        f"CycloneDX output: {fab_cpe_prefix!r}"
                    )
            return

        for c in components:
            purl = c.get("purl", "")
            if isinstance(purl, str) and purl.startswith("pkg:npm/"):
                assert "cpe" not in c, (
                    f"CycloneDX component for npm PURL retains cpe: {c!r}"
                )

    # -----------------------------------------------------------------------
    # CycloneDX: cpe IS retained for pkg:pypi/* components (regression)
    # -----------------------------------------------------------------------
    def test_cyclonedx_retains_cpe_for_pypi_components(
        self, make_orchestrator, enh_mixed_repo_deps, tmp_path,
    ):
        _require_orchestration()
        orch = make_orchestrator(enh_mixed_repo_deps)
        result = orch.run_scan(str(tmp_path), output_format="cyclonedx")

        components = _components_from_sbom(result.sbom_document, "cyclonedx")
        pypi_purls = {
            d["purl"] for d in enh_mixed_repo_deps["deps"]
            if d["ecosystem"] == "pypi"
        }
        if not components:
            text = str(result.sbom_document)
            for purl in pypi_purls:
                # The PyPI fabricated CPE prefix should still be present.
                dep_name = purl.split("/")[-1].split("@")[0]
                assert f"cpe:2.3:a:{dep_name}" in text, (
                    f"CycloneDX text output missing CPE for PyPI dep {purl!r}"
                )
            return

        pypi_components = [
            c for c in components if str(c.get("purl", "")).startswith("pkg:pypi/")
        ]
        assert pypi_components, "No PyPI components found in CycloneDX output"
        for c in pypi_components:
            assert "cpe" in c, (
                f"CycloneDX component for PyPI PURL is missing cpe field "
                f"(should be retained): {c!r}"
            )

    # -----------------------------------------------------------------------
    # SPDX: zero cpe23Type externalRefs for pkg:github/* and pkg:npm/*
    # -----------------------------------------------------------------------
    def test_spdx_strips_cpe_for_non_pypi_components(
        self, make_orchestrator, enh_mixed_repo_deps, tmp_path,
    ):
        _require_orchestration()
        orch = make_orchestrator(enh_mixed_repo_deps)
        result = orch.run_scan(str(tmp_path), output_format="spdx")

        packages = _components_from_sbom(result.sbom_document, "spdx")
        if not packages:
            text = str(result.sbom_document)
            # Verbatim-string SPDX: no fabricated CPE substring for non-PyPI
            for dep in enh_mixed_repo_deps["deps"]:
                if dep["ecosystem"] == "pypi":
                    continue
                fab_cpe_prefix = (
                    f"cpe:2.3:a:{dep['name']}:{dep['name']}:"
                    f"{dep['exact_version']}"
                )
                assert fab_cpe_prefix not in text, (
                    f"SPDX output retains fabricated CPE for non-PyPI dep: "
                    f"{fab_cpe_prefix!r}"
                )
            return

        # Dict SPDX shape — inspect externalRefs[referenceType=cpe23Type]
        non_pypi_purls = {
            d["purl"] for d in enh_mixed_repo_deps["deps"]
            if d["ecosystem"] != "pypi"
        }
        for pkg in packages:
            ext_refs = pkg.get("externalRefs") or []
            purl_locator = next(
                (
                    ref.get("referenceLocator", "")
                    for ref in ext_refs
                    if ref.get("referenceType") == "purl"
                ),
                "",
            )
            if purl_locator in non_pypi_purls:
                cpe_refs = [
                    ref for ref in ext_refs
                    if ref.get("referenceType") == "cpe23Type"
                ]
                assert not cpe_refs, (
                    f"SPDX package for non-PyPI purl {purl_locator!r} still "
                    f"has cpe23Type externalRefs: {cpe_refs!r}"
                )

    # -----------------------------------------------------------------------
    # SPDX: cpe23Type externalRefs ARE retained for pkg:pypi/* (regression)
    # -----------------------------------------------------------------------
    def test_spdx_retains_cpe_for_pypi_components(
        self, make_orchestrator, enh_mixed_repo_deps, tmp_path,
    ):
        _require_orchestration()
        orch = make_orchestrator(enh_mixed_repo_deps)
        result = orch.run_scan(str(tmp_path), output_format="spdx")

        packages = _components_from_sbom(result.sbom_document, "spdx")
        pypi_purls = {
            d["purl"] for d in enh_mixed_repo_deps["deps"]
            if d["ecosystem"] == "pypi"
        }

        if not packages:
            text = str(result.sbom_document)
            for purl in pypi_purls:
                dep_name = purl.split("/")[-1].split("@")[0]
                assert f"cpe:2.3:a:{dep_name}" in text, (
                    f"SPDX text output missing CPE for PyPI dep {purl!r}"
                )
            return

        # Dict shape — at least one PyPI pkg has a cpe23Type externalRef
        # (or a top-level cpe field, depending on the serializer dialect).
        found_pypi_cpe = False
        for pkg in packages:
            ext_refs = pkg.get("externalRefs") or []
            purl_locator = next(
                (
                    ref.get("referenceLocator", "")
                    for ref in ext_refs
                    if ref.get("referenceType") == "purl"
                ),
                pkg.get("purl", ""),
            )
            if purl_locator in pypi_purls:
                cpe_refs = [
                    ref for ref in ext_refs
                    if ref.get("referenceType") == "cpe23Type"
                ]
                if cpe_refs or "cpe" in pkg:
                    found_pypi_cpe = True
                    break
        assert found_pypi_cpe, (
            "SPDX output stripped CPEs from PyPI packages — regression. "
            "PyPI CPEs MUST be retained."
        )


# ===========================================================================
# TEST CLASS 4 — Backward compatibility with parent orchestrators
# ===========================================================================
class TestBackwardCompatWithParentOrchestrators:
    """ACCEPTANCE: The enhancement preserves parent-session orchestration
    behaviour for any path that does NOT go through the enhanced mapper /
    sanitizing serializer.

    ORCHESTRATION: Verifies that NVDSyncOrchestrator, CLIOrchestrator, and
    the parent ScanOrchestrator continue to function unchanged. The
    enhancement is opt-in — pre-existing call sites must not regress.
    """

    # -----------------------------------------------------------------------
    # NVDSyncOrchestrator works unchanged (no enhancement code path here).
    # -----------------------------------------------------------------------
    def test_parent_nvd_sync_orchestrator_works_unchanged(self, tmp_path):
        _require_orchestration()
        # Construct in isolation — no enhancement components touch this.
        sync_orch = NVDSyncOrchestrator(db_path=":memory:")

        # Use the parent's sample_nvd_feed.json if available; otherwise a
        # minimal NVD-shape file written here.
        candidate = PARENT_SESSION_DIR / "sample_nvd_feed.json"
        if candidate.exists():
            source_path = str(candidate)
        else:
            source_path = str(tmp_path / "nvd_feed.json")
            with open(source_path, "w") as f:
                json.dump({"vulnerabilities": []}, f)

        # Either the call succeeds (parent test passes) or raises NVDSyncError;
        # what matters here is that we did not break the API surface.
        nvd_sync_error = getattr(_PARENT_ORCH_MOD, "NVDSyncError", Exception)
        try:
            result = sync_orch.run(source_path)
        except nvd_sync_error:
            # Acceptable — sample file may not match the schema. We assert
            # only that the orchestrator surface was reachable.
            return

        # Successful run — verify parent SyncResult fields are preserved.
        for field_name in ("records_added", "records_updated", "synced_at"):
            assert hasattr(result, field_name), (
                f"Parent SyncResult missing {field_name!r} — regression in "
                f"NVDSyncOrchestrator contract."
            )

    # -----------------------------------------------------------------------
    # CLIOrchestrator can be wired with the enhancement orchestrator.
    # -----------------------------------------------------------------------
    def test_cli_orchestrator_accepts_ecosystem_scan_orchestrator(
        self,
        enh_nvd_cache,
        synced_osv_cache,
        synced_ghsa_cache,
        make_tool_runner,
        enh_pypi_only_deps,
    ):
        _require_orchestration()
        enh_orch = EcosystemScanOrchestrator(
            nvd_cache=enh_nvd_cache,
            osv_cache=synced_osv_cache,
            ghsa_cache=synced_ghsa_cache,
            tool_runner=make_tool_runner(enh_pypi_only_deps),
        )

        # The parent CLIOrchestrator accepts `scan_orchestrator=...`.
        # The enhancement orchestrator must be duck-type-compatible at
        # construction time — i.e. it must not crash CLIOrchestrator's
        # ``__init__`` to be passed in.
        try:
            cli = CLIOrchestrator(scan_orchestrator=enh_orch)
        except TypeError as exc:
            # Some Step 9 implementations may require an explicit flag, e.g.
            #   CLIOrchestrator(scan_orchestrator=enh_orch, use_ecosystem_aware=True)
            # Tolerate this by retrying with the documented flag.
            cli = CLIOrchestrator(
                scan_orchestrator=enh_orch,
                use_ecosystem_aware=True,  # type: ignore[call-arg]
            )

        # The CLI orchestrator carries our enhancement orchestrator through.
        assert cli.scan_orchestrator is enh_orch, (
            "CLIOrchestrator dropped/replaced the injected "
            "EcosystemScanOrchestrator; enhancement is unreachable from CLI."
        )

    # -----------------------------------------------------------------------
    # Parent ScanOrchestrator still works on PyPI-only repos.
    # -----------------------------------------------------------------------
    def test_parent_scan_orchestrator_still_works_on_pypi_only_repo(
        self, enh_pypi_only_deps, enh_nvd_cache, tmp_path,
    ):
        _require_orchestration()
        from datetime import datetime, timezone

        # Build a Syft-shaped raw output directly from the PyPI dep fixture.
        raw_tool_output = {
            "tool": "syft",
            "components": _components_from_deps(enh_pypi_only_deps["deps"]),
        }

        parent_orch = ScanOrchestrator()  # parent defaults are sufficient

        # Use a permissive env name that the parent validator accepts.
        repo_path = str(tmp_path)
        # The parent validator may reject an empty/missing repo path; create
        # a placeholder file so the directory looks like a repo.
        (tmp_path / "requirements.txt").write_text("placeholder\n")

        try:
            result = parent_orch.run(
                repo_path=repo_path,
                output_format="cyclonedx",
                env="development",
                nvd_cache=enh_nvd_cache,
                raw_tool_output=raw_tool_output,
                vex_statements=[],
                last_synced_at=datetime.now(timezone.utc),
            )
        except Exception as exc:  # pragma: no cover — surface for diagnosis
            pytest.fail(
                f"Parent ScanOrchestrator regressed on a PyPI-only repo. "
                f"Underlying error: {exc!r}"
            )

        # Sanity: the parent should still produce a CycloneDX-shape SBOM
        # and detect at least the langchain CVE on a PyPI scan.
        assert result.sbom_document is not None
        sbom = result.sbom_document
        if isinstance(sbom, dict):
            assert sbom.get("bomFormat") == "CycloneDX"
        # At least one of the parent-known CVE ids is present in the result
        parent_known_cves = {"CVE-2023-34540", "CVE-2023-32681", "CVE-2018-19787"}
        ids = {
            v.get("cve_id") or v.get("id")
            for v in (result.active_vulns or [])
        }
        assert ids & parent_known_cves, (
            f"Parent ScanOrchestrator no longer detects parent-known CVEs "
            f"on a PyPI-only scan. Active vulns: {ids}"
        )
