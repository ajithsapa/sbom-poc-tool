"""
step8_tdd_red_phase_orchestration_tests.py
SBOM POC Tool — Orchestration TDD Red Phase Unit Tests
Session: SBOM-20260409-sb01

ALL TESTS MUST FAIL. The orchestration classes (ScanOrchestrator,
NVDSyncOrchestrator, CLIOrchestrator) raise NotImplementedError until
Step 9 implements them. ScanWorkflowState transitions are also tested
as failing stubs requiring a state-machine enforcement layer.

Each test class mocks the business layer components (Step 6) so that
unit tests isolate ONLY orchestration logic — not business logic.

Test count targets:
  TestScanOrchestratorInit          : 6
  TestScanOrchestratorCallOrder     : 12
  TestScanOrchestratorStaleness     : 7
  TestScanOrchestratorFormats       : 6
  TestScanOrchestratorErrorPaths    : 8
  TestScanOrchestratorResultShape   : 8
  TestNVDSyncOrchestratorDelegation : 8
  TestNVDSyncOrchestratorResult     : 7
  TestNVDSyncOrchestratorErrors     : 6
  TestCLIOrchestratorScanCommand    : 18
  TestCLIOrchestratorSyncCommand    : 10
  TestCLIOrchestratorOutputFlag     : 7
  TestScanWorkflowStateTransitions  : 14
  TestScanWorkflowStateMachine      : 10
  Total                             : 127
"""

import json
import os
import sys
import tempfile
from copy import deepcopy
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Any, Dict, List, Optional
from unittest.mock import MagicMock, call, patch, PropertyMock

import pytest

# ---------------------------------------------------------------------------
# Import business-layer types from Step 6 (stable — must not be re-implemented
# in the orchestration layer; only mocked in unit tests).
# ---------------------------------------------------------------------------
sys.path.insert(0, os.path.dirname(__file__))

from step6_tdd_green_phase import (
    CycloneDXSerializer,
    DependencyRecord,
    FilterResult,
    NVDCacheManager,
    NVDSyncError,
    NVDSyncResult,
    OSSToolAdapter,
    RemediationEnricher,
    SPDXSerializer,
    ScanJobValidator,
    StalenessResult,
    ValidationResult,
    VEXFilter,
    VulnerabilityMapper,
)

# ---------------------------------------------------------------------------
# Import orchestration stubs from Step 7.  These raise NotImplementedError
# in __init__ which is why every test that instantiates them will fail until
# Step 9 provides real implementations.
# ---------------------------------------------------------------------------
from step7_atdd_orchestration import (
    CLIOrchestrator,
    NVDSyncOrchestrator,
    NVDSyncWorkflowState,
    NVDWorkflowStateMachine,
    ScanOrchestrator,
    ScanResult,
    ScanWorkflowState,
    SyncResult,
    WorkflowStateMachine,
)

# ---------------------------------------------------------------------------
# Shared test data constants
# ---------------------------------------------------------------------------

NVD_CACHE_SEED: Dict = {
    "pkg:pypi/langchain@0.0.101": {
        "cve_id": "CVE-2023-34540",
        "cvss_score": 9.8,
        "severity": "High",
        "fixed_version": "0.0.247",
        "advisory_url": "https://nvd.nist.gov/vuln/detail/CVE-2023-34540",
    },
    "pkg:pypi/requests@2.27.1": {
        "cve_id": "CVE-2023-32681",
        "cvss_score": 6.1,
        "severity": "Medium",
        "fixed_version": "2.31.0",
        "advisory_url": "https://nvd.nist.gov/vuln/detail/CVE-2023-32681",
    },
    "pkg:pypi/numpy@1.22.0": {
        "cve_id": "CVE-2021-33430",
        "cvss_score": 5.5,
        "severity": "Medium",
        "fixed_version": "1.22.2",
        "advisory_url": "https://nvd.nist.gov/vuln/detail/CVE-2021-33430",
    },
}

RAW_SYFT_OUTPUT: Dict = {
    "tool": "syft",
    "components": [
        {
            "name": "langchain",
            "version": "0.0.101",
            "purl": "pkg:pypi/langchain@0.0.101",
            "cpes": ["cpe:2.3:a:langchain:langchain:0.0.101:*:*:*:*:python:*:*"],
            "metadata": {"Author": "LangChain, Inc."},
        },
        {
            "name": "requests",
            "version": "2.27.1",
            "purl": "pkg:pypi/requests@2.27.1",
            "cpes": ["cpe:2.3:a:python-requests:requests:2.27.1:*:*:*:*:python:*:*"],
            "metadata": {},
        },
    ],
}

DEDUPED_DEPS: List[Dict] = [
    {"name": "langchain", "exact_version": "0.0.101",
     "purl": "pkg:pypi/langchain@0.0.101", "supplier": "LangChain, Inc."},
    {"name": "requests", "exact_version": "2.27.1",
     "purl": "pkg:pypi/requests@2.27.1", "supplier": "Unknown"},
]

MAPPED_VULNS: List[Dict] = [
    {"cve_id": "CVE-2023-34540", "purl": "pkg:pypi/langchain@0.0.101",
     "cvss_score": 9.8, "severity": "High",
     "dep_name": "langchain", "dep_purl": "pkg:pypi/langchain@0.0.101"},
    {"cve_id": "CVE-2023-32681", "purl": "pkg:pypi/requests@2.27.1",
     "cvss_score": 6.1, "severity": "Medium",
     "dep_name": "requests", "dep_purl": "pkg:pypi/requests@2.27.1"},
]

ENRICHED_VULNS: List[Dict] = [
    {"cve_id": "CVE-2023-34540", "purl": "pkg:pypi/langchain@0.0.101",
     "cvss_score": 9.8, "severity": "High",
     "advisory_url": "https://nvd.nist.gov/vuln/detail/CVE-2023-34540",
     "fixed_version": "0.0.247",
     "upgrade_command": "pip install --upgrade langchain==0.0.247"},
    {"cve_id": "CVE-2023-32681", "purl": "pkg:pypi/requests@2.27.1",
     "cvss_score": 6.1, "severity": "Medium",
     "advisory_url": "https://nvd.nist.gov/vuln/detail/CVE-2023-32681",
     "fixed_version": "2.31.0", "upgrade_command": None},
]

CYCLONEDX_SBOM: Dict = {
    "bomFormat": "CycloneDX",
    "specVersion": "1.4",
    "serialNumber": "urn:uuid:test-1234",
    "version": 1,
    "metadata": {"timestamp": "2026-04-09T00:00:00Z", "tools": []},
    "components": [],
    "vulnerabilities": [],
}

SPDX_SBOM: Dict = {
    "spdxVersion": "SPDX-2.3",
    "dataLicense": "CC0-1.0",
    "SPDXID": "SPDXRef-DOCUMENT",
    "name": "test-repo",
    "documentNamespace": "https://sbom-tool.example.com/spdx/scan_001",
    "creationInfo": {"created": "2026-04-09T00:00:00Z", "creators": []},
    "packages": [],
}

VEX_SUPPRESS_LANGCHAIN: List[Dict] = [
    {
        "cve_id": "CVE-2023-34540",
        "purl": "pkg:pypi/langchain@0.0.101",
        "status": "not_affected",
        "justification": "vulnerable_code_not_in_execute_path",
    }
]

SYNC_NVD_RESULT = NVDSyncResult(records_added=5, records_updated=2)

FRESH_TIMESTAMP = datetime.now(timezone.utc)
STALE_TIMESTAMP = datetime.now(timezone.utc) - timedelta(days=8)


# ---------------------------------------------------------------------------
# Helper: build a fully-mocked set of business components
# ---------------------------------------------------------------------------

def _make_mock_components(
    valid: bool = True,
    normalised: Optional[List] = None,
    deduped: Optional[List] = None,
    mapped_vulns: Optional[List] = None,
    filter_result=None,
    enriched: Optional[List] = None,
    is_stale: bool = False,
    cdx_sbom: Optional[Dict] = None,
    spdx_sbom: Optional[Dict] = None,
) -> Dict[str, MagicMock]:
    """Return a dict of all 8 business-layer mocks with sensible defaults."""
    normalised = normalised if normalised is not None else list(DEDUPED_DEPS)
    deduped = deduped if deduped is not None else list(DEDUPED_DEPS)
    mapped_vulns = mapped_vulns if mapped_vulns is not None else list(MAPPED_VULNS)
    enriched = enriched if enriched is not None else list(ENRICHED_VULNS)
    cdx_sbom = cdx_sbom if cdx_sbom is not None else dict(CYCLONEDX_SBOM)
    spdx_sbom = spdx_sbom if spdx_sbom is not None else dict(SPDX_SBOM)

    if filter_result is None:
        fr = MagicMock()
        fr.active = list(mapped_vulns)
        fr.suppressed = []
        filter_result = fr

    validator = MagicMock(spec=ScanJobValidator)
    validator.validate.return_value = ValidationResult(valid=valid, errors=[] if valid else ["invalid path"])

    adapter = MagicMock(spec=OSSToolAdapter)
    adapter.normalise.return_value = list(normalised)
    adapter.deduplicate.return_value = list(deduped)

    mapper = MagicMock(spec=VulnerabilityMapper)
    mapper.map_vulnerabilities.return_value = list(mapped_vulns)

    vex_filter = MagicMock(spec=VEXFilter)
    vex_filter.apply.return_value = filter_result

    enricher = MagicMock(spec=RemediationEnricher)
    # enrich() returns one enriched vuln per call
    enricher.enrich.side_effect = lambda vuln, cache_entry: dict(
        enriched[0] if enriched else vuln
    )

    nvd_cache_manager = MagicMock(spec=NVDCacheManager)
    nvd_cache_manager.is_stale.return_value = is_stale

    cyclonedx_serializer = MagicMock(spec=CycloneDXSerializer)
    cyclonedx_serializer.serialize.return_value = dict(cdx_sbom)

    spdx_serializer = MagicMock(spec=SPDXSerializer)
    spdx_serializer.serialize.return_value = dict(spdx_sbom)

    return {
        "validator": validator,
        "adapter": adapter,
        "mapper": mapper,
        "vex_filter": vex_filter,
        "enricher": enricher,
        "nvd_cache_manager": nvd_cache_manager,
        "cyclonedx_serializer": cyclonedx_serializer,
        "spdx_serializer": spdx_serializer,
    }


# ===========================================================================
# CLASS 1: TestScanOrchestratorInit (6 tests)
# Verifies constructor stores injected components and raises on missing
# required deps.
# ===========================================================================

class TestScanOrchestratorInit:
    """Unit tests for ScanOrchestrator.__init__ dependency injection."""

    def test_instantiation_with_all_deps_does_not_raise(self):
        """ScanOrchestrator accepts all 8 injected components — MUST FAIL."""
        mocks = _make_mock_components()
        # NotImplementedError expected until Step 9 implements this
        orch = ScanOrchestrator(
            validator=mocks["validator"],
            adapter=mocks["adapter"],
            mapper=mocks["mapper"],
            vex_filter=mocks["vex_filter"],
            enricher=mocks["enricher"],
            nvd_cache_manager=mocks["nvd_cache_manager"],
            cyclonedx_serializer=mocks["cyclonedx_serializer"],
            spdx_serializer=mocks["spdx_serializer"],
        )
        assert orch is not None, "ScanOrchestrator should be constructable with all deps"

    def test_injected_validator_stored_on_instance(self):
        """Injected validator accessible as orch.validator — MUST FAIL."""
        mocks = _make_mock_components()
        orch = ScanOrchestrator(**mocks)
        assert orch.validator is mocks["validator"], (
            "ScanOrchestrator must store injected validator"
        )

    def test_injected_adapter_stored_on_instance(self):
        """Injected adapter accessible as orch.adapter — MUST FAIL."""
        mocks = _make_mock_components()
        orch = ScanOrchestrator(**mocks)
        assert orch.adapter is mocks["adapter"], (
            "ScanOrchestrator must store injected adapter"
        )

    def test_injected_nvd_cache_manager_stored_on_instance(self):
        """Injected nvd_cache_manager accessible on instance — MUST FAIL."""
        mocks = _make_mock_components()
        orch = ScanOrchestrator(**mocks)
        assert orch.nvd_cache_manager is mocks["nvd_cache_manager"], (
            "ScanOrchestrator must store injected nvd_cache_manager"
        )

    def test_instantiation_with_default_none_deps_uses_real_classes(self):
        """ScanOrchestrator() with no args defaults to real business classes — MUST FAIL."""
        orch = ScanOrchestrator()
        assert isinstance(orch.validator, ScanJobValidator), (
            "Default validator must be ScanJobValidator instance"
        )
        assert isinstance(orch.adapter, OSSToolAdapter), (
            "Default adapter must be OSSToolAdapter instance"
        )

    def test_run_method_exists_and_is_callable(self):
        """ScanOrchestrator exposes a callable .run() method — MUST FAIL."""
        mocks = _make_mock_components()
        orch = ScanOrchestrator(**mocks)
        assert callable(getattr(orch, "run", None)), (
            "ScanOrchestrator must have a callable run() method"
        )


# ===========================================================================
# CLASS 2: TestScanOrchestratorCallOrder (12 tests)
# Critical: validates that business components are called in the mandated
# sequence and with correct arguments.
# ===========================================================================

class TestScanOrchestratorCallOrder:
    """Unit tests for ScanOrchestrator component call ordering."""

    def test_validator_called_before_adapter_normalise(self, tmp_path):
        """validate() must be called before normalise() — MUST FAIL."""
        mocks = _make_mock_components()
        call_log: List[str] = []

        mocks["validator"].validate.side_effect = (
            lambda *a, **kw: call_log.append("validate")
            or ValidationResult(valid=True)
        )
        mocks["adapter"].normalise.side_effect = (
            lambda *a, **kw: call_log.append("normalise") or list(DEDUPED_DEPS)
        )

        orch = ScanOrchestrator(**mocks)
        orch.run(
            repo_path=str(tmp_path),
            output_format="cyclonedx",
            env="development",
            nvd_cache=NVD_CACHE_SEED,
            raw_tool_output=RAW_SYFT_OUTPUT,
        )

        assert "validate" in call_log, "validate() must be called"
        assert "normalise" in call_log, "normalise() must be called"
        assert call_log.index("validate") < call_log.index("normalise"), (
            "validate() must be called before normalise()"
        )

    def test_deduplicate_called_after_normalise(self, tmp_path):
        """deduplicate() must be called after normalise() — MUST FAIL."""
        mocks = _make_mock_components()
        call_log: List[str] = []

        mocks["adapter"].normalise.side_effect = (
            lambda *a, **kw: call_log.append("normalise") or list(DEDUPED_DEPS)
        )
        mocks["adapter"].deduplicate.side_effect = (
            lambda *a, **kw: call_log.append("deduplicate") or list(DEDUPED_DEPS)
        )

        orch = ScanOrchestrator(**mocks)
        orch.run(
            repo_path=str(tmp_path),
            output_format="cyclonedx",
            env="development",
            nvd_cache=NVD_CACHE_SEED,
            raw_tool_output=RAW_SYFT_OUTPUT,
        )

        assert "deduplicate" in call_log, "deduplicate() must be called"
        assert call_log.index("normalise") < call_log.index("deduplicate"), (
            "deduplicate() must be called after normalise()"
        )

    def test_map_vulnerabilities_called_with_deduped_deps(self, tmp_path):
        """map_vulnerabilities() receives the deduped list, not the raw list — MUST FAIL."""
        mocks = _make_mock_components()
        deduped = [{"name": "langchain", "exact_version": "0.0.101",
                    "purl": "pkg:pypi/langchain@0.0.101", "supplier": "LangChain, Inc."}]
        mocks["adapter"].deduplicate.return_value = deduped

        orch = ScanOrchestrator(**mocks)
        orch.run(
            repo_path=str(tmp_path),
            output_format="cyclonedx",
            env="development",
            nvd_cache=NVD_CACHE_SEED,
            raw_tool_output=RAW_SYFT_OUTPUT,
        )

        mocks["mapper"].map_vulnerabilities.assert_called_once()
        call_args = mocks["mapper"].map_vulnerabilities.call_args
        actual_deps = call_args[0][0] if call_args[0] else call_args[1].get("deps")
        assert actual_deps == deduped, (
            "map_vulnerabilities() must receive the deduplicated dependency list"
        )

    def test_deduplicate_called_before_map_vulnerabilities(self, tmp_path):
        """deduplicate() must precede map_vulnerabilities() — MUST FAIL."""
        mocks = _make_mock_components()
        call_log: List[str] = []

        mocks["adapter"].deduplicate.side_effect = (
            lambda *a, **kw: call_log.append("deduplicate") or list(DEDUPED_DEPS)
        )
        mocks["mapper"].map_vulnerabilities.side_effect = (
            lambda *a, **kw: call_log.append("map_vulnerabilities") or list(MAPPED_VULNS)
        )

        orch = ScanOrchestrator(**mocks)
        orch.run(
            repo_path=str(tmp_path),
            output_format="cyclonedx",
            env="development",
            nvd_cache=NVD_CACHE_SEED,
            raw_tool_output=RAW_SYFT_OUTPUT,
        )

        assert call_log.index("deduplicate") < call_log.index("map_vulnerabilities"), (
            "deduplicate() must be called before map_vulnerabilities()"
        )

    def test_vex_filter_called_before_enricher(self, tmp_path):
        """VEXFilter.apply() must be called before RemediationEnricher.enrich() — MUST FAIL."""
        mocks = _make_mock_components()
        call_log: List[str] = []

        fr = MagicMock()
        fr.active = list(MAPPED_VULNS)
        fr.suppressed = []
        mocks["vex_filter"].apply.side_effect = (
            lambda *a, **kw: call_log.append("vex_apply") or fr
        )
        mocks["enricher"].enrich.side_effect = (
            lambda *a, **kw: call_log.append("enrich") or dict(ENRICHED_VULNS[0])
        )

        orch = ScanOrchestrator(**mocks)
        orch.run(
            repo_path=str(tmp_path),
            output_format="cyclonedx",
            env="development",
            nvd_cache=NVD_CACHE_SEED,
            raw_tool_output=RAW_SYFT_OUTPUT,
        )

        assert "vex_apply" in call_log, "VEXFilter.apply() must be called"
        assert "enrich" in call_log, "RemediationEnricher.enrich() must be called"
        assert call_log.index("vex_apply") < call_log.index("enrich"), (
            "VEXFilter.apply() must be called before RemediationEnricher.enrich()"
        )

    def test_nvd_staleness_checked_before_vulnerability_mapping(self, tmp_path):
        """NVDCacheManager.is_stale() must be checked before map_vulnerabilities() — MUST FAIL."""
        mocks = _make_mock_components()
        call_log: List[str] = []

        mocks["nvd_cache_manager"].is_stale.side_effect = (
            lambda *a, **kw: call_log.append("is_stale") or False
        )
        mocks["mapper"].map_vulnerabilities.side_effect = (
            lambda *a, **kw: call_log.append("map_vulnerabilities") or list(MAPPED_VULNS)
        )

        orch = ScanOrchestrator(**mocks)
        orch.run(
            repo_path=str(tmp_path),
            output_format="cyclonedx",
            env="development",
            nvd_cache=NVD_CACHE_SEED,
            raw_tool_output=RAW_SYFT_OUTPUT,
            last_synced_at=FRESH_TIMESTAMP,
        )

        assert "is_stale" in call_log, "is_stale() must be called"
        assert "map_vulnerabilities" in call_log, "map_vulnerabilities() must be called"
        assert call_log.index("is_stale") < call_log.index("map_vulnerabilities"), (
            "is_stale() must be checked before map_vulnerabilities() is invoked"
        )

    def test_validator_receives_repo_path_not_inline_data(self, tmp_path):
        """ScanJobValidator.validate() is called with repo_path string — MUST FAIL."""
        mocks = _make_mock_components()
        repo = str(tmp_path)

        orch = ScanOrchestrator(**mocks)
        orch.run(
            repo_path=repo,
            output_format="cyclonedx",
            env="development",
            nvd_cache=NVD_CACHE_SEED,
            raw_tool_output=RAW_SYFT_OUTPUT,
        )

        call_args = mocks["validator"].validate.call_args
        # First positional argument (or 'repo_path' kwarg) must be the path string
        first_arg = call_args[0][0] if call_args[0] else call_args[1].get("repo_path")
        assert first_arg == repo, (
            "validate() must receive the repo_path string, not any inline scan data"
        )

    def test_validator_receives_env_parameter(self, tmp_path):
        """ScanJobValidator.validate() receives the env parameter — MUST FAIL."""
        mocks = _make_mock_components()

        orch = ScanOrchestrator(**mocks)
        orch.run(
            repo_path=str(tmp_path),
            output_format="cyclonedx",
            env="production",
            nvd_cache=NVD_CACHE_SEED,
            raw_tool_output=RAW_SYFT_OUTPUT,
        )

        call_args = mocks["validator"].validate.call_args
        positional = call_args[0]
        keyword = call_args[1] if call_args[1] else {}
        env_received = (
            keyword.get("env")
            or (positional[1] if len(positional) > 1 else None)
        )
        assert env_received == "production", (
            "validate() must receive the env='production' parameter"
        )

    def test_adapter_normalise_called_with_raw_tool_output(self, tmp_path):
        """OSSToolAdapter.normalise() is called with raw_tool_output dict — MUST FAIL."""
        mocks = _make_mock_components()

        orch = ScanOrchestrator(**mocks)
        orch.run(
            repo_path=str(tmp_path),
            output_format="cyclonedx",
            env="development",
            nvd_cache=NVD_CACHE_SEED,
            raw_tool_output=RAW_SYFT_OUTPUT,
        )

        mocks["adapter"].normalise.assert_called_once_with(RAW_SYFT_OUTPUT)

    def test_map_vulnerabilities_called_with_nvd_cache(self, tmp_path):
        """map_vulnerabilities() receives the nvd_cache dict — MUST FAIL."""
        mocks = _make_mock_components()

        orch = ScanOrchestrator(**mocks)
        orch.run(
            repo_path=str(tmp_path),
            output_format="cyclonedx",
            env="development",
            nvd_cache=NVD_CACHE_SEED,
            raw_tool_output=RAW_SYFT_OUTPUT,
        )

        call_args = mocks["mapper"].map_vulnerabilities.call_args
        positional = call_args[0]
        keyword = call_args[1] if call_args[1] else {}
        cache_received = (
            keyword.get("cache")
            or (positional[1] if len(positional) > 1 else None)
        )
        assert cache_received == NVD_CACHE_SEED, (
            "map_vulnerabilities() must receive the nvd_cache dict"
        )

    def test_enrich_called_only_for_active_vulns_not_suppressed(self, tmp_path):
        """enrich() is called only for vulns passing VEX filter — MUST FAIL."""
        mocks = _make_mock_components()
        langchain_vuln = dict(MAPPED_VULNS[0])
        requests_vuln = dict(MAPPED_VULNS[1])

        fr = MagicMock()
        fr.active = [requests_vuln]   # langchain suppressed
        fr.suppressed = [langchain_vuln]
        mocks["vex_filter"].apply.return_value = fr

        orch = ScanOrchestrator(**mocks)
        orch.run(
            repo_path=str(tmp_path),
            output_format="cyclonedx",
            env="development",
            nvd_cache=NVD_CACHE_SEED,
            raw_tool_output=RAW_SYFT_OUTPUT,
            vex_statements=VEX_SUPPRESS_LANGCHAIN,
        )

        # enrich() should be called exactly once (for requests, not langchain)
        assert mocks["enricher"].enrich.call_count == 1, (
            "enrich() must be called only for active_vulns, not suppressed ones"
        )

    def test_cyclonedx_serializer_not_called_when_spdx_requested(self, tmp_path):
        """CycloneDXSerializer.serialize() is NOT called when format is spdx — MUST FAIL."""
        mocks = _make_mock_components()

        orch = ScanOrchestrator(**mocks)
        orch.run(
            repo_path=str(tmp_path),
            output_format="spdx",
            env="development",
            nvd_cache=NVD_CACHE_SEED,
            raw_tool_output=RAW_SYFT_OUTPUT,
        )

        mocks["cyclonedx_serializer"].serialize.assert_not_called()
        mocks["spdx_serializer"].serialize.assert_called_once()


# ===========================================================================
# CLASS 3: TestScanOrchestratorStaleness (7 tests)
# ===========================================================================

class TestScanOrchestratorStaleness:
    """Unit tests for ScanOrchestrator NVD cache staleness handling."""

    def test_stale_cache_adds_warning_to_result(self, tmp_path):
        """Stale cache produces non-empty ScanResult.warnings — MUST FAIL."""
        mocks = _make_mock_components(is_stale=True)

        orch = ScanOrchestrator(**mocks)
        result = orch.run(
            repo_path=str(tmp_path),
            output_format="cyclonedx",
            env="development",
            nvd_cache=NVD_CACHE_SEED,
            raw_tool_output=RAW_SYFT_OUTPUT,
            last_synced_at=STALE_TIMESTAMP,
        )

        assert len(result.warnings) > 0, (
            "ScanResult.warnings must be non-empty when cache is stale"
        )

    def test_stale_cache_scan_completes_does_not_abort(self, tmp_path):
        """Stale cache does not raise an exception — MUST FAIL."""
        mocks = _make_mock_components(is_stale=True)

        orch = ScanOrchestrator(**mocks)
        # Must complete without raising
        result = orch.run(
            repo_path=str(tmp_path),
            output_format="cyclonedx",
            env="development",
            nvd_cache=NVD_CACHE_SEED,
            raw_tool_output=RAW_SYFT_OUTPUT,
            last_synced_at=STALE_TIMESTAMP,
        )

        assert result is not None, "ScanOrchestrator must return a result even when cache is stale"
        assert result.sbom_document is not None, "sbom_document must be produced on stale run"

    def test_fresh_cache_produces_no_stale_warning(self, tmp_path):
        """Fresh cache (synced today) produces empty warnings list — MUST FAIL."""
        mocks = _make_mock_components(is_stale=False)

        orch = ScanOrchestrator(**mocks)
        result = orch.run(
            repo_path=str(tmp_path),
            output_format="cyclonedx",
            env="development",
            nvd_cache=NVD_CACHE_SEED,
            raw_tool_output=RAW_SYFT_OUTPUT,
            last_synced_at=FRESH_TIMESTAMP,
        )

        # No stale warning when cache is fresh
        stale_warnings = [w for w in result.warnings if "stale" in w.lower()]
        assert stale_warnings == [], (
            "ScanResult.warnings must not contain stale-cache messages for a fresh cache"
        )

    def test_is_stale_called_with_last_synced_at_timestamp(self, tmp_path):
        """is_stale() receives the last_synced_at timestamp arg — MUST FAIL."""
        mocks = _make_mock_components(is_stale=False)

        orch = ScanOrchestrator(**mocks)
        orch.run(
            repo_path=str(tmp_path),
            output_format="cyclonedx",
            env="development",
            nvd_cache=NVD_CACHE_SEED,
            raw_tool_output=RAW_SYFT_OUTPUT,
            last_synced_at=FRESH_TIMESTAMP,
        )

        mocks["nvd_cache_manager"].is_stale.assert_called_once_with(FRESH_TIMESTAMP)

    def test_stale_warning_message_contains_stale_keyword(self, tmp_path):
        """Stale warning message includes meaningful text — MUST FAIL."""
        mocks = _make_mock_components(is_stale=True)

        orch = ScanOrchestrator(**mocks)
        result = orch.run(
            repo_path=str(tmp_path),
            output_format="cyclonedx",
            env="development",
            nvd_cache=NVD_CACHE_SEED,
            raw_tool_output=RAW_SYFT_OUTPUT,
            last_synced_at=STALE_TIMESTAMP,
        )

        warning_text = " ".join(result.warnings).lower()
        assert "stale" in warning_text or "sync" in warning_text, (
            "Stale warning must reference 'stale' or 'sync' in its message text"
        )

    def test_none_last_synced_at_does_not_cause_error(self, tmp_path):
        """None last_synced_at is handled gracefully — MUST FAIL."""
        mocks = _make_mock_components(is_stale=False)

        orch = ScanOrchestrator(**mocks)
        # Must not raise TypeError when last_synced_at is None
        result = orch.run(
            repo_path=str(tmp_path),
            output_format="cyclonedx",
            env="development",
            nvd_cache=NVD_CACHE_SEED,
            raw_tool_output=RAW_SYFT_OUTPUT,
            last_synced_at=None,
        )

        assert result is not None, "run() must handle None last_synced_at without crashing"

    def test_stale_warning_does_not_prevent_sbom_generation(self, tmp_path):
        """sbom_document is still populated when stale warning fires — MUST FAIL."""
        mocks = _make_mock_components(is_stale=True)

        orch = ScanOrchestrator(**mocks)
        result = orch.run(
            repo_path=str(tmp_path),
            output_format="cyclonedx",
            env="development",
            nvd_cache=NVD_CACHE_SEED,
            raw_tool_output=RAW_SYFT_OUTPUT,
            last_synced_at=STALE_TIMESTAMP,
        )

        assert result.sbom_document is not None, (
            "sbom_document must still be generated even when stale warning is present"
        )
        assert result.sbom_document.get("bomFormat") == "CycloneDX", (
            "sbom_document must be valid CycloneDX even when stale"
        )


# ===========================================================================
# CLASS 4: TestScanOrchestratorFormats (6 tests)
# ===========================================================================

class TestScanOrchestratorFormats:
    """Unit tests for ScanOrchestrator serialisation format routing."""

    def test_cyclonedx_format_routes_to_cyclonedx_serializer(self, tmp_path):
        """output_format='cyclonedx' calls CycloneDXSerializer.serialize() — MUST FAIL."""
        mocks = _make_mock_components()

        orch = ScanOrchestrator(**mocks)
        orch.run(
            repo_path=str(tmp_path),
            output_format="cyclonedx",
            env="development",
            nvd_cache=NVD_CACHE_SEED,
            raw_tool_output=RAW_SYFT_OUTPUT,
        )

        mocks["cyclonedx_serializer"].serialize.assert_called_once()

    def test_spdx_format_routes_to_spdx_serializer(self, tmp_path):
        """output_format='spdx' calls SPDXSerializer.serialize() — MUST FAIL."""
        mocks = _make_mock_components()

        orch = ScanOrchestrator(**mocks)
        orch.run(
            repo_path=str(tmp_path),
            output_format="spdx",
            env="development",
            nvd_cache=NVD_CACHE_SEED,
            raw_tool_output=RAW_SYFT_OUTPUT,
        )

        mocks["spdx_serializer"].serialize.assert_called_once()

    def test_spdx_format_does_not_call_cyclonedx_serializer(self, tmp_path):
        """output_format='spdx' never calls CycloneDXSerializer — MUST FAIL."""
        mocks = _make_mock_components()

        orch = ScanOrchestrator(**mocks)
        orch.run(
            repo_path=str(tmp_path),
            output_format="spdx",
            env="development",
            nvd_cache=NVD_CACHE_SEED,
            raw_tool_output=RAW_SYFT_OUTPUT,
        )

        mocks["cyclonedx_serializer"].serialize.assert_not_called()

    def test_cyclonedx_result_has_correct_bom_format(self, tmp_path):
        """ScanResult.sbom_document has bomFormat=CycloneDX for cdx run — MUST FAIL."""
        mocks = _make_mock_components()

        orch = ScanOrchestrator(**mocks)
        result = orch.run(
            repo_path=str(tmp_path),
            output_format="cyclonedx",
            env="development",
            nvd_cache=NVD_CACHE_SEED,
            raw_tool_output=RAW_SYFT_OUTPUT,
        )

        assert result.sbom_document.get("bomFormat") == "CycloneDX", (
            "sbom_document must carry bomFormat='CycloneDX' for cyclonedx output"
        )

    def test_spdx_result_has_correct_spdx_version(self, tmp_path):
        """ScanResult.sbom_document has spdxVersion=SPDX-2.3 for spdx run — MUST FAIL."""
        mocks = _make_mock_components(spdx_sbom=dict(SPDX_SBOM))

        orch = ScanOrchestrator(**mocks)
        result = orch.run(
            repo_path=str(tmp_path),
            output_format="spdx",
            env="development",
            nvd_cache=NVD_CACHE_SEED,
            raw_tool_output=RAW_SYFT_OUTPUT,
        )

        assert result.sbom_document.get("spdxVersion") == "SPDX-2.3", (
            "sbom_document must carry spdxVersion='SPDX-2.3' for spdx output"
        )

    def test_unknown_format_raises_value_error(self, tmp_path):
        """output_format='xml' raises ValueError — MUST FAIL."""
        mocks = _make_mock_components()

        orch = ScanOrchestrator(**mocks)
        with pytest.raises((ValueError, NotImplementedError)):
            orch.run(
                repo_path=str(tmp_path),
                output_format="xml",
                env="development",
                nvd_cache=NVD_CACHE_SEED,
                raw_tool_output=RAW_SYFT_OUTPUT,
            )


# ===========================================================================
# CLASS 5: TestScanOrchestratorErrorPaths (8 tests)
# ===========================================================================

class TestScanOrchestratorErrorPaths:
    """Unit tests for ScanOrchestrator validation and error propagation."""

    def test_invalid_validation_aborts_before_normalise(self, tmp_path):
        """On invalid job, normalise() must never be called — MUST FAIL."""
        mocks = _make_mock_components(valid=False)

        orch = ScanOrchestrator(**mocks)
        with pytest.raises(Exception):
            orch.run(
                repo_path="/comma,path",
                output_format="cyclonedx",
                env="development",
                nvd_cache=NVD_CACHE_SEED,
                raw_tool_output=RAW_SYFT_OUTPUT,
            )

        mocks["adapter"].normalise.assert_not_called()

    def test_invalid_validation_aborts_before_mapper(self, tmp_path):
        """On invalid job, map_vulnerabilities() must never be called — MUST FAIL."""
        mocks = _make_mock_components(valid=False)

        orch = ScanOrchestrator(**mocks)
        with pytest.raises(Exception):
            orch.run(
                repo_path="/comma,path",
                output_format="cyclonedx",
                env="development",
                nvd_cache=NVD_CACHE_SEED,
                raw_tool_output=RAW_SYFT_OUTPUT,
            )

        mocks["mapper"].map_vulnerabilities.assert_not_called()

    def test_multi_repo_path_raises_on_validation(self, tmp_path):
        """Comma-separated repo path raises ValueError or ValidationError — MUST FAIL."""
        mocks = _make_mock_components(valid=False)

        orch = ScanOrchestrator(**mocks)
        with pytest.raises(Exception) as exc_info:
            orch.run(
                repo_path="/repo1,/repo2",
                output_format="cyclonedx",
                env="production",
                nvd_cache=NVD_CACHE_SEED,
                raw_tool_output=RAW_SYFT_OUTPUT,
            )

        assert exc_info.value is not None, (
            "Multi-repo path must raise an exception at the orchestration boundary"
        )

    def test_unknown_env_raises_on_validation(self, tmp_path):
        """Unknown env value raises at the orchestration boundary — MUST FAIL."""
        validator_mock = MagicMock(spec=ScanJobValidator)
        validator_mock.validate.return_value = ValidationResult(
            valid=False, errors=["Unknown environment: sandbox"]
        )
        mocks = _make_mock_components()
        mocks["validator"] = validator_mock

        orch = ScanOrchestrator(**mocks)
        with pytest.raises(Exception):
            orch.run(
                repo_path=str(tmp_path),
                output_format="cyclonedx",
                env="sandbox",
                nvd_cache=NVD_CACHE_SEED,
                raw_tool_output=RAW_SYFT_OUTPUT,
            )

    def test_nvd_sync_error_propagates_through_orchestrator(self, tmp_path):
        """NVDSyncError raised by a component propagates — is not swallowed — MUST FAIL."""
        mocks = _make_mock_components()
        mocks["nvd_cache_manager"].is_stale.side_effect = NVDSyncError(
            "Cache DB corruption"
        )

        orch = ScanOrchestrator(**mocks)
        with pytest.raises(NVDSyncError):
            orch.run(
                repo_path=str(tmp_path),
                output_format="cyclonedx",
                env="development",
                nvd_cache=NVD_CACHE_SEED,
                raw_tool_output=RAW_SYFT_OUTPUT,
            )

    def test_serializer_error_propagates_through_orchestrator(self, tmp_path):
        """Serializer runtime error propagates — is not swallowed — MUST FAIL."""
        mocks = _make_mock_components()
        mocks["cyclonedx_serializer"].serialize.side_effect = RuntimeError(
            "Serialization failed"
        )

        orch = ScanOrchestrator(**mocks)
        with pytest.raises(RuntimeError):
            orch.run(
                repo_path=str(tmp_path),
                output_format="cyclonedx",
                env="development",
                nvd_cache=NVD_CACHE_SEED,
                raw_tool_output=RAW_SYFT_OUTPUT,
            )

    def test_no_socket_connect_during_scan(self, tmp_path):
        """socket.socket.connect must never be called during run() — MUST FAIL (AC-12)."""
        mocks = _make_mock_components()

        orch = ScanOrchestrator(**mocks)
        with patch("socket.socket.connect") as mock_connect:
            orch.run(
                repo_path=str(tmp_path),
                output_format="cyclonedx",
                env="development",
                nvd_cache=NVD_CACHE_SEED,
                raw_tool_output=RAW_SYFT_OUTPUT,
                last_synced_at=FRESH_TIMESTAMP,
            )
            mock_connect.assert_not_called()

    def test_empty_raw_tool_output_returns_empty_deps_scan_result(self, tmp_path):
        """Empty raw_tool_output produces ScanResult with empty deps — MUST FAIL."""
        mocks = _make_mock_components(normalised=[], deduped=[], mapped_vulns=[])

        orch = ScanOrchestrator(**mocks)
        result = orch.run(
            repo_path=str(tmp_path),
            output_format="cyclonedx",
            env="development",
            nvd_cache={},
            raw_tool_output={"tool": "syft", "components": []},
        )

        assert result.dependencies == [], "Empty tool output should yield no dependencies"
        assert result.active_vulns == [], "Empty tool output should yield no active vulns"


# ===========================================================================
# CLASS 6: TestScanOrchestratorResultShape (8 tests)
# ===========================================================================

class TestScanOrchestratorResultShape:
    """Unit tests for ScanResult data contract compliance."""

    def test_run_returns_scan_result_instance(self, tmp_path):
        """run() returns a ScanResult dataclass instance — MUST FAIL."""
        mocks = _make_mock_components()
        orch = ScanOrchestrator(**mocks)
        result = orch.run(
            repo_path=str(tmp_path),
            output_format="cyclonedx",
            env="development",
            nvd_cache=NVD_CACHE_SEED,
            raw_tool_output=RAW_SYFT_OUTPUT,
        )
        assert isinstance(result, ScanResult), (
            "run() must return a ScanResult instance"
        )

    def test_result_dependencies_field_populated_from_deduped(self, tmp_path):
        """ScanResult.dependencies equals the deduped dep list — MUST FAIL."""
        deduped = [{"name": "flask", "exact_version": "3.0.0",
                    "purl": "pkg:pypi/flask@3.0.0", "supplier": "Pallets"}]
        mocks = _make_mock_components(deduped=deduped)

        orch = ScanOrchestrator(**mocks)
        result = orch.run(
            repo_path=str(tmp_path),
            output_format="cyclonedx",
            env="development",
            nvd_cache={},
            raw_tool_output={"tool": "syft", "components": []},
        )

        assert result.dependencies == deduped, (
            "ScanResult.dependencies must be set to the deduplicated dependency list"
        )

    def test_result_suppressed_vulns_from_vex_filter(self, tmp_path):
        """ScanResult.suppressed_vulns carries VEX-suppressed entries — MUST FAIL."""
        suppressed = [dict(MAPPED_VULNS[0])]
        fr = MagicMock()
        fr.active = [dict(MAPPED_VULNS[1])]
        fr.suppressed = suppressed
        mocks = _make_mock_components(filter_result=fr)

        orch = ScanOrchestrator(**mocks)
        result = orch.run(
            repo_path=str(tmp_path),
            output_format="cyclonedx",
            env="development",
            nvd_cache=NVD_CACHE_SEED,
            raw_tool_output=RAW_SYFT_OUTPUT,
            vex_statements=VEX_SUPPRESS_LANGCHAIN,
        )

        assert result.suppressed_vulns == suppressed, (
            "ScanResult.suppressed_vulns must carry the list returned by VEXFilter.apply()"
        )

    def test_result_active_vulns_are_enriched(self, tmp_path):
        """ScanResult.active_vulns contains enriched records — MUST FAIL."""
        mocks = _make_mock_components()

        orch = ScanOrchestrator(**mocks)
        result = orch.run(
            repo_path=str(tmp_path),
            output_format="cyclonedx",
            env="development",
            nvd_cache=NVD_CACHE_SEED,
            raw_tool_output=RAW_SYFT_OUTPUT,
        )

        for vuln in result.active_vulns:
            assert "advisory_url" in vuln, (
                "Each active_vuln must have advisory_url from RemediationEnricher"
            )

    def test_result_sbom_document_not_none_for_cyclonedx(self, tmp_path):
        """ScanResult.sbom_document is not None for cyclonedx run — MUST FAIL."""
        mocks = _make_mock_components()
        orch = ScanOrchestrator(**mocks)
        result = orch.run(
            repo_path=str(tmp_path),
            output_format="cyclonedx",
            env="development",
            nvd_cache=NVD_CACHE_SEED,
            raw_tool_output=RAW_SYFT_OUTPUT,
        )
        assert result.sbom_document is not None, "sbom_document must not be None"

    def test_result_warnings_is_list_type(self, tmp_path):
        """ScanResult.warnings is always a list — MUST FAIL."""
        mocks = _make_mock_components()
        orch = ScanOrchestrator(**mocks)
        result = orch.run(
            repo_path=str(tmp_path),
            output_format="cyclonedx",
            env="development",
            nvd_cache=NVD_CACHE_SEED,
            raw_tool_output=RAW_SYFT_OUTPUT,
        )
        assert isinstance(result.warnings, list), "ScanResult.warnings must be a list"

    def test_result_workflow_states_visited_is_list(self, tmp_path):
        """ScanResult.workflow_states_visited is a list — MUST FAIL."""
        mocks = _make_mock_components()
        orch = ScanOrchestrator(**mocks)
        result = orch.run(
            repo_path=str(tmp_path),
            output_format="cyclonedx",
            env="development",
            nvd_cache=NVD_CACHE_SEED,
            raw_tool_output=RAW_SYFT_OUTPUT,
        )
        assert isinstance(result.workflow_states_visited, list), (
            "ScanResult.workflow_states_visited must be a list"
        )

    def test_result_workflow_states_visited_records_all_pipeline_stages(self, tmp_path):
        """workflow_states_visited records all 7 scan pipeline stages — MUST FAIL."""
        mocks = _make_mock_components()
        orch = ScanOrchestrator(**mocks)
        result = orch.run(
            repo_path=str(tmp_path),
            output_format="cyclonedx",
            env="development",
            nvd_cache=NVD_CACHE_SEED,
            raw_tool_output=RAW_SYFT_OUTPUT,
        )

        expected_states = {
            ScanWorkflowState.IDLE.value,
            ScanWorkflowState.SCANNING_DEPENDENCIES.value,
            ScanWorkflowState.DEDUPLICATING_OUTPUT.value,
            ScanWorkflowState.MATCHING_VULNERABILITIES.value,
            ScanWorkflowState.FILTERING_VEX.value,
            ScanWorkflowState.ENRICHING_REMEDIATION.value,
            ScanWorkflowState.EXPORTING_SBOM.value,
        }
        visited = set(result.workflow_states_visited)
        assert expected_states.issubset(visited), (
            f"workflow_states_visited must record all 7 pipeline stages. "
            f"Missing: {expected_states - visited}"
        )


# ===========================================================================
# CLASS 7: TestNVDSyncOrchestratorDelegation (8 tests)
# ===========================================================================

class TestNVDSyncOrchestratorDelegation:
    """Unit tests for NVDSyncOrchestrator delegation to NVDCacheManager."""

    def test_instantiation_with_cache_manager_does_not_raise(self):
        """NVDSyncOrchestrator accepts injected cache_manager — MUST FAIL."""
        cache_manager = MagicMock(spec=NVDCacheManager)
        sync_orch = NVDSyncOrchestrator(cache_manager=cache_manager)
        assert sync_orch is not None, "NVDSyncOrchestrator must be constructable"

    def test_cache_manager_stored_on_instance(self):
        """Injected cache_manager accessible on instance — MUST FAIL."""
        cache_manager = MagicMock(spec=NVDCacheManager)
        sync_orch = NVDSyncOrchestrator(cache_manager=cache_manager)
        assert sync_orch.cache_manager is cache_manager, (
            "NVDSyncOrchestrator must store injected cache_manager"
        )

    def test_run_delegates_to_cache_manager_sync(self, tmp_path):
        """run() calls NVDCacheManager.sync(source_path) exactly once — MUST FAIL."""
        source_path = str(tmp_path / "nvd_feed.json")
        (tmp_path / "nvd_feed.json").write_text('{"CVE_Items": []}')

        cache_manager = MagicMock(spec=NVDCacheManager)
        cache_manager.sync.return_value = SYNC_NVD_RESULT

        sync_orch = NVDSyncOrchestrator(cache_manager=cache_manager)
        sync_orch.run(source_path)

        cache_manager.sync.assert_called_once_with(source_path)

    def test_run_does_not_reimplement_sync_logic(self, tmp_path):
        """NVDSyncOrchestrator does not open files itself — delegates fully — MUST FAIL."""
        source_path = str(tmp_path / "nvd_feed.json")
        (tmp_path / "nvd_feed.json").write_text('{"CVE_Items": []}')

        cache_manager = MagicMock(spec=NVDCacheManager)
        cache_manager.sync.return_value = SYNC_NVD_RESULT

        sync_orch = NVDSyncOrchestrator(cache_manager=cache_manager)

        with patch("builtins.open") as mock_open:
            sync_orch.run(source_path)
            # Orchestrator must not open files directly — NVDCacheManager handles I/O
            mock_open.assert_not_called()

    def test_run_returns_sync_result_instance(self, tmp_path):
        """run() returns a SyncResult instance — MUST FAIL."""
        source_path = str(tmp_path / "feed.json")
        (tmp_path / "feed.json").write_text('{"CVE_Items": []}')

        cache_manager = MagicMock(spec=NVDCacheManager)
        cache_manager.sync.return_value = SYNC_NVD_RESULT

        sync_orch = NVDSyncOrchestrator(cache_manager=cache_manager)
        result = sync_orch.run(source_path)

        assert isinstance(result, SyncResult), (
            "NVDSyncOrchestrator.run() must return a SyncResult"
        )

    def test_run_records_sync_log_after_successful_sync(self, tmp_path):
        """SyncResult.sync_log is populated after a successful sync — MUST FAIL."""
        source_path = str(tmp_path / "feed.json")
        (tmp_path / "feed.json").write_text('{"CVE_Items": []}')

        cache_manager = MagicMock(spec=NVDCacheManager)
        cache_manager.sync.return_value = SYNC_NVD_RESULT

        sync_orch = NVDSyncOrchestrator(cache_manager=cache_manager)
        result = sync_orch.run(source_path)

        assert result.sync_log is not None, "SyncResult.sync_log must be set after successful sync"
        assert "synced_at" in result.sync_log, "sync_log must contain 'synced_at'"
        assert "source_path" in result.sync_log, "sync_log must contain 'source_path'"

    def test_run_source_path_recorded_in_result(self, tmp_path):
        """SyncResult.source_path matches the path passed to run() — MUST FAIL."""
        source_path = str(tmp_path / "nvd.json")
        (tmp_path / "nvd.json").write_text('{"CVE_Items": []}')

        cache_manager = MagicMock(spec=NVDCacheManager)
        cache_manager.sync.return_value = SYNC_NVD_RESULT

        sync_orch = NVDSyncOrchestrator(cache_manager=cache_manager)
        result = sync_orch.run(source_path)

        assert result.source_path == source_path, (
            "SyncResult.source_path must record the path passed to run()"
        )

    def test_run_synced_at_is_iso8601_string(self, tmp_path):
        """SyncResult.synced_at is a non-empty ISO 8601 timestamp string — MUST FAIL."""
        source_path = str(tmp_path / "feed.json")
        (tmp_path / "feed.json").write_text('{"CVE_Items": []}')

        cache_manager = MagicMock(spec=NVDCacheManager)
        cache_manager.sync.return_value = SYNC_NVD_RESULT

        sync_orch = NVDSyncOrchestrator(cache_manager=cache_manager)
        result = sync_orch.run(source_path)

        assert result.synced_at is not None, "SyncResult.synced_at must not be None"
        assert isinstance(result.synced_at, str), "SyncResult.synced_at must be a string"
        # ISO 8601 contains 'T'
        assert "T" in result.synced_at, (
            "SyncResult.synced_at must be an ISO 8601 datetime string (contains 'T')"
        )


# ===========================================================================
# CLASS 8: TestNVDSyncOrchestratorResult (7 tests)
# ===========================================================================

class TestNVDSyncOrchestratorResult:
    """Unit tests for NVDSyncOrchestrator SyncResult data contract."""

    def test_records_added_from_cache_manager_result(self, tmp_path):
        """SyncResult.records_added equals NVDSyncResult.records_added — MUST FAIL."""
        source = str(tmp_path / "f.json")
        (tmp_path / "f.json").write_text('{"CVE_Items": []}')

        cache_manager = MagicMock(spec=NVDCacheManager)
        cache_manager.sync.return_value = NVDSyncResult(records_added=12, records_updated=3)

        sync_orch = NVDSyncOrchestrator(cache_manager=cache_manager)
        result = sync_orch.run(source)

        assert result.records_added == 12, (
            "SyncResult.records_added must reflect NVDSyncResult.records_added"
        )

    def test_records_updated_from_cache_manager_result(self, tmp_path):
        """SyncResult.records_updated equals NVDSyncResult.records_updated — MUST FAIL."""
        source = str(tmp_path / "f.json")
        (tmp_path / "f.json").write_text('{"CVE_Items": []}')

        cache_manager = MagicMock(spec=NVDCacheManager)
        cache_manager.sync.return_value = NVDSyncResult(records_added=12, records_updated=3)

        sync_orch = NVDSyncOrchestrator(cache_manager=cache_manager)
        result = sync_orch.run(source)

        assert result.records_updated == 3, (
            "SyncResult.records_updated must reflect NVDSyncResult.records_updated"
        )

    def test_empty_feed_zero_records_added(self, tmp_path):
        """Empty NVD feed returns SyncResult with records_added=0 — MUST FAIL."""
        source = str(tmp_path / "empty.json")
        (tmp_path / "empty.json").write_text('{"CVE_Items": []}')

        cache_manager = MagicMock(spec=NVDCacheManager)
        cache_manager.sync.return_value = NVDSyncResult(records_added=0, records_updated=0)

        sync_orch = NVDSyncOrchestrator(cache_manager=cache_manager)
        result = sync_orch.run(source)

        assert result.records_added == 0, (
            "Empty feed must return SyncResult with records_added=0 without error"
        )

    def test_empty_feed_does_not_raise(self, tmp_path):
        """Empty feed is handled without exception — MUST FAIL."""
        source = str(tmp_path / "empty.json")
        (tmp_path / "empty.json").write_text('{"CVE_Items": []}')

        cache_manager = MagicMock(spec=NVDCacheManager)
        cache_manager.sync.return_value = NVDSyncResult(records_added=0, records_updated=0)

        sync_orch = NVDSyncOrchestrator(cache_manager=cache_manager)
        # Must not raise for empty feed
        result = sync_orch.run(source)
        assert result is not None

    def test_sync_log_contains_correct_counts(self, tmp_path):
        """sync_log reflects added/updated counts from cache manager — MUST FAIL."""
        source = str(tmp_path / "f.json")
        (tmp_path / "f.json").write_text('{"CVE_Items": []}')

        cache_manager = MagicMock(spec=NVDCacheManager)
        cache_manager.sync.return_value = NVDSyncResult(records_added=7, records_updated=1)

        sync_orch = NVDSyncOrchestrator(cache_manager=cache_manager)
        result = sync_orch.run(source)

        assert result.sync_log["records_added"] == 7, (
            "sync_log.records_added must match NVDSyncResult"
        )
        assert result.sync_log["records_updated"] == 1, (
            "sync_log.records_updated must match NVDSyncResult"
        )

    def test_sync_log_source_path_matches_run_arg(self, tmp_path):
        """sync_log.source_path matches the path argument — MUST FAIL."""
        source = str(tmp_path / "feed.json")
        (tmp_path / "feed.json").write_text('{"CVE_Items": []}')

        cache_manager = MagicMock(spec=NVDCacheManager)
        cache_manager.sync.return_value = NVDSyncResult(records_added=0, records_updated=0)

        sync_orch = NVDSyncOrchestrator(cache_manager=cache_manager)
        result = sync_orch.run(source)

        assert result.sync_log["source_path"] == source, (
            "sync_log.source_path must equal the path passed to run()"
        )

    def test_default_constructor_creates_real_cache_manager(self):
        """NVDSyncOrchestrator() with no args defaults to real NVDCacheManager — MUST FAIL."""
        sync_orch = NVDSyncOrchestrator()
        assert isinstance(sync_orch.cache_manager, NVDCacheManager), (
            "Default cache_manager must be NVDCacheManager instance"
        )


# ===========================================================================
# CLASS 9: TestNVDSyncOrchestratorErrors (6 tests)
# ===========================================================================

class TestNVDSyncOrchestratorErrors:
    """Unit tests for NVDSyncOrchestrator error propagation."""

    def test_nvd_sync_error_propagates_on_missing_source(self):
        """NVDSyncError propagates when source_path does not exist — MUST FAIL."""
        cache_manager = MagicMock(spec=NVDCacheManager)
        cache_manager.sync.side_effect = NVDSyncError(
            "NVD feed source not found: /nonexistent/path.json"
        )

        sync_orch = NVDSyncOrchestrator(cache_manager=cache_manager)
        with pytest.raises(NVDSyncError):
            sync_orch.run("/nonexistent/path.json")

    def test_nvd_sync_error_not_caught_and_swallowed(self):
        """NVDSyncOrchestrator does NOT swallow NVDSyncError — MUST FAIL."""
        cache_manager = MagicMock(spec=NVDCacheManager)
        cache_manager.sync.side_effect = NVDSyncError("Disk full")

        sync_orch = NVDSyncOrchestrator(cache_manager=cache_manager)
        # If the orchestrator swallowed the error, no exception would raise
        with pytest.raises(NVDSyncError) as exc_info:
            sync_orch.run("/some/path.json")
        assert "Disk full" in str(exc_info.value), (
            "NVDSyncError message must propagate unchanged"
        )

    def test_nvd_sync_error_preserves_original_message(self):
        """NVDSyncError message is not modified during propagation — MUST FAIL."""
        original_msg = "NVD feed source not found: /missing.json"
        cache_manager = MagicMock(spec=NVDCacheManager)
        cache_manager.sync.side_effect = NVDSyncError(original_msg)

        sync_orch = NVDSyncOrchestrator(cache_manager=cache_manager)
        with pytest.raises(NVDSyncError) as exc_info:
            sync_orch.run("/missing.json")
        assert original_msg in str(exc_info.value), (
            "NVDSyncError message must not be modified by orchestrator"
        )

    def test_sync_log_not_populated_on_error(self):
        """sync_log must not be set when NVDSyncError is raised — MUST FAIL."""
        cache_manager = MagicMock(spec=NVDCacheManager)
        cache_manager.sync.side_effect = NVDSyncError("Connection refused")

        sync_orch = NVDSyncOrchestrator(cache_manager=cache_manager)
        with pytest.raises(NVDSyncError):
            sync_orch.run("/some/path.json")

        # After failed run, last_sync_log should be None or absent
        last_log = getattr(sync_orch, "last_sync_log", None)
        assert last_log is None, (
            "sync_log must not be recorded when NVDSyncError is raised"
        )

    def test_invalid_json_in_feed_raises_nvd_sync_error(self, tmp_path):
        """Invalid JSON in feed raises NVDSyncError (via cache manager) — MUST FAIL."""
        source = str(tmp_path / "bad.json")
        (tmp_path / "bad.json").write_text("{not valid json}")

        cache_manager = MagicMock(spec=NVDCacheManager)
        cache_manager.sync.side_effect = NVDSyncError("Invalid JSON in feed")

        sync_orch = NVDSyncOrchestrator(cache_manager=cache_manager)
        with pytest.raises(NVDSyncError):
            sync_orch.run(source)

    def test_run_method_exists(self):
        """NVDSyncOrchestrator exposes a callable run() method — MUST FAIL."""
        cache_manager = MagicMock(spec=NVDCacheManager)
        sync_orch = NVDSyncOrchestrator(cache_manager=cache_manager)
        assert callable(getattr(sync_orch, "run", None)), (
            "NVDSyncOrchestrator must have a callable run() method"
        )


# ===========================================================================
# CLASS 10: TestCLIOrchestratorScanCommand (18 tests)
# ===========================================================================

class TestCLIOrchestratorScanCommand:
    """Unit tests for CLIOrchestrator.invoke_scan() exit codes and streams."""

    def _make_cli(self, scan_result: Optional[ScanResult] = None,
                  validation_error: bool = False,
                  stale_warning: bool = False) -> "CLIOrchestrator":
        """Build CLIOrchestrator with mocked sub-orchestrators."""
        if scan_result is None:
            sbom = dict(CYCLONEDX_SBOM)
            warnings = ["NVD cache is stale. Please sync."] if stale_warning else []
            scan_result = ScanResult(
                dependencies=list(DEDUPED_DEPS),
                active_vulns=list(ENRICHED_VULNS),
                suppressed_vulns=[],
                warnings=warnings,
                sbom_document=sbom,
                workflow_states_visited=[],
            )

        scan_orch = MagicMock(spec=ScanOrchestrator)
        if validation_error:
            scan_orch.run.side_effect = ValueError("Validation failed: invalid repo path")
        else:
            scan_orch.run.return_value = scan_result

        sync_orch = MagicMock(spec=NVDSyncOrchestrator)

        return CLIOrchestrator(
            scan_orchestrator=scan_orch,
            sync_orchestrator=sync_orch,
        ), scan_orch, sync_orch

    def test_valid_scan_returns_exit_code_zero(self, tmp_path):
        """invoke_scan with valid args returns exit_code=0 — MUST FAIL."""
        cli, _, _ = self._make_cli()
        result = cli.invoke_scan(
            repo=str(tmp_path),
            fmt="cyclonedx",
            env="development",
        )
        assert result["exit_code"] == 0, (
            "invoke_scan must return exit_code=0 on successful scan"
        )

    def test_valid_scan_stdout_contains_json(self, tmp_path):
        """invoke_scan stdout contains valid JSON for a successful run — MUST FAIL."""
        cli, _, _ = self._make_cli()
        result = cli.invoke_scan(
            repo=str(tmp_path),
            fmt="cyclonedx",
            env="development",
        )
        assert result["stdout"] is not None, "stdout must not be None"
        # stdout must be parseable JSON
        parsed = json.loads(result["stdout"])
        assert isinstance(parsed, dict), "stdout must contain a JSON object"

    def test_valid_scan_stderr_is_empty_for_clean_run(self, tmp_path):
        """invoke_scan stderr is empty when no warnings — MUST FAIL."""
        cli, _, _ = self._make_cli(stale_warning=False)
        result = cli.invoke_scan(
            repo=str(tmp_path),
            fmt="cyclonedx",
            env="development",
        )
        assert result["stderr"] == "" or result["stderr"] is None, (
            "stderr must be empty when no warnings or errors exist"
        )

    def test_invalid_repo_returns_non_zero_exit_code(self, tmp_path):
        """invoke_scan with invalid repo returns non-zero exit_code — MUST FAIL."""
        cli, _, _ = self._make_cli(validation_error=True)
        result = cli.invoke_scan(
            repo="/nonexistent/repo",
            fmt="cyclonedx",
            env="development",
        )
        assert result["exit_code"] != 0, (
            "invoke_scan must return non-zero exit_code for invalid repo"
        )

    def test_invalid_repo_error_message_to_stderr(self, tmp_path):
        """invoke_scan with invalid repo writes error message to stderr — MUST FAIL."""
        cli, _, _ = self._make_cli(validation_error=True)
        result = cli.invoke_scan(
            repo="/nonexistent/repo",
            fmt="cyclonedx",
            env="development",
        )
        assert result["stderr"] is not None and len(result["stderr"]) > 0, (
            "invoke_scan must write error message to stderr for invalid repo"
        )

    def test_invalid_repo_stdout_is_empty(self, tmp_path):
        """invoke_scan with invalid repo writes nothing to stdout — MUST FAIL."""
        cli, _, _ = self._make_cli(validation_error=True)
        result = cli.invoke_scan(
            repo="/nonexistent/repo",
            fmt="cyclonedx",
            env="development",
        )
        assert result["stdout"] == "" or result["stdout"] is None, (
            "stdout must be empty when scan fails on invalid repo"
        )

    def test_stale_cache_returns_exit_code_zero(self, tmp_path):
        """Stale cache warning does not cause non-zero exit — MUST FAIL (AC-3)."""
        cli, _, _ = self._make_cli(stale_warning=True)
        result = cli.invoke_scan(
            repo=str(tmp_path),
            fmt="cyclonedx",
            env="development",
        )
        assert result["exit_code"] == 0, (
            "invoke_scan must return exit_code=0 even when cache is stale"
        )

    def test_stale_cache_warning_written_to_stderr_not_stdout(self, tmp_path):
        """Stale cache warning goes to stderr, not stdout — MUST FAIL."""
        cli, _, _ = self._make_cli(stale_warning=True)
        result = cli.invoke_scan(
            repo=str(tmp_path),
            fmt="cyclonedx",
            env="development",
        )
        assert result["stderr"] is not None and len(result["stderr"]) > 0, (
            "Stale cache warning must be written to stderr"
        )
        # stdout must still be valid JSON (not contaminated with warning text)
        parsed = json.loads(result["stdout"])
        assert isinstance(parsed, dict), (
            "stdout must remain valid JSON even when stale cache warning fires"
        )

    def test_stale_cache_stdout_is_valid_sbom_json(self, tmp_path):
        """Stale cache run still produces SBOM JSON in stdout — MUST FAIL."""
        cli, _, _ = self._make_cli(stale_warning=True)
        result = cli.invoke_scan(
            repo=str(tmp_path),
            fmt="cyclonedx",
            env="development",
        )
        parsed = json.loads(result["stdout"])
        assert "bomFormat" in parsed or "spdxVersion" in parsed, (
            "stdout must contain a valid SBOM document even when stale warning fires"
        )

    def test_cyclonedx_format_flag_accepted(self, tmp_path):
        """--format cyclonedx is accepted without error — MUST FAIL."""
        cli, scan_orch, _ = self._make_cli()
        result = cli.invoke_scan(
            repo=str(tmp_path),
            fmt="cyclonedx",
            env="development",
        )
        assert result["exit_code"] == 0, "--format cyclonedx must be accepted"
        call_kwargs = scan_orch.run.call_args[1] if scan_orch.run.call_args[1] else {}
        call_args = scan_orch.run.call_args[0]
        fmt_passed = call_kwargs.get("output_format") or (
            call_args[1] if len(call_args) > 1 else None
        )
        assert fmt_passed == "cyclonedx", "scan_orch.run must receive output_format='cyclonedx'"

    def test_spdx_format_flag_accepted(self, tmp_path):
        """--format spdx is accepted without error — MUST FAIL."""
        spdx_result = ScanResult(
            dependencies=[],
            active_vulns=[],
            suppressed_vulns=[],
            warnings=[],
            sbom_document=dict(SPDX_SBOM),
            workflow_states_visited=[],
        )
        cli, scan_orch, _ = self._make_cli(scan_result=spdx_result)
        result = cli.invoke_scan(
            repo=str(tmp_path),
            fmt="spdx",
            env="development",
        )
        assert result["exit_code"] == 0, "--format spdx must be accepted"

    def test_missing_repo_returns_non_zero(self, tmp_path):
        """invoke_scan with empty repo string returns non-zero — MUST FAIL."""
        cli, _, _ = self._make_cli(validation_error=True)
        result = cli.invoke_scan(
            repo="",
            fmt="cyclonedx",
            env="development",
        )
        assert result["exit_code"] != 0, (
            "invoke_scan must return non-zero when --repo is empty"
        )

    def test_invoke_scan_calls_scan_orchestrator_run(self, tmp_path):
        """invoke_scan delegates to ScanOrchestrator.run() — MUST FAIL."""
        cli, scan_orch, _ = self._make_cli()
        cli.invoke_scan(
            repo=str(tmp_path),
            fmt="cyclonedx",
            env="development",
        )
        scan_orch.run.assert_called_once()

    def test_invoke_scan_result_dict_has_required_keys(self, tmp_path):
        """Return dict from invoke_scan has exit_code, stdout, stderr keys — MUST FAIL."""
        cli, _, _ = self._make_cli()
        result = cli.invoke_scan(
            repo=str(tmp_path),
            fmt="cyclonedx",
            env="development",
        )
        assert "exit_code" in result, "Result must contain 'exit_code'"
        assert "stdout" in result, "Result must contain 'stdout'"
        assert "stderr" in result, "Result must contain 'stderr'"

    def test_sbom_written_to_output_file_not_stdout_when_flag_set(self, tmp_path):
        """When output_path is set, SBOM written to file — stdout empty — MUST FAIL."""
        output_file = str(tmp_path / "sbom.json")
        cli, _, _ = self._make_cli()
        result = cli.invoke_scan(
            repo=str(tmp_path),
            fmt="cyclonedx",
            env="development",
            output_path=output_file,
        )

        assert result["exit_code"] == 0, "exit_code must be 0 when output_path specified"
        assert os.path.exists(output_file), "SBOM file must be written to output_path"
        assert result["stdout"] == "" or result["stdout"] is None, (
            "stdout must be empty when output_path flag is used"
        )

    def test_output_file_contains_valid_sbom_json(self, tmp_path):
        """File written to output_path contains valid SBOM JSON — MUST FAIL."""
        output_file = str(tmp_path / "sbom.json")
        cli, _, _ = self._make_cli()
        cli.invoke_scan(
            repo=str(tmp_path),
            fmt="cyclonedx",
            env="development",
            output_path=output_file,
        )

        with open(output_file) as fh:
            content = json.load(fh)
        assert isinstance(content, dict), "output_path file must contain a JSON object"
        assert "bomFormat" in content or "spdxVersion" in content, (
            "output_path file must contain a valid SBOM document"
        )

    def test_nvd_sync_error_during_scan_returns_non_zero(self, tmp_path):
        """NVDSyncError raised by ScanOrchestrator causes non-zero exit — MUST FAIL."""
        scan_orch = MagicMock(spec=ScanOrchestrator)
        scan_orch.run.side_effect = NVDSyncError("Cache DB corrupted")
        sync_orch = MagicMock(spec=NVDSyncOrchestrator)

        cli = CLIOrchestrator(
            scan_orchestrator=scan_orch,
            sync_orchestrator=sync_orch,
        )
        result = cli.invoke_scan(
            repo=str(tmp_path),
            fmt="cyclonedx",
            env="development",
        )
        assert result["exit_code"] != 0, (
            "NVDSyncError must cause non-zero exit code from invoke_scan"
        )

    def test_exception_message_written_to_stderr(self, tmp_path):
        """Exception message from ScanOrchestrator is written to stderr — MUST FAIL."""
        scan_orch = MagicMock(spec=ScanOrchestrator)
        scan_orch.run.side_effect = ValueError("repo path not found")
        sync_orch = MagicMock(spec=NVDSyncOrchestrator)

        cli = CLIOrchestrator(
            scan_orchestrator=scan_orch,
            sync_orchestrator=sync_orch,
        )
        result = cli.invoke_scan(
            repo="/bad/path",
            fmt="cyclonedx",
            env="development",
        )
        assert "repo path not found" in result["stderr"], (
            "Exception message must be present in stderr output"
        )


# ===========================================================================
# CLASS 11: TestCLIOrchestratorSyncCommand (10 tests)
# ===========================================================================

class TestCLIOrchestratorSyncCommand:
    """Unit tests for CLIOrchestrator.invoke_sync() exit codes and output."""

    def _make_sync_cli(
        self,
        sync_error: bool = False,
        records_added: int = 5,
        records_updated: int = 2,
    ):
        scan_orch = MagicMock(spec=ScanOrchestrator)
        sync_orch = MagicMock(spec=NVDSyncOrchestrator)

        if sync_error:
            sync_orch.run.side_effect = NVDSyncError(
                "NVD feed source not found: /missing.json"
            )
        else:
            synced_at = datetime.now(timezone.utc).isoformat()
            sync_orch.run.return_value = SyncResult(
                records_added=records_added,
                records_updated=records_updated,
                synced_at=synced_at,
                source_path="/some/feed.json",
                sync_log={
                    "synced_at": synced_at,
                    "source_path": "/some/feed.json",
                    "records_added": records_added,
                    "records_updated": records_updated,
                },
            )

        cli = CLIOrchestrator(
            scan_orchestrator=scan_orch,
            sync_orchestrator=sync_orch,
        )
        return cli, scan_orch, sync_orch

    def test_valid_sync_returns_exit_code_zero(self):
        """invoke_sync with valid source returns exit_code=0 — MUST FAIL."""
        cli, _, _ = self._make_sync_cli()
        result = cli.invoke_sync(source="/valid/nvd_feed.json")
        assert result["exit_code"] == 0, (
            "invoke_sync must return exit_code=0 on successful sync"
        )

    def test_valid_sync_prints_records_added_to_stdout(self):
        """invoke_sync prints records_added count to stdout — MUST FAIL."""
        cli, _, _ = self._make_sync_cli(records_added=7)
        result = cli.invoke_sync(source="/valid/nvd_feed.json")
        assert "7" in result["stdout"], (
            "stdout must contain the records_added count"
        )

    def test_valid_sync_prints_records_updated_to_stdout(self):
        """invoke_sync prints records_updated count to stdout — MUST FAIL."""
        cli, _, _ = self._make_sync_cli(records_updated=3)
        result = cli.invoke_sync(source="/valid/nvd_feed.json")
        assert "3" in result["stdout"], (
            "stdout must contain the records_updated count"
        )

    def test_nvd_sync_error_returns_non_zero(self):
        """NVDSyncError during sync returns non-zero exit_code — MUST FAIL."""
        cli, _, _ = self._make_sync_cli(sync_error=True)
        result = cli.invoke_sync(source="/missing/feed.json")
        assert result["exit_code"] != 0, (
            "invoke_sync must return non-zero exit_code when NVDSyncError is raised"
        )

    def test_nvd_sync_error_message_written_to_stderr(self):
        """NVDSyncError message is written to stderr — MUST FAIL."""
        cli, _, _ = self._make_sync_cli(sync_error=True)
        result = cli.invoke_sync(source="/missing/feed.json")
        assert result["stderr"] is not None and len(result["stderr"]) > 0, (
            "NVDSyncError message must be written to stderr"
        )

    def test_nvd_sync_error_stdout_empty(self):
        """stdout is empty when NVDSyncError occurs — MUST FAIL."""
        cli, _, _ = self._make_sync_cli(sync_error=True)
        result = cli.invoke_sync(source="/missing/feed.json")
        assert result["stdout"] == "" or result["stdout"] is None, (
            "stdout must be empty when NVDSyncError is raised"
        )

    def test_invoke_sync_delegates_to_sync_orchestrator_run(self):
        """invoke_sync calls NVDSyncOrchestrator.run(source) — MUST FAIL."""
        cli, _, sync_orch = self._make_sync_cli()
        cli.invoke_sync(source="/feed.json")
        sync_orch.run.assert_called_once_with("/feed.json")

    def test_invoke_sync_does_not_call_scan_orchestrator(self):
        """invoke_sync does not call ScanOrchestrator — MUST FAIL."""
        cli, scan_orch, _ = self._make_sync_cli()
        cli.invoke_sync(source="/feed.json")
        scan_orch.run.assert_not_called()

    def test_invoke_sync_result_has_required_keys(self):
        """Return dict from invoke_sync has exit_code, stdout, stderr — MUST FAIL."""
        cli, _, _ = self._make_sync_cli()
        result = cli.invoke_sync(source="/feed.json")
        assert "exit_code" in result, "Result must contain 'exit_code'"
        assert "stdout" in result, "Result must contain 'stdout'"
        assert "stderr" in result, "Result must contain 'stderr'"

    def test_valid_sync_stderr_empty(self):
        """invoke_sync stderr is empty for a successful sync — MUST FAIL."""
        cli, _, _ = self._make_sync_cli()
        result = cli.invoke_sync(source="/feed.json")
        assert result["stderr"] == "" or result["stderr"] is None, (
            "stderr must be empty for a successful sync operation"
        )


# ===========================================================================
# CLASS 12: TestCLIOrchestratorOutputFlag (7 tests)
# ===========================================================================

class TestCLIOrchestratorOutputFlag:
    """Unit tests for CLIOrchestrator --output file flag behaviour."""

    def _make_cli_for_output(self, tmp_path) -> "CLIOrchestrator":
        sbom = dict(CYCLONEDX_SBOM)
        scan_result = ScanResult(
            dependencies=list(DEDUPED_DEPS),
            active_vulns=[],
            suppressed_vulns=[],
            warnings=[],
            sbom_document=sbom,
            workflow_states_visited=[],
        )
        scan_orch = MagicMock(spec=ScanOrchestrator)
        scan_orch.run.return_value = scan_result
        sync_orch = MagicMock(spec=NVDSyncOrchestrator)

        return CLIOrchestrator(
            scan_orchestrator=scan_orch,
            sync_orchestrator=sync_orch,
        )

    def test_output_path_none_writes_sbom_to_stdout(self, tmp_path):
        """When output_path=None, SBOM JSON goes to stdout — MUST FAIL."""
        cli = self._make_cli_for_output(tmp_path)
        result = cli.invoke_scan(
            repo=str(tmp_path),
            fmt="cyclonedx",
            env="development",
            output_path=None,
        )
        assert result["stdout"] is not None and len(result["stdout"]) > 0, (
            "stdout must contain SBOM JSON when output_path is None"
        )

    def test_output_path_set_creates_file(self, tmp_path):
        """When output_path is set, file is created on disk — MUST FAIL."""
        output_file = str(tmp_path / "output.json")
        cli = self._make_cli_for_output(tmp_path)
        cli.invoke_scan(
            repo=str(tmp_path),
            fmt="cyclonedx",
            env="development",
            output_path=output_file,
        )
        assert os.path.isfile(output_file), (
            "Output file must be created when output_path is specified"
        )

    def test_output_path_file_contains_bom_format_key(self, tmp_path):
        """File at output_path contains bomFormat key — MUST FAIL."""
        output_file = str(tmp_path / "sbom_out.json")
        cli = self._make_cli_for_output(tmp_path)
        cli.invoke_scan(
            repo=str(tmp_path),
            fmt="cyclonedx",
            env="development",
            output_path=output_file,
        )
        with open(output_file) as fh:
            data = json.load(fh)
        assert "bomFormat" in data, (
            "File at output_path must contain the 'bomFormat' key for CycloneDX"
        )

    def test_output_path_stdout_is_empty(self, tmp_path):
        """stdout is empty when output_path is specified — MUST FAIL."""
        output_file = str(tmp_path / "sbom.json")
        cli = self._make_cli_for_output(tmp_path)
        result = cli.invoke_scan(
            repo=str(tmp_path),
            fmt="cyclonedx",
            env="development",
            output_path=output_file,
        )
        assert result["stdout"] == "" or result["stdout"] is None, (
            "stdout must be empty when SBOM is written to output_path"
        )

    def test_output_path_exit_code_zero_on_success(self, tmp_path):
        """exit_code=0 when SBOM is written to file successfully — MUST FAIL."""
        output_file = str(tmp_path / "sbom.json")
        cli = self._make_cli_for_output(tmp_path)
        result = cli.invoke_scan(
            repo=str(tmp_path),
            fmt="cyclonedx",
            env="development",
            output_path=output_file,
        )
        assert result["exit_code"] == 0, (
            "exit_code must be 0 when SBOM is written to output_path successfully"
        )

    def test_output_path_non_zero_on_write_error(self, tmp_path):
        """Non-zero exit code when output_path is in a non-writable location — MUST FAIL."""
        output_file = "/root/cannot_write_here/sbom.json"  # non-writable path
        cli = self._make_cli_for_output(tmp_path)
        result = cli.invoke_scan(
            repo=str(tmp_path),
            fmt="cyclonedx",
            env="development",
            output_path=output_file,
        )
        assert result["exit_code"] != 0, (
            "exit_code must be non-zero when SBOM cannot be written to output_path"
        )

    def test_output_path_write_error_message_to_stderr(self, tmp_path):
        """Write error message goes to stderr when output_path fails — MUST FAIL."""
        output_file = "/root/cannot_write_here/sbom.json"
        cli = self._make_cli_for_output(tmp_path)
        result = cli.invoke_scan(
            repo=str(tmp_path),
            fmt="cyclonedx",
            env="development",
            output_path=output_file,
        )
        assert result["stderr"] is not None and len(result["stderr"]) > 0, (
            "Write error must be reported to stderr when output_path is unwritable"
        )


# ===========================================================================
# CLASS 13: TestScanWorkflowStateTransitions (14 tests)
# Verifies the state machine enforces correct transition order.
# Requires a WorkflowStateMachine class (or equivalent) to be implemented
# in Step 9.
# ===========================================================================

# WorkflowStateMachine is imported from step9 via step7_atdd_orchestration.
# The import at the top of this file provides the real implementation.


class TestScanWorkflowStateTransitions:
    """Unit tests for ScanWorkflowState machine ordering and guards."""

    def test_initial_state_is_idle(self):
        """WorkflowStateMachine starts in IDLE — MUST FAIL."""
        machine = WorkflowStateMachine(initial_state=ScanWorkflowState.IDLE)
        assert machine.state == ScanWorkflowState.IDLE, (
            "Initial workflow state must be IDLE"
        )

    def test_idle_to_scanning_dependencies_allowed(self):
        """IDLE -> SCANNING_DEPENDENCIES is a valid transition — MUST FAIL."""
        machine = WorkflowStateMachine(initial_state=ScanWorkflowState.IDLE)
        assert machine.can_transition(ScanWorkflowState.SCANNING_DEPENDENCIES), (
            "IDLE -> SCANNING_DEPENDENCIES must be allowed"
        )

    def test_idle_to_scanning_transition_changes_state(self):
        """After IDLE -> SCANNING_DEPENDENCIES, state is SCANNING_DEPENDENCIES — MUST FAIL."""
        machine = WorkflowStateMachine(initial_state=ScanWorkflowState.IDLE)
        machine.transition(ScanWorkflowState.SCANNING_DEPENDENCIES)
        assert machine.state == ScanWorkflowState.SCANNING_DEPENDENCIES, (
            "State must be SCANNING_DEPENDENCIES after transition"
        )

    def test_idle_cannot_skip_to_matching_vulnerabilities(self):
        """IDLE -> MATCHING_VULNERABILITIES is not a valid skip — MUST FAIL."""
        machine = WorkflowStateMachine(initial_state=ScanWorkflowState.IDLE)
        assert not machine.can_transition(ScanWorkflowState.MATCHING_VULNERABILITIES), (
            "IDLE cannot skip directly to MATCHING_VULNERABILITIES"
        )

    def test_idle_cannot_skip_to_exporting_sbom(self):
        """IDLE -> EXPORTING_SBOM is not a valid skip — MUST FAIL."""
        machine = WorkflowStateMachine(initial_state=ScanWorkflowState.IDLE)
        assert not machine.can_transition(ScanWorkflowState.EXPORTING_SBOM), (
            "IDLE cannot skip directly to EXPORTING_SBOM"
        )

    def test_scanning_to_deduplicating_allowed(self):
        """SCANNING_DEPENDENCIES -> DEDUPLICATING_OUTPUT is valid — MUST FAIL."""
        machine = WorkflowStateMachine(initial_state=ScanWorkflowState.IDLE)
        machine.transition(ScanWorkflowState.SCANNING_DEPENDENCIES)
        assert machine.can_transition(ScanWorkflowState.DEDUPLICATING_OUTPUT), (
            "SCANNING_DEPENDENCIES -> DEDUPLICATING_OUTPUT must be allowed"
        )

    def test_deduplicating_to_matching_allowed(self):
        """DEDUPLICATING_OUTPUT -> MATCHING_VULNERABILITIES is valid — MUST FAIL."""
        machine = WorkflowStateMachine(initial_state=ScanWorkflowState.IDLE)
        machine.transition(ScanWorkflowState.SCANNING_DEPENDENCIES)
        machine.transition(ScanWorkflowState.DEDUPLICATING_OUTPUT)
        assert machine.can_transition(ScanWorkflowState.MATCHING_VULNERABILITIES), (
            "DEDUPLICATING_OUTPUT -> MATCHING_VULNERABILITIES must be allowed"
        )

    def test_matching_to_filtering_allowed(self):
        """MATCHING_VULNERABILITIES -> FILTERING_VEX is valid — MUST FAIL."""
        machine = WorkflowStateMachine(initial_state=ScanWorkflowState.IDLE)
        machine.transition(ScanWorkflowState.SCANNING_DEPENDENCIES)
        machine.transition(ScanWorkflowState.DEDUPLICATING_OUTPUT)
        machine.transition(ScanWorkflowState.MATCHING_VULNERABILITIES)
        assert machine.can_transition(ScanWorkflowState.FILTERING_VEX), (
            "MATCHING_VULNERABILITIES -> FILTERING_VEX must be allowed"
        )

    def test_filtering_to_enriching_allowed(self):
        """FILTERING_VEX -> ENRICHING_REMEDIATION is valid — MUST FAIL."""
        machine = WorkflowStateMachine(initial_state=ScanWorkflowState.IDLE)
        for state in [
            ScanWorkflowState.SCANNING_DEPENDENCIES,
            ScanWorkflowState.DEDUPLICATING_OUTPUT,
            ScanWorkflowState.MATCHING_VULNERABILITIES,
            ScanWorkflowState.FILTERING_VEX,
        ]:
            machine.transition(state)
        assert machine.can_transition(ScanWorkflowState.ENRICHING_REMEDIATION), (
            "FILTERING_VEX -> ENRICHING_REMEDIATION must be allowed"
        )

    def test_enriching_to_exporting_allowed(self):
        """ENRICHING_REMEDIATION -> EXPORTING_SBOM is valid — MUST FAIL."""
        machine = WorkflowStateMachine(initial_state=ScanWorkflowState.IDLE)
        for state in [
            ScanWorkflowState.SCANNING_DEPENDENCIES,
            ScanWorkflowState.DEDUPLICATING_OUTPUT,
            ScanWorkflowState.MATCHING_VULNERABILITIES,
            ScanWorkflowState.FILTERING_VEX,
            ScanWorkflowState.ENRICHING_REMEDIATION,
        ]:
            machine.transition(state)
        assert machine.can_transition(ScanWorkflowState.EXPORTING_SBOM), (
            "ENRICHING_REMEDIATION -> EXPORTING_SBOM must be allowed"
        )

    def test_invalid_transition_raises_value_error(self):
        """Attempting invalid transition raises ValueError — MUST FAIL."""
        machine = WorkflowStateMachine(initial_state=ScanWorkflowState.IDLE)
        with pytest.raises(ValueError):
            machine.transition(ScanWorkflowState.EXPORTING_SBOM)

    def test_cannot_revert_from_exporting_to_enriching(self):
        """EXPORTING_SBOM -> ENRICHING_REMEDIATION is not a valid revert — MUST FAIL."""
        machine = WorkflowStateMachine(initial_state=ScanWorkflowState.IDLE)
        for state in [
            ScanWorkflowState.SCANNING_DEPENDENCIES,
            ScanWorkflowState.DEDUPLICATING_OUTPUT,
            ScanWorkflowState.MATCHING_VULNERABILITIES,
            ScanWorkflowState.FILTERING_VEX,
            ScanWorkflowState.ENRICHING_REMEDIATION,
            ScanWorkflowState.EXPORTING_SBOM,
        ]:
            machine.transition(state)
        assert not machine.can_transition(ScanWorkflowState.ENRICHING_REMEDIATION), (
            "Cannot revert from EXPORTING_SBOM to ENRICHING_REMEDIATION"
        )

    def test_visited_states_records_full_sequence(self):
        """visited_states() returns ordered list of all states traversed — MUST FAIL."""
        machine = WorkflowStateMachine(initial_state=ScanWorkflowState.IDLE)
        ordered = [
            ScanWorkflowState.SCANNING_DEPENDENCIES,
            ScanWorkflowState.DEDUPLICATING_OUTPUT,
            ScanWorkflowState.MATCHING_VULNERABILITIES,
            ScanWorkflowState.FILTERING_VEX,
            ScanWorkflowState.ENRICHING_REMEDIATION,
            ScanWorkflowState.EXPORTING_SBOM,
        ]
        for state in ordered:
            machine.transition(state)

        visited = machine.visited_states()
        assert ScanWorkflowState.IDLE.value in visited, (
            "IDLE must be in visited_states"
        )
        for state in ordered:
            assert state.value in visited, (
                f"{state.value} must appear in visited_states"
            )


# ===========================================================================
# CLASS 14: TestScanWorkflowStateMachine (10 tests)
# Additional state machine edge cases and NVD sync workflow.
# ===========================================================================

class TestScanWorkflowStateMachine:
    """Additional state machine unit tests including NVD sync workflow."""

    def test_stale_flag_not_set_before_scanning_state(self):
        """is_cache_stale flag is False before SCANNING_DEPENDENCIES — MUST FAIL."""
        machine = WorkflowStateMachine(initial_state=ScanWorkflowState.IDLE)
        # Before scanning begins, stale flag should not be set
        assert not getattr(machine, "is_cache_stale", False), (
            "is_cache_stale must not be True before SCANNING_DEPENDENCIES state"
        )

    def test_stale_flag_settable_at_scanning_state(self):
        """is_cache_stale can be set once machine enters SCANNING_DEPENDENCIES — MUST FAIL."""
        machine = WorkflowStateMachine(initial_state=ScanWorkflowState.IDLE)
        machine.transition(ScanWorkflowState.SCANNING_DEPENDENCIES)
        # Simulate setting the stale flag
        machine.is_cache_stale = True
        assert machine.is_cache_stale is True, (
            "is_cache_stale must be settable at SCANNING_DEPENDENCIES"
        )

    def test_nvd_sync_state_machine_starts_idle(self):
        """NVD sync workflow state machine starts in IDLE."""
        from step7_atdd_orchestration import NVDSyncWorkflowState
        machine = NVDWorkflowStateMachine()
        assert machine.state == NVDSyncWorkflowState.IDLE, (
            "NVD sync state machine must start in IDLE"
        )

    def test_nvd_sync_idle_to_syncing_allowed(self):
        """NVD sync: IDLE -> SYNCING_NVD is valid."""
        from step7_atdd_orchestration import NVDSyncWorkflowState
        machine = NVDWorkflowStateMachine()
        assert machine.can_transition(NVDSyncWorkflowState.SYNCING_NVD), (
            "NVD sync state machine: IDLE -> SYNCING_NVD must be allowed"
        )

    def test_scan_state_enum_has_seven_states(self):
        """ScanWorkflowState enum has exactly 7 members — MUST FAIL."""
        members = list(ScanWorkflowState)
        assert len(members) == 7, (
            f"ScanWorkflowState must have exactly 7 states, got {len(members)}"
        )

    def test_scan_state_enum_contains_idle(self):
        """ScanWorkflowState.IDLE member exists — MUST FAIL."""
        assert hasattr(ScanWorkflowState, "IDLE"), (
            "ScanWorkflowState must have IDLE member"
        )
        assert ScanWorkflowState.IDLE.value == "idle", (
            "ScanWorkflowState.IDLE.value must be 'idle'"
        )

    def test_scan_state_enum_contains_exporting_sbom(self):
        """ScanWorkflowState.EXPORTING_SBOM member exists — MUST FAIL."""
        assert hasattr(ScanWorkflowState, "EXPORTING_SBOM"), (
            "ScanWorkflowState must have EXPORTING_SBOM member"
        )

    def test_nvd_sync_state_enum_has_four_states(self):
        """NVDSyncWorkflowState enum has exactly 4 members — MUST FAIL."""
        from step7_atdd_orchestration import NVDSyncWorkflowState
        members = list(NVDSyncWorkflowState)
        assert len(members) == 4, (
            f"NVDSyncWorkflowState must have exactly 4 states, got {len(members)}"
        )

    def test_multiple_invalid_transition_attempts_leave_state_unchanged(self):
        """Multiple failed transitions do not corrupt state — MUST FAIL."""
        machine = WorkflowStateMachine(initial_state=ScanWorkflowState.IDLE)

        for _ in range(3):
            with pytest.raises(ValueError):
                machine.transition(ScanWorkflowState.EXPORTING_SBOM)

        assert machine.state == ScanWorkflowState.IDLE, (
            "State must remain IDLE after multiple failed transition attempts"
        )

    def test_complete_scan_pipeline_state_sequence_in_order(self):
        """Full pipeline visits all 7 states in correct order — MUST FAIL."""
        machine = WorkflowStateMachine(initial_state=ScanWorkflowState.IDLE)
        ordered_states = [
            ScanWorkflowState.SCANNING_DEPENDENCIES,
            ScanWorkflowState.DEDUPLICATING_OUTPUT,
            ScanWorkflowState.MATCHING_VULNERABILITIES,
            ScanWorkflowState.FILTERING_VEX,
            ScanWorkflowState.ENRICHING_REMEDIATION,
            ScanWorkflowState.EXPORTING_SBOM,
        ]
        for state in ordered_states:
            machine.transition(state)

        visited = machine.visited_states()
        # IDLE should be first, EXPORTING_SBOM last
        assert visited[0] == ScanWorkflowState.IDLE.value, (
            "First visited state must be IDLE"
        )
        assert visited[-1] == ScanWorkflowState.EXPORTING_SBOM.value, (
            "Last visited state must be EXPORTING_SBOM"
        )
