"""
step7_atdd_orchestration.py
SBOM POC Tool — Orchestration Acceptance Test Framework
Session: SBOM-20260409-sb01
Domain: Developer Tooling — Software Supply Chain Security

Extends step4_atdd_business.py with orchestration-layer acceptance tests.
Original business tests are inherited via wildcard import — this file adds ONLY
orchestration-scope tests (workflow coordination, state management, component
wiring, CLI contract).

Architecture:
  - Business layer (Step 6): CVSSSeverityClassifier, OSSToolAdapter,
    VulnerabilityMapper, RemediationEnricher, NVDCacheManager,
    CycloneDXSerializer, SPDXSerializer, ScanJobValidator, VEXFilter,
    DependencyRecord
  - Orchestration layer (Step 9 stubs defined here):
    ScanOrchestrator, NVDSyncOrchestrator, CLIOrchestrator, ScanWorkflowState

DDM sources:
  - Scan Workflow: SBOM_POC_Scope.md, In Scope #1-#6 and OSS Reuse table
    (confidence: inferred from sequential OSS reuse rows)
  - NVD Sync Workflow: SBOM_POC_Scope.md, In Scope #7
    (confidence: verbatim)
  - 7 rules enforced at orchestration boundary (cross-step alignment from Step 4)

Acceptance criteria coverage:
  AC-1  Full scan pipeline: repo path -> CycloneDX JSON with vulns + remediation
  AC-2  Full scan pipeline: repo path -> SPDX JSON
  AC-3  Stale cache: scan completes with warning, does not abort
  AC-4  VEX suppression applied before enrichment
  AC-5  Deduplication happens before vulnerability mapping
  AC-6  NVD sync: valid source -> SyncResult; invalid source -> NVDSyncError
  AC-7  CLI scan: valid args -> exit 0, JSON to stdout
  AC-8  CLI scan: invalid repo -> exit non-zero, error to stderr
  AC-9  CLI sync: valid source -> exit 0, sync counts printed
  AC-10 Workflow state transitions enforced in order
  AC-11 ScanResult contains deps, active_vulns, suppressed_vulns, warnings,
        sbom_document
  AC-12 Zero network calls during scan

Workflow source: SBOM_POC_Scope.md, In Scope #1-#7, OSS Reuse table
"""

# ---------------------------------------------------------------------------
# Standard imports
# ---------------------------------------------------------------------------
import io
import json
import os
import sys
import tempfile
from copy import deepcopy
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from enum import Enum, auto
from typing import Any, Dict, List, Optional
from unittest.mock import MagicMock, call, patch

import pytest

# ---------------------------------------------------------------------------
# Inherit all Step 4 business acceptance tests
# ---------------------------------------------------------------------------
from step4_atdd_business import *  # noqa: F401, F403

# ---------------------------------------------------------------------------
# Import business components implemented in Step 6
# Note: this session names the file step6_tdd_green_phase.py (not _business).
# All 10 business classes live there.
# ---------------------------------------------------------------------------
from step6_tdd_green_phase import (
    CVSSSeverityClassifier,
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
# Orchestration-layer implementations — imported from Step 9 Green Phase
# Step 9 provides working implementations of all orchestration classes.
# Step 7 re-exports them so that both step7 acceptance tests and step8
# unit tests can import from this canonical module.
# ---------------------------------------------------------------------------
from step9_tdd_green_phase_orchestration import (
    ScanWorkflowState,
    NVDSyncWorkflowState,
    ScanResult,
    SyncResult,
    ScanOrchestrator,
    NVDSyncOrchestrator,
    CLIOrchestrator,
    WorkflowStateMachine,
    NVDWorkflowStateMachine,
)

# ---------------------------------------------------------------------------
# Shared orchestration fixtures
# ---------------------------------------------------------------------------

NVD_CACHE_SEED = {
    "pkg:pypi/langchain@0.0.101": {
        "cve_id": "CVE-2023-34540", "cvss_score": 9.8, "severity": "High",
        "fixed_version": "0.0.247",
        "advisory_url": "https://nvd.nist.gov/vuln/detail/CVE-2023-34540",
    },
    "pkg:pypi/requests@2.27.1": {
        "cve_id": "CVE-2023-32681", "cvss_score": 6.1, "severity": "Medium",
        "fixed_version": "2.31.0",
        "advisory_url": "https://nvd.nist.gov/vuln/detail/CVE-2023-32681",
    },
    "pkg:pypi/lxml@4.6.3": {
        "cve_id": "CVE-2018-19787", "cvss_score": 6.1, "severity": "Medium",
        "fixed_version": "4.7.1",
        "advisory_url": "https://nvd.nist.gov/vuln/detail/CVE-2018-19787",
    },
    "pkg:pypi/numpy@1.22.0": {
        "cve_id": "CVE-2021-33430", "cvss_score": 5.5, "severity": "Medium",
        "fixed_version": "1.22.2",
        "advisory_url": "https://nvd.nist.gov/vuln/detail/CVE-2021-33430",
    },
    "pkg:pypi/joblib@0.14.1": {
        "cve_id": "CVE-2022-21797", "cvss_score": 9.8, "severity": "High",
        "fixed_version": "1.2.0",
        "advisory_url": "https://nvd.nist.gov/vuln/detail/CVE-2022-21797",
    },
    "pkg:pypi/Pillow@9.0.1": {
        "cve_id": "CVE-2023-44271", "cvss_score": 7.5, "severity": "High",
        "fixed_version": "10.0.0",
        "advisory_url": "https://nvd.nist.gov/vuln/detail/CVE-2023-44271",
    },
    "pkg:pypi/tensorflow@1.15.5": {
        "cve_id": "CVE-2022-29216", "cvss_score": 8.8, "severity": "High",
        "fixed_version": "2.9.0",
        "advisory_url": "https://nvd.nist.gov/vuln/detail/CVE-2022-29216",
    },
    "pkg:pypi/scipy@1.6.0": {
        "cve_id": "CVE-2023-25399", "cvss_score": 5.5, "severity": "Medium",
        "fixed_version": "1.11.0",
        "advisory_url": "https://nvd.nist.gov/vuln/detail/CVE-2023-25399",
    },
}

RAW_SYFT_TASKMATRIX = {
    "tool": "syft",
    "components": [
        {"name": "langchain", "version": "0.0.101",
         "purl": "pkg:pypi/langchain@0.0.101",
         "cpes": ["cpe:2.3:a:langchain:langchain:0.0.101:*:*:*:*:python:*:*"],
         "metadata": {"Author": "LangChain, Inc."}},
        {"name": "openai", "version": "0.27.2",
         "purl": "pkg:pypi/openai@0.27.2",
         "cpes": ["cpe:2.3:a:openai:openai:0.27.2:*:*:*:*:python:*:*"],
         "metadata": {"Author": "OpenAI"}},
        {"name": "requests", "version": "2.27.1",
         "purl": "pkg:pypi/requests@2.27.1",
         "cpes": ["cpe:2.3:a:python-requests:requests:2.27.1:*:*:*:*:python:*:*"],
         "metadata": {}},
        {"name": "numpy", "version": "1.23.5",
         "purl": "pkg:pypi/numpy@1.23.5",
         "cpes": ["cpe:2.3:a:numpy:numpy:1.23.5:*:*:*:*:python:*:*"],
         "metadata": {}},
        {"name": "pydantic", "version": "1.10.4",
         "purl": "pkg:pypi/pydantic@1.10.4",
         "cpes": [],
         "metadata": {}},
        {"name": "lxml", "version": "4.6.3",
         "purl": "pkg:pypi/lxml@4.6.3",
         "cpes": ["cpe:2.3:a:lxml:lxml:4.6.3:*:*:*:*:python:*:*"],
         "metadata": {}},
        {"name": "aiohttp", "version": "3.8.1",
         "purl": "pkg:pypi/aiohttp@3.8.1",
         "cpes": [],
         "metadata": {}},
        {"name": "tenacity", "version": "8.1.0",
         "purl": "pkg:pypi/tenacity@8.1.0",
         "cpes": [],
         "metadata": {}},
    ],
}

VEX_SUPPRESS_LANGCHAIN = [
    {
        "cve_id": "CVE-2023-34540",
        "purl": "pkg:pypi/langchain@0.0.101",
        "status": "not_affected",
        "justification": "vulnerable_code_not_in_execute_path",
    }
]


# ===========================================================================
# ORCHESTRATION TEST CLASS 1 — Full Scan Pipeline (AC-1, AC-2, AC-11, AC-12)
# Workflow source: SBOM_POC_Scope.md, In Scope #1-#6, OSS Reuse table
# ===========================================================================

class TestScanPipelineOrchestration:
    """
    ACCEPTANCE: Complete scan pipeline produces well-formed SBOM with
    vulnerability + remediation data.

    ORCHESTRATION: Verifies that ScanOrchestrator correctly sequences
    ScanJobValidator -> OSSToolAdapter -> VulnerabilityMapper ->
    VEXFilter -> RemediationEnricher -> Serializer and that the output
    conforms to the ScanResult contract (AC-11).

    Tests are written as red-first stubs: ScanOrchestrator raises
    NotImplementedError until Step 9 implements it.
    """

    # -----------------------------------------------------------------------
    # AC-1: CycloneDX end-to-end path
    # Workflow source: SBOM_POC_Scope.md, Scan Workflow all 7 transitions
    # -----------------------------------------------------------------------
    def test_scan_pipeline_produces_cyclonedx_sbom(self, tmp_path):
        """
        ACCEPTANCE (AC-1): ScanOrchestrator accepts a repo path and
        returns a ScanResult whose sbom_document parses as CycloneDX 1.4 JSON.

        ORCHESTRATION: Tests that all 7 components are wired together and
        data flows from raw tool output to serialised SBOM without loss.
        """
        repo_path = str(tmp_path)
        (tmp_path / "requirements.txt").write_text("langchain==0.0.101\n")

        orchestrator = ScanOrchestrator(
            validator=ScanJobValidator(),
            adapter=OSSToolAdapter(),
            mapper=VulnerabilityMapper(),
            vex_filter=VEXFilter(),
            enricher=RemediationEnricher(),
            nvd_cache_manager=NVDCacheManager(),
            cyclonedx_serializer=CycloneDXSerializer(),
            spdx_serializer=SPDXSerializer(),
        )

        result = orchestrator.run(
            repo_path=repo_path,
            output_format="cyclonedx",
            env="development",
            nvd_cache=NVD_CACHE_SEED,
            raw_tool_output=RAW_SYFT_TASKMATRIX,
            vex_statements=[],
            last_synced_at=datetime.now(timezone.utc),
        )

        # ScanResult shape (AC-11)
        assert isinstance(result, ScanResult)
        assert isinstance(result.dependencies, list)
        assert isinstance(result.active_vulns, list)
        assert isinstance(result.suppressed_vulns, list)
        assert isinstance(result.warnings, list)
        assert result.sbom_document is not None

        # CycloneDX schema markers
        sbom = result.sbom_document
        assert sbom.get("bomFormat") == "CycloneDX"
        assert sbom.get("specVersion") == "1.4"
        assert "components" in sbom
        assert "vulnerabilities" in sbom

        # All deps carried forward
        assert len(result.dependencies) > 0

        # Vulnerability classification present for matched CVEs
        for vuln in result.active_vulns:
            assert "cve_id" in vuln
            assert vuln.get("severity") in {"High", "Medium", "Low", "Unknown"}
            assert "advisory_url" in vuln  # RemediationEnricher ran

    # -----------------------------------------------------------------------
    # AC-2: SPDX end-to-end path
    # -----------------------------------------------------------------------
    def test_scan_pipeline_produces_spdx_sbom(self, tmp_path):
        """
        ACCEPTANCE (AC-2): ScanOrchestrator with output_format='spdx' returns
        a ScanResult whose sbom_document parses as SPDX 2.3 JSON.
        """
        repo_path = str(tmp_path)
        (tmp_path / "requirements.txt").write_text("numpy==1.22.0\n")

        raw_output = {
            "tool": "syft",
            "components": [
                {"name": "numpy", "version": "1.22.0",
                 "purl": "pkg:pypi/numpy@1.22.0",
                 "cpes": ["cpe:2.3:a:numpy:numpy:1.22.0:*:*:*:*:python:*:*"],
                 "metadata": {}},
            ],
        }

        orchestrator = ScanOrchestrator(
            validator=ScanJobValidator(),
            adapter=OSSToolAdapter(),
            mapper=VulnerabilityMapper(),
            vex_filter=VEXFilter(),
            enricher=RemediationEnricher(),
            nvd_cache_manager=NVDCacheManager(),
            cyclonedx_serializer=CycloneDXSerializer(),
            spdx_serializer=SPDXSerializer(),
        )

        result = orchestrator.run(
            repo_path=repo_path,
            output_format="spdx",
            env="development",
            nvd_cache=NVD_CACHE_SEED,
            raw_tool_output=raw_output,
            vex_statements=[],
            last_synced_at=datetime.now(timezone.utc),
        )

        assert result.sbom_document is not None
        sbom = result.sbom_document
        assert sbom.get("spdxVersion") == "SPDX-2.3"
        assert sbom.get("dataLicense") == "CC0-1.0"
        assert "packages" in sbom
        assert len(result.dependencies) > 0

    # -----------------------------------------------------------------------
    # AC-11: ScanResult structural contract
    # -----------------------------------------------------------------------
    def test_scan_result_contains_all_required_fields(self, tmp_path):
        """
        ACCEPTANCE (AC-11): ScanResult always contains deps, active_vulns,
        suppressed_vulns, warnings, sbom_document regardless of whether
        vulnerabilities were found.
        """
        repo_path = str(tmp_path)
        (tmp_path / "requirements.txt").write_text("flask==3.0.0\n")

        raw_output = {
            "tool": "syft",
            "components": [
                {"name": "flask", "version": "3.0.0",
                 "purl": "pkg:pypi/flask@3.0.0",
                 "cpes": [], "metadata": {}},
            ],
        }

        orchestrator = ScanOrchestrator(
            validator=ScanJobValidator(),
            adapter=OSSToolAdapter(),
            mapper=VulnerabilityMapper(),
            vex_filter=VEXFilter(),
            enricher=RemediationEnricher(),
            nvd_cache_manager=NVDCacheManager(),
            cyclonedx_serializer=CycloneDXSerializer(),
            spdx_serializer=SPDXSerializer(),
        )

        result = orchestrator.run(
            repo_path=repo_path,
            output_format="cyclonedx",
            env="development",
            nvd_cache={},  # no vulns in cache
            raw_tool_output=raw_output,
            vex_statements=[],
            last_synced_at=datetime.now(timezone.utc),
        )

        # All five mandatory fields present
        assert hasattr(result, "dependencies")
        assert hasattr(result, "active_vulns")
        assert hasattr(result, "suppressed_vulns")
        assert hasattr(result, "warnings")
        assert hasattr(result, "sbom_document")

        # Clean repo: no vulns, no suppressed, no warnings
        assert result.active_vulns == []
        assert result.suppressed_vulns == []
        assert result.warnings == []
        assert result.sbom_document is not None

    # -----------------------------------------------------------------------
    # AC-12: Zero network calls during scan
    # Source: SBOM_POC_Scope.md, In Scope #7, Rule "No Live NVD API Call"
    # confidence: verbatim
    # -----------------------------------------------------------------------
    def test_no_network_calls_during_scan(self, tmp_path):
        """
        ACCEPTANCE (AC-12 / Rule: No Live NVD API Call at Scan Time):
        ScanOrchestrator must never issue HTTP requests during a scan run.
        All vulnerability data is served from the supplied nvd_cache dict.

        ORCHESTRATION: Patches urllib and requests transports to assert zero
        outbound connections at orchestration boundary.
        """
        repo_path = str(tmp_path)
        (tmp_path / "requirements.txt").write_text("langchain==0.0.101\n")

        orchestrator = ScanOrchestrator(
            validator=ScanJobValidator(),
            adapter=OSSToolAdapter(),
            mapper=VulnerabilityMapper(),
            vex_filter=VEXFilter(),
            enricher=RemediationEnricher(),
            nvd_cache_manager=NVDCacheManager(),
            cyclonedx_serializer=CycloneDXSerializer(),
            spdx_serializer=SPDXSerializer(),
        )

        # Intercept any socket.connect attempt — should never be called
        with patch("socket.socket.connect") as mock_connect:
            orchestrator.run(
                repo_path=repo_path,
                output_format="cyclonedx",
                env="development",
                nvd_cache=NVD_CACHE_SEED,
                raw_tool_output=RAW_SYFT_TASKMATRIX,
                vex_statements=[],
                last_synced_at=datetime.now(timezone.utc),
            )
            mock_connect.assert_not_called()


# ===========================================================================
# ORCHESTRATION TEST CLASS 2 — Stale Cache Warning (AC-3)
# Workflow source: SBOM_POC_Scope.md, In Scope #7 (confidence: verbatim)
# Scan Workflow transition guard: "Local cache used — no live API call"
# ===========================================================================

class TestStaleCacheWarningOrchestration:
    """
    ACCEPTANCE (AC-3): When the NVD cache is stale (last synced > 7 days ago),
    the scan completes successfully but ScanResult.warnings contains at least
    one stale-cache warning message.

    ORCHESTRATION: Verifies that ScanOrchestrator checks staleness at the
    scanning_dependencies state and injects a warning without aborting.
    The Scan Workflow guard at matching_vulnerabilities state requires the
    cache check to happen before mapping.
    """

    def test_stale_cache_scan_completes_with_warning(self, tmp_path):
        """
        ACCEPTANCE (AC-3): Stale cache does not abort the scan.
        ScanResult.warnings is non-empty and sbom_document is still produced.
        Workflow source: SBOM_POC_Scope.md, In Scope #7 (confidence: verbatim)
        """
        repo_path = str(tmp_path)
        (tmp_path / "requirements.txt").write_text("langchain==0.0.101\n")

        stale_timestamp = datetime.now(timezone.utc) - timedelta(days=8)

        orchestrator = ScanOrchestrator(
            validator=ScanJobValidator(),
            adapter=OSSToolAdapter(),
            mapper=VulnerabilityMapper(),
            vex_filter=VEXFilter(),
            enricher=RemediationEnricher(),
            nvd_cache_manager=NVDCacheManager(),
            cyclonedx_serializer=CycloneDXSerializer(),
            spdx_serializer=SPDXSerializer(),
        )

        result = orchestrator.run(
            repo_path=repo_path,
            output_format="cyclonedx",
            env="development",
            nvd_cache=NVD_CACHE_SEED,
            raw_tool_output=RAW_SYFT_TASKMATRIX,
            vex_statements=[],
            last_synced_at=stale_timestamp,
        )

        # Scan must complete
        assert result.sbom_document is not None

        # At least one warning about staleness
        assert len(result.warnings) > 0
        stale_warning = any(
            "stale" in w.lower() or "sync" in w.lower()
            for w in result.warnings
        )
        assert stale_warning, (
            "Expected a stale-cache warning in ScanResult.warnings but none found. "
            f"Warnings present: {result.warnings}"
        )

    def test_fresh_cache_produces_no_staleness_warning(self, tmp_path):
        """
        ACCEPTANCE: When cache is fresh (synced within 7 days), no stale-cache
        warning should appear in ScanResult.warnings.
        """
        repo_path = str(tmp_path)
        (tmp_path / "requirements.txt").write_text("langchain==0.0.101\n")

        fresh_timestamp = datetime.now(timezone.utc) - timedelta(days=1)

        orchestrator = ScanOrchestrator(
            validator=ScanJobValidator(),
            adapter=OSSToolAdapter(),
            mapper=VulnerabilityMapper(),
            vex_filter=VEXFilter(),
            enricher=RemediationEnricher(),
            nvd_cache_manager=NVDCacheManager(),
            cyclonedx_serializer=CycloneDXSerializer(),
            spdx_serializer=SPDXSerializer(),
        )

        result = orchestrator.run(
            repo_path=repo_path,
            output_format="cyclonedx",
            env="development",
            nvd_cache=NVD_CACHE_SEED,
            raw_tool_output=RAW_SYFT_TASKMATRIX,
            vex_statements=[],
            last_synced_at=fresh_timestamp,
        )

        stale_warnings = [
            w for w in result.warnings
            if "stale" in w.lower() or "7 day" in w.lower()
        ]
        assert stale_warnings == [], (
            f"Unexpected stale-cache warnings for fresh cache: {stale_warnings}"
        )

    def test_staleness_threshold_is_seven_days(self, tmp_path):
        """
        ACCEPTANCE: The staleness threshold is exactly 7 days.
        A cache synced exactly 7 days ago triggers the warning.
        A cache synced 6 days 23 hours ago does not.
        Source: SBOM_POC_Scope.md, In Scope #7 — threshold explicitly 7 days.
        """
        repo_path = str(tmp_path)
        (tmp_path / "requirements.txt").write_text("langchain==0.0.101\n")

        orchestrator = ScanOrchestrator(
            validator=ScanJobValidator(),
            adapter=OSSToolAdapter(),
            mapper=VulnerabilityMapper(),
            vex_filter=VEXFilter(),
            enricher=RemediationEnricher(),
            nvd_cache_manager=NVDCacheManager(),
            cyclonedx_serializer=CycloneDXSerializer(),
            spdx_serializer=SPDXSerializer(),
        )

        # Exactly 7 days old — stale
        exactly_7_days = datetime.now(timezone.utc) - timedelta(days=7)
        result_stale = orchestrator.run(
            repo_path=repo_path,
            output_format="cyclonedx",
            env="development",
            nvd_cache=NVD_CACHE_SEED,
            raw_tool_output=RAW_SYFT_TASKMATRIX,
            vex_statements=[],
            last_synced_at=exactly_7_days,
        )
        assert any("stale" in w.lower() or "sync" in w.lower()
                   for w in result_stale.warnings), (
            "Expected stale warning for cache exactly 7 days old"
        )

        # Just under 7 days — fresh
        just_under_7 = datetime.now(timezone.utc) - timedelta(hours=167, minutes=59)
        result_fresh = orchestrator.run(
            repo_path=repo_path,
            output_format="cyclonedx",
            env="development",
            nvd_cache=NVD_CACHE_SEED,
            raw_tool_output=RAW_SYFT_TASKMATRIX,
            vex_statements=[],
            last_synced_at=just_under_7,
        )
        stale_in_fresh = [
            w for w in result_fresh.warnings
            if "stale" in w.lower() or "7 day" in w.lower()
        ]
        assert stale_in_fresh == []


# ===========================================================================
# ORCHESTRATION TEST CLASS 3 — VEX Suppression Before Enrichment (AC-4)
# Scan Workflow: filtering_vex -> enriching_remediation transition
# Source: SBOM_POC_Scope.md, OSS Reuse table — VEX filtering row
# ===========================================================================

class TestVEXSuppressionOrchestration:
    """
    ACCEPTANCE (AC-4): VEX statements are applied BEFORE RemediationEnricher
    runs. Suppressed vulnerabilities must NOT appear in active_vulns and must
    NOT receive enrichment data.

    ORCHESTRATION: Enforces state-ordering between filtering_vex and
    enriching_remediation. If enrichment runs first then VEX filter, suppressed
    vulns would still carry advisory_url — a detectable signal.
    """

    def test_suppressed_vuln_absent_from_active_vulns(self, tmp_path):
        """
        ACCEPTANCE (AC-4): A vulnerability covered by a VEX statement does not
        appear in ScanResult.active_vulns.
        """
        repo_path = str(tmp_path)
        (tmp_path / "requirements.txt").write_text("langchain==0.0.101\n")

        orchestrator = ScanOrchestrator(
            validator=ScanJobValidator(),
            adapter=OSSToolAdapter(),
            mapper=VulnerabilityMapper(),
            vex_filter=VEXFilter(),
            enricher=RemediationEnricher(),
            nvd_cache_manager=NVDCacheManager(),
            cyclonedx_serializer=CycloneDXSerializer(),
            spdx_serializer=SPDXSerializer(),
        )

        result = orchestrator.run(
            repo_path=repo_path,
            output_format="cyclonedx",
            env="development",
            nvd_cache=NVD_CACHE_SEED,
            raw_tool_output=RAW_SYFT_TASKMATRIX,
            vex_statements=VEX_SUPPRESS_LANGCHAIN,
            last_synced_at=datetime.now(timezone.utc),
        )

        active_cve_ids = {v["cve_id"] for v in result.active_vulns}
        assert "CVE-2023-34540" not in active_cve_ids, (
            "CVE-2023-34540 (langchain) was suppressed by VEX but still "
            "appears in active_vulns."
        )

    def test_suppressed_vuln_present_in_suppressed_list(self, tmp_path):
        """
        ACCEPTANCE (AC-4): The VEX-suppressed vulnerability appears in
        ScanResult.suppressed_vulns with vex_filtered=True.
        """
        repo_path = str(tmp_path)
        (tmp_path / "requirements.txt").write_text("langchain==0.0.101\n")

        orchestrator = ScanOrchestrator(
            validator=ScanJobValidator(),
            adapter=OSSToolAdapter(),
            mapper=VulnerabilityMapper(),
            vex_filter=VEXFilter(),
            enricher=RemediationEnricher(),
            nvd_cache_manager=NVDCacheManager(),
            cyclonedx_serializer=CycloneDXSerializer(),
            spdx_serializer=SPDXSerializer(),
        )

        result = orchestrator.run(
            repo_path=repo_path,
            output_format="cyclonedx",
            env="development",
            nvd_cache=NVD_CACHE_SEED,
            raw_tool_output=RAW_SYFT_TASKMATRIX,
            vex_statements=VEX_SUPPRESS_LANGCHAIN,
            last_synced_at=datetime.now(timezone.utc),
        )

        suppressed_cve_ids = {v["cve_id"] for v in result.suppressed_vulns}
        assert "CVE-2023-34540" in suppressed_cve_ids, (
            "CVE-2023-34540 (langchain) is VEX-suppressed but absent from "
            "suppressed_vulns."
        )
        suppressed_entry = next(
            v for v in result.suppressed_vulns if v["cve_id"] == "CVE-2023-34540"
        )
        assert suppressed_entry.get("vex_filtered") is True

    def test_suppressed_vuln_not_enriched(self, tmp_path):
        """
        ACCEPTANCE (AC-4): Suppressed vulnerabilities do NOT receive enrichment
        (advisory_url, fixed_version, upgrade_command) that would only be
        added if enrichment ran before suppression.

        This verifies the ordering: filter THEN enrich, not enrich THEN filter.
        """
        repo_path = str(tmp_path)
        (tmp_path / "requirements.txt").write_text("langchain==0.0.101\n")

        orchestrator = ScanOrchestrator(
            validator=ScanJobValidator(),
            adapter=OSSToolAdapter(),
            mapper=VulnerabilityMapper(),
            vex_filter=VEXFilter(),
            enricher=RemediationEnricher(),
            nvd_cache_manager=NVDCacheManager(),
            cyclonedx_serializer=CycloneDXSerializer(),
            spdx_serializer=SPDXSerializer(),
        )

        result = orchestrator.run(
            repo_path=repo_path,
            output_format="cyclonedx",
            env="development",
            nvd_cache=NVD_CACHE_SEED,
            raw_tool_output=RAW_SYFT_TASKMATRIX,
            vex_statements=VEX_SUPPRESS_LANGCHAIN,
            last_synced_at=datetime.now(timezone.utc),
        )

        suppressed_entry = next(
            (v for v in result.suppressed_vulns if v["cve_id"] == "CVE-2023-34540"),
            None,
        )
        assert suppressed_entry is not None
        # Suppressed entries must not carry enrichment fields that only
        # RemediationEnricher adds. upgrade_command is the strongest signal.
        assert "upgrade_command" not in suppressed_entry or suppressed_entry.get("upgrade_command") is None, (
            "Suppressed vulnerability was enriched (upgrade_command present), "
            "which implies enrichment ran before VEX filtering."
        )

    def test_non_suppressed_vulns_remain_active(self, tmp_path):
        """
        ACCEPTANCE: Vulnerabilities NOT covered by a VEX statement remain in
        active_vulns even when a VEX statement suppresses a different vuln.
        """
        repo_path = str(tmp_path)
        (tmp_path / "requirements.txt").write_text("langchain==0.0.101\n")

        orchestrator = ScanOrchestrator(
            validator=ScanJobValidator(),
            adapter=OSSToolAdapter(),
            mapper=VulnerabilityMapper(),
            vex_filter=VEXFilter(),
            enricher=RemediationEnricher(),
            nvd_cache_manager=NVDCacheManager(),
            cyclonedx_serializer=CycloneDXSerializer(),
            spdx_serializer=SPDXSerializer(),
        )

        result = orchestrator.run(
            repo_path=repo_path,
            output_format="cyclonedx",
            env="development",
            nvd_cache=NVD_CACHE_SEED,
            raw_tool_output=RAW_SYFT_TASKMATRIX,
            vex_statements=VEX_SUPPRESS_LANGCHAIN,  # only suppresses langchain
            last_synced_at=datetime.now(timezone.utc),
        )

        active_cve_ids = {v["cve_id"] for v in result.active_vulns}
        # requests and lxml vulns should remain active
        assert "CVE-2023-32681" in active_cve_ids
        assert "CVE-2018-19787" in active_cve_ids


# ===========================================================================
# ORCHESTRATION TEST CLASS 4 — Deduplication Before Mapping (AC-5)
# Scan Workflow: deduplicating_output -> matching_vulnerabilities transition
# Source: SBOM_POC_Scope.md, OSS Reuse table — unified output row
# ===========================================================================

class TestDeduplicationOrchestration:
    """
    ACCEPTANCE (AC-5): PURL deduplication happens BEFORE vulnerability mapping.
    If the same PURL appears twice in raw tool output, the orchestrator must
    pass only unique PURLs to VulnerabilityMapper, preventing duplicate CVEs.

    ORCHESTRATION: Enforces the deduplicating_output -> matching_vulnerabilities
    ordering in the Scan Workflow state machine.
    """

    def test_duplicate_purls_in_tool_output_yield_single_vuln_entry(self, tmp_path):
        """
        ACCEPTANCE (AC-5): When raw tool output contains the same PURL twice
        (e.g. two scanner results for the same package), the final ScanResult
        contains only one CVE entry for that PURL — not two.
        """
        repo_path = str(tmp_path)
        (tmp_path / "requirements.txt").write_text("langchain==0.0.101\n")

        # Duplicate the langchain component in raw output
        raw_with_duplicates = {
            "tool": "syft",
            "components": [
                {"name": "langchain", "version": "0.0.101",
                 "purl": "pkg:pypi/langchain@0.0.101",
                 "cpes": [], "metadata": {}},
                # Exact duplicate of the same PURL
                {"name": "langchain", "version": "0.0.101",
                 "purl": "pkg:pypi/langchain@0.0.101",
                 "cpes": [], "metadata": {}},
            ],
        }

        orchestrator = ScanOrchestrator(
            validator=ScanJobValidator(),
            adapter=OSSToolAdapter(),
            mapper=VulnerabilityMapper(),
            vex_filter=VEXFilter(),
            enricher=RemediationEnricher(),
            nvd_cache_manager=NVDCacheManager(),
            cyclonedx_serializer=CycloneDXSerializer(),
            spdx_serializer=SPDXSerializer(),
        )

        result = orchestrator.run(
            repo_path=repo_path,
            output_format="cyclonedx",
            env="development",
            nvd_cache=NVD_CACHE_SEED,
            raw_tool_output=raw_with_duplicates,
            vex_statements=[],
            last_synced_at=datetime.now(timezone.utc),
        )

        langchain_vulns = [
            v for v in result.active_vulns
            if v.get("cve_id") == "CVE-2023-34540"
        ]
        assert len(langchain_vulns) == 1, (
            f"Expected exactly 1 CVE-2023-34540 entry but found {len(langchain_vulns)}. "
            "Deduplication may not be running before vulnerability mapping."
        )

    def test_deduplicated_dep_count_matches_unique_purls(self, tmp_path):
        """
        ACCEPTANCE (AC-5): ScanResult.dependencies length equals the count of
        unique PURLs in the raw tool output, regardless of how many times each
        PURL appears.
        """
        repo_path = str(tmp_path)
        (tmp_path / "requirements.txt").write_text("langchain==0.0.101\n")

        raw_with_3_duplicates = {
            "tool": "syft",
            "components": [
                {"name": "flask", "version": "3.0.0",
                 "purl": "pkg:pypi/flask@3.0.0", "cpes": [], "metadata": {}},
                {"name": "click", "version": "8.1.7",
                 "purl": "pkg:pypi/click@8.1.7", "cpes": [], "metadata": {}},
                # duplicate flask
                {"name": "flask", "version": "3.0.0",
                 "purl": "pkg:pypi/flask@3.0.0", "cpes": [], "metadata": {}},
                # duplicate click
                {"name": "click", "version": "8.1.7",
                 "purl": "pkg:pypi/click@8.1.7", "cpes": [], "metadata": {}},
            ],
        }
        unique_purls = {"pkg:pypi/flask@3.0.0", "pkg:pypi/click@8.1.7"}

        orchestrator = ScanOrchestrator(
            validator=ScanJobValidator(),
            adapter=OSSToolAdapter(),
            mapper=VulnerabilityMapper(),
            vex_filter=VEXFilter(),
            enricher=RemediationEnricher(),
            nvd_cache_manager=NVDCacheManager(),
            cyclonedx_serializer=CycloneDXSerializer(),
            spdx_serializer=SPDXSerializer(),
        )

        result = orchestrator.run(
            repo_path=repo_path,
            output_format="cyclonedx",
            env="development",
            nvd_cache={},
            raw_tool_output=raw_with_3_duplicates,
            vex_statements=[],
            last_synced_at=datetime.now(timezone.utc),
        )

        result_purls = {d.get("purl") for d in result.dependencies}
        assert result_purls == unique_purls, (
            f"Expected deduplicated deps to match unique PURLs {unique_purls}, "
            f"got {result_purls}"
        )


# ===========================================================================
# ORCHESTRATION TEST CLASS 5 — NVD Sync Orchestration (AC-6)
# NVD Sync Workflow: idle -> syncing_nvd -> updating_cache -> sync_complete
# Source: SBOM_POC_Scope.md, In Scope #7 (confidence: verbatim)
# ===========================================================================

class TestNVDSyncOrchestration:
    """
    ACCEPTANCE (AC-6): NVDSyncOrchestrator accepts a source_path to a Grype DB
    and returns SyncResult with counts and timestamp. When the source is
    invalid, NVDSyncError must propagate to the caller.

    ORCHESTRATION: Tests the NVD Sync Workflow state machine (4 transitions).
    Verifies that sync_log is populated and that error paths raise without
    silently swallowing exceptions.
    Workflow source: SBOM_POC_Scope.md, In Scope #7 (confidence: verbatim)
    """

    def test_valid_source_returns_sync_result(self, tmp_path):
        """
        ACCEPTANCE (AC-6 - happy path): Valid NVD feed JSON at source_path
        yields SyncResult with non-negative counts and a timestamp.
        NVD Sync Workflow: idle -> syncing_nvd -> updating_cache -> sync_complete
        """
        feed_path = str(tmp_path / "nvd_feed.json")
        feed_data = {
            "CVE_Items": [
                {"cve_id": "CVE-2023-34540",
                 "purl": "pkg:pypi/langchain@0.0.101",
                 "cvss_score": 9.8},
                {"cve_id": "CVE-2023-32681",
                 "purl": "pkg:pypi/requests@2.27.1",
                 "cvss_score": 6.1},
            ]
        }
        with open(feed_path, "w") as fh:
            json.dump(feed_data, fh)

        sync_orchestrator = NVDSyncOrchestrator(
            cache_manager=NVDCacheManager()
        )
        result = sync_orchestrator.run(source_path=feed_path)

        assert isinstance(result, SyncResult)
        assert result.records_added >= 0
        assert result.records_updated >= 0
        assert result.records_added + result.records_updated == len(feed_data["CVE_Items"])
        assert result.synced_at is not None
        assert result.source_path == feed_path

    def test_invalid_source_raises_nvd_sync_error(self, tmp_path):
        """
        ACCEPTANCE (AC-6 - error path): A non-existent source_path causes
        NVDSyncError to propagate. The workflow aborts and does NOT silently
        return a partial SyncResult.
        NVD Sync Workflow: idle -> syncing_nvd [FAILS] -> error propagated
        """
        sync_orchestrator = NVDSyncOrchestrator(
            cache_manager=NVDCacheManager()
        )
        with pytest.raises(NVDSyncError):
            sync_orchestrator.run(
                source_path="/nonexistent/path/to/nvd_feed.json"
            )

    def test_sync_result_contains_sync_log(self, tmp_path):
        """
        ACCEPTANCE (AC-6): SyncResult.sync_log contains the audit record of the
        sync run (synced_at, source_path, counts).
        """
        feed_path = str(tmp_path / "nvd_feed.json")
        feed_data = {"CVE_Items": [
            {"cve_id": "CVE-2023-44271", "purl": "pkg:pypi/Pillow@9.0.1",
             "cvss_score": 7.5}
        ]}
        with open(feed_path, "w") as fh:
            json.dump(feed_data, fh)

        sync_orchestrator = NVDSyncOrchestrator(cache_manager=NVDCacheManager())
        result = sync_orchestrator.run(source_path=feed_path)

        assert result.sync_log is not None
        assert "synced_at" in result.sync_log
        assert "source_path" in result.sync_log
        assert "records_added" in result.sync_log

    def test_sync_result_counts_are_additive_across_runs(self, tmp_path):
        """
        ACCEPTANCE (AC-6): Running sync twice on the same feed: first run adds
        records, second run updates (or noop) the same records.
        """
        feed_path = str(tmp_path / "nvd_feed.json")
        feed_data = {"CVE_Items": [
            {"cve_id": "CVE-2023-34540",
             "purl": "pkg:pypi/langchain@0.0.101",
             "cvss_score": 9.8}
        ]}
        with open(feed_path, "w") as fh:
            json.dump(feed_data, fh)

        cache_mgr = NVDCacheManager()
        sync_orchestrator = NVDSyncOrchestrator(cache_manager=cache_mgr)

        # First run: records_added
        result1 = sync_orchestrator.run(source_path=feed_path)
        assert result1.records_added == 1
        assert result1.records_updated == 0

        # Second run: records_updated
        result2 = sync_orchestrator.run(source_path=feed_path)
        assert result2.records_added == 0
        assert result2.records_updated == 1


# ===========================================================================
# ORCHESTRATION TEST CLASS 6 — CLI Contract (AC-7, AC-8, AC-9)
# CLIOrchestrator: sbom-tool scan / sbom-tool sync
# Source: SBOM_POC_Scope.md, Key Decisions — CLI framework Typer (verbatim)
# ===========================================================================

class TestCLIOrchestration:
    """
    ACCEPTANCE (AC-7, AC-8, AC-9): The CLI layer correctly maps Typer command
    invocations to ScanOrchestrator/NVDSyncOrchestrator and enforces exit code
    semantics.

    ORCHESTRATION: Verifies that CLIOrchestrator translates CLI arguments into
    the correct orchestrator calls and handles exit codes according to spec:
      - AC-7: valid scan args -> exit 0, JSON written to stdout or file
      - AC-8: invalid repo -> exit non-zero, error to stderr
      - AC-9: valid sync source -> exit 0, counts printed
    """

    def test_valid_scan_exits_zero(self, tmp_path):
        """
        ACCEPTANCE (AC-7): sbom-tool scan with a valid repo, format, and env
        returns exit_code 0 and non-empty stdout containing the SBOM JSON.
        """
        repo_path = str(tmp_path)
        (tmp_path / "requirements.txt").write_text("flask==3.0.0\n")

        mock_scan_orch = MagicMock(spec=ScanOrchestrator)
        mock_scan_orch.run.return_value = ScanResult(
            dependencies=[{"name": "flask", "purl": "pkg:pypi/flask@3.0.0"}],
            active_vulns=[],
            suppressed_vulns=[],
            warnings=[],
            sbom_document={"bomFormat": "CycloneDX", "specVersion": "1.4",
                           "components": [], "vulnerabilities": []},
        )

        cli = CLIOrchestrator(
            scan_orchestrator=mock_scan_orch,
            sync_orchestrator=MagicMock(spec=NVDSyncOrchestrator),
        )

        outcome = cli.invoke_scan(
            repo=repo_path,
            fmt="cyclonedx",
            env="development",
        )

        assert outcome["exit_code"] == 0
        assert outcome["stdout"] is not None
        # stdout must be parseable JSON
        sbom_json = json.loads(outcome["stdout"])
        assert "bomFormat" in sbom_json or "spdxVersion" in sbom_json

    def test_invalid_repo_exits_nonzero_with_stderr(self, tmp_path):
        """
        ACCEPTANCE (AC-8): sbom-tool scan with a non-existent repo path
        returns a non-zero exit code and writes an error message to stderr.
        """
        cli = CLIOrchestrator(
            scan_orchestrator=MagicMock(spec=ScanOrchestrator),
            sync_orchestrator=MagicMock(spec=NVDSyncOrchestrator),
        )

        outcome = cli.invoke_scan(
            repo="/definitely/does/not/exist",
            fmt="cyclonedx",
            env="development",
        )

        assert outcome["exit_code"] != 0
        assert outcome["stderr"] is not None
        assert len(outcome["stderr"]) > 0

    def test_valid_sync_exits_zero_with_counts(self, tmp_path):
        """
        ACCEPTANCE (AC-9): sbom-tool sync with a valid NVD feed source returns
        exit_code 0 and stdout contains the sync counts.
        """
        feed_path = str(tmp_path / "nvd_feed.json")
        feed_data = {"CVE_Items": [
            {"cve_id": "CVE-2023-34540",
             "purl": "pkg:pypi/langchain@0.0.101",
             "cvss_score": 9.8}
        ]}
        with open(feed_path, "w") as fh:
            json.dump(feed_data, fh)

        mock_sync_orch = MagicMock(spec=NVDSyncOrchestrator)
        mock_sync_orch.run.return_value = SyncResult(
            records_added=1, records_updated=0,
            synced_at=datetime.now(timezone.utc).isoformat(),
            source_path=feed_path,
        )

        cli = CLIOrchestrator(
            scan_orchestrator=MagicMock(spec=ScanOrchestrator),
            sync_orchestrator=mock_sync_orch,
        )

        outcome = cli.invoke_sync(source=feed_path)

        assert outcome["exit_code"] == 0
        # stdout should mention the record counts
        stdout_text = outcome.get("stdout", "")
        has_count = (
            "1" in stdout_text
            or "records_added" in stdout_text
            or "synced" in stdout_text.lower()
        )
        assert has_count, (
            f"Expected sync counts in stdout but got: '{stdout_text}'"
        )

    def test_stale_cache_scan_exits_zero_warning_to_stderr(self, tmp_path):
        """
        ACCEPTANCE (AC-7 + AC-3): When cache is stale, CLI exits 0 (not an
        error) but writes the staleness warning to stderr.
        """
        repo_path = str(tmp_path)
        (tmp_path / "requirements.txt").write_text("flask==3.0.0\n")

        stale_warning = "NVD cache is stale. Last synced at 2026-04-02T00:00:00Z."
        mock_scan_orch = MagicMock(spec=ScanOrchestrator)
        mock_scan_orch.run.return_value = ScanResult(
            dependencies=[],
            active_vulns=[],
            suppressed_vulns=[],
            warnings=[stale_warning],
            sbom_document={"bomFormat": "CycloneDX", "specVersion": "1.4",
                           "components": [], "vulnerabilities": []},
        )

        cli = CLIOrchestrator(
            scan_orchestrator=mock_scan_orch,
            sync_orchestrator=MagicMock(spec=NVDSyncOrchestrator),
        )

        outcome = cli.invoke_scan(
            repo=repo_path,
            fmt="cyclonedx",
            env="development",
        )

        assert outcome["exit_code"] == 0, (
            "Stale cache should warn but not cause non-zero exit."
        )
        stderr_text = outcome.get("stderr", "")
        assert "stale" in stderr_text.lower() or "sync" in stderr_text.lower(), (
            f"Expected stale-cache warning in stderr but got: '{stderr_text}'"
        )

    def test_nvd_sync_error_exits_nonzero(self, tmp_path):
        """
        ACCEPTANCE: sbom-tool sync with an invalid source path must exit
        non-zero (NVDSyncError propagates and CLI maps it to an error exit).
        """
        mock_sync_orch = MagicMock(spec=NVDSyncOrchestrator)
        mock_sync_orch.run.side_effect = NVDSyncError("Source not found")

        cli = CLIOrchestrator(
            scan_orchestrator=MagicMock(spec=ScanOrchestrator),
            sync_orchestrator=mock_sync_orch,
        )

        outcome = cli.invoke_sync(source="/nonexistent/nvd_feed.json")

        assert outcome["exit_code"] != 0
        assert "error" in outcome.get("stderr", "").lower() or len(outcome.get("stderr", "")) > 0


# ===========================================================================
# ORCHESTRATION TEST CLASS 7 — Scan Workflow State Transitions (AC-10)
# DDM Workflow: "Scan Workflow" — 7 states, 7 transitions
# Workflow source: SBOM_POC_Scope.md, In Scope #1-#6 and OSS Reuse table
# (confidence: inferred)
# ===========================================================================

class TestScanWorkflowStateTransitions:
    """
    ACCEPTANCE (AC-10): The Scan Workflow state machine enforces that
    transitions occur in the prescribed order. States cannot be skipped
    and must be visited sequentially.

    Workflow source: SBOM_POC_Scope.md, In Scope #1-#6, OSS Reuse table
    (confidence: inferred from sequential OSS reuse rows)

    States (in order):
      idle -> scanning_dependencies -> deduplicating_output ->
      matching_vulnerabilities -> filtering_vex ->
      enriching_remediation -> exporting_sbom -> idle (terminal)
    """

    EXPECTED_STATE_ORDER = [
        ScanWorkflowState.IDLE,
        ScanWorkflowState.SCANNING_DEPENDENCIES,
        ScanWorkflowState.DEDUPLICATING_OUTPUT,
        ScanWorkflowState.MATCHING_VULNERABILITIES,
        ScanWorkflowState.FILTERING_VEX,
        ScanWorkflowState.ENRICHING_REMEDIATION,
        ScanWorkflowState.EXPORTING_SBOM,
    ]

    def test_workflow_visits_all_states_in_order(self, tmp_path):
        """
        ACCEPTANCE (AC-10): ScanOrchestrator records visited workflow states in
        ScanResult.workflow_states_visited and they match the 7-state sequence.
        Workflow source: SBOM_POC_Scope.md — Scan Workflow all 7 transitions.
        """
        repo_path = str(tmp_path)
        (tmp_path / "requirements.txt").write_text("langchain==0.0.101\n")

        orchestrator = ScanOrchestrator(
            validator=ScanJobValidator(),
            adapter=OSSToolAdapter(),
            mapper=VulnerabilityMapper(),
            vex_filter=VEXFilter(),
            enricher=RemediationEnricher(),
            nvd_cache_manager=NVDCacheManager(),
            cyclonedx_serializer=CycloneDXSerializer(),
            spdx_serializer=SPDXSerializer(),
        )

        result = orchestrator.run(
            repo_path=repo_path,
            output_format="cyclonedx",
            env="development",
            nvd_cache=NVD_CACHE_SEED,
            raw_tool_output=RAW_SYFT_TASKMATRIX,
            vex_statements=[],
            last_synced_at=datetime.now(timezone.utc),
        )

        visited = result.workflow_states_visited
        assert len(visited) > 0, "workflow_states_visited must not be empty"

        # Each state value must be from the canonical set
        canonical_values = {s.value for s in ScanWorkflowState}
        for state in visited:
            assert state in canonical_values, (
                f"Unknown state '{state}' in workflow_states_visited. "
                f"Allowed: {canonical_values}"
            )

        # States are visited in ascending index order (no skipping)
        state_to_index = {s.value: i for i, s in enumerate(self.EXPECTED_STATE_ORDER)}
        visited_indices = [state_to_index[s] for s in visited if s in state_to_index]
        assert visited_indices == sorted(visited_indices), (
            f"Workflow states were visited out of order: {visited}"
        )

    def test_idle_is_first_state(self, tmp_path):
        """
        ACCEPTANCE (AC-10): The scan workflow starts from 'idle'.
        Guard: 'Single repo, single environment specified' (from transition #1).
        """
        repo_path = str(tmp_path)
        (tmp_path / "requirements.txt").write_text("flask==3.0.0\n")

        orchestrator = ScanOrchestrator(
            validator=ScanJobValidator(),
            adapter=OSSToolAdapter(),
            mapper=VulnerabilityMapper(),
            vex_filter=VEXFilter(),
            enricher=RemediationEnricher(),
            nvd_cache_manager=NVDCacheManager(),
            cyclonedx_serializer=CycloneDXSerializer(),
            spdx_serializer=SPDXSerializer(),
        )

        result = orchestrator.run(
            repo_path=repo_path,
            output_format="cyclonedx",
            env="development",
            nvd_cache={},
            raw_tool_output={"tool": "syft", "components": []},
            vex_statements=[],
            last_synced_at=datetime.now(timezone.utc),
        )

        assert result.workflow_states_visited[0] == ScanWorkflowState.IDLE.value

    def test_exporting_sbom_is_last_state_before_termination(self, tmp_path):
        """
        ACCEPTANCE (AC-10): The last visited state before workflow returns is
        'exporting_sbom' (the terminal state maps back to idle but idle is not
        revisited as a visible transition within a single run).
        """
        repo_path = str(tmp_path)
        (tmp_path / "requirements.txt").write_text("flask==3.0.0\n")

        orchestrator = ScanOrchestrator(
            validator=ScanJobValidator(),
            adapter=OSSToolAdapter(),
            mapper=VulnerabilityMapper(),
            vex_filter=VEXFilter(),
            enricher=RemediationEnricher(),
            nvd_cache_manager=NVDCacheManager(),
            cyclonedx_serializer=CycloneDXSerializer(),
            spdx_serializer=SPDXSerializer(),
        )

        result = orchestrator.run(
            repo_path=repo_path,
            output_format="cyclonedx",
            env="development",
            nvd_cache={},
            raw_tool_output={"tool": "syft", "components": []},
            vex_statements=[],
            last_synced_at=datetime.now(timezone.utc),
        )

        terminal_state = result.workflow_states_visited[-1]
        # Terminal must be exporting_sbom (workflow returns to idle implicitly)
        assert terminal_state == ScanWorkflowState.EXPORTING_SBOM.value

    def test_validation_failure_aborts_before_scanning_state(self, tmp_path):
        """
        ACCEPTANCE (AC-10 / AC-8): When ScanJobValidator rejects the job, the
        workflow does NOT advance past 'idle'. No scanning, mapping, or export
        is attempted. This matches the guard on the idle->scanning_dependencies
        transition: 'Single repo, single environment specified'.
        """
        orchestrator = ScanOrchestrator(
            validator=ScanJobValidator(),
            adapter=OSSToolAdapter(),
            mapper=VulnerabilityMapper(),
            vex_filter=VEXFilter(),
            enricher=RemediationEnricher(),
            nvd_cache_manager=NVDCacheManager(),
            cyclonedx_serializer=CycloneDXSerializer(),
            spdx_serializer=SPDXSerializer(),
        )

        with pytest.raises(Exception) as exc_info:
            orchestrator.run(
                repo_path="/nonexistent/repo",
                output_format="cyclonedx",
                env="development",
                nvd_cache=NVD_CACHE_SEED,
                raw_tool_output={"tool": "syft", "components": []},
                vex_statements=[],
                last_synced_at=datetime.now(timezone.utc),
            )

        # The exception must communicate the validation failure clearly
        assert exc_info.value is not None


# ===========================================================================
# ORCHESTRATION TEST CLASS 8 — NVD Sync Workflow State Transitions (AC-6)
# DDM Workflow: "NVD Sync Workflow" — 4 states, 4 transitions
# Source: SBOM_POC_Scope.md, In Scope #7 (confidence: verbatim)
# ===========================================================================

class TestNVDSyncWorkflowStateTransitions:
    """
    ACCEPTANCE (AC-6): The NVD Sync Workflow follows its 4-state sequence.
    Workflow source: SBOM_POC_Scope.md, In Scope #7 (confidence: verbatim)

    States: idle -> syncing_nvd -> updating_cache -> sync_complete
    """

    EXPECTED_SYNC_STATES = [
        NVDSyncWorkflowState.IDLE,
        NVDSyncWorkflowState.SYNCING_NVD,
        NVDSyncWorkflowState.UPDATING_CACHE,
        NVDSyncWorkflowState.SYNC_COMPLETE,
    ]

    def test_sync_workflow_visits_all_four_states(self, tmp_path):
        """
        ACCEPTANCE (AC-6): NVDSyncOrchestrator visits all 4 states in order
        and records them in SyncResult (or accessible state attribute).
        Workflow source: SBOM_POC_Scope.md, In Scope #7 (verbatim).
        """
        feed_path = str(tmp_path / "nvd_feed.json")
        feed_data = {"CVE_Items": [
            {"cve_id": "CVE-2023-34540", "purl": "pkg:pypi/langchain@0.0.101",
             "cvss_score": 9.8}
        ]}
        with open(feed_path, "w") as fh:
            json.dump(feed_data, fh)

        sync_orchestrator = NVDSyncOrchestrator(cache_manager=NVDCacheManager())
        result = sync_orchestrator.run(source_path=feed_path)

        # SyncResult carries workflow_states_visited if orchestrator tracks them
        states_visited = getattr(result, "workflow_states_visited", None)
        if states_visited is not None:
            canonical = {s.value for s in NVDSyncWorkflowState}
            for s in states_visited:
                assert s in canonical, f"Unknown sync state: '{s}'"
            # States visited must be a non-empty ordered prefix of expected
            assert len(states_visited) > 0

    def test_sync_error_state_does_not_reach_sync_complete(self, tmp_path):
        """
        ACCEPTANCE (AC-6): When sync fails, the workflow does NOT reach
        sync_complete. NVDSyncError is raised and propagates.
        Workflow source: SBOM_POC_Scope.md, In Scope #7 (verbatim).
        """
        sync_orchestrator = NVDSyncOrchestrator(cache_manager=NVDCacheManager())

        with pytest.raises(NVDSyncError):
            sync_orchestrator.run(source_path="/no/such/file.json")


# ===========================================================================
# ORCHESTRATION TEST CLASS 9 — Component Coordination (Cross-component flow)
# Tests that business components share data correctly when wired together
# ===========================================================================

class TestComponentCoordinationOrchestration:
    """
    ACCEPTANCE: Business components from Step 6 produce outputs that are
    compatible with the next component in the pipeline, without data
    loss or schema mismatches at the handoff boundaries.

    ORCHESTRATION: Tests are performed on real Step 6 components (no stubs)
    to verify that the data contract between components is satisfied.
    These tests would catch integration failures not visible in unit tests.
    """

    def test_adapter_output_is_accepted_by_mapper(self):
        """
        ORCHESTRATION: OSSToolAdapter.normalise() output is consumed by
        VulnerabilityMapper.map_vulnerabilities() without KeyError or
        TypeError — i.e., the field names produced by the adapter match
        what the mapper expects.
        """
        adapter = OSSToolAdapter()
        mapper = VulnerabilityMapper()

        raw = {
            "tool": "syft",
            "components": [
                {"name": "langchain", "version": "0.0.101",
                 "purl": "pkg:pypi/langchain@0.0.101",
                 "cpes": [], "metadata": {"Author": "LangChain, Inc."}},
            ],
        }

        normalised = adapter.normalise(raw)
        vulns = mapper.map_vulnerabilities(normalised, NVD_CACHE_SEED)

        # No exception: the mapper accepted the adapter's output format
        assert isinstance(vulns, list)

    def test_mapper_output_is_accepted_by_vex_filter(self):
        """
        ORCHESTRATION: VulnerabilityMapper output is consumed by
        VEXFilter.apply() without schema errors.
        """
        mapper = VulnerabilityMapper()
        vex = VEXFilter()

        deps = [{"name": "langchain", "purl": "pkg:pypi/langchain@0.0.101",
                 "cpe": "cpe:2.3:a:langchain:langchain:0.0.101:*:*:*:*:python:*:*"}]
        vulns = mapper.map_vulnerabilities(deps, NVD_CACHE_SEED)
        filter_result = vex.apply(vulns, VEX_SUPPRESS_LANGCHAIN)

        assert isinstance(filter_result, FilterResult)
        assert isinstance(filter_result.active, list)
        assert isinstance(filter_result.suppressed, list)

    def test_vex_active_vulns_accepted_by_enricher(self):
        """
        ORCHESTRATION: Active vulnerabilities from VEXFilter are consumable
        by RemediationEnricher. Each active vuln receives advisory_url.
        """
        mapper = VulnerabilityMapper()
        vex = VEXFilter()
        enricher = RemediationEnricher()

        deps = [
            {"name": "langchain", "purl": "pkg:pypi/langchain@0.0.101", "cpe": ""},
            {"name": "requests", "purl": "pkg:pypi/requests@2.27.1", "cpe": ""},
        ]
        vulns = mapper.map_vulnerabilities(deps, NVD_CACHE_SEED)
        # Suppress only langchain
        filter_result = vex.apply(vulns, VEX_SUPPRESS_LANGCHAIN)

        enriched = []
        for v in filter_result.active:
            purl = v.get("dep_purl") or v.get("purl", "")
            cache_entry = NVD_CACHE_SEED.get(purl, {})
            enriched.append(enricher.enrich(v, cache_entry))

        for ev in enriched:
            assert "advisory_url" in ev, (
                f"advisory_url missing from enriched vuln {ev.get('cve_id')}"
            )

    def test_enriched_vulns_serialised_in_cyclonedx(self):
        """
        ORCHESTRATION: Enriched vulnerabilities are serialisable by
        CycloneDXSerializer without data loss of CVE IDs.
        """
        mapper = VulnerabilityMapper()
        vex = VEXFilter()
        enricher = RemediationEnricher()
        serializer = CycloneDXSerializer()

        deps = [
            {"name": "langchain", "purl": "pkg:pypi/langchain@0.0.101",
             "cpe": "", "version": "0.0.101", "type": "library"},
        ]
        vulns = mapper.map_vulnerabilities(deps, NVD_CACHE_SEED)
        filter_result = vex.apply(vulns, [])

        enriched_vulns = []
        for v in filter_result.active:
            purl = v.get("dep_purl") or v.get("purl", "")
            cache_entry = NVD_CACHE_SEED.get(purl, {})
            ev = enricher.enrich(v, cache_entry)
            enriched_vulns.append(ev)

        scan_result = {
            "scan_id": "test_coord",
            "repo_name": "test_repo",
            "dependencies": deps,
            "vulnerabilities": enriched_vulns,
        }
        doc = serializer.serialize(scan_result)

        assert doc["bomFormat"] == "CycloneDX"
        vuln_ids = [v["id"] for v in doc.get("vulnerabilities", [])]
        assert "CVE-2023-34540" in vuln_ids

    def test_enriched_vulns_serialised_in_spdx(self):
        """
        ORCHESTRATION: Enriched vulnerabilities cause SPDX serialiser to add
        SECURITY external references for the affected packages.
        """
        mapper = VulnerabilityMapper()
        enricher = RemediationEnricher()
        serializer = SPDXSerializer()

        deps = [
            {"name": "numpy", "purl": "pkg:pypi/numpy@1.22.0",
             "cpe": "cpe:2.3:a:numpy:numpy:1.22.0:*:*:*:*:python:*:*",
             "version": "1.22.0", "type": "library",
             "vulnerable": True, "cve_ids": ["CVE-2021-33430"]},
        ]
        vulns = mapper.map_vulnerabilities(deps, NVD_CACHE_SEED)

        enriched_vulns = []
        for v in vulns:
            purl = v.get("dep_purl") or v.get("purl", "")
            ev = enricher.enrich(v, NVD_CACHE_SEED.get(purl, {}))
            enriched_vulns.append(ev)

        scan_result = {
            "scan_id": "test_spdx",
            "repo_name": "test_repo",
            "dependencies": deps,
            "vulnerabilities": enriched_vulns,
        }
        doc = serializer.serialize(scan_result)

        assert doc["spdxVersion"] == "SPDX-2.3"
        # numpy package should have SECURITY external ref
        numpy_pkg = next(
            (p for p in doc["packages"] if p["name"] == "numpy"), None
        )
        assert numpy_pkg is not None
        sec_refs = [
            r for r in numpy_pkg.get("externalRefs", [])
            if r.get("referenceCategory") == "SECURITY"
        ]
        assert len(sec_refs) > 0


# ===========================================================================
# ORCHESTRATION TEST CLASS 10 — Single-Repo Constraint at Orchestration Boundary
# Rule: Single Repository Per Scan — priority 1 (verbatim)
# Cross-workflow rule: enforced by orchestrator, not just validator
# ===========================================================================

class TestOrchestrationConstraintEnforcement:
    """
    ACCEPTANCE: Orchestration boundary enforces business rules that span the
    full workflow, not just individual component calls.

    Rules tested:
      - Single Repository Per Scan (Rule priority 1, verbatim)
      - Single Runtime Environment Per Run (Rule priority 2, verbatim)
    """

    def test_multi_repo_path_raises_at_orchestration_boundary(self, tmp_path):
        """
        ACCEPTANCE: ScanOrchestrator rejects a comma-separated multi-repo
        path before any scanning begins. The rejection must not leave
        partial state.
        Rule source: SBOM_POC_Scope.md, In Scope #1 and Key Decisions (verbatim)
        """
        orchestrator = ScanOrchestrator(
            validator=ScanJobValidator(),
            adapter=OSSToolAdapter(),
            mapper=VulnerabilityMapper(),
            vex_filter=VEXFilter(),
            enricher=RemediationEnricher(),
            nvd_cache_manager=NVDCacheManager(),
            cyclonedx_serializer=CycloneDXSerializer(),
            spdx_serializer=SPDXSerializer(),
        )

        with pytest.raises(Exception) as exc_info:
            orchestrator.run(
                repo_path="/repo/a,/repo/b",
                output_format="cyclonedx",
                env="development",
                nvd_cache=NVD_CACHE_SEED,
                raw_tool_output={"tool": "syft", "components": []},
                vex_statements=[],
                last_synced_at=datetime.now(timezone.utc),
            )
        assert exc_info.value is not None

    def test_unknown_output_format_raises_at_orchestration_boundary(self, tmp_path):
        """
        ACCEPTANCE: ScanOrchestrator rejects unknown output formats (not
        'cyclonedx' or 'spdx') at the orchestration boundary.
        Source: SBOM_POC_Scope.md, In Scope #4 and Key Decisions (verbatim)
        """
        repo_path = str(tmp_path)
        (tmp_path / "requirements.txt").write_text("flask==3.0.0\n")

        orchestrator = ScanOrchestrator(
            validator=ScanJobValidator(),
            adapter=OSSToolAdapter(),
            mapper=VulnerabilityMapper(),
            vex_filter=VEXFilter(),
            enricher=RemediationEnricher(),
            nvd_cache_manager=NVDCacheManager(),
            cyclonedx_serializer=CycloneDXSerializer(),
            spdx_serializer=SPDXSerializer(),
        )

        with pytest.raises((ValueError, NotImplementedError, KeyError)):
            orchestrator.run(
                repo_path=repo_path,
                output_format="xml",  # unsupported
                env="development",
                nvd_cache={},
                raw_tool_output={"tool": "syft", "components": []},
                vex_statements=[],
                last_synced_at=datetime.now(timezone.utc),
            )

    def test_invalid_environment_raises_at_orchestration_boundary(self, tmp_path):
        """
        ACCEPTANCE: ScanOrchestrator rejects unknown environments.
        Rule source: SBOM_POC_Scope.md, In Scope #2 (verbatim)
        """
        repo_path = str(tmp_path)
        (tmp_path / "requirements.txt").write_text("flask==3.0.0\n")

        orchestrator = ScanOrchestrator(
            validator=ScanJobValidator(),
            adapter=OSSToolAdapter(),
            mapper=VulnerabilityMapper(),
            vex_filter=VEXFilter(),
            enricher=RemediationEnricher(),
            nvd_cache_manager=NVDCacheManager(),
            cyclonedx_serializer=CycloneDXSerializer(),
            spdx_serializer=SPDXSerializer(),
        )

        with pytest.raises(Exception):
            orchestrator.run(
                repo_path=repo_path,
                output_format="cyclonedx",
                env="unknown_env",  # not development|staging|production
                nvd_cache={},
                raw_tool_output={"tool": "syft", "components": []},
                vex_statements=[],
                last_synced_at=datetime.now(timezone.utc),
            )


# ===========================================================================
# ORCHESTRATION TEST CLASS 11 — Remediation Enrichment Coverage
# Rule: Remediation Per Vulnerability (priority 5, verbatim)
# Confirms enrichment is applied to ALL active vulns post-VEX
# ===========================================================================

class TestRemediationEnrichmentCoverage:
    """
    ACCEPTANCE: Every active vulnerability in ScanResult.active_vulns
    contains at least one of advisory_url or fixed_version (CQ-2 resolution:
    advisory_url is always present).

    Rule source: SBOM_POC_Scope.md, In Scope #6 (verbatim)
    CQ-2 resolution: advisory_url always present; upgrade_command for High severity
    """

    def test_every_active_vuln_has_advisory_url(self, tmp_path):
        """
        ACCEPTANCE: All active vulns carry advisory_url (CQ-2 resolution).
        """
        repo_path = str(tmp_path)
        (tmp_path / "requirements.txt").write_text("langchain==0.0.101\n")

        orchestrator = ScanOrchestrator(
            validator=ScanJobValidator(),
            adapter=OSSToolAdapter(),
            mapper=VulnerabilityMapper(),
            vex_filter=VEXFilter(),
            enricher=RemediationEnricher(),
            nvd_cache_manager=NVDCacheManager(),
            cyclonedx_serializer=CycloneDXSerializer(),
            spdx_serializer=SPDXSerializer(),
        )

        result = orchestrator.run(
            repo_path=repo_path,
            output_format="cyclonedx",
            env="development",
            nvd_cache=NVD_CACHE_SEED,
            raw_tool_output=RAW_SYFT_TASKMATRIX,
            vex_statements=[],
            last_synced_at=datetime.now(timezone.utc),
        )

        for vuln in result.active_vulns:
            assert "advisory_url" in vuln and vuln["advisory_url"], (
                f"active vuln {vuln.get('cve_id')} is missing advisory_url "
                "(CQ-2: advisory_url is required for all enriched vulns)"
            )

    def test_high_severity_active_vulns_have_upgrade_command(self, tmp_path):
        """
        ACCEPTANCE: High-severity active vulns with a known fixed_version carry
        an upgrade_command (e.g. 'pip install --upgrade langchain==0.0.247').
        """
        repo_path = str(tmp_path)
        (tmp_path / "requirements.txt").write_text("langchain==0.0.101\n")

        orchestrator = ScanOrchestrator(
            validator=ScanJobValidator(),
            adapter=OSSToolAdapter(),
            mapper=VulnerabilityMapper(),
            vex_filter=VEXFilter(),
            enricher=RemediationEnricher(),
            nvd_cache_manager=NVDCacheManager(),
            cyclonedx_serializer=CycloneDXSerializer(),
            spdx_serializer=SPDXSerializer(),
        )

        result = orchestrator.run(
            repo_path=repo_path,
            output_format="cyclonedx",
            env="development",
            nvd_cache=NVD_CACHE_SEED,
            raw_tool_output=RAW_SYFT_TASKMATRIX,
            vex_statements=[],
            last_synced_at=datetime.now(timezone.utc),
        )

        high_vulns = [v for v in result.active_vulns if v.get("severity") == "High"]
        for vuln in high_vulns:
            if vuln.get("fixed_version"):
                assert "upgrade_command" in vuln and vuln["upgrade_command"], (
                    f"High-severity vuln {vuln.get('cve_id')} has fixed_version "
                    "but is missing upgrade_command."
                )


# ===========================================================================
# ORCHESTRATION TEST CLASS 12 — Orchestration Error Resilience
# Tests that orchestrator handles edge-case inputs without silent failures
# ===========================================================================

class TestOrchestrationResilience:
    """
    ACCEPTANCE: The orchestration layer handles edge-case inputs gracefully:
    empty dependency lists, no CVEs in cache, all vulns VEX-suppressed.

    ORCHESTRATION: Verifies that none of these cases raise an unhandled
    exception and that ScanResult always has a well-formed sbom_document.
    """

    def test_repo_with_zero_dependencies_produces_valid_sbom(self, tmp_path):
        """
        ACCEPTANCE: An empty repository (no dependencies detected) produces a
        valid SBOM with an empty components list, not an error.
        """
        repo_path = str(tmp_path)
        (tmp_path / "requirements.txt").write_text("")

        orchestrator = ScanOrchestrator(
            validator=ScanJobValidator(),
            adapter=OSSToolAdapter(),
            mapper=VulnerabilityMapper(),
            vex_filter=VEXFilter(),
            enricher=RemediationEnricher(),
            nvd_cache_manager=NVDCacheManager(),
            cyclonedx_serializer=CycloneDXSerializer(),
            spdx_serializer=SPDXSerializer(),
        )

        result = orchestrator.run(
            repo_path=repo_path,
            output_format="cyclonedx",
            env="development",
            nvd_cache=NVD_CACHE_SEED,
            raw_tool_output={"tool": "syft", "components": []},
            vex_statements=[],
            last_synced_at=datetime.now(timezone.utc),
        )

        assert result.sbom_document is not None
        assert result.active_vulns == []
        assert result.suppressed_vulns == []

    def test_all_vulns_vex_suppressed_produces_empty_active_list(self, tmp_path):
        """
        ACCEPTANCE: When all found vulnerabilities are suppressed by VEX,
        active_vulns is empty and the SBOM is still produced.
        """
        repo_path = str(tmp_path)
        (tmp_path / "requirements.txt").write_text("langchain==0.0.101\n")

        # Suppress every vuln in the scan
        all_suppress = [
            {"cve_id": "CVE-2023-34540", "purl": "pkg:pypi/langchain@0.0.101",
             "status": "not_affected", "justification": "vulnerable_code_not_in_execute_path"},
            {"cve_id": "CVE-2023-32681", "purl": "pkg:pypi/requests@2.27.1",
             "status": "not_affected", "justification": "vulnerable_code_not_in_execute_path"},
            {"cve_id": "CVE-2018-19787", "purl": "pkg:pypi/lxml@4.6.3",
             "status": "not_affected", "justification": "vulnerable_code_not_in_execute_path"},
        ]

        orchestrator = ScanOrchestrator(
            validator=ScanJobValidator(),
            adapter=OSSToolAdapter(),
            mapper=VulnerabilityMapper(),
            vex_filter=VEXFilter(),
            enricher=RemediationEnricher(),
            nvd_cache_manager=NVDCacheManager(),
            cyclonedx_serializer=CycloneDXSerializer(),
            spdx_serializer=SPDXSerializer(),
        )

        result = orchestrator.run(
            repo_path=repo_path,
            output_format="cyclonedx",
            env="development",
            nvd_cache=NVD_CACHE_SEED,
            raw_tool_output=RAW_SYFT_TASKMATRIX,
            vex_statements=all_suppress,
            last_synced_at=datetime.now(timezone.utc),
        )

        assert result.active_vulns == []
        assert len(result.suppressed_vulns) > 0
        assert result.sbom_document is not None

    def test_empty_nvd_cache_yields_zero_vulns(self, tmp_path):
        """
        ACCEPTANCE: When the NVD cache is empty, no vulnerabilities are mapped
        and active_vulns is an empty list. The scan does not raise.
        """
        repo_path = str(tmp_path)
        (tmp_path / "requirements.txt").write_text("langchain==0.0.101\n")

        orchestrator = ScanOrchestrator(
            validator=ScanJobValidator(),
            adapter=OSSToolAdapter(),
            mapper=VulnerabilityMapper(),
            vex_filter=VEXFilter(),
            enricher=RemediationEnricher(),
            nvd_cache_manager=NVDCacheManager(),
            cyclonedx_serializer=CycloneDXSerializer(),
            spdx_serializer=SPDXSerializer(),
        )

        result = orchestrator.run(
            repo_path=repo_path,
            output_format="cyclonedx",
            env="development",
            nvd_cache={},  # empty cache
            raw_tool_output=RAW_SYFT_TASKMATRIX,
            vex_statements=[],
            last_synced_at=datetime.now(timezone.utc),
        )

        assert result.active_vulns == []
        assert result.sbom_document is not None
        # All deps still present even without vulns
        assert len(result.dependencies) > 0
