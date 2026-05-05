"""
Auto-generated from step7_5_api_contract.yaml — DO NOT EDIT

Pydantic v2 request/response models for the SBOM POC Tool API.
Session: SBOM-20260409-sb01

Traceability:
  - Schemas derived from step7_5_api_contract.yaml components/schemas
  - Field names and types match step9_tdd_green_phase_orchestration.py (ScanResult, SyncResult)
  - Enum values match step6_tdd_green_phase.py (ScanJobValidator, CVSSSeverityClassifier)
  - Example values derived from step1b_mock_entities.json
"""

from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, ConfigDict, Field


# ---------------------------------------------------------------------------
# Enumerations
# ---------------------------------------------------------------------------


class SbomFormat(str, Enum):
    """Output format for the generated SBOM document."""
    cyclonedx = "cyclonedx"
    spdx = "spdx"


class Environment(str, Enum):
    """Runtime environment context for the scanned repository."""
    development = "development"
    staging = "staging"
    production = "production"


class Severity(str, Enum):
    """
    CVSS v3.1 severity band.
    High: score >= 7.0 | Medium: 4.0–6.9 | Low: < 4.0 | Unknown: score absent.
    """
    High = "High"
    Medium = "Medium"
    Low = "Low"
    Unknown = "Unknown"


class DependencyType(str, Enum):
    """Whether the dependency is directly declared or pulled transitively."""
    direct = "direct"
    transitive = "transitive"


class VexStatus(str, Enum):
    """OpenVEX exploitability status values."""
    not_affected = "not_affected"
    affected = "affected"
    fixed = "fixed"
    under_investigation = "under_investigation"


class HealthStatus(str, Enum):
    """Overall service health status."""
    ok = "ok"
    degraded = "degraded"
    down = "down"


# ---------------------------------------------------------------------------
# Component-level schemas (reusable entity models)
# ---------------------------------------------------------------------------


class DependencyRecord(BaseModel):
    """
    A single discovered dependency (direct or transitive).
    Maps to DependencyRecord dataclass in step6_tdd_green_phase.py.
    """
    model_config = ConfigDict(populate_by_name=True)

    name: str = Field(
        ...,
        description="Package name as it appears in the package registry",
        examples=["langchain"],
    )
    version: str = Field(
        ...,
        description="Exact installed version",
        examples=["0.0.101"],
    )
    purl: str = Field(
        ...,
        description=(
            "**PURL** (Package URL) in `pkg:ecosystem/name@version` format. "
            "Modern, ecosystem-aware package identifier used as the primary "
            "key when mapping this dependency against **NVD** "
            "(National Vulnerability Database, NIST) **CVE** "
            "(Common Vulnerabilities and Exposures) records (POC Req 5)."
        ),
        examples=["pkg:pypi/langchain@0.0.101"],
    )
    cpe: Optional[str] = Field(
        default=None,
        description=(
            "**CPE** (Common Platform Enumeration) identifier — NIST's native "
            "vulnerability identifier format, used as the fallback match when "
            "PURL lookup misses (POC Req 5)."
        ),
        examples=["cpe:2.3:a:langchain:langchain:0.0.101:*:*:*:*:python:*:*"],
    )
    supplier: Optional[str] = Field(
        default=None,
        description="Package maintainer or organization (POC Req 3 — supplier attribution).",
        examples=["LangChain, Inc."],
    )
    dependency_type: DependencyType = Field(
        ...,
        description=(
            "`direct` if declared in this repository's manifest, `transitive` if "
            "pulled in by another dependency (POC Req 3 — direct + transitive mapping)."
        ),
    )
    transitive_via: Optional[str] = Field(
        default=None,
        description="For transitive deps, the direct dependency that introduced this one.",
        examples=["langchain"],
    )


class VulnerabilityRecord(BaseModel):
    """
    A vulnerability matched against a dependency from the local NVD cache.
    Maps to vulnerability dict shape in step6_tdd_green_phase.py (VulnerabilityMapper).
    """
    model_config = ConfigDict(populate_by_name=True)

    cve_id: str = Field(
        ...,
        description=(
            "**CVE** (Common Vulnerabilities and Exposures) ID — the globally "
            "unique catalog entry for this security flaw, issued by MITRE."
        ),
        examples=["CVE-2023-34540"],
    )
    purl: str = Field(
        ...,
        description="**PURL** (Package URL) of the affected package.",
        examples=["pkg:pypi/langchain@0.0.101"],
    )
    cpe: Optional[str] = Field(
        default=None,
        description="**CPE** (Common Platform Enumeration) identifier of the affected package.",
        examples=["cpe:2.3:a:langchain:langchain:0.0.101:*:*:*:*:python:*:*"],
    )
    cvss_score: float = Field(
        ...,
        ge=0.0,
        le=10.0,
        description=(
            "**CVSS** (Common Vulnerability Scoring System) v3.1 base score, "
            "0.0–10.0. Higher = more severe (POC Req 6)."
        ),
        examples=[9.8],
    )
    severity: Severity = Field(
        ...,
        description=(
            "Severity band derived from the CVSS score (POC Req 6 — High / "
            "Medium / Low classification): Critical (≥ 9.0), High (7.0–8.9), "
            "Medium (4.0–6.9), Low (< 4.0)."
        ),
    )
    affected_version: Optional[str] = Field(
        default=None,
        description="Version range or exact version that is affected",
        examples=["0.0.101"],
    )
    fixed_version: Optional[str] = Field(
        default=None,
        description=(
            "First package version that resolves this CVE. The remediation "
            "recommendation per POC Req 6."
        ),
        examples=["0.0.247"],
    )
    advisory_url: Optional[str] = Field(
        default=None,
        description="Link to the NVD advisory or vendor security advisory (POC Req 6).",
        examples=["https://nvd.nist.gov/vuln/detail/CVE-2023-34540"],
    )


class EnrichedVulnerability(VulnerabilityRecord):
    """
    A vulnerability enriched by RemediationEnricher.
    Adds upgrade_command and vex_filtered to the base VulnerabilityRecord.
    Maps to enriched vuln dicts in step9_tdd_green_phase_orchestration.py (ScanOrchestrator.run).
    """
    upgrade_command: Optional[str] = Field(
        default=None,
        description=(
            "Ready-to-run package manager command that installs the fixed "
            "version (POC Req 6 — actionable remediation)."
        ),
        examples=["pip install langchain==0.0.247"],
    )
    vex_filtered: bool = Field(
        default=False,
        description="True if this vulnerability was suppressed by a VEX statement",
    )


class VexStatement(BaseModel):
    """
    An OpenVEX statement declaring exploitability status for a CVE/package pair.
    Maps to VEX_SUPPRESS_LANGCHAIN fixture in step7_atdd_orchestration.py.
    """
    model_config = ConfigDict(populate_by_name=True)

    cve_id: str = Field(
        ...,
        description="CVE identifier this statement applies to",
        examples=["CVE-2023-34540"],
    )
    purl: str = Field(
        ...,
        description="PURL of the package this statement covers",
        examples=["pkg:pypi/langchain@0.0.101"],
    )
    status: VexStatus = Field(
        ...,
        description="OpenVEX exploitability status",
    )
    justification: Optional[str] = Field(
        default=None,
        description="OpenVEX justification for the status assessment",
        examples=["vulnerable_code_not_in_execute_path"],
    )


# ---------------------------------------------------------------------------
# Request models
# ---------------------------------------------------------------------------


class ScanRequest(BaseModel):
    """
    Request body for POST /scans.
    Specifies the repository to scan, the SBOM output format, the runtime
    environment, and any optional VEX statements to apply.
    """
    model_config = ConfigDict(
        populate_by_name=True,
        json_schema_extra={
            "example": {
                "repo_path": "/Users/ajith/Code/demo-repos/handson-ml-fixture",
                "format": "cyclonedx",
                "env": "development",
                "vex_statements": [
                    {
                        "cve_id": "CVE-2022-21797",
                        "purl": "pkg:pypi/joblib@0.14.1",
                        "status": "not_affected",
                        "justification": "vulnerable_code_not_in_execute_path",
                    }
                ],
            }
        },
    )

    repo_path: str = Field(
        ...,
        description=(
            "Absolute or relative filesystem path to the repository to scan. "
            "The path must exist on the server. Must not be empty."
        ),
        examples=["/Users/ajith/Code/demo-repos/handson-ml-fixture"],
    )
    format: SbomFormat = Field(
        ...,
        description=(
            "SBOM output format (POC Req 4). `cyclonedx` produces CycloneDX 1.4 "
            "with vulnerabilities[] inline; `spdx` produces SPDX 2.3 with "
            "PURL+CPE refs per package."
        ),
    )
    env: Environment = Field(
        ...,
        description=(
            "Runtime environment for this scan (POC Req 2 — single-environment "
            "discovery and reporting per scan)."
        ),
    )
    vex_statements: List[VexStatement] = Field(
        default_factory=list,
        description="Optional list of OpenVEX statements to apply before enrichment",
    )


class SyncRequest(BaseModel):
    """
    Request body for POST /sync.
    Maps to source_path parameter of NVDSyncOrchestrator.run() in step9_tdd_green_phase_orchestration.py.
    """
    model_config = ConfigDict(populate_by_name=True)

    source_path: str = Field(
        ...,
        description=(
            "Filesystem path to an NVD feed JSON or Grype vulnerability DB to "
            "sync from. The cache is the only source of truth for vulnerability "
            "lookup at scan time (POC Req 7)."
        ),
        examples=["/Users/ajith/Code/agent-for-agent/outputs/sessions/SBOM-20260409-sb01/sample_nvd_feed.json"],
    )


# ---------------------------------------------------------------------------
# Response models
# ---------------------------------------------------------------------------


class ScanResponse(BaseModel):
    """
    Response body for POST /scans and GET /scans/{scan_id}.
    Carries the full SBOM, dependency inventory, and CVE matches for a scan.
    """
    model_config = ConfigDict(
        populate_by_name=True,
        json_schema_extra={
            "example": {
                "scan_id": "82adcf4e-429a-4dbc-8b10-8b3ab03b2dd6",
                "repo_name": "handson-ml-fixture",
                "output_format": "cyclonedx",
                "dependencies": [
                    {
                        "name": "joblib",
                        "version": "0.14.1",
                        "purl": "pkg:pypi/joblib@0.14.1",
                        "cpe": "cpe:2.3:a:python:joblib:0.14.1:*:*:*:*:*:*:*",
                        "supplier": "PyPI",
                        "dependency_type": "direct",
                        "transitive_via": None,
                    },
                    {
                        "name": "tensorflow",
                        "version": "1.15.5",
                        "purl": "pkg:pypi/tensorflow@1.15.5",
                        "cpe": "cpe:2.3:a:google:tensorflow:1.15.5:*:*:*:*:*:*:*",
                        "supplier": "PyPI",
                        "dependency_type": "direct",
                        "transitive_via": None,
                    },
                ],
                "active_vulns": [
                    {
                        "cve_id": "CVE-2022-21797",
                        "purl": "pkg:pypi/joblib@0.14.1",
                        "cpe": "cpe:2.3:a:python:joblib:0.14.1:*:*:*:*:*:*:*",
                        "cvss_score": 9.8,
                        "severity": "High",
                        "affected_version": "< 1.2.0",
                        "fixed_version": "1.2.0",
                        "advisory_url": "https://nvd.nist.gov/vuln/detail/CVE-2022-21797",
                        "upgrade_command": "pip install joblib==1.2.0",
                        "vex_filtered": False,
                    },
                    {
                        "cve_id": "CVE-2022-29216",
                        "purl": "pkg:pypi/tensorflow@1.15.5",
                        "cpe": "cpe:2.3:a:google:tensorflow:1.15.5:*:*:*:*:*:*:*",
                        "cvss_score": 8.8,
                        "severity": "High",
                        "affected_version": "< 2.9.0",
                        "fixed_version": "2.9.0",
                        "advisory_url": "https://nvd.nist.gov/vuln/detail/CVE-2022-29216",
                        "upgrade_command": "pip install tensorflow==2.9.0",
                        "vex_filtered": False,
                    },
                ],
                "suppressed_vulns": [],
                "warnings": [
                    "NVD cache is stale (last synced: 2026-04-10T13:15:46+00:00). Please run sbom-tool sync to refresh vulnerability data."
                ],
                "sbom_document": {
                    "bomFormat": "CycloneDX",
                    "specVersion": "1.4",
                    "serialNumber": "urn:uuid:82adcf4e-429a-4dbc-8b10-8b3ab03b2dd6",
                    "version": 1,
                    "metadata": {
                        "timestamp": "2026-05-05T13:15:46Z",
                        "tools": [{"vendor": "SBOM POC", "name": "sbom-tool", "version": "1.0.0"}],
                    },
                    "components": [
                        {
                            "type": "library",
                            "name": "joblib",
                            "version": "0.14.1",
                            "purl": "pkg:pypi/joblib@0.14.1",
                            "supplier": {"name": "PyPI"},
                        }
                    ],
                    "vulnerabilities": [
                        {
                            "id": "CVE-2022-21797",
                            "ratings": [{"score": 9.8, "severity": "high", "method": "CVSSv31"}],
                            "affects": [{"ref": "pkg:pypi/joblib@0.14.1"}],
                            "advisories": [{"url": "https://nvd.nist.gov/vuln/detail/CVE-2022-21797"}],
                            "recommendation": "Upgrade to 1.2.0",
                        }
                    ],
                },
                "workflow_states_visited": [
                    "idle",
                    "scanning_dependencies",
                    "deduplicating_output",
                    "matching_vulnerabilities",
                    "filtering_vex",
                    "enriching_remediation",
                    "exporting_sbom",
                ],
            }
        },
    )

    scan_id: str = Field(
        ...,
        description="UUID identifying this scan run",
        examples=["a1b2c3d4-e5f6-7890-abcd-ef1234567890"],
    )
    repo_name: str = Field(
        ...,
        description="Basename of the scanned repository path",
        examples=["TaskMatrix"],
    )
    output_format: SbomFormat = Field(
        ...,
        description="SBOM format that was produced",
    )
    dependencies: List[DependencyRecord] = Field(
        ...,
        description=(
            "Full dependency inventory (POC Req 3): every component with name, "
            "exact version, supplier, and direct/transitive marker. Deduplicated."
        ),
    )
    active_vulns: List[EnrichedVulnerability] = Field(
        ...,
        description=(
            "CVEs matched against this repository's dependencies (POC Reqs 5 & 6). "
            "Each entry carries CVSS score, severity band (High / Medium / Low), "
            "fixed_version, advisory URL, and an upgrade command. Excludes any "
            "CVE suppressed by a VEX statement."
        ),
    )
    suppressed_vulns: List[VulnerabilityRecord] = Field(
        ...,
        description=(
            "CVEs suppressed by a matching **VEX** (Vulnerability Exploitability "
            "eXchange) statement — vulnerabilities that exist in the code but "
            "are flagged as not exploitable (e.g. `not_affected` because the "
            "vulnerable code path is never reached)."
        ),
    )
    warnings: List[str] = Field(
        ...,
        description=(
            "Non-fatal warnings. Includes a stale-cache notice when the NVD "
            "cache is older than 7 days (POC Req 7)."
        ),
    )
    sbom_document: Dict[str, Any] = Field(
        ...,
        description=(
            "Machine-readable **SBOM** (Software Bill of Materials) document "
            "(POC Req 4). CycloneDX 1.4 or **SPDX** (Software Package Data "
            "Exchange) 2.3 JSON depending on `output_format`. Downloadable "
            "as-is for ingestion by other SBOM-aware tools."
        ),
    )
    workflow_states_visited: List[str] = Field(
        ...,
        description="Ordered list of scan workflow state values traversed during this scan",
        examples=[
            [
                "idle",
                "scanning_dependencies",
                "deduplicating_output",
                "matching_vulnerabilities",
                "filtering_vex",
                "enriching_remediation",
                "exporting_sbom",
            ]
        ],
    )


class SyncResponse(BaseModel):
    """
    Response body for POST /sync.
    Maps directly to SyncResult dataclass in step9_tdd_green_phase_orchestration.py.
    """
    model_config = ConfigDict(populate_by_name=True)

    records_added: int = Field(
        ...,
        ge=0,
        description="Number of new vulnerability records inserted into the local cache",
        examples=[1247],
    )
    records_updated: int = Field(
        ...,
        ge=0,
        description="Number of existing vulnerability records refreshed",
        examples=[83],
    )
    synced_at: str = Field(
        ...,
        description="ISO 8601 timestamp of when the sync completed",
        examples=["2026-04-09T10:00:00Z"],
    )
    source_path: str = Field(
        ...,
        description="Filesystem path of the source Grype DB that was synced",
        examples=["/var/grype/db/vulnerability.db"],
    )
    sync_log: Optional[Dict[str, Any]] = Field(
        default=None,
        description="Optional internal sync log with per-source statistics",
    )


class CacheStatusResponse(BaseModel):
    """
    Response body for GET /cache/status.
    Derived from NVDCacheManager.is_stale() and StalenessResult in step6_tdd_green_phase.py.
    """
    model_config = ConfigDict(populate_by_name=True)

    last_synced_at: Optional[str] = Field(
        default=None,
        description="ISO 8601 timestamp of the most recent successful NVD sync. Null if never synced.",
        examples=["2026-04-09T10:00:00Z"],
    )
    age_days: Optional[float] = Field(
        default=None,
        description="Age of the cache in days since last sync. Null if never synced.",
        examples=[0.0],
    )
    is_stale: bool = Field(
        ...,
        description="True if cache age exceeds 7 days or has never been synced",
    )
    record_count: int = Field(
        ...,
        ge=0,
        description="Total number of vulnerability records in the local NVD cache",
        examples=[82451],
    )


class HealthResponse(BaseModel):
    """
    Response body for GET /health.
    """
    model_config = ConfigDict(populate_by_name=True)

    status: HealthStatus = Field(
        ...,
        description="Overall service health status",
    )
    version: str = Field(
        ...,
        description="Deployed application version",
        examples=["1.0.0"],
    )
    cache_status: Optional[CacheStatusResponse] = Field(
        default=None,
        description="Current NVD cache health summary",
    )


class ErrorResponse(BaseModel):
    """
    Unified error response for all 4xx and 5xx responses.
    """
    model_config = ConfigDict(populate_by_name=True)

    error: str = Field(
        ...,
        description="Machine-readable error code",
        examples=["INVALID_REPO_PATH"],
    )
    message: str = Field(
        ...,
        description="Human-readable error description",
        examples=["Repository path does not exist: '/repos/missing'"],
    )
    details: Optional[Dict[str, Any]] = Field(
        default=None,
        description="Optional structured context (field name, received value, etc.)",
    )


# ---------------------------------------------------------------------------
# Export list
# ---------------------------------------------------------------------------

__all__ = [
    # Enums
    "SbomFormat",
    "Environment",
    "Severity",
    "DependencyType",
    "VexStatus",
    "HealthStatus",
    # Component schemas
    "DependencyRecord",
    "VulnerabilityRecord",
    "EnrichedVulnerability",
    "VexStatement",
    # Requests
    "ScanRequest",
    "SyncRequest",
    # Responses
    "ScanResponse",
    "SyncResponse",
    "CacheStatusResponse",
    "HealthResponse",
    "ErrorResponse",
]
