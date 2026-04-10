# SBOM POC Tool — API Contract Summary

**Session:** SBOM-20260409-sb01
**Step:** 7.5 — API Contract Generation
**Generated:** 2026-04-09
**Pipeline source:** backend (Step 7 orchestration ATDD complete)
**Contract version:** 1.0.0

---

## Overview

This contract formalizes the REST API surface of the SBOM POC Tool. It is extracted faithfully from the Step 7 orchestration acceptance tests and Step 9 implementation — it does not introduce new behavior.

The API exposes two orchestration workflows:
1. **Scan workflow** — dependency discovery → vulnerability mapping → VEX filtering → enrichment → SBOM export
2. **NVD sync workflow** — ingest a local Grype database into the SQLite NVD cache

All vulnerability lookups use the local NVD cache. Zero live NVD API calls occur at scan time (AC-12).

---

## Base URL

```
{protocol}://{host}:{port}/api/v1
```

Default: `http://localhost:8000/api/v1`

---

## Endpoints

| Method | Path | Operation ID | Tag | Description |
|--------|------|-------------|-----|-------------|
| POST | `/scans` | `createScan` | business-logic | Trigger a full SBOM scan pipeline |
| GET | `/scans/{scan_id}` | `getScan` | business-logic | Retrieve a stored scan result by ID |
| POST | `/sync` | `syncNvdCache` | orchestration | Sync local NVD cache from a Grype DB file |
| GET | `/cache/status` | `getCacheStatus` | workflow-state | Get NVD cache staleness and record count |
| GET | `/health` | `getHealth` | workflow-state | Service liveness and readiness probe |

---

## POST /scans

**Request body:**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `repo_path` | string | Yes | Filesystem path to the repository. Must exist on the server. |
| `format` | `cyclonedx` \| `spdx` | Yes | SBOM output format |
| `env` | `development` \| `staging` \| `production` | Yes | Runtime environment context |
| `vex_statements` | VexStatement[] | No | OpenVEX suppression statements applied before enrichment |

**Response (200):** `ScanResponse`

| Field | Type | Description |
|-------|------|-------------|
| `scan_id` | string (UUID) | Unique identifier for this scan run |
| `repo_name` | string | Basename of the scanned repo path |
| `output_format` | SbomFormat | Format that was produced |
| `dependencies` | DependencyRecord[] | All deduplicated discovered dependencies |
| `active_vulns` | EnrichedVulnerability[] | Vulnerabilities enriched with remediation, not suppressed by VEX |
| `suppressed_vulns` | VulnerabilityRecord[] | Vulnerabilities suppressed by a VEX statement |
| `warnings` | string[] | Non-fatal notices (e.g., stale NVD cache). Non-empty does NOT mean failure. |
| `sbom_document` | object | CycloneDX 1.4 or SPDX 2.3 JSON document |
| `workflow_states_visited` | string[] | Ordered scan state machine trace |

**Error responses:**

| Status | Trigger |
|--------|---------|
| 422 | Invalid or missing `repo_path`, unsupported `format` or `env` |
| 500 | Unexpected internal pipeline failure |

**Important:** A stale NVD cache (age > 7 days) returns HTTP 200 with a warning in `warnings[]`, not an error. The scan always completes. This matches AC-3.

---

## GET /scans/{scan_id}

Returns a stored `ScanResponse` by UUID. Requires the scan to have been completed and persisted via `POST /scans`.

**Error responses:** 404 if not found, 500 on internal error.

---

## POST /sync

**Request body:**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `source_path` | string | Yes | Path to a Grype vulnerability database file on the server filesystem |

**Response (200):** `SyncResponse`

| Field | Type | Description |
|-------|------|-------------|
| `records_added` | integer | New NVD records inserted |
| `records_updated` | integer | Existing NVD records refreshed |
| `synced_at` | string (ISO 8601) | Timestamp of sync completion |
| `source_path` | string | Source DB path that was ingested |
| `sync_log` | object \| null | Internal statistics |

**Error responses:**

| Status | Trigger |
|--------|---------|
| 404 | `source_path` not found on the server (maps to `NVDSyncError`) |
| 500 | Unexpected failure (e.g., corrupt database file) |

---

## GET /cache/status

Returns current NVD cache health.

**Response (200):** `CacheStatusResponse`

| Field | Type | Description |
|-------|------|-------------|
| `last_synced_at` | string \| null | ISO 8601 of last successful sync. Null if never synced. |
| `age_days` | number \| null | Days since last sync. Null if never synced. |
| `is_stale` | boolean | True if age > 7 days or never synced |
| `record_count` | integer | Total vulnerability records in cache |

---

## GET /health

Returns service liveness status.

**Response (200):** `HealthResponse`

| Field | Type | Description |
|-------|------|-------------|
| `status` | `ok` \| `degraded` \| `down` | Overall service health |
| `version` | string | Deployed version |
| `cache_status` | CacheStatusResponse | NVD cache health summary |

---

## Data Models

### DependencyRecord

Represents a single dependency found in the scanned repository.

```
name           string           Package name (e.g. "langchain")
version        string           Exact version (e.g. "0.0.101")
purl           string           PURL (e.g. "pkg:pypi/langchain@0.0.101")
cpe            string | null    CPE identifier (optional)
supplier       string | null    Package maintainer
dependency_type direct|transitive
transitive_via string | null    Parent dependency name (for transitive deps)
```

### VulnerabilityRecord

Matched from the local NVD SQLite cache by PURL or CPE.

```
cve_id          string          e.g. "CVE-2023-34540"
purl            string          e.g. "pkg:pypi/langchain@0.0.101"
cpe             string | null
cvss_score      float           0.0–10.0
severity        High|Medium|Low|Unknown
affected_version string | null
fixed_version   string | null   e.g. "0.0.247"
advisory_url    string | null   e.g. "https://nvd.nist.gov/vuln/detail/CVE-2023-34540"
```

### EnrichedVulnerability

Extends `VulnerabilityRecord` with enrichment from `RemediationEnricher`.

```
+ upgrade_command  string | null  e.g. "pip install langchain==0.0.247"
+ vex_filtered     boolean        true if suppressed by VEX
```

### VexStatement

OpenVEX suppression statement applied before enrichment.

```
cve_id        string
purl          string
status        not_affected|affected|fixed|under_investigation
justification string | null   e.g. "vulnerable_code_not_in_execute_path"
```

---

## Error Response Shape

All error responses use a single schema:

```json
{
  "error": "INVALID_REPO_PATH",
  "message": "Repository path does not exist: '/repos/missing'",
  "details": {
    "field": "repo_path",
    "received": "/repos/missing"
  }
}
```

---

## Known Error Codes

| Code | HTTP Status | Source |
|------|------------|--------|
| `INVALID_REPO_PATH` | 422 | ScanJobValidator: empty or missing path |
| `UNSUPPORTED_FORMAT` | 422 | ScanOrchestrator: format not cyclonedx or spdx |
| `INVALID_ENVIRONMENT` | 422 | ScanJobValidator: env not in allowed set |
| `SCAN_NOT_FOUND` | 404 | GET /scans/{scan_id}: no matching record |
| `NVD_SOURCE_NOT_FOUND` | 404 | NVDSyncError: source_path not found |
| `NVD_SYNC_FAILED` | 500 | Unexpected failure in NVDCacheManager.sync() |
| `INTERNAL_ERROR` | 500 | Unhandled exception in scan or health pipeline |

---

## Authentication

A `bearerAuth` (JWT) security scheme is defined in the OpenAPI spec as a placeholder. Authentication is **not enforced in the POC scope** (per SBOM_POC_Scope.md Out of Scope: RBAC). The scheme is present to support future Phase 2 Governance Layer requirements.

---

## SBOM Format Notes

**CycloneDX 1.4** response includes: `bomFormat`, `specVersion`, `serialNumber`, `version`, `components[]`, `vulnerabilities[]`

**SPDX 2.3** response includes: `spdxVersion` ("SPDX-2.3"), `dataLicense` ("CC0-1.0"), `SPDXID`, `name`, `packages[]`, `relationships[]`

The `sbom_document` field in `ScanResponse` is typed as an open object (`additionalProperties: true`) to accommodate the full schema of either format without a fixed contract. Consumers should branch on `output_format` to interpret the document structure.

---

## Workflow State Sequence

Every `ScanResponse.workflow_states_visited` follows this mandatory order (WorkflowStateMachine in step9):

```
idle → scanning_dependencies → deduplicating_output →
matching_vulnerabilities → filtering_vex →
enriching_remediation → exporting_sbom
```

---

## Generated Artifacts

| File | Purpose |
|------|---------|
| `step7_5_api_contract.yaml` | OpenAPI 3.1.0 specification (YAML) |
| `step7_5_api_contract.json` | OpenAPI 3.1.0 specification (JSON) |
| `step7_5_pydantic_models.py` | Pydantic v2 request/response models |
| `step7_5_typescript_types.ts` | TypeScript types (components + paths namespaces) |
| `step7_5_contract_summary.md` | This document |
| `step7_5_contract_metadata.json` | Traceability metadata |

---

## Traceability Matrix

| Contract Element | Source Artifact |
|-----------------|----------------|
| POST /scans request/response shape | `step7_atdd_orchestration.py` AC-1, AC-2, AC-11 |
| Stale-cache warning behavior | `step7_atdd_orchestration.py` AC-3 |
| VEX suppression in scan response | `step7_atdd_orchestration.py` AC-4 |
| POST /sync request/response shape | `step7_atdd_orchestration.py` AC-6, `step9_tdd_green_phase_orchestration.py` NVDSyncOrchestrator |
| DependencyRecord fields | `step1b_mock_entities.json` DependencyInventory, `step6_tdd_green_phase.py` DependencyRecord |
| VulnerabilityRecord fields | `step1b_mock_entities.json` VulnerabilityRecord, `step6_tdd_green_phase.py` nvd_cache fixture |
| EnrichedVulnerability fields | `step6_tdd_green_phase.py` RemediationEnricher |
| Severity enum values | `step6_tdd_green_phase.py` CVSSSeverityClassifier (High/Medium/Low/Unknown) |
| CVSS threshold: High >= 7.0 | `step6_tdd_green_phase.py` CVSSSeverityClassifier docstring |
| Stale threshold: 7 days | `step7_atdd_orchestration.py` test_staleness_threshold_is_seven_days |
| NVDSyncError → 404 mapping | `step9_tdd_green_phase_orchestration.py` NVDSyncOrchestrator, `step6_tdd_green_phase.py` NVDSyncError |
| Workflow state sequence | `step9_tdd_green_phase_orchestration.py` WorkflowStateMachine._VALID_TRANSITIONS |
