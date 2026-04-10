/**
 * Auto-generated from step7_5_api_contract.yaml — DO NOT EDIT
 *
 * TypeScript types for the SBOM POC Tool API.
 * Session: SBOM-20260409-sb01
 *
 * Traceability:
 *   - Schemas derived from step7_5_api_contract.yaml components/schemas
 *   - Enum values match step6_tdd_green_phase.py (CVSSSeverityClassifier, ScanJobValidator)
 *   - Field shapes match step9_tdd_green_phase_orchestration.py (ScanResult, SyncResult)
 *   - Example values derived from step1b_mock_entities.json
 *
 * Usage:
 *   import type { Schemas, Paths } from './step7_5_typescript_types';
 *
 *   // Access a schema type:
 *   const dep: Schemas['DependencyRecord'] = { ... };
 *
 *   // Access a request/response type:
 *   const body: Paths['/scans']['post']['requestBody'] = { ... };
 */

// ---------------------------------------------------------------------------
// Enumerations
// ---------------------------------------------------------------------------

/** Output format for the generated SBOM document */
export type SbomFormat = 'cyclonedx' | 'spdx';

/** Runtime environment context for the scanned repository */
export type Environment = 'development' | 'staging' | 'production';

/**
 * CVSS v3.1 severity band.
 * High: score >= 7.0 | Medium: 4.0–6.9 | Low: < 4.0 | Unknown: score absent
 */
export type Severity = 'High' | 'Medium' | 'Low' | 'Unknown';

/** Whether the dependency is directly declared or pulled transitively */
export type DependencyType = 'direct' | 'transitive';

/** OpenVEX exploitability status values */
export type VexStatus = 'not_affected' | 'affected' | 'fixed' | 'under_investigation';

/** Overall service health status */
export type HealthStatus = 'ok' | 'degraded' | 'down';

// ---------------------------------------------------------------------------
// Namespace: components
// Mirrors OpenAPI components/schemas — use $ref paths as type accessors
// ---------------------------------------------------------------------------

export namespace components {
  export namespace schemas {

    /**
     * A single discovered dependency (direct or transitive).
     * Maps to DependencyRecord in step6_tdd_green_phase.py.
     */
    export interface DependencyRecord {
      /** Package name as it appears in the package registry. Example: "langchain" */
      name: string;
      /** Exact installed version. Example: "0.0.101" */
      version: string;
      /** Package URL (PURL) in pkg:ecosystem/name@version format. Example: "pkg:pypi/langchain@0.0.101" */
      purl: string;
      /** Common Platform Enumeration identifier. May be null for some packages. */
      cpe?: string | null;
      /** Package maintainer or organization. Example: "LangChain, Inc." */
      supplier?: string | null;
      /** Whether the dependency is direct or transitive */
      dependency_type: DependencyType;
      /** Name of the direct dependency that introduced this transitive dependency. Null for direct deps. */
      transitive_via?: string | null;
    }

    /**
     * A vulnerability matched against a dependency from the local NVD cache.
     * Maps to vulnerability dicts produced by VulnerabilityMapper in step6_tdd_green_phase.py.
     */
    export interface VulnerabilityRecord {
      /** CVE identifier. Example: "CVE-2023-34540" */
      cve_id: string;
      /** PURL of the affected package. Example: "pkg:pypi/langchain@0.0.101" */
      purl: string;
      /** CPE identifier of the affected package. May be null. */
      cpe?: string | null;
      /** CVSS v3.1 base score (0.0–10.0). Example: 9.8 */
      cvss_score: number;
      /** CVSS severity band derived from the score */
      severity: Severity;
      /** Version range or exact version that is affected. May be null. */
      affected_version?: string | null;
      /** First version that resolves the vulnerability. May be null. */
      fixed_version?: string | null;
      /** Link to NVD advisory or vendor security advisory. May be null. */
      advisory_url?: string | null;
    }

    /**
     * A vulnerability enriched by RemediationEnricher.
     * Extends VulnerabilityRecord with upgrade_command and vex_filtered.
     * Maps to active_vulns items in ScanResult from step9_tdd_green_phase_orchestration.py.
     */
    export interface EnrichedVulnerability extends VulnerabilityRecord {
      /** Package manager upgrade command derived from fixed_version. Example: "pip install langchain==0.0.247" */
      upgrade_command?: string | null;
      /** True if this vulnerability was suppressed by a VEX statement */
      vex_filtered: boolean;
    }

    /**
     * An OpenVEX statement declaring exploitability status for a CVE/package pair.
     * Maps to VEX_SUPPRESS_LANGCHAIN fixture in step7_atdd_orchestration.py.
     */
    export interface VexStatement {
      /** CVE identifier this statement applies to. Example: "CVE-2023-34540" */
      cve_id: string;
      /** PURL of the package this statement covers. Example: "pkg:pypi/langchain@0.0.101" */
      purl: string;
      /** OpenVEX exploitability status */
      status: VexStatus;
      /** OpenVEX justification for the status assessment. May be null. */
      justification?: string | null;
    }

    /**
     * The serialized SBOM document.
     * CycloneDX 1.4 JSON (bomFormat, specVersion, components, vulnerabilities)
     * or SPDX 2.3 JSON (spdxVersion, dataLicense, packages, relationships).
     * Intentionally open to accommodate the full CycloneDX / SPDX schemas.
     */
    export type SbomDocument = Record<string, unknown>;

    // ------------------------------------------------------------------
    // Request schemas
    // ------------------------------------------------------------------

    /**
     * Request body for POST /scans.
     * Maps to ScanOrchestrator.run() parameters in step9_tdd_green_phase_orchestration.py.
     */
    export interface ScanRequest {
      /**
       * Absolute or relative filesystem path to the repository to scan.
       * Must exist on the server and must not be empty.
       * Example: "/repos/TaskMatrix"
       */
      repo_path: string;
      /** Output format for the generated SBOM document */
      format: SbomFormat;
      /** Runtime environment context for the scanned repository */
      env: Environment;
      /** Optional OpenVEX statements to apply before enrichment */
      vex_statements?: VexStatement[];
    }

    /**
     * Request body for POST /sync.
     * Maps to NVDSyncOrchestrator.run() source_path parameter.
     */
    export interface SyncRequest {
      /** Filesystem path to the Grype vulnerability database to sync from. Example: "/var/grype/db/vulnerability.db" */
      source_path: string;
    }

    // ------------------------------------------------------------------
    // Response schemas
    // ------------------------------------------------------------------

    /**
     * Response body for POST /scans and GET /scans/{scan_id}.
     * Maps directly to ScanResult dataclass in step9_tdd_green_phase_orchestration.py.
     */
    export interface ScanResponse {
      /** UUID identifying this scan run */
      scan_id: string;
      /** Basename of the scanned repository path. Example: "TaskMatrix" */
      repo_name: string;
      /** SBOM format that was produced */
      output_format: SbomFormat;
      /** All deduplicated dependencies discovered in the repository */
      dependencies: DependencyRecord[];
      /** Vulnerabilities not suppressed by VEX statements, enriched with remediation */
      active_vulns: EnrichedVulnerability[];
      /** Vulnerabilities suppressed by a matching VEX statement */
      suppressed_vulns: VulnerabilityRecord[];
      /**
       * Non-fatal warnings. Includes stale NVD cache notice when cache age > 7 days.
       * A non-empty warnings array does NOT indicate scan failure.
       */
      warnings: string[];
      /** Serialized SBOM document (CycloneDX 1.4 or SPDX 2.3) */
      sbom_document: SbomDocument;
      /** Ordered list of scan workflow state values traversed during this scan */
      workflow_states_visited: string[];
    }

    /**
     * Response body for POST /sync.
     * Maps directly to SyncResult dataclass in step9_tdd_green_phase_orchestration.py.
     */
    export interface SyncResponse {
      /** Number of new vulnerability records inserted into the local cache */
      records_added: number;
      /** Number of existing vulnerability records refreshed */
      records_updated: number;
      /** ISO 8601 timestamp of when the sync completed. Example: "2026-04-09T10:00:00Z" */
      synced_at: string;
      /** Filesystem path of the source Grype DB that was synced */
      source_path: string;
      /** Optional internal sync log with per-source statistics */
      sync_log?: Record<string, unknown> | null;
    }

    /**
     * Response body for GET /cache/status.
     * Derived from NVDCacheManager.is_stale() and StalenessResult in step6_tdd_green_phase.py.
     */
    export interface CacheStatusResponse {
      /** ISO 8601 timestamp of the most recent successful NVD sync. Null if never synced. */
      last_synced_at: string | null;
      /** Age of the cache in days since last sync. Null if never synced. */
      age_days: number | null;
      /** True if cache age exceeds 7 days or has never been synced */
      is_stale: boolean;
      /** Total number of vulnerability records in the local NVD cache */
      record_count: number;
    }

    /**
     * Response body for GET /health.
     */
    export interface HealthResponse {
      /** Overall service health status */
      status: HealthStatus;
      /** Deployed application version. Example: "1.0.0" */
      version: string;
      /** Current NVD cache health summary */
      cache_status?: CacheStatusResponse;
    }

    /**
     * Unified error response for all 4xx and 5xx responses.
     */
    export interface ErrorResponse {
      /** Machine-readable error code. Example: "INVALID_REPO_PATH" */
      error: string;
      /** Human-readable error description */
      message: string;
      /** Optional structured context (field name, received value, etc.) */
      details?: Record<string, unknown> | null;
    }

  }
}

// ---------------------------------------------------------------------------
// Namespace: paths
// Mirrors OpenAPI paths — typed request/response shapes per operation
// ---------------------------------------------------------------------------

export namespace paths {

  export namespace PostScans {
    export interface RequestBody {
      content: {
        'application/json': components['schemas']['ScanRequest'];
      };
    }
    export interface Responses {
      200: {
        content: {
          'application/json': components['schemas']['ScanResponse'];
        };
      };
      422: {
        content: {
          'application/json': components['schemas']['ErrorResponse'];
        };
      };
      500: {
        content: {
          'application/json': components['schemas']['ErrorResponse'];
        };
      };
    }
  }

  export namespace GetScans {
    export interface PathParams {
      scan_id: string;
    }
    export interface Responses {
      200: {
        content: {
          'application/json': components['schemas']['ScanResponse'];
        };
      };
      404: {
        content: {
          'application/json': components['schemas']['ErrorResponse'];
        };
      };
      500: {
        content: {
          'application/json': components['schemas']['ErrorResponse'];
        };
      };
    }
  }

  export namespace PostSync {
    export interface RequestBody {
      content: {
        'application/json': components['schemas']['SyncRequest'];
      };
    }
    export interface Responses {
      200: {
        content: {
          'application/json': components['schemas']['SyncResponse'];
        };
      };
      404: {
        content: {
          'application/json': components['schemas']['ErrorResponse'];
        };
      };
      500: {
        content: {
          'application/json': components['schemas']['ErrorResponse'];
        };
      };
    }
  }

  export namespace GetCacheStatus {
    export interface Responses {
      200: {
        content: {
          'application/json': components['schemas']['CacheStatusResponse'];
        };
      };
      500: {
        content: {
          'application/json': components['schemas']['ErrorResponse'];
        };
      };
    }
  }

  export namespace GetHealth {
    export interface Responses {
      200: {
        content: {
          'application/json': components['schemas']['HealthResponse'];
        };
      };
      500: {
        content: {
          'application/json': components['schemas']['ErrorResponse'];
        };
      };
    }
  }

}

// ---------------------------------------------------------------------------
// Convenience type aliases
// (Use these in application code rather than namespace paths for brevity)
// ---------------------------------------------------------------------------

export type Schemas = components['schemas'];

// Entity types
export type DependencyRecord     = Schemas['DependencyRecord'];
export type VulnerabilityRecord  = Schemas['VulnerabilityRecord'];
export type EnrichedVulnerability = Schemas['EnrichedVulnerability'];
export type VexStatement         = Schemas['VexStatement'];
export type SbomDocument         = Schemas['SbomDocument'];

// Request types
export type ScanRequest  = Schemas['ScanRequest'];
export type SyncRequest  = Schemas['SyncRequest'];

// Response types
export type ScanResponse        = Schemas['ScanResponse'];
export type SyncResponse        = Schemas['SyncResponse'];
export type CacheStatusResponse = Schemas['CacheStatusResponse'];
export type HealthResponse      = Schemas['HealthResponse'];
export type ErrorResponse       = Schemas['ErrorResponse'];
