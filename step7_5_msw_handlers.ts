/**
 * Auto-generated from step7_5_api_contract.yaml — DO NOT EDIT
 *
 * MSW v2 mock handlers for the SBOM POC Tool API.
 * Session: SBOM-20260409-sb01
 *
 * Usage (in test setup or browser DevTools):
 *   import { handlers } from './step7_5_msw_handlers';
 *   import { setupServer } from 'msw/node';
 *   const server = setupServer(...handlers);
 *
 * Mock fixtures are derived from step1b_mock_entities.json
 * (TaskMatrix scan_001, handson-ml scan_002, clean-api scan_003).
 */

import { http, HttpResponse } from 'msw';
import type {
  ScanResponse,
  SyncResponse,
  CacheStatusResponse,
  HealthResponse,
  ErrorResponse,
  DependencyRecord,
  EnrichedVulnerability,
} from './step7_5_typescript_types';

// ---------------------------------------------------------------------------
// Mock fixture data — derived from step1b_mock_entities.json
// ---------------------------------------------------------------------------

const mockDependencies: Record<string, DependencyRecord[]> = {
  scan_001: [
    {
      name: 'langchain',
      version: '0.0.101',
      purl: 'pkg:pypi/langchain@0.0.101',
      cpe: 'cpe:2.3:a:langchain:langchain:0.0.101:*:*:*:*:python:*:*',
      supplier: 'LangChain, Inc.',
      dependency_type: 'direct',
      transitive_via: null,
    },
    {
      name: 'requests',
      version: '2.27.1',
      purl: 'pkg:pypi/requests@2.27.1',
      cpe: 'cpe:2.3:a:python-requests:requests:2.27.1:*:*:*:*:python:*:*',
      supplier: 'Kenneth Reitz',
      dependency_type: 'transitive',
      transitive_via: 'langchain',
    },
    {
      name: 'lxml',
      version: '4.6.3',
      purl: 'pkg:pypi/lxml@4.6.3',
      cpe: 'cpe:2.3:a:lxml:lxml:4.6.3:*:*:*:*:python:*:*',
      supplier: 'lxml developers',
      dependency_type: 'transitive',
      transitive_via: 'langchain',
    },
  ],
  scan_002: [
    {
      name: 'numpy',
      version: '1.22.0',
      purl: 'pkg:pypi/numpy@1.22.0',
      cpe: 'cpe:2.3:a:numpy:numpy:1.22.0:*:*:*:*:python:*:*',
      supplier: 'NumPy Developers',
      dependency_type: 'direct',
      transitive_via: null,
    },
    {
      name: 'joblib',
      version: '0.14.1',
      purl: 'pkg:pypi/joblib@0.14.1',
      cpe: 'cpe:2.3:a:joblib:joblib:0.14.1:*:*:*:*:python:*:*',
      supplier: 'Gael Varoquaux',
      dependency_type: 'transitive',
      transitive_via: 'scikit-learn',
    },
  ],
  scan_003: [
    {
      name: 'flask',
      version: '3.0.0',
      purl: 'pkg:pypi/flask@3.0.0',
      cpe: 'cpe:2.3:a:palletsprojects:flask:3.0.0:*:*:*:*:python:*:*',
      supplier: 'Pallets',
      dependency_type: 'direct',
      transitive_via: null,
    },
  ],
};

const mockActiveVulns: Record<string, EnrichedVulnerability[]> = {
  scan_001: [
    {
      cve_id: 'CVE-2023-34540',
      purl: 'pkg:pypi/langchain@0.0.101',
      cpe: 'cpe:2.3:a:langchain:langchain:0.0.101:*:*:*:*:python:*:*',
      cvss_score: 9.8,
      severity: 'High',
      affected_version: '0.0.101',
      fixed_version: '0.0.247',
      advisory_url: 'https://nvd.nist.gov/vuln/detail/CVE-2023-34540',
      upgrade_command: 'pip install langchain==0.0.247',
      vex_filtered: false,
    },
    {
      cve_id: 'CVE-2023-32681',
      purl: 'pkg:pypi/requests@2.27.1',
      cpe: 'cpe:2.3:a:python-requests:requests:2.27.1:*:*:*:*:python:*:*',
      cvss_score: 6.1,
      severity: 'Medium',
      affected_version: '2.27.1',
      fixed_version: '2.31.0',
      advisory_url: 'https://nvd.nist.gov/vuln/detail/CVE-2023-32681',
      upgrade_command: 'pip install requests==2.31.0',
      vex_filtered: false,
    },
  ],
  scan_002: [
    {
      cve_id: 'CVE-2022-21797',
      purl: 'pkg:pypi/joblib@0.14.1',
      cpe: 'cpe:2.3:a:joblib:joblib:0.14.1:*:*:*:*:python:*:*',
      cvss_score: 9.8,
      severity: 'High',
      affected_version: '0.14.1',
      fixed_version: '1.2.0',
      advisory_url: 'https://nvd.nist.gov/vuln/detail/CVE-2022-21797',
      upgrade_command: 'pip install joblib==1.2.0',
      vex_filtered: false,
    },
    {
      cve_id: 'CVE-2021-33430',
      purl: 'pkg:pypi/numpy@1.22.0',
      cvss_score: 5.5,
      severity: 'Medium',
      affected_version: '1.22.0',
      fixed_version: '1.22.2',
      advisory_url: 'https://nvd.nist.gov/vuln/detail/CVE-2021-33430',
      upgrade_command: 'pip install numpy==1.22.2',
      vex_filtered: false,
    },
  ],
  scan_003: [],
};

const mockScanResults: Record<string, ScanResponse> = {
  scan_001: {
    scan_id: 'scan_001',
    repo_name: 'TaskMatrix',
    output_format: 'cyclonedx',
    dependencies: mockDependencies['scan_001'],
    active_vulns: mockActiveVulns['scan_001'],
    suppressed_vulns: [],
    warnings: [],
    sbom_document: {
      bomFormat: 'CycloneDX',
      specVersion: '1.4',
      serialNumber: 'urn:uuid:scan-001-mock-serial',
      version: 1,
      components: mockDependencies['scan_001'].map((d) => ({
        type: 'library',
        name: d.name,
        version: d.version,
        purl: d.purl,
      })),
      vulnerabilities: mockActiveVulns['scan_001'].map((v) => ({
        id: v.cve_id,
        ratings: [{ score: v.cvss_score, severity: v.severity.toLowerCase() }],
      })),
    },
    workflow_states_visited: [
      'idle',
      'scanning_dependencies',
      'deduplicating_output',
      'matching_vulnerabilities',
      'filtering_vex',
      'enriching_remediation',
      'exporting_sbom',
    ],
  },
  scan_002: {
    scan_id: 'scan_002',
    repo_name: 'handson-ml',
    output_format: 'spdx',
    dependencies: mockDependencies['scan_002'],
    active_vulns: mockActiveVulns['scan_002'],
    suppressed_vulns: [],
    warnings: [],
    sbom_document: {
      spdxVersion: 'SPDX-2.3',
      dataLicense: 'CC0-1.0',
      SPDXID: 'SPDXRef-DOCUMENT',
      name: 'handson-ml',
      packages: mockDependencies['scan_002'].map((d) => ({
        name: d.name,
        versionInfo: d.version,
        SPDXID: `SPDXRef-${d.name}`,
      })),
    },
    workflow_states_visited: [
      'idle',
      'scanning_dependencies',
      'deduplicating_output',
      'matching_vulnerabilities',
      'filtering_vex',
      'enriching_remediation',
      'exporting_sbom',
    ],
  },
  scan_003: {
    scan_id: 'scan_003',
    repo_name: 'clean-api',
    output_format: 'cyclonedx',
    dependencies: mockDependencies['scan_003'],
    active_vulns: [],
    suppressed_vulns: [],
    warnings: [],
    sbom_document: {
      bomFormat: 'CycloneDX',
      specVersion: '1.4',
      serialNumber: 'urn:uuid:scan-003-mock-serial',
      version: 1,
      components: mockDependencies['scan_003'].map((d) => ({
        type: 'library',
        name: d.name,
        version: d.version,
        purl: d.purl,
      })),
      vulnerabilities: [],
    },
    workflow_states_visited: [
      'idle',
      'scanning_dependencies',
      'deduplicating_output',
      'matching_vulnerabilities',
      'filtering_vex',
      'enriching_remediation',
      'exporting_sbom',
    ],
  },
};

const mockCacheStatus: CacheStatusResponse = {
  last_synced_at: '2026-04-09T10:00:00Z',
  age_days: 0.0,
  is_stale: false,
  record_count: 82451,
};

// In-memory store for dynamically created scans during tests
const scanStore: Record<string, ScanResponse> = { ...mockScanResults };
let scanCounter = 100;

// ---------------------------------------------------------------------------
// MSW v2 handlers
// ---------------------------------------------------------------------------

export const handlers = [

  // POST /api/v1/scans
  http.post('*/api/v1/scans', async ({ request }) => {
    const body = await request.json() as {
      repo_path?: string;
      format?: string;
      env?: string;
      vex_statements?: unknown[];
    };

    // Validate required fields
    if (!body.repo_path || body.repo_path.trim() === '') {
      return HttpResponse.json<ErrorResponse>(
        {
          error: 'INVALID_REPO_PATH',
          message: 'Repository path must not be empty.',
          details: { field: 'repo_path', received: body.repo_path ?? null },
        },
        { status: 422 },
      );
    }

    if (!body.format || !['cyclonedx', 'spdx'].includes(body.format)) {
      return HttpResponse.json<ErrorResponse>(
        {
          error: 'UNSUPPORTED_FORMAT',
          message: `Unsupported format: ${body.format}. Accepted: cyclonedx, spdx.`,
          details: { field: 'format', received: body.format ?? null },
        },
        { status: 422 },
      );
    }

    if (!body.env || !['development', 'staging', 'production'].includes(body.env)) {
      return HttpResponse.json<ErrorResponse>(
        {
          error: 'INVALID_ENVIRONMENT',
          message: `Invalid environment: ${body.env}. Accepted: development, staging, production.`,
          details: { field: 'env', received: body.env ?? null },
        },
        { status: 422 },
      );
    }

    // Stale-cache scenario: if repo_path contains "stale"
    const warnings: string[] = [];
    if (body.repo_path.includes('stale')) {
      warnings.push(
        'NVD cache is stale (last synced: 2026-04-01T10:00:00Z). Please run sbom-tool sync to refresh vulnerability data.',
      );
    }

    // Return scan_003 (clean) for paths containing "clean", scan_002 for "handson", default to scan_001
    let baseResult: ScanResponse;
    if (body.repo_path.includes('clean')) {
      baseResult = mockScanResults['scan_003'];
    } else if (body.repo_path.includes('handson')) {
      baseResult = mockScanResults['scan_002'];
    } else {
      baseResult = mockScanResults['scan_001'];
    }

    const newScanId = `mock-scan-${++scanCounter}`;
    const result: ScanResponse = {
      ...baseResult,
      scan_id: newScanId,
      output_format: body.format as ScanResponse['output_format'],
      warnings,
    };

    // Persist for later GET retrieval
    scanStore[newScanId] = result;

    return HttpResponse.json<ScanResponse>(result, { status: 200 });
  }),

  // GET /api/v1/scans/:scan_id
  http.get('*/api/v1/scans/:scan_id', ({ params }) => {
    const scanId = params['scan_id'] as string;
    const result = scanStore[scanId];

    if (!result) {
      return HttpResponse.json<ErrorResponse>(
        {
          error: 'SCAN_NOT_FOUND',
          message: `No scan result found for ID: ${scanId}`,
          details: { scan_id: scanId },
        },
        { status: 404 },
      );
    }

    return HttpResponse.json<ScanResponse>(result, { status: 200 });
  }),

  // POST /api/v1/sync
  http.post('*/api/v1/sync', async ({ request }) => {
    const body = await request.json() as { source_path?: string };

    if (!body.source_path || body.source_path.trim() === '') {
      return HttpResponse.json<ErrorResponse>(
        {
          error: 'INVALID_SOURCE_PATH',
          message: 'source_path must not be empty.',
          details: { field: 'source_path', received: body.source_path ?? null },
        },
        { status: 422 },
      );
    }

    // Simulate 404 for paths containing "missing" or "notfound"
    if (
      body.source_path.includes('missing') ||
      body.source_path.includes('notfound')
    ) {
      return HttpResponse.json<ErrorResponse>(
        {
          error: 'NVD_SOURCE_NOT_FOUND',
          message: `NVD source database not found: ${body.source_path}`,
          details: { source_path: body.source_path },
        },
        { status: 404 },
      );
    }

    const now = new Date().toISOString();
    const response: SyncResponse = {
      records_added: 1247,
      records_updated: 83,
      synced_at: now,
      source_path: body.source_path,
      sync_log: {
        synced_at: now,
        source_path: body.source_path,
        records_added: 1247,
        records_updated: 83,
      },
    };

    // Update mock cache status after sync
    mockCacheStatus.last_synced_at = now;
    mockCacheStatus.age_days = 0.0;
    mockCacheStatus.is_stale = false;

    return HttpResponse.json<SyncResponse>(response, { status: 200 });
  }),

  // GET /api/v1/cache/status
  http.get('*/api/v1/cache/status', () => {
    return HttpResponse.json<CacheStatusResponse>(mockCacheStatus, { status: 200 });
  }),

  // GET /api/v1/health
  http.get('*/api/v1/health', () => {
    const response: HealthResponse = {
      status: mockCacheStatus.is_stale ? 'degraded' : 'ok',
      version: '1.0.0',
      cache_status: { ...mockCacheStatus },
    };
    return HttpResponse.json<HealthResponse>(response, { status: 200 });
  }),

];

// ---------------------------------------------------------------------------
// Test utilities
// ---------------------------------------------------------------------------

/** Reset the in-memory scan store to the original mock fixtures */
export function resetScanStore(): void {
  Object.keys(scanStore).forEach((key) => {
    if (!['scan_001', 'scan_002', 'scan_003'].includes(key)) {
      delete scanStore[key];
    }
  });
  scanCounter = 100;
}

/** Inject a stale cache status for testing stale-cache warning behavior */
export function injectStaleCache(): void {
  mockCacheStatus.last_synced_at = '2026-03-30T08:00:00Z';
  mockCacheStatus.age_days = 10.1;
  mockCacheStatus.is_stale = true;
}

/** Restore a fresh cache status */
export function restoreFreshCache(): void {
  mockCacheStatus.last_synced_at = '2026-04-09T10:00:00Z';
  mockCacheStatus.age_days = 0.0;
  mockCacheStatus.is_stale = false;
}
