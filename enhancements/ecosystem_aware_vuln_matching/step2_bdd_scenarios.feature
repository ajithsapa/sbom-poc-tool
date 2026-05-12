# Enhancement Session: SBOM-20260409-sb01-ecosystem_aware_vuln_matching
# Parent Session:      SBOM-20260409-sb01
# Domain:              Developer Tooling — Software Supply Chain Security
# Architecture:        DETERMINISTIC_TOOL (PURL dispatch + file-backed caches, no AI/ML)
# Complexity Tier:     MODERATE (inherited from parent, score 11)
# Enhancement Type:    feature_addition (3 new classes, 1 serializer extension)
# Scenario count:      18 (6 happy path + 3 regression + 4 edge case + 3 error path + 2 integration)
# Mock scenarios referenced: enhancement step1b_mock_scenarios.json scenario_enh_001 through scenario_enh_009
# Capabilities under test: CAP-DISPATCH, CAP-OSV, CAP-GHSA, CAP-NVD-PRESERVED,
#                          CAP-CPE-SANITIZE, CAP-CACHE-PATTERN, CAP-O1-DISPATCH
#
# Parent-session constraints preserved:
#   - No live network in CI (Rule: No Live Network In CI, priority 4)
#   - Determinism — identical inputs produce byte-equal outputs
#   - Backward compatibility — all PyPI/NVD parent tests must keep passing

Feature: Ecosystem-Aware Vulnerability Matching — PURL Dispatch + OSV + GHSA + CPE Sanitization
  As a CI/CD pipeline scanning a multi-ecosystem repository
  I want each dependency routed to the correct vulnerability backend based on its PURL type
  And I want fabricated CPE strings stripped from non-NVD-indexed components in the emitted SBOM
  So that npm, Go, Cargo, Composer, and GitHub Action vulnerabilities are detected (not false-negatived)
  And so that downstream consumers of the SBOM are not polluted with bogus CPEs

  Background:
    # Rule: Cache Sync Required Before Lookup (priority 5)
    # Rule: No Live Network In CI (priority 4)
    Given the NVD cache is synced from "fixtures/nvd_seed.json" (inherited from parent)
    And the OSV cache is synced from "fixtures/osv_sample.json"
    And the GHSA cache is synced from "fixtures/ghsa_sample.json"
    And no outbound network calls to "osv.dev", "api.github.com", or "nvd.nist.gov" are permitted during scan execution
    And the PurlDispatchTable is loaded with the authoritative mapping from "purl_dispatch_table_001"

  # ===========================================================================
  # RULE 1 — Dispatch By PURL Type
  # Maps to: business_rule_catalog.rules["Dispatch By PURL Type"] (priority 1)
  # ===========================================================================
  Rule: Dispatch By PURL Type
    Each dependency must be routed to exactly one of {nvd, osv, ghsa, skipped}
    based solely on the type segment of its PURL string. Dispatch is O(1) via dict lookup.

    # -----------------------------------------------------------------------
    # Scenario 1 — Happy path: NVD backend dispatch for PyPI dep
    # Mock scenario: scenario_enh_002 (PyPI-only regression)
    # -----------------------------------------------------------------------
    @happy-path @CAP-DISPATCH @CAP-NVD-PRESERVED @CAP-O1-DISPATCH
    Scenario: PyPI dependency dispatches to NVD backend and returns parent-equivalent record
      Given a single dependency with purl "pkg:pypi/langchain@0.0.101"
      And the NVD cache contains "CVE-2023-34540" matched to "pkg:pypi/langchain@0.0.101" with CVSS score "9.8"
      When the EcosystemVulnerabilityMapper.map_vulnerabilities is called with the dep
      Then dispatch_counts equals {"nvd": 1, "osv": 0, "ghsa": 0, "skipped": 0}
      And the result contains CVE-2023-34540 for "pkg:pypi/langchain@0.0.101"
      And the vulnerability record carries the tag backend="nvd"
      And OSVCache.lookup was called 0 times
      And GHSACache.lookup was called 0 times
      And dispatch_correctness_score = 1.0  # Routed to expected backend
      And nvd_path_preservation_score = 1.0  # Parent NVD behaviour unchanged

    # -----------------------------------------------------------------------
    # Scenario 2 — Happy path: OSV backend dispatch for npm dep (vulnerable)
    # Mock scenario: scenario_enh_001 (mixed-ecosystem) — npm slice
    # -----------------------------------------------------------------------
    @happy-path @CAP-DISPATCH @CAP-OSV
    Scenario: npm dependency dispatches to OSV backend and returns GHSA-xvch advisory
      Given a single dependency with purl "pkg:npm/minimist@1.2.5"
      And the OSV cache contains record "GHSA-xvch-5gv4-984h" (CVE-2021-44906) for "pkg:npm/minimist@1.2.5"
      When the EcosystemVulnerabilityMapper.map_vulnerabilities is called with the dep
      Then dispatch_counts equals {"nvd": 0, "osv": 1, "ghsa": 0, "skipped": 0}
      And the result contains GHSA-xvch-5gv4-984h for "pkg:npm/minimist@1.2.5"
      And the vulnerability record carries the tag backend="osv"
      And the severity for "GHSA-xvch-5gv4-984h" is "MEDIUM"
      And NVDCacheManager.lookup was called 0 times
      And GHSACache.lookup was called 0 times
      And dispatch_correctness_score = 1.0
      And osv_match_coverage_score = 1.0  # Known-vulnerable npm PURL produced match

    # -----------------------------------------------------------------------
    # Scenario 3 — Happy path: OSV backend dispatch for golang dep
    # Mock scenario: scenario_enh_001 (mixed-ecosystem) — golang slice
    # -----------------------------------------------------------------------
    @happy-path @CAP-DISPATCH @CAP-OSV
    Scenario: golang dependency dispatches to OSV backend and returns GHSA-vvpx advisory
      Given a single dependency with purl "pkg:golang/golang.org/x/net@0.0.0-20190813141303-74dc4d7220e7"
      And the OSV cache contains record "GHSA-vvpx-j8f3-3w6h" (CVE-2021-31525) for the same PURL
      When the EcosystemVulnerabilityMapper.map_vulnerabilities is called with the dep
      Then dispatch_counts equals {"nvd": 0, "osv": 1, "ghsa": 0, "skipped": 0}
      And the result contains GHSA-vvpx-j8f3-3w6h for "pkg:golang/golang.org/x/net@0.0.0-20190813141303-74dc4d7220e7"
      And the vulnerability record carries the tag backend="osv"
      And the severity for "GHSA-vvpx-j8f3-3w6h" is "HIGH"
      And NVDCacheManager.lookup was called 0 times
      And GHSACache.lookup was called 0 times
      And dispatch_correctness_score = 1.0
      And osv_match_coverage_score = 1.0

    # -----------------------------------------------------------------------
    # Scenario 4 — Happy path: GHSA backend dispatch for GitHub Action dep
    # Mock scenario: scenario_enh_003 (github actions only) — slice
    # -----------------------------------------------------------------------
    @happy-path @CAP-DISPATCH @CAP-GHSA
    Scenario: GitHub Action dependency dispatches to GHSA backend and returns GHSA-mrrh advisory
      Given a single dependency with purl "pkg:github/tj-actions/changed-files@v35"
      And the GHSA cache contains record "GHSA-mrrh-fwg8-r2c3" (CVE-2025-30066) for the same PURL
      When the EcosystemVulnerabilityMapper.map_vulnerabilities is called with the dep
      Then dispatch_counts equals {"nvd": 0, "osv": 0, "ghsa": 1, "skipped": 0}
      And the result contains GHSA-mrrh-fwg8-r2c3 for "pkg:github/tj-actions/changed-files@v35"
      And the vulnerability record carries the tag backend="ghsa"
      And the severity for "GHSA-mrrh-fwg8-r2c3" is "HIGH"
      And NVDCacheManager.lookup was called 0 times
      And OSVCache.lookup was called 0 times
      And dispatch_correctness_score = 1.0
      And ghsa_match_coverage_score = 1.0  # Known-vulnerable github PURL produced match

    # -----------------------------------------------------------------------
    # Scenario 5 — Happy path: Mixed-ecosystem scan, all three backends hit
    # Mock scenario: scenario_enh_001 (mixed_repo_deps)
    # -----------------------------------------------------------------------
    @happy-path @CAP-DISPATCH @CAP-NVD-PRESERVED @CAP-OSV @CAP-GHSA
    Scenario: Mixed-ecosystem repository produces correct dispatch counts and 5 vulnerabilities
      Given the dependency list from fixture "mixed_repo_deps" (2 PyPI + 3 OSV + 1 GHSA)
      And the NVD cache contains records for "pkg:pypi/langchain@0.0.101" (CVE-2023-34540) and "pkg:pypi/joblib@0.14.1" (CVE-2022-21797)
      And the OSV cache contains records for "pkg:npm/minimist@1.2.5" and "pkg:golang/golang.org/x/net@0.0.0-20190813141303-74dc4d7220e7"
      And the GHSA cache contains record for "pkg:github/tj-actions/changed-files@v35"
      And the lodash dependency at "pkg:npm/lodash@4.17.20" is at its FIXED boundary version
      When the EcosystemVulnerabilityMapper.map_vulnerabilities is called with mixed_repo_deps.deps
      Then dispatch_counts equals {"nvd": 2, "osv": 3, "ghsa": 1, "skipped": 0}
      And the result contains exactly 5 vulnerability records
      And the result contains CVE-2023-34540 for "pkg:pypi/langchain@0.0.101" with backend="nvd"
      And the result contains CVE-2022-21797 for "pkg:pypi/joblib@0.14.1" with backend="nvd"
      And the result contains GHSA-xvch-5gv4-984h for "pkg:npm/minimist@1.2.5" with backend="osv"
      And the result contains GHSA-vvpx-j8f3-3w6h for "pkg:golang/golang.org/x/net@0.0.0-20190813141303-74dc4d7220e7" with backend="osv"
      And the result contains GHSA-mrrh-fwg8-r2c3 for "pkg:github/tj-actions/changed-files@v35" with backend="ghsa"
      And no record is produced for "pkg:npm/lodash@4.17.20"  # 4.17.20 is the fixed version
      And lodash@4.17.20 dispatch was routed to OSV (verified via call spy on OSVCache.lookup)
      And dispatch_correctness_score = 1.0
      And vulnerability_completeness_score = 1.0  # All 5 expected vulns present, no extras

  # ===========================================================================
  # RULE 2 — Preserve PyPI NVD Path
  # Maps to: business_rule_catalog.rules["Preserve PyPI NVD Path"] (priority 2)
  # ===========================================================================
  Rule: Preserve PyPI NVD Path
    All NVD-indexed ecosystems (pypi, nuget, maven, gem, deb, rpm, apk) must continue
    using the parent NVDCacheManager.lookup unchanged. Backward compatibility is critical.

    # -----------------------------------------------------------------------
    # Scenario 6 — Regression: pure PyPI scan still produces parent-equivalent result
    # Mock scenario: scenario_enh_002 (pypi_only_deps)
    # -----------------------------------------------------------------------
    @regression @CAP-NVD-PRESERVED @CAP-DISPATCH
    Scenario: PyPI-only repository scan produces parent-equivalent vulnerability set with zero OSV/GHSA calls
      Given the dependency list from fixture "pypi_only_deps" (5 PyPI deps from parent TaskMatrix scan_001)
      And the NVD cache contains "CVE-2023-34540" for "pkg:pypi/langchain@0.0.101"
      And the NVD cache contains "CVE-2023-32681" for "pkg:pypi/requests@2.27.1"
      And the NVD cache contains "CVE-2018-19787" for "pkg:pypi/lxml@4.6.3"
      And the NVD cache contains no records for "pkg:pypi/openai@0.27.2" or "pkg:pypi/pydantic@1.10.4"
      When the EcosystemVulnerabilityMapper.map_vulnerabilities is called with pypi_only_deps.deps
      Then dispatch_counts equals {"nvd": 5, "osv": 0, "ghsa": 0, "skipped": 0}
      And the result contains exactly 3 vulnerability records
      And the result contains CVE-2023-34540 for "pkg:pypi/langchain@0.0.101" with severity "High"
      And the result contains CVE-2023-32681 for "pkg:pypi/requests@2.27.1" with severity "Medium"
      And the result contains CVE-2018-19787 for "pkg:pypi/lxml@4.6.3" with severity "Medium"
      And OSVCache.lookup was called 0 times
      And GHSACache.lookup was called 0 times
      And the output set is byte-equal to the parent VulnerabilityMapper output for the same deps
      And backward_compatibility_score = 1.0  # Parent PyPI tests continue to pass
      And nvd_path_preservation_score = 1.0

    # -----------------------------------------------------------------------
    # Scenario 7 — Regression: parent CVE detection still works for PyPI deps
    # Mock scenario: scenario_enh_002 — drill-down on individual parent vuln
    # -----------------------------------------------------------------------
    @regression @CAP-NVD-PRESERVED
    Scenario: Parent-session vulnerabilities (CVE-2023-34540, CVE-2022-21797) remain detectable through enhanced mapper
      Given a dependency list containing "pkg:pypi/langchain@0.0.101" and "pkg:pypi/joblib@0.14.1"
      And the NVD cache contains "CVE-2023-34540" mapped to "pkg:pypi/langchain@0.0.101"
      And the NVD cache contains "CVE-2022-21797" mapped to "pkg:pypi/joblib@0.14.1"
      When the EcosystemVulnerabilityMapper.map_vulnerabilities is called with the dep list
      Then the result contains CVE-2023-34540 for "pkg:pypi/langchain@0.0.101"
      And the result contains CVE-2022-21797 for "pkg:pypi/joblib@0.14.1"
      And both records carry the tag backend="nvd"
      And the records are produced via NVDCacheManager.lookup (verified via call spy)
      And backward_compatibility_score = 1.0

    # -----------------------------------------------------------------------
    # Scenario 8 — Regression: existing NVD-cache-keyed-by-CPE lookup still works
    # Mock scenario: scenario_enh_002 (implicit — preserves parent NVD lookup mechanics)
    # -----------------------------------------------------------------------
    @regression @CAP-NVD-PRESERVED @CAP-CACHE-PATTERN
    Scenario: NVD cache CPE-keyed lookup path is preserved unchanged for PyPI deps
      Given the NVD cache uses CPE-based indexing for "pkg:pypi/langchain@0.0.101"
      And the parent NVDCacheManager.lookup signature is unchanged
      When the EcosystemVulnerabilityMapper dispatches "pkg:pypi/langchain@0.0.101" to NVD
      Then NVDCacheManager.lookup is invoked with the original PURL argument
      And the lookup returns the same record the parent VulnerabilityMapper would have returned
      And no wrapping, transformation, or PURL rewriting is applied before the lookup call
      And nvd_path_preservation_score = 1.0
      And cache_lookup_complexity_score = 1.0  # O(1) dict lookup preserved

  # ===========================================================================
  # RULE 3 — Strip Fabricated CPEs From SBOM Output
  # Maps to: business_rule_catalog.rules["Strip Fabricated CPEs From SBOM Output"] (priority 3)
  # ===========================================================================
  Rule: Strip Fabricated CPEs From SBOM Output
    During CycloneDX/SPDX serialization, components whose PURL type is NOT in the NVD-indexed
    set must have their cpe field removed. The purl field is preserved in all cases.

    # -----------------------------------------------------------------------
    # Scenario 9 — Happy path: CycloneDX sanitization strips CPEs from non-NVD components
    # Mock scenario: scenario_enh_007 (mixed component CPE sanitization)
    # -----------------------------------------------------------------------
    @happy-path @CAP-CPE-SANITIZE
    Scenario: CycloneDX serializer strips CPE from npm, github, and golang components but keeps PyPI CPE
      Given a component list containing one PyPI, one npm, one github, and one golang component
      And each component carries a CPE string (fabricated for non-NVD ecosystems, legitimate for PyPI)
      And the PyPI component is "pkg:pypi/langchain@0.0.101" with CPE "cpe:2.3:a:langchain:langchain:0.0.101:*:*:*:*:python:*:*"
      And the npm component is "pkg:npm/lodash@4.17.20" with fabricated CPE "cpe:2.3:a:lodash:lodash:4.17.20:*:*:*:*:node.js:*:*"
      And the github component is "pkg:github/actions/cache@v4" with fabricated CPE "cpe:2.3:a:actions\/cache:actions\/cache:v4:*:*:*:*:*:*:*"
      And the golang component is "pkg:golang/golang.org/x/net@0.0.0-20190813141303-74dc4d7220e7" with fabricated CPE "cpe:2.3:a:golang.org\/x\/net:golang.org\/x\/net:v0.0.0:*:*:*:*:*:*:*"
      When the CPESanitizingCycloneDXSerializer serializes the component list
      Then the emitted CycloneDX document has exactly 4 components
      And the PyPI component retains its "cpe" field with the original value
      And the npm component has no "cpe" key
      And the github component has no "cpe" key
      And the golang component has no "cpe" key
      And all 4 components retain their "purl" field unchanged
      And cpe_sanitization_correctness_score = 1.0  # Zero fabricated CPEs in emitted SBOM
      And purl_preservation_score = 1.0  # All PURLs unchanged

    # -----------------------------------------------------------------------
    # Scenario 10 — Happy path: SPDX sanitization mirrors CycloneDX behaviour
    # Mock scenario: scenario_enh_007 (SPDX equivalence clause in assertions)
    # -----------------------------------------------------------------------
    @happy-path @CAP-CPE-SANITIZE
    Scenario: SPDX serializer removes cpe23Type externalRefs from non-NVD-indexed components
      Given a component list containing "pkg:pypi/langchain@0.0.101", "pkg:npm/lodash@4.17.20", and "pkg:github/actions/cache@v4"
      And each component has an externalRefs entry with referenceType "cpe23Type"
      When the CPESanitizingSPDXSerializer serializes the component list
      Then the emitted SPDX document contains 3 packages
      And the package for "pkg:pypi/langchain@0.0.101" retains its cpe23Type externalRef
      And the package for "pkg:npm/lodash@4.17.20" has no externalRef with referenceType "cpe23Type"
      And the package for "pkg:github/actions/cache@v4" has no externalRef with referenceType "cpe23Type"
      And all 3 packages retain their PURL externalRef (referenceType "purl") unchanged
      And cpe_sanitization_correctness_score = 1.0
      And purl_preservation_score = 1.0

  # ===========================================================================
  # RULE 4 — No Live Network In CI
  # Maps to: business_rule_catalog.rules["No Live Network In CI"] (priority 4)
  # ===========================================================================
  Rule: No Live Network In CI
    All OSV and GHSA lookups must use fixture files only. Zero outbound network calls
    are permitted during enhancement test execution. NVD path retains parent behaviour.

    # -----------------------------------------------------------------------
    # Scenario 11 — Edge case: empty deps list short-circuits with no backend calls
    # Mock scenario: scenario_enh_005 (empty deps)
    # -----------------------------------------------------------------------
    @edge-case @CAP-DISPATCH
    Scenario: Empty dependency list returns empty result with no backend calls
      Given an empty dependency list []
      When the EcosystemVulnerabilityMapper.map_vulnerabilities is called with the empty list
      Then dispatch_counts equals {"nvd": 0, "osv": 0, "ghsa": 0, "skipped": 0}
      And the result is an empty list
      And NVDCacheManager.lookup was called 0 times
      And OSVCache.lookup was called 0 times
      And GHSACache.lookup was called 0 times
      And no WARNING or higher log line is emitted
      And no exception is raised

    # -----------------------------------------------------------------------
    # Scenario 12 — Edge case: unknown PURL type applies fallback (skip with warning)
    # Mock scenario: scenario_enh_004 (unknown PURL type)
    # -----------------------------------------------------------------------
    @edge-case @CAP-DISPATCH
    Scenario: Unknown PURL type is skipped with a structured warning, scan does not crash
      Given a single dependency with purl "pkg:unknownftype/foo@1.0"
      And the PurlDispatchTable has no entry for "unknownftype"
      And the dispatch fallback behaviour is "skip_with_log_warning"
      When the EcosystemVulnerabilityMapper.map_vulnerabilities is called with the dep
      Then dispatch_counts equals {"nvd": 0, "osv": 0, "ghsa": 0, "skipped": 1}
      And the result is an empty list
      And exactly one WARNING log line is emitted with code "dispatch.unknown_purl_type"
      And the log line includes the substring "unknownftype"
      And the log line includes the substring "pkg:unknownftype/foo@1.0"
      And NVDCacheManager.lookup was called 0 times
      And OSVCache.lookup was called 0 times
      And GHSACache.lookup was called 0 times
      And no exception is raised
      And dispatch_correctness_score = 1.0  # Correctly classified as 'none'

    # -----------------------------------------------------------------------
    # Scenario 13 — Edge case: dep missing purl field skips with warning
    # Mock scenario: scenario_enh_004 (variant — missing purl is an unknown route)
    # -----------------------------------------------------------------------
    @edge-case @CAP-DISPATCH
    Scenario: Dependency missing purl field is skipped with structured warning
      Given a dependency object with name "mystery-pkg" and no "purl" field set
      When the EcosystemVulnerabilityMapper.map_vulnerabilities is called with the dep
      Then dispatch_counts equals {"nvd": 0, "osv": 0, "ghsa": 0, "skipped": 1}
      And the result is an empty list
      And exactly one WARNING log line is emitted with code "dispatch.missing_purl"
      And the log line includes the substring "mystery-pkg"
      And no exception is raised
      And no backend lookup is invoked

    # -----------------------------------------------------------------------
    # Scenario 14 — Edge case: malformed PURL string skips with warning
    # Mock scenario: scenario_enh_004 (variant — malformed PURL is uncategorisable)
    # -----------------------------------------------------------------------
    @edge-case @CAP-DISPATCH
    Scenario: Malformed PURL string is skipped with structured warning
      Given a dependency with purl "not-a-purl-at-all"
      When the EcosystemVulnerabilityMapper.map_vulnerabilities is called with the dep
      Then dispatch_counts equals {"nvd": 0, "osv": 0, "ghsa": 0, "skipped": 1}
      And the result is an empty list
      And exactly one WARNING log line is emitted with code "dispatch.malformed_purl"
      And the log line includes the substring "not-a-purl-at-all"
      And no exception is raised
      And no backend lookup is invoked

  # ===========================================================================
  # RULE 5 — Cache Sync Required Before Lookup
  # Maps to: business_rule_catalog.rules["Cache Sync Required Before Lookup"] (priority 5)
  # ===========================================================================
  Rule: Cache Sync Required Before Lookup
    Calling OSVCache.lookup, GHSACache.lookup, or NVDCacheManager.lookup before sync()
    must raise a typed *NotSyncedError with an actionable message — never a bare KeyError
    or silent empty result.

    # -----------------------------------------------------------------------
    # Scenario 15 — Error path: OSV cache not synced raises OSVCacheNotSyncedError
    # Mock scenario: scenario_enh_006 (offline / un-synced OSV cache)
    # -----------------------------------------------------------------------
    @error-path @CAP-CACHE-PATTERN @CAP-OSV
    Scenario: OSV cache lookup before sync raises OSVCacheNotSyncedError with actionable message
      Given an OSVCache instance that has never been synced
      And a dependency with purl "pkg:npm/minimist@1.2.5" that routes to OSV
      And OSVCache.is_synced() returns False
      When the EcosystemVulnerabilityMapper.map_vulnerabilities is called with the dep
      Then an exception of type "OSVCacheNotSyncedError" is raised
      And the exception message contains the substring "OSV cache not initialized"
      And the exception message contains the substring "run sync first"
      And the exception type is NOT KeyError
      And the exception type is NOT generic Exception
      And no partial result is returned
      And the process exit code (if propagated to CLI) is 1

    # -----------------------------------------------------------------------
    # Scenario 16 — Error path: GHSA cache not synced raises GHSACacheNotSyncedError
    # Mock scenario: scenario_enh_006 (variant — GHSA cache)
    # -----------------------------------------------------------------------
    @error-path @CAP-CACHE-PATTERN @CAP-GHSA
    Scenario: GHSA cache lookup before sync raises GHSACacheNotSyncedError with actionable message
      Given a GHSACache instance that has never been synced
      And a dependency with purl "pkg:github/tj-actions/changed-files@v35" that routes to GHSA
      And GHSACache.is_synced() returns False
      When the EcosystemVulnerabilityMapper.map_vulnerabilities is called with the dep
      Then an exception of type "GHSACacheNotSyncedError" is raised
      And the exception message contains the substring "GHSA cache not initialized"
      And the exception message contains the substring "run sync first"
      And the exception type is NOT KeyError
      And the exception type is NOT generic Exception
      And no partial result is returned

    # -----------------------------------------------------------------------
    # Scenario 17 — Error path: NVD cache not synced raises NVDSyncError (parent error preserved)
    # Mock scenario: scenario_enh_006 (variant — NVD cache, parent error class)
    # -----------------------------------------------------------------------
    @error-path @CAP-CACHE-PATTERN @CAP-NVD-PRESERVED
    Scenario: NVD cache lookup before sync raises NVDSyncError (parent error class preserved)
      Given an NVDCacheManager instance that has never been synced
      And a dependency with purl "pkg:pypi/langchain@0.0.101" that routes to NVD
      And the parent NVDSyncError exception class is preserved unchanged
      When the EcosystemVulnerabilityMapper.map_vulnerabilities is called with the dep
      Then an exception of type "NVDSyncError" is raised  # Parent error class, not redefined
      And the exception message contains the substring "NVD cache"
      And no partial result is returned
      And nvd_path_preservation_score = 1.0  # Parent error semantics intact

  # ===========================================================================
  # INTEGRATION SCENARIOS — full-pipeline assertions across multiple rules
  # ===========================================================================
  Rule: End-to-End Multi-Ecosystem Integration With Serialization
    Full-pipeline scenarios that exercise dispatch + lookup + serialization + CPE sanitization
    together against the canonical mixed-ecosystem fixture.

    # -----------------------------------------------------------------------
    # Scenario 18 — Integration: full scan + CycloneDX serialization
    # Mock scenario: scenario_enh_001 + scenario_enh_003 + scenario_enh_007
    # -----------------------------------------------------------------------
    @integration @CAP-DISPATCH @CAP-OSV @CAP-GHSA @CAP-NVD-PRESERVED @CAP-CPE-SANITIZE
    Scenario: Mixed-ecosystem scan emits CycloneDX with all 5 vulnerabilities and zero fabricated CPEs
      Given the dependency list from fixture "mixed_repo_deps" (2 PyPI + 3 OSV + 1 GHSA)
      And each non-PyPI component carries a fabricated CPE string from Syft --add-cpes-if-none
      And the NVD, OSV, and GHSA caches are all synced from their respective fixtures
      When the full pipeline runs: map_vulnerabilities + CPESanitizingCycloneDXSerializer.serialize
      Then the CLI exits with code 0
      And the emitted CycloneDX 1.4 JSON contains 6 components and 5 vulnerabilities
      And the vulnerabilities array contains CVE-2023-34540, CVE-2022-21797, GHSA-xvch-5gv4-984h, GHSA-vvpx-j8f3-3w6h, GHSA-mrrh-fwg8-r2c3
      And components for "pkg:pypi/langchain@0.0.101" and "pkg:pypi/joblib@0.14.1" retain their "cpe" field
      And components for "pkg:npm/lodash@4.17.20", "pkg:npm/minimist@1.2.5", "pkg:golang/golang.org/x/net@0.0.0-20190813141303-74dc4d7220e7", and "pkg:github/tj-actions/changed-files@v35" have no "cpe" key
      And every component retains its "purl" field unchanged
      And the emitted CycloneDX JSON contains exactly 2 "cpe" string occurrences (the two PyPI components only)
      And no outbound network call is made during the full pipeline run
      And dispatch_correctness_score = 1.0
      And cpe_sanitization_correctness_score = 1.0
      And schema_validation_score = 1.0  # Emitted JSON validates against CycloneDX 1.4 schema

    # -----------------------------------------------------------------------
    # Scenario 19 — Integration: full scan + SPDX serialization
    # Mock scenario: scenario_enh_001 + scenario_enh_007 (SPDX equivalence clause)
    # -----------------------------------------------------------------------
    @integration @CAP-DISPATCH @CAP-OSV @CAP-GHSA @CAP-NVD-PRESERVED @CAP-CPE-SANITIZE
    Scenario: Mixed-ecosystem scan emits SPDX with all 5 vulnerabilities and zero fabricated CPEs
      Given the dependency list from fixture "mixed_repo_deps" (2 PyPI + 3 OSV + 1 GHSA)
      And each non-PyPI component has an externalRefs entry with referenceType "cpe23Type" (fabricated)
      And the NVD, OSV, and GHSA caches are all synced from their respective fixtures
      When the full pipeline runs: map_vulnerabilities + CPESanitizingSPDXSerializer.serialize
      Then the CLI exits with code 0
      And the emitted SPDX 2.3 JSON has "spdxVersion" equal to "SPDX-2.3"
      And the packages array contains 6 entries
      And the vulnerabilities (in spdx-relationship or via externalRefs of type "securityAdvisory") cover CVE-2023-34540, CVE-2022-21797, GHSA-xvch-5gv4-984h, GHSA-vvpx-j8f3-3w6h, GHSA-mrrh-fwg8-r2c3
      And the packages for the 2 PyPI components retain their cpe23Type externalRef
      And the packages for the 4 non-PyPI components (lodash, minimist, golang.org/x/net, tj-actions/changed-files) have no externalRef with referenceType "cpe23Type"
      And every package retains its referenceType "purl" externalRef unchanged
      And the emitted SPDX JSON contains exactly 2 externalRefs with referenceType "cpe23Type"
      And no outbound network call is made during the full pipeline run
      And dispatch_correctness_score = 1.0
      And cpe_sanitization_correctness_score = 1.0
      And schema_validation_score = 1.0  # Emitted JSON validates against SPDX 2.3 schema
