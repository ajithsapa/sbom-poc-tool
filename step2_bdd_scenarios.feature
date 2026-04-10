# Session: SBOM-20260409-sb01
# Domain: Developer Tooling — Software Supply Chain Security
# Architecture: DETERMINISTIC_TOOL (CLI + FastAPI, no AI/ML)
# Complexity Tier: MODERATE (estimated score 11)
# DDM Source: SBOM_POC_Scope.md (Document-Driven Mode)
# Scenario count: 20 (14 business functionality + 6 orchestration/infrastructure)
# Open clarifications carried as comments: CQ-1 (CVSS thresholds), CQ-2 (remediation optionality)
# CQ-1 resolution applied: CVSS v3.1 standard banding — High >= 7.0, Medium 4.0–6.9, Low < 4.0
# CQ-2 resolution applied: at least advisory_url always present; recommendation is additional enrichment

Feature: SBOM Scan — Business Functionality
  As a CI/CD pipeline or developer
  I want to scan a single Python or JS/TS repository
  So that I receive a machine-readable SBOM with classified vulnerabilities and remediation guidance

  Background:
    # Source: SBOM_POC_Scope.md, In Scope #7 and Key Decisions
    # Rule: No Live NVD API Call at Scan Time (priority 6)
    # Rule: Single Repository Per Scan (priority 1)
    Given the NVD local cache is populated at "./nvd_cache.db"
    And the cache was last synced within the staleness threshold (7 days)
    And no live calls to "nvd.nist.gov" are permitted during scan execution
    And the sbom-tool CLI is installed and available on PATH

  # ---------------------------------------------------------------------------
  # Scenario 1: Happy path — Python LLM project, CycloneDX output, High CVE
  # Source: SBOM_POC_Scope.md, In Scope #1, #3, #4, #5, #6
  # Rule: SPDX/CycloneDX Baseline Field Alignment (priority 3)
  # Rule: CVSS Severity Classification (priority 4)
  # Rule: Remediation Per Vulnerability (priority 5)
  # BDD Focus: "Happy path: scan Python repo and export CycloneDX JSON"
  # BDD Focus: "CVSS severity classification: High, Medium, Low assigned per vulnerability"
  # BDD Focus: "Remediation enrichment: at least one of (recommendation, advisory link) per vulnerability"
  # Mock Entity: scan_001, TaskMatrix, /repos/TaskMatrix, 8 deps, vuln_001 (CVE-2023-34540, langchain 0.0.101, CVSS 9.8)
  # ---------------------------------------------------------------------------
  Scenario: Scan Python LLM project and produce CycloneDX JSON with High severity CVE
    Given the repository at "/repos/TaskMatrix" contains a Python project
    And the project has a "requirements.txt" specifying "langchain==0.0.101" as a direct dependency
    And the following dependencies are discoverable by Syft:
      | name      | version  | type        | purl                             |
      | langchain | 0.0.101  | direct      | pkg:pypi/langchain@0.0.101       |
      | openai    | 0.27.2   | direct      | pkg:pypi/openai@0.27.2           |
      | requests  | 2.27.1   | transitive  | pkg:pypi/requests@2.27.1         |
      | numpy     | 1.23.5   | transitive  | pkg:pypi/numpy@1.23.5            |
      | pydantic  | 1.10.4   | transitive  | pkg:pypi/pydantic@1.10.4         |
      | lxml      | 4.6.3    | transitive  | pkg:pypi/lxml@4.6.3              |
      | aiohttp   | 3.8.1    | transitive  | pkg:pypi/aiohttp@3.8.1           |
      | tenacity  | 8.1.0    | transitive  | pkg:pypi/tenacity@8.1.0          |
    And the NVD cache contains "CVE-2023-34540" matched to "pkg:pypi/langchain@0.0.101" with CVSS score "9.8"
    When the user runs "sbom-tool scan /repos/TaskMatrix --format cyclonedx --output ./TaskMatrix-sbom.cdx.json"
    Then the CLI exits with code 0
    And the output file "./TaskMatrix-sbom.cdx.json" exists and parses as valid CycloneDX 1.4 JSON
    And the "components" array contains exactly 8 entries
    And every component entry has a non-empty "purl" field
    And the vulnerability "CVE-2023-34540" is present in the vulnerabilities section
    And "CVE-2023-34540" is mapped to component "langchain" version "0.0.101"
    And the severity for "CVE-2023-34540" is "High"
    # CQ-1: CVSS v3.1 banding applied — score 9.8 >= 7.0 threshold
    And the CVSS score for "CVE-2023-34540" is "9.8"
    And the vulnerability entry for "CVE-2023-34540" contains at least one of "remediation_recommendation" or "advisory_link"
    # CQ-2: advisory_link is the minimum required enrichment field
    And the "advisory_link" for "CVE-2023-34540" is "https://nvd.nist.gov/vuln/detail/CVE-2023-34540"
    And no network request is made to "nvd.nist.gov" during scan execution
    And dependency_completeness_score = 1.0  # All 8 deps present with name, version, supplier, purl
    And schema_validation_score = 1.0        # CycloneDX 1.4 JSON passes spec validation
    And vulnerability_classification_accuracy = 1.0  # CVE mapped to correct dep with correct severity

  # ---------------------------------------------------------------------------
  # Scenario 2: Happy path — classic ML project, SPDX output, mixed severity CVEs
  # Source: SBOM_POC_Scope.md, In Scope #1, #3, #4, #5, #6
  # Rule: SPDX/CycloneDX Baseline Field Alignment (priority 3)
  # Rule: CVSS Severity Classification (priority 4)
  # BDD Focus: "Happy path: scan JS/TS repo and export SPDX JSON" (adapted to Python SPDX output)
  # Mock Entity: scan_002, handson-ml, 9 deps, mixed vulns — 3 High, 2 Medium
  # ---------------------------------------------------------------------------
  Scenario: Scan classic ML project and produce SPDX JSON with mixed severity distribution
    Given the repository at "/repos/handson-ml" contains a Python project
    And the project has a "requirements.txt" with the following direct dependencies:
      | name         | version  | purl                               |
      | numpy        | 1.22.0   | pkg:pypi/numpy@1.22.0              |
      | pandas       | 1.2.2    | pkg:pypi/pandas@1.2.2              |
      | scikit-learn | 0.24.1   | pkg:pypi/scikit-learn@0.24.1       |
      | scipy        | 1.6.0    | pkg:pypi/scipy@1.6.0               |
      | matplotlib   | 3.3.4    | pkg:pypi/matplotlib@3.3.4          |
      | Pillow       | 9.0.1    | pkg:pypi/Pillow@9.0.1              |
      | tensorflow   | 1.15.5   | pkg:pypi/tensorflow@1.15.5         |
    And "scikit-learn@0.24.1" transitively pulls in "joblib@0.14.1" (pkg:pypi/joblib@0.14.1)
    And "scikit-learn@0.24.1" transitively pulls in "threadpoolctl@2.1.0" (pkg:pypi/threadpoolctl@2.1.0)
    And the NVD cache contains vulnerability records matching the following:
      | cve_id          | purl                          | cvss  | severity |
      | CVE-2022-21797  | pkg:pypi/joblib@0.14.1        | 9.8   | High     |
      | CVE-2023-44271  | pkg:pypi/Pillow@9.0.1         | 7.5   | High     |
      | CVE-2022-29216  | pkg:pypi/tensorflow@1.15.5    | 8.8   | High     |
      | CVE-2021-33430  | pkg:pypi/numpy@1.22.0         | 5.5   | Medium   |
      | CVE-2023-25399  | pkg:pypi/scipy@1.6.0          | 5.5   | Medium   |
    When the user runs "sbom-tool scan /repos/handson-ml --format spdx --output ./handson-ml-sbom.spdx.json"
    Then the CLI exits with code 0
    And the output file "./handson-ml-sbom.spdx.json" exists and parses as valid SPDX 2.3 JSON
    And the SPDX document contains "spdxVersion" field equal to "SPDX-2.3"
    And the "packages" array contains exactly 9 entries
    And the severity distribution contains 3 "High" vulnerabilities and 2 "Medium" vulnerabilities and 0 "Low" vulnerabilities
    And every vulnerable package entry includes both "purl" and "cpe" in its "externalRefs" array
    And each vulnerability entry contains at least one of "remediation_recommendation" or "advisory_link"
    And no network request is made to "nvd.nist.gov" during scan execution
    And dependency_completeness_score = 1.0  # All 9 deps (7 direct + 2 transitive) captured
    And schema_validation_score = 1.0        # SPDX 2.3 JSON passes spec validation
    And severity_distribution_accuracy = 1.0  # Correct High/Medium/Low counts

  # ---------------------------------------------------------------------------
  # Scenario 3: Happy path — clean project, zero CVEs
  # Source: SBOM_POC_Scope.md, In Scope #1, #3, #4
  # BDD Focus: "Happy path: scan Python repo and export CycloneDX JSON"
  # BDD Focus: "CI/CD gate: non-zero exit code on scan error" (inverse — clean scan exits 0)
  # Mock Entity: scan_003, clean-api, 4 deps (flask 3.0.0 + 3 transitive), 0 vulnerabilities
  # ---------------------------------------------------------------------------
  Scenario: Scan clean project with no known CVEs produces empty vulnerability list and exits cleanly
    Given the repository at "/repos/clean-api" contains a Python project
    And the project has a "requirements.txt" specifying "flask==3.0.0" as a direct dependency
    And the following dependencies are discoverable by Syft:
      | name         | version | type       | purl                               |
      | flask        | 3.0.0   | direct     | pkg:pypi/flask@3.0.0               |
      | click        | 8.1.7   | transitive | pkg:pypi/click@8.1.7               |
      | werkzeug     | 3.0.1   | transitive | pkg:pypi/werkzeug@3.0.1            |
      | itsdangerous | 2.1.2   | transitive | pkg:pypi/itsdangerous@2.1.2        |
    And none of these packages have matching entries in the NVD cache
    When the user runs "sbom-tool scan /repos/clean-api --format cyclonedx --output ./clean-api-sbom.cdx.json"
    Then the CLI exits with code 0
    And the output file "./clean-api-sbom.cdx.json" exists and parses as valid CycloneDX 1.4 JSON
    And the "components" array contains exactly 4 entries
    And the "vulnerabilities" array is empty
    And the stdout output does not contain any of the labels "High", "Medium", "Low"
    And no output file is partially written (file is complete and schema-valid)
    And clean_scan_exit_code_accuracy = 1.0  # Exit 0 on clean scan
    And schema_validation_score = 1.0        # CycloneDX output valid even with zero vulns
    And false_positive_rate = 0.0            # No fabricated CVEs on clean project

  # ---------------------------------------------------------------------------
  # Scenario 4: Transitive dependency carries CVE — not the direct parent dep
  # Source: SBOM_POC_Scope.md, In Scope #3, #5
  # Rule: SPDX/CycloneDX Baseline Field Alignment (priority 3)
  # BDD Focus: "Dependency completeness: direct + transitive captured with name, version, supplier"
  # BDD Focus: "PURL/CPE identifier presence on each dependency"
  # Mock Entity: dep_hml_007 (joblib 0.14.1, transitive via scikit-learn 0.24.1), vuln_002 (CVE-2022-21797)
  # ---------------------------------------------------------------------------
  Scenario: CVE on transitive dependency is attributed to the transitive package not its direct parent
    Given the repository at "/repos/handson-ml" is scanned
    And "scikit-learn==0.24.1" is present as a direct dependency with purl "pkg:pypi/scikit-learn@0.24.1"
    And "joblib==0.14.1" is a transitive dependency pulled in by "scikit-learn==0.24.1"
    And "joblib@0.14.1" has purl "pkg:pypi/joblib@0.14.1"
    And the NVD cache contains "CVE-2022-21797" matched to "pkg:pypi/joblib@0.14.1" with CVSS score "9.8"
    And the NVD cache contains NO vulnerability matched to "pkg:pypi/scikit-learn@0.24.1"
    When the user runs "sbom-tool scan /repos/handson-ml --format spdx --output ./handson-ml-sbom.spdx.json"
    Then the output SBOM contains "joblib" version "0.14.1" as a component
    And "CVE-2022-21797" is mapped to the component with purl "pkg:pypi/joblib@0.14.1"
    And "CVE-2022-21797" is NOT mapped to "pkg:pypi/scikit-learn@0.24.1"
    And the component entry for "joblib" records its dependency type as "transitive"
    And the component entry for "joblib" records its transitive path through "scikit-learn"
    And the severity for "CVE-2022-21797" is "High"
    # CQ-1: score 9.8 >= 7.0 → High
    And the vulnerability entry for "CVE-2022-21797" includes "advisory_link" or "remediation_recommendation"
    And transitive_cve_attribution_accuracy = 1.0  # CVE attached to correct transitive dep
    And purl_coverage_score = 1.0                  # All deps including transitive have valid PURLs

  # ---------------------------------------------------------------------------
  # Scenario 5: VEX filtering — lxml XSS CVE suppressed via OpenVEX statement
  # Source: SBOM_POC_Scope.md, OSS Reuse — VEX filtering row
  # BDD Focus: "VEX filtering: suppressed vulnerabilities not included in output (or flagged)"
  # Risk Scenario: "VEX filtering: VEX-suppressed vulnerability does not appear as unfiltered in output"
  # Mock Entity: vuln_006 (CVE-2018-19787, lxml 4.6.3), VEX status "not_affected"
  # ---------------------------------------------------------------------------
  Scenario: OpenVEX statement suppresses lxml CVE which then does not appear in active vulnerability list
    Given the repository at "/repos/TaskMatrix" is scanned
    And "lxml==4.6.3" is present as a transitive dependency with purl "pkg:pypi/lxml@4.6.3"
    And the NVD cache contains "CVE-2018-19787" matched to "pkg:pypi/lxml@4.6.3"
    And a VEX document at "/config/vex-filter.json" declares the following statement:
      | cve_id          | package_purl             | status       | justification                        |
      | CVE-2018-19787  | pkg:pypi/lxml@4.6.3      | not_affected | vulnerable_code_not_in_execute_path  |
    And the VEX document note states "TaskMatrix does not invoke lxml.html.clean module"
    When the user runs "sbom-tool scan /repos/TaskMatrix --format cyclonedx --output ./TaskMatrix-sbom-vex.cdx.json"
    Then the CLI exits with code 0
    And "CVE-2018-19787" does NOT appear in the active "vulnerabilities" section of the output
    And the active vulnerability count is 2 containing "CVE-2023-34540" and "CVE-2023-32681"
    And if the output includes a suppressed-vulnerabilities section, "CVE-2018-19787" appears there with status "not_affected"
    And the output is still schema-valid CycloneDX JSON
    And vex_filtering_accuracy = 1.0  # VEX-suppressed CVE absent from active vulnerability list
    And schema_validation_score = 1.0  # Output remains valid after VEX filtering

  # ---------------------------------------------------------------------------
  # Scenario 6: Remediation enrichment — every active vulnerability has at least one enrichment field
  # Source: SBOM_POC_Scope.md, In Scope #6
  # Rule: Remediation Per Vulnerability (priority 5)
  # BDD Focus: "Remediation enrichment: at least one of (recommendation, advisory link) per vulnerability"
  # CQ-2: Scenario tests minimum requirement (advisory_link always present)
  # Mock Entities: vuln_001 through vuln_008
  # ---------------------------------------------------------------------------
  Scenario: Every active vulnerability in SBOM output contains at least one remediation enrichment field
    Given the repository at "/repos/handson-ml" is scanned
    And the NVD cache contains records for the following vulnerabilities:
      | cve_id          | package             | advisory_link_present | recommendation_present |
      | CVE-2022-21797  | joblib@0.14.1       | true                  | true                   |
      | CVE-2023-44271  | Pillow@9.0.1        | true                  | true                   |
      | CVE-2022-29216  | tensorflow@1.15.5   | true                  | true                   |
      | CVE-2021-33430  | numpy@1.22.0        | true                  | true                   |
      | CVE-2023-25399  | scipy@1.6.0         | true                  | true                   |
    When the user runs "sbom-tool scan /repos/handson-ml --format spdx --output ./handson-ml-sbom.spdx.json"
    Then the CLI exits with code 0
    And every vulnerability entry in the output contains at least one of "advisory_link" or "remediation_recommendation"
    And no vulnerability entry has both "advisory_link" and "remediation_recommendation" empty or null
    # CQ-2: If only advisory_link is populated that satisfies the minimum requirement
    And the "advisory_link" field for each CVE points to "https://nvd.nist.gov/vuln/detail/{cve_id}"
    And remediation_coverage_score = 1.0  # All active vulns have at least one enrichment field
    And advisory_link_presence_score = 1.0  # advisory_link present on all matched CVEs

  # ---------------------------------------------------------------------------
  # Scenario 7: PURL and CPE identifier presence on all dependency entries
  # Source: SBOM_POC_Scope.md, In Scope #5
  # BDD Focus: "PURL/CPE identifier presence on each dependency"
  # Mock Entity: scan_001 — 8 dependencies, all with purl and cpe fields in SBOMDocument
  # ---------------------------------------------------------------------------
  Scenario: All dependency entries in SBOM output carry valid PURL and CPE identifiers
    Given the repository at "/repos/TaskMatrix" is scanned
    And Syft discovers all 8 dependencies including direct and transitive entries
    When the user runs "sbom-tool scan /repos/TaskMatrix --format cyclonedx --output ./TaskMatrix-sbom.cdx.json"
    Then the CLI exits with code 0
    And every component in the "components" array has a non-empty "purl" field
    And the "purl" value for "langchain" is "pkg:pypi/langchain@0.0.101"
    And the "purl" value for "requests" is "pkg:pypi/requests@2.27.1"
    And the "purl" value for "lxml" is "pkg:pypi/lxml@4.6.3"
    And every vulnerable component in the "components" array has a non-empty "cpe" field
    And the "cpe" value for "langchain" matches pattern "cpe:2.3:a:langchain:langchain:0.0.101:*"
    And purl_coverage_score = 1.0   # All 8 components have valid PURL
    And cpe_coverage_score = 1.0    # All vulnerable components have CPE

  # ---------------------------------------------------------------------------
  # Scenario 8: CycloneDX JSON schema compliance for TaskMatrix scan
  # Source: SBOM_POC_Scope.md, In Scope #4 and Key Decisions
  # Rule: SPDX/CycloneDX Baseline Field Alignment (priority 3)
  # BDD Focus: "Output format schema compliance: SPDX and CycloneDX JSON pass spec validation"
  # Success Criteria: "SPDX and CycloneDX JSON export passes format schema validation"
  # ---------------------------------------------------------------------------
  Scenario: CycloneDX JSON output for TaskMatrix passes CycloneDX 1.4 schema validation
    Given the repository at "/repos/TaskMatrix" has been successfully scanned (scan_001)
    And the output file "./TaskMatrix-sbom.cdx.json" was produced by sbom-tool
    When the output file is validated against the CycloneDX 1.4 JSON schema
    Then the validation reports zero schema errors
    And the document contains a "bomFormat" field with value "CycloneDX"
    And the document contains a "specVersion" field with value "1.4"
    And the document contains a "serialNumber" field in URN UUID format
    And the document contains a "metadata" object with "timestamp" and "tools" fields
    And the document contains a "components" array with at least one entry
    And the document contains a "vulnerabilities" array (may be empty)
    And schema_validation_score = 1.0  # Zero CycloneDX 1.4 schema violations

  # ---------------------------------------------------------------------------
  # Scenario 9: SPDX JSON schema compliance for handson-ml scan
  # Source: SBOM_POC_Scope.md, In Scope #4 and Key Decisions
  # Rule: SPDX/CycloneDX Baseline Field Alignment (priority 3)
  # BDD Focus: "Output format schema compliance: SPDX and CycloneDX JSON pass spec validation"
  # ---------------------------------------------------------------------------
  Scenario: SPDX JSON output for handson-ml passes SPDX 2.3 schema validation
    Given the repository at "/repos/handson-ml" has been successfully scanned (scan_002)
    And the output file "./handson-ml-sbom.spdx.json" was produced by sbom-tool
    When the output file is validated against the SPDX 2.3 JSON schema
    Then the validation reports zero schema errors
    And the document contains "spdxVersion" with value "SPDX-2.3"
    And the document contains "dataLicense" with value "CC0-1.0"
    And the document contains a "SPDXID" field with value "SPDXRef-DOCUMENT"
    And the document contains a "packages" array where each entry has "SPDXID", "name", "versionInfo", and "externalRefs"
    And external references for vulnerable packages include entries of type "SECURITY" referencing the CVE advisory URL
    And schema_validation_score = 1.0  # Zero SPDX 2.3 schema violations

  # ---------------------------------------------------------------------------
  # Scenario 10: CVSS v3.1 boundary conditions — exact band thresholds
  # Source: SBOM_POC_Scope.md, In Scope #6
  # Rule: CVSS Severity Classification (priority 4)
  # Risk Scenario: "CVSS threshold boundary: score at exact boundary between severity bands"
  # BDD Focus: "CVSS severity classification: High, Medium, Low assigned per vulnerability"
  # CQ-1: Uses CVSS v3.1 standard banding as clarification resolution
  # ---------------------------------------------------------------------------
  Scenario Outline: CVSS severity classifier assigns correct band at exact v3.1 thresholds
    Given the CVSS Severity Classifier receives a score of "<cvss_score>"
    When the classifier evaluates the score against CVSS v3.1 bands
    # CQ-1: High >= 7.0, Medium >= 4.0 AND < 7.0, Low > 0 AND < 4.0
    Then the assigned severity is "<expected_severity>"

    Examples:
      | cvss_score | expected_severity | notes                               |
      | 10.0       | High              | maximum possible score              |
      | 9.8        | High              | typical critical-class score        |
      | 7.0        | High              | High lower boundary — inclusive     |
      | 6.9        | Medium            | Medium upper boundary — inclusive   |
      | 5.5        | Medium            | typical medium score                |
      | 4.0        | Medium            | Medium lower boundary — inclusive   |
      | 3.9        | Low               | Low upper boundary — inclusive      |
      | 3.3        | Low               | typical low score                   |
      | 0.1        | Low               | near-zero low score                 |

  # ---------------------------------------------------------------------------
  # Scenario 11: Null CVSS score classified as Unknown — not silently dropped
  # Source: SBOM_POC_Scope.md, In Scope #6
  # Rule: CVSS Severity Classification (priority 4)
  # CQ-1: null score resolution — Unknown severity (not dropped or defaulted)
  # ---------------------------------------------------------------------------
  Scenario: Vulnerability with null CVSS score is classified as Unknown and not silently discarded
    Given a NVD cache record for vulnerability "CVE-UNKNOWN-0001" with a null CVSS score
    And the affected package is "pkg:pypi/some-package@1.0.0"
    When the CVSS Severity Classifier evaluates this vulnerability record
    Then the assigned severity label is "Unknown"
    And the vulnerability entry is included in the SBOM output with severity "Unknown"
    And the vulnerability is NOT silently discarded or omitted from the output
    And the vulnerability entry still includes "advisory_link" if available in the cache record
    And null_cvss_handling_accuracy = 1.0  # Unknown label assigned, entry retained in output

  # ---------------------------------------------------------------------------
  # Scenario 12: Single repository constraint — reject invocation with multiple repos
  # Source: SBOM_POC_Scope.md, Key Decisions and In Scope #1
  # Rule: Single Repository Per Scan (priority 1)
  # BDD Focus: "Single repository constraint: reject invocation with multiple repos"
  # ---------------------------------------------------------------------------
  Scenario: Invocation with multiple repository paths is rejected with non-zero exit and informative error
    Given the sbom-tool CLI is invoked with two repository paths
    When the user runs "sbom-tool scan /repos/TaskMatrix /repos/handson-ml --format cyclonedx --output ./multi-sbom.cdx.json"
    Then the CLI exits with a non-zero exit code
    And the stderr output contains a message referencing the single-repository constraint
    And no SBOM output file is created at "./multi-sbom.cdx.json"
    And the error message suggests running separate scans for each repository
    And single_repo_constraint_enforcement = 1.0  # Rejected with clear error, no output produced

  # ---------------------------------------------------------------------------
  # Scenario 13: Unsupported language — graceful error, non-zero exit, no silent empty SBOM
  # Source: SBOM_POC_Scope.md, Out of Scope — Multi-language support beyond Python + JS/TS
  # BDD Focus: "CI/CD gate: non-zero exit code on scan error"
  # Risk Scenario: "Unsupported language repository scanned: graceful error, not silent empty output"
  # Mock Entity: scenario_010, /repos/some-go-project, language=Go
  # ---------------------------------------------------------------------------
  Scenario: Scanning a Go repository produces a non-zero exit code and informative error without a partial SBOM
    Given the repository at "/repos/some-go-project" contains a Go project
    And the detected language is "Go"
    And "Go" is not in the supported language list ("Python", "JS/TS")
    When the user runs "sbom-tool scan /repos/some-go-project --format cyclonedx --output ./go-sbom.cdx.json"
    Then the CLI exits with a non-zero exit code (1 or 2)
    And the stderr output contains a message referencing unsupported ecosystem or language
    And the stderr message references the supported languages "Python" and "JS/TS" (or "pypi" and "npm")
    And no output file is created at "./go-sbom.cdx.json"
    And no partial SBOM structure is written to stdout
    And unsupported_language_exit_code_accuracy = 1.0  # Non-zero exit on unsupported language
    And error_message_clarity_score >= 0.9             # Error names the unsupported language and supported alternatives

  # ---------------------------------------------------------------------------
  # Scenario 14: Stale NVD cache — warning emitted, zero-vuln SBOM not silently produced
  # Source: SBOM_POC_Scope.md, In Scope #7
  # Risk Scenario: "NVD cache stale or empty at scan time: system should warn or error, not silently produce zero vulnerabilities"
  # Mock Entity: scenario_007 — nvd_cache last_synced 8 days ago, staleness_threshold = 7 days
  # ---------------------------------------------------------------------------
  Scenario: Scan with stale NVD cache emits staleness warning rather than producing a silent zero-vulnerability SBOM
    Given the repository at "/repos/TaskMatrix" is being scanned
    And the NVD cache last_synced timestamp is "2026-04-01T06:00:00Z" (8 days ago)
    And the configured staleness threshold is 7 days
    When the user runs "sbom-tool scan /repos/TaskMatrix --format cyclonedx --output ./TaskMatrix-sbom.cdx.json"
    Then the tool detects that the cache is 8 days old which exceeds the 7-day threshold
    And at least one of the following staleness signals is emitted:
      | signal_type           | description                                                                 |
      | non_zero_exit_code    | exit code 3 with stderr message "NVD cache is 8 days old (threshold: 7 days)" |
      | sbom_metadata_warning | SBOM metadata field "nvd_cache_staleness_warning" present with age message |
    And the tool does NOT silently produce a zero-vulnerability SBOM for "/repos/TaskMatrix"
    And the staleness message references the "sbom-tool sync" command for remediation
    And stale_cache_detection_score = 1.0   # Staleness condition correctly detected
    And silent_failure_prevention_score = 1.0  # Zero-vuln SBOM not produced without warning


Feature: SBOM Infrastructure — NVD Cache, Deduplication, and Workflow
  As a CLI-based SBOM engine
  I want to manage NVD cache synchronization and OSS tool output deduplication
  So that vulnerability lookups are accurate, fresh, and free of duplicate entries

  # ---------------------------------------------------------------------------
  # Scenario 15: NVD cache on-demand sync — populates local SQLite cache
  # Source: SBOM_POC_Scope.md, In Scope #7
  # Workflow: NVD Sync Workflow — idle → syncing_nvd → updating_cache → sync_complete
  # BDD Focus: "NVD sync: on-demand refresh command populates local cache"
  # Mock Entity: scenario_004 — on_demand sync, 3 new records, 1 updated record
  # ---------------------------------------------------------------------------
  Scenario: On-demand NVD sync command downloads new CVE records and updates the local SQLite cache
    Given the NVD local cache at "./nvd_cache.db" currently contains 8 vulnerability records
    And the cache "last_synced_at" timestamp is "2026-04-09T06:00:00Z"
    And the upstream NVD source has 3 new CVE records and 1 updated record since last sync:
      | cve_id          | type    | purl                          | cvss | severity |
      | CVE-2024-11001  | new     | pkg:pypi/aiohttp@3.8.1        | 7.5  | High     |
      | CVE-2024-11002  | new     | pkg:pypi/pydantic@1.10.4      | 5.0  | Medium   |
      | CVE-2024-11003  | new     | pkg:pypi/tenacity@8.1.0       | 3.1  | Low      |
      | CVE-2023-34540  | update  | pkg:pypi/langchain@0.0.101    | 9.8  | High     |
    When the user runs "sbom-tool sync --source nvd --db ./nvd_cache.db"
    Then the CLI exits with code 0
    And the "sync_log" table contains a new row with "source" equal to "on_demand"
    And the new sync_log row records "records_added" equal to 3
    And the new sync_log row records "records_updated" equal to 1
    And the total vulnerability record count in the cache is now 11
    And the "last_synced_at" value for the new sync_log row is a current timestamp
    And "CVE-2023-34540" "fixed_version" field is updated to the latest value "0.0.300"
    And cache_sync_accuracy_score = 1.0   # Correct record counts added and updated
    And cache_update_completeness = 1.0   # All new and updated records persisted

  # ---------------------------------------------------------------------------
  # Scenario 16: Daily NVD cache sync — triggered by scheduler
  # Source: SBOM_POC_Scope.md, In Scope #7
  # Workflow: NVD Sync Workflow — idle → syncing_nvd (trigger: daily schedule)
  # BDD Focus: "NVD sync: daily schedule trigger populates local cache"
  # ---------------------------------------------------------------------------
  Scenario: Daily scheduled NVD sync completes and records source as scheduled in sync log
    Given the NVD sync service is configured with a daily schedule trigger
    And the current time matches the scheduled daily sync time
    When the scheduler triggers "sbom-tool sync --source nvd --db ./nvd_cache.db"
    Then the CLI exits with code 0
    And the "sync_log" table contains a new row with "source" equal to "scheduled"
    And the new sync_log row has a "synced_at" timestamp within the last 60 seconds
    And the NVD cache "last_synced_at" field advances to the new sync timestamp
    And the sync completes in the background without blocking concurrent scan requests
    And scheduled_sync_trigger_accuracy = 1.0  # sync_log records correct source=scheduled
    And cache_timestamp_update_accuracy = 1.0   # last_synced_at advances correctly

  # ---------------------------------------------------------------------------
  # Scenario 17: Dependency deduplication — Trivy and Syft both report same dep → once in SBOM
  # Source: SBOM_POC_Scope.md, OSS Reuse — Unified output + deduplication row
  # Rule: OSS-First Build Strategy — novel layer: Unified output + deduplication (priority 7)
  # Risk Scenario: "Dependency deduplication: Trivy and Syft report same dependency — output contains it exactly once"
  # Mock Entity: scenario_008 — dual-tool mode, numpy@1.22.0 and scipy@1.6.0 each reported by both Syft and Trivy
  # ---------------------------------------------------------------------------
  Scenario: OSSToolAdapter deduplicates identical PURL entries from Syft and Trivy in dual-tool mode
    Given the OSSToolAdapter is configured in dual-tool mode with both Syft and Trivy
    And both Syft and Trivy are run against the same repository
    And both tools produce the following overlapping raw dependency reports:
      | tool  | name    | version | purl                        |
      | Syft  | numpy   | 1.22.0  | pkg:pypi/numpy@1.22.0       |
      | Trivy | numpy   | 1.22.0  | pkg:pypi/numpy@1.22.0       |
      | Syft  | scipy   | 1.6.0   | pkg:pypi/scipy@1.6.0        |
      | Trivy | scipy   | 1.6.0   | pkg:pypi/scipy@1.6.0        |
    And the deduplication key is "purl"
    When the OSSToolAdapter merges and deduplicates the raw dependency lists
    Then the deduplicated output contains exactly 2 unique dependency entries
    And "pkg:pypi/numpy@1.22.0" appears exactly once in the output
    And "pkg:pypi/scipy@1.6.0" appears exactly once in the output
    And no two entries in the output share the same "purl" value
    And the total raw entry count (4) is reduced to 2 unique entries
    And deduplication_accuracy = 1.0  # All duplicate PURL entries collapsed to one occurrence
    And purl_uniqueness_score = 1.0   # No two output entries share the same PURL

  # ---------------------------------------------------------------------------
  # Scenario 18: No live NVD API call at scan time — network isolation verification
  # Source: SBOM_POC_Scope.md, In Scope #7 and Out of Scope
  # Rule: No Live NVD API Call at Scan Time (priority 6)
  # BDD Focus: "No live NVD API call at scan time: all lookups from local cache only"
  # Success Criteria: "Zero live NVD API calls during scan (verified by network isolation test)"
  # ---------------------------------------------------------------------------
  Scenario: Scan execution makes zero outbound network calls to NVD API endpoints
    Given the repository at "/repos/TaskMatrix" is ready to be scanned
    And network monitoring is active on the test host recording all outbound HTTP/S connections
    And the local NVD cache at "./nvd_cache.db" is populated and fresh
    When the user runs "sbom-tool scan /repos/TaskMatrix --format cyclonedx --output ./TaskMatrix-sbom.cdx.json"
    Then the CLI exits with code 0
    And the network monitor records zero outbound connections to "nvd.nist.gov"
    And the network monitor records zero outbound connections to "services.nvd.nist.gov"
    And all vulnerability lookups are resolved from the local SQLite cache
    And the output SBOM contains the expected vulnerabilities sourced from cache
    And live_nvd_api_call_count = 0          # Zero live API calls to NVD during scan
    And local_cache_lookup_success_rate = 1.0  # All lookups hit local cache, none fall through to network

  # ---------------------------------------------------------------------------
  # Scenario 19: Both output formats produced for the same scan — CycloneDX and SPDX
  # Source: SBOM_POC_Scope.md, In Scope #4 and Key Decisions
  # BDD Focus: "Output format schema compliance: SPDX and CycloneDX JSON pass spec validation"
  # Tests dual-format capability for the same source repository
  # Mock Entity: scan_001 (TaskMatrix) run twice: once as cyclonedx, once as spdx
  # ---------------------------------------------------------------------------
  Scenario: The same repository scan produces both a valid CycloneDX and a valid SPDX output when each format is requested
    Given the repository at "/repos/TaskMatrix" with the same Syft-discovered dependency graph
    And the NVD cache is populated with "CVE-2023-34540" for "langchain@0.0.101"
    When the user runs "sbom-tool scan /repos/TaskMatrix --format cyclonedx --output ./TaskMatrix.cdx.json"
    Then the file "./TaskMatrix.cdx.json" exists and passes CycloneDX 1.4 JSON schema validation
    And the CycloneDX output contains all 8 components and the "CVE-2023-34540" vulnerability entry
    When the user runs "sbom-tool scan /repos/TaskMatrix --format spdx --output ./TaskMatrix.spdx.json"
    Then the file "./TaskMatrix.spdx.json" exists and passes SPDX 2.3 JSON schema validation
    And the SPDX output contains all 8 packages and the "CVE-2023-34540" vulnerability entry
    And the dependency content of both outputs is semantically equivalent
    And cyclonedx_schema_validation_score = 1.0  # CycloneDX output passes format spec
    And spdx_schema_validation_score = 1.0       # SPDX output passes format spec
    And cross_format_content_consistency_score >= 0.95  # Both formats represent the same scan data

  # ---------------------------------------------------------------------------
  # Scenario 20: Scan workflow state transitions complete end-to-end for TaskMatrix
  # Source: SBOM_POC_Scope.md, In Scope #1–#6 and OSS Reuse table
  # Workflow: Scan Workflow — idle → scanning_dependencies → deduplicating_output →
  #           matching_vulnerabilities → filtering_vex → enriching_remediation → exporting_sbom → idle
  # Rule: Single Repository Per Scan (priority 1) — guard at idle → scanning_dependencies
  # Rule: No Live NVD API Call at Scan Time (priority 6) — guard at matching_vulnerabilities
  # ---------------------------------------------------------------------------
  Scenario: Complete scan workflow traverses all seven stages for TaskMatrix and produces enriched SBOM
    Given the sbom-tool scan workflow is in "idle" state
    And the user invokes the CLI with a single repository "/repos/TaskMatrix" and a single environment "development"
    And the single-repository and single-environment guards are satisfied
    When the workflow transitions from "idle" to "scanning_dependencies"
    Then Syft scans "/repos/TaskMatrix" and discovers the dependency graph (8 packages)
    When the workflow transitions from "scanning_dependencies" to "deduplicating_output"
    Then the OSSToolAdapter merges tool outputs and removes any duplicate PURLs
    When the workflow transitions from "deduplicating_output" to "matching_vulnerabilities"
    Then Grype matches deduplicated package PURLs against the local NVD cache without live API calls
    When the workflow transitions from "matching_vulnerabilities" to "filtering_vex"
    Then OpenVEX applies the VEX filter document and marks suppressed vulnerabilities
    When the workflow transitions from "filtering_vex" to "enriching_remediation"
    Then the RemediationEngine adds "advisory_link" and "remediation_recommendation" to each active vulnerability
    When the workflow transitions from "enriching_remediation" to "exporting_sbom"
    Then the SBOMDocument is serialized to "./TaskMatrix-sbom.cdx.json" in CycloneDX 1.4 format
    When the workflow transitions from "exporting_sbom" to "idle"
    Then the output file is schema-valid and the CLI exits with code 0
    And workflow_stage_completion_rate = 1.0   # All 7 stages completed without interruption
    And workflow_guard_enforcement_score = 1.0  # Single-repo and cache-only guards enforced
    And end_to_end_scan_success_rate = 1.0      # Final SBOM written and CLI exits 0
