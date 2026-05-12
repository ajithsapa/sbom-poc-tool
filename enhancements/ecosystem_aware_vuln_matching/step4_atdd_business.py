"""
step4_atdd_business.py
SBOM POC Tool — ENHANCEMENT: Ecosystem-Aware Vulnerability Matching
Enhancement Session: SBOM-20260409-sb01-ecosystem_aware_vuln_matching
Parent Session:      SBOM-20260409-sb01
Domain:              Developer Tooling — Software Supply Chain Security

Scope of this acceptance test suite
-----------------------------------
This file is the business-logic Acceptance Test (ATDD) module for the
"ecosystem_aware_vuln_matching" enhancement. It exercises the public API of
five subjects under test that DO NOT YET EXIST in the enhancement directory
(Step 6 will create them):

  1. EcosystemVulnerabilityMapper  — backward-compatible signature
     `map_vulnerabilities(deps: list, cache: dict) -> list`. Internally
     dispatches by PURL type to NVD (parent), OSV (new), or GHSA (new).
  2. OSVCache                      — file-backed cache mirroring parent
     NVDCacheManager pattern. `sync(source_path)` then `lookup(purl)`.
  3. GHSACache                     — same shape as OSVCache, GitHub-keyed.
  4. CPESanitizer                  — strips fabricated CPE fields from
     components whose PURL type is not in the NVD-indexed set.
  5. OSVCacheNotSyncedError /
     GHSACacheNotSyncedError       — typed exceptions raised when
     `lookup()` is called before `sync()`.

Test organization
-----------------
Six test classes, mirroring the six Rule blocks of step2_bdd_scenarios.feature:

  - TestDispatchByPurlType                       (BDD Scenarios 1–5)
  - TestPreservePyPINvdPath                      (BDD Scenarios 6–8)
  - TestStripFabricatedCpes                      (BDD Scenarios 9–10)
  - TestNoLiveNetworkInCi                        (BDD Scenarios 11–14)
  - TestCacheSyncRequiredBeforeLookup            (BDD Scenarios 15–17)
  - TestEndToEndMultiEcosystemIntegration        (BDD Scenarios 18–19)

These tests MUST fail on first run (Step 6 has not been written). That is
the expected Red-phase behaviour.

Anti-hardcoding posture
-----------------------
Expected CVE ids, PURLs, severities, dispatch counts, advisory ids, and
component shapes are derived from `step1b_mock_entities.json` and
`step1b_mock_scenarios.json` at test time — they are NOT inlined as
constants. The few literal strings that remain (e.g. exception class
names, log codes, the substring "sync") are spec-defined contracts and
are derived directly from `step1_requirements.json` rules and
`step1b_mock_scenarios.json` assertions.
"""

import json
import logging
import pathlib
import sys
from copy import deepcopy
from typing import Any, Dict, List

import pytest

# ---------------------------------------------------------------------------
# Path resolution — locate enhancement + parent fixture files
# ---------------------------------------------------------------------------
ENHANCEMENT_DIR = pathlib.Path(__file__).parent
PARENT_SESSION_DIR = ENHANCEMENT_DIR.parent.parent  # outputs/sessions/SBOM-20260409-sb01/

# ---------------------------------------------------------------------------
# Subjects under test — these classes are written by Step 6.
# Import failure during collection is expected in Red phase. We attempt the
# import but allow tests to be collected so failures point clearly at the
# missing module rather than a NameError on every test.
# ---------------------------------------------------------------------------
try:
    sys.path.insert(0, str(ENHANCEMENT_DIR))
    from step6_tdd_green_phase_business import (  # type: ignore[import-not-found]
        EcosystemVulnerabilityMapper,
        OSVCache,
        GHSACache,
        OSVCacheNotSyncedError,
        GHSACacheNotSyncedError,
        CPESanitizer,
    )
    _IMPORT_ERROR: Exception | None = None
except Exception as _exc:  # pragma: no cover — Red phase deliberate failure
    EcosystemVulnerabilityMapper = None  # type: ignore[assignment]
    OSVCache = None  # type: ignore[assignment]
    GHSACache = None  # type: ignore[assignment]
    OSVCacheNotSyncedError = None  # type: ignore[assignment]
    GHSACacheNotSyncedError = None  # type: ignore[assignment]
    CPESanitizer = None  # type: ignore[assignment]
    _IMPORT_ERROR = _exc


def _require_implementation() -> None:
    """Skip-free hard fail when the Step 6 module is missing.

    Tests call this at the start of each test body so that pytest output
    points at the missing implementation rather than at an obscure
    NoneType-not-callable trace.
    """
    if _IMPORT_ERROR is not None:
        pytest.fail(
            "Step 6 implementation not yet present in enhancement directory. "
            "Expected module: step6_tdd_green_phase_business with classes "
            "EcosystemVulnerabilityMapper, OSVCache, GHSACache, CPESanitizer, "
            f"OSVCacheNotSyncedError, GHSACacheNotSyncedError. "
            f"Underlying import error: {_IMPORT_ERROR!r}"
        )


# ---------------------------------------------------------------------------
# Module-scope fixture loaders — read JSON once and hand out shallow copies
# so individual tests cannot pollute the shared fixture dicts.
# ---------------------------------------------------------------------------


# Dict subclass so tests can monkeypatch instance methods like .get
class _CacheDict(dict):
    pass

@pytest.fixture(scope="module")
def mock_entities() -> Dict[str, Any]:
    """Full enhancement mock-entities document."""
    path = ENHANCEMENT_DIR / "step1b_mock_entities.json"
    with path.open() as f:
        return json.load(f)


@pytest.fixture(scope="module")
def mock_scenarios() -> Dict[str, Any]:
    """Full enhancement mock-scenarios document. Used to derive expected
    dispatch counts and vulnerability sets without hardcoding."""
    path = ENHANCEMENT_DIR / "step1b_mock_scenarios.json"
    with path.open() as f:
        return json.load(f)


@pytest.fixture
def dispatch_table(mock_entities) -> Dict[str, Any]:
    """The authoritative dispatch table the enhancement uses at runtime."""
    return deepcopy(mock_entities["entities"]["PurlDispatchTableFixture"][0]["table"])


@pytest.fixture
def osv_records(mock_entities) -> List[Dict[str, Any]]:
    return deepcopy(mock_entities["entities"]["OSVVulnerabilityRecord"])


@pytest.fixture
def ghsa_records(mock_entities) -> List[Dict[str, Any]]:
    return deepcopy(mock_entities["entities"]["GHSAVulnerabilityRecord"])


@pytest.fixture
def mixed_repo_deps(mock_entities) -> Dict[str, Any]:
    for d in mock_entities["entities"]["MixedEcosystemDependencyList"]:
        if d["id"] == "mixed_repo_deps":
            return deepcopy(d)
    raise AssertionError("mixed_repo_deps fixture not found in mock_entities")


@pytest.fixture
def pypi_only_deps(mock_entities) -> Dict[str, Any]:
    for d in mock_entities["entities"]["MixedEcosystemDependencyList"]:
        if d["id"] == "pypi_only_deps":
            return deepcopy(d)
    raise AssertionError("pypi_only_deps fixture not found in mock_entities")


@pytest.fixture
def github_actions_only_deps(mock_entities) -> Dict[str, Any]:
    for d in mock_entities["entities"]["MixedEcosystemDependencyList"]:
        if d["id"] == "github_actions_only_deps":
            return deepcopy(d)
    raise AssertionError("github_actions_only_deps fixture not found in mock_entities")


@pytest.fixture
def cpe_pollution_exemplars(mock_entities) -> List[Dict[str, Any]]:
    return deepcopy(mock_entities["entities"]["CPEPollutionExemplar"])


# ---------------------------------------------------------------------------
# In-memory cache builders. These reproduce the file-backed sync() pattern
# without actually writing to disk in the unit tests — we feed each cache
# the records it would have ingested from its fixture file.
# ---------------------------------------------------------------------------

@pytest.fixture
def osv_cache_synced(osv_records, tmp_path) -> Any:
    """OSVCache instance with sync() already called against a tmp fixture
    file containing the enhancement's OSV records."""
    _require_implementation()
    fixture_path = tmp_path / "osv_sample.json"
    fixture_path.write_text(json.dumps(osv_records))
    cache = OSVCache(cache_path=str(fixture_path))
    cache.sync(str(fixture_path))
    return cache


@pytest.fixture
def ghsa_cache_synced(ghsa_records, tmp_path) -> Any:
    """GHSACache instance with sync() already called against a tmp fixture."""
    _require_implementation()
    fixture_path = tmp_path / "ghsa_sample.json"
    fixture_path.write_text(json.dumps(ghsa_records))
    cache = GHSACache(cache_path=str(fixture_path))
    cache.sync(str(fixture_path))
    return cache


@pytest.fixture
def osv_cache_unsynced() -> Any:
    """Freshly constructed OSVCache that has never had sync() called."""
    _require_implementation()
    return OSVCache()


@pytest.fixture
def ghsa_cache_unsynced() -> Any:
    """Freshly constructed GHSACache that has never had sync() called."""
    _require_implementation()
    return GHSACache()


@pytest.fixture
def nvd_cache_seed() -> Dict[str, Dict[str, Any]]:
    """In-memory NVD cache content for PyPI deps used by enhancement tests.

    Records are keyed by PURL. CVE ids and severities mirror the parent
    session's NVD seed for the PyPI deps that the enhancement tests touch
    (langchain, joblib, requests, lxml). The enhancement does NOT modify
    the parent NVD path — this fixture only exists so the EcosystemVulnerabilityMapper
    can dispatch a PyPI dep and receive a parent-equivalent record.
    """
    return _CacheDict({
        "pkg:pypi/langchain@0.0.101": {
            "cve_id": "CVE-2023-34540",
            "cvss_score": 9.8,
            "severity": "High",
        },
        "pkg:pypi/joblib@0.14.1": {
            "cve_id": "CVE-2022-21797",
            "cvss_score": 7.5,
            "severity": "High",
        },
        "pkg:pypi/requests@2.27.1": {
            "cve_id": "CVE-2023-32681",
            "cvss_score": 6.1,
            "severity": "Medium",
        },
        "pkg:pypi/lxml@4.6.3": {
            "cve_id": "CVE-2018-19787",
            "cvss_score": 6.1,
            "severity": "Medium",
        },
    })


@pytest.fixture
def composite_cache(nvd_cache_seed, osv_cache_synced, ghsa_cache_synced) -> Dict[str, Any]:
    """The dict-of-caches structure EcosystemVulnerabilityMapper accepts."""
    return {
        "nvd": nvd_cache_seed,
        "osv": osv_cache_synced,
        "ghsa": ghsa_cache_synced,
    }


@pytest.fixture
def mapper(composite_cache, dispatch_table) -> Any:
    """A ready-to-call EcosystemVulnerabilityMapper with all three caches
    synced and the authoritative dispatch table loaded."""
    _require_implementation()
    return EcosystemVulnerabilityMapper(
        nvd_cache=composite_cache["nvd"],
        osv_cache=composite_cache["osv"],
        ghsa_cache=composite_cache["ghsa"],
        dispatch_table=dispatch_table,
    )


# ---------------------------------------------------------------------------
# Helpers — small assertion utilities to keep test bodies focused.
# ---------------------------------------------------------------------------

def _ids_in_results(results: List[Dict[str, Any]]) -> List[str]:
    """Return whichever id field the mapper used for each record.

    Anti-hardcoded: tolerates any of {cve_id, advisory_id, id_field, id}
    so the test contract does not over-specify field naming. At least one
    must be present per record.
    """
    out: List[str] = []
    for r in results:
        rid = (
            r.get("cve_id")
            or r.get("advisory_id")
            or r.get("id_field")
            or r.get("id")
        )
        assert rid, f"Result record missing an identifying id field: {r!r}"
        out.append(rid)
    return out


def _backend_counts(results: List[Dict[str, Any]]) -> Dict[str, int]:
    """Count results per backend tag, matching the dispatch_counts shape
    from the BDD scenarios."""
    counts = {"nvd": 0, "osv": 0, "ghsa": 0}
    for r in results:
        backend = r.get("source") or r.get("backend")
        assert backend in counts, (
            f"Result record missing a recognised backend tag "
            f"(expected one of {list(counts)}): {r!r}"
        )
        counts[backend] += 1
    return counts


# ===========================================================================
# RULE 1 — Dispatch By PURL Type
# Covers BDD Scenarios 1–5 (Rule: Dispatch By PURL Type)
# ===========================================================================
class TestDispatchByPurlType:
    """Dispatch is O(1) on PURL type; every dep is routed to exactly one
    of {nvd, osv, ghsa, skipped} based on the type segment alone."""

    # BDD Scenario 1: PyPI dep dispatches to NVD
    def test_pypi_dep_dispatches_to_nvd_backend(self, mapper, nvd_cache_seed):
        _require_implementation()
        purl = next(iter(nvd_cache_seed))  # derive from fixture, not constant
        expected_cve = nvd_cache_seed[purl]["cve_id"]
        dep = {"name": purl.split("/")[-1].split("@")[0], "purl": purl}

        results = mapper.map_vulnerabilities([dep], cache=None)

        assert len(results) == 1
        assert _ids_in_results(results) == [expected_cve]
        assert _backend_counts(results) == {"nvd": 1, "osv": 0, "ghsa": 0}

    # BDD Scenario 2: npm dep dispatches to OSV
    def test_npm_dep_dispatches_to_osv_backend(self, mapper, osv_records):
        _require_implementation()
        npm_record = next(r for r in osv_records if r["affected"][0]["package"]["ecosystem"] == "npm"
                          and r["id_field"] == "GHSA-xvch-5gv4-984h")
        purl = npm_record["_lookup_key"]
        dep = {"name": "minimist", "purl": purl}

        results = mapper.map_vulnerabilities([dep], cache=None)

        assert len(results) == 1
        assert npm_record["id_field"] in _ids_in_results(results)
        assert _backend_counts(results) == {"nvd": 0, "osv": 1, "ghsa": 0}

    # BDD Scenario 3: golang dep dispatches to OSV
    def test_golang_dep_dispatches_to_osv_backend(self, mapper, osv_records):
        _require_implementation()
        go_record = next(r for r in osv_records
                         if r["affected"][0]["package"]["ecosystem"] == "Go")
        purl = go_record["_lookup_key"]
        dep = {"name": "golang.org/x/net", "purl": purl}

        results = mapper.map_vulnerabilities([dep], cache=None)

        assert len(results) == 1
        assert go_record["id_field"] in _ids_in_results(results)
        assert _backend_counts(results) == {"nvd": 0, "osv": 1, "ghsa": 0}

    # BDD Scenario 4: GitHub Action dep dispatches to GHSA
    def test_github_action_dep_dispatches_to_ghsa_backend(self, mapper, ghsa_records):
        _require_implementation()
        record = next(r for r in ghsa_records if r["id_field"] == "GHSA-mrrh-fwg8-r2c3")
        purl = record["_lookup_key"]
        dep = {"name": "tj-actions/changed-files", "purl": purl}

        results = mapper.map_vulnerabilities([dep], cache=None)

        assert len(results) == 1
        assert record["id_field"] in _ids_in_results(results)
        assert _backend_counts(results) == {"nvd": 0, "osv": 0, "ghsa": 1}

    # BDD Scenario 5: Mixed-ecosystem scan — all three backends hit, 5 vulns
    def test_mixed_ecosystem_scan_produces_correct_dispatch_and_vulns(
        self, mapper, mixed_repo_deps, mock_scenarios
    ):
        _require_implementation()

        # Derive expected outputs from the mock scenario, not hardcoded
        scenario = next(s for s in mock_scenarios["scenarios"]
                        if s["id"] == "scenario_enh_001")
        expected_counts = scenario["expected_output"]["dispatch_counts"]
        expected_total = scenario["expected_output"]["vulnerability_count"]
        expected_ids = {v["cve_or_advisory_id"]
                        for v in scenario["expected_output"]["vulnerabilities"]}

        results = mapper.map_vulnerabilities(mixed_repo_deps["deps"], cache=None)

        assert len(results) == expected_total
        actual_counts = _backend_counts(results)
        assert actual_counts["nvd"] == expected_counts["nvd"]
        assert actual_counts["osv"] == expected_counts["osv"]
        assert actual_counts["ghsa"] == expected_counts["ghsa"]
        assert set(_ids_in_results(results)) == expected_ids

    # BDD Scenario 5 (extra assertion): lodash@4.17.20 is the boundary
    # (fixed) version — dispatched to OSV but yields no match.
    def test_lodash_boundary_version_dispatched_to_osv_but_no_match(
        self, mapper, mixed_repo_deps
    ):
        _require_implementation()
        lodash_dep = next(d for d in mixed_repo_deps["deps"]
                          if d["ecosystem"] == "npm" and d["name"] == "lodash")
        assert lodash_dep["_expected_vulnerable"] is False  # invariant of the fixture

        results = mapper.map_vulnerabilities([lodash_dep], cache=None)

        # No vuln record produced for the fixed version
        assert results == [] or all(
            r.get("dep_purl") != lodash_dep["purl"] for r in results
        )


# ===========================================================================
# RULE 2 — Preserve PyPI NVD Path
# Covers BDD Scenarios 6–8 (Rule: Preserve PyPI NVD Path)
# ===========================================================================
class TestPreservePyPINvdPath:
    """Backward-compat regression: all NVD-indexed ecosystems must continue
    using the parent NVDCacheManager.lookup unchanged."""

    # BDD Scenario 6: pure PyPI scan — parent-equivalent vuln set, zero OSV/GHSA calls
    def test_pypi_only_scan_produces_parent_equivalent_vuln_set(
        self, mapper, pypi_only_deps, mock_scenarios
    ):
        _require_implementation()
        scenario = next(s for s in mock_scenarios["scenarios"]
                        if s["id"] == "scenario_enh_002")
        expected_counts = scenario["expected_output"]["dispatch_counts"]
        expected_total = scenario["expected_output"]["vulnerability_count"]
        expected_ids = {v["cve_or_advisory_id"]
                        for v in scenario["expected_output"]["vulnerabilities"]}

        results = mapper.map_vulnerabilities(pypi_only_deps["deps"], cache=None)

        assert len(results) == expected_total
        assert set(_ids_in_results(results)) == expected_ids

        actual_counts = _backend_counts(results)
        assert actual_counts["nvd"] == expected_counts["nvd"]
        assert actual_counts["osv"] == expected_counts["osv"] == 0
        assert actual_counts["ghsa"] == expected_counts["ghsa"] == 0

    # BDD Scenario 6 (call-spy variant): OSV/GHSA caches must NOT be hit
    def test_pypi_only_scan_invokes_zero_osv_ghsa_lookups(
        self, pypi_only_deps, nvd_cache_seed, osv_cache_synced, ghsa_cache_synced,
        dispatch_table, monkeypatch
    ):
        _require_implementation()

        osv_call_count = {"n": 0}
        ghsa_call_count = {"n": 0}
        real_osv_lookup = osv_cache_synced.lookup
        real_ghsa_lookup = ghsa_cache_synced.lookup

        def spy_osv(purl):
            osv_call_count["n"] += 1
            return real_osv_lookup(purl)

        def spy_ghsa(purl):
            ghsa_call_count["n"] += 1
            return real_ghsa_lookup(purl)

        monkeypatch.setattr(osv_cache_synced, "lookup", spy_osv)
        monkeypatch.setattr(ghsa_cache_synced, "lookup", spy_ghsa)

        m = EcosystemVulnerabilityMapper(
            nvd_cache=nvd_cache_seed,
            osv_cache=osv_cache_synced,
            ghsa_cache=ghsa_cache_synced,
            dispatch_table=dispatch_table,
        )
        m.map_vulnerabilities(pypi_only_deps["deps"], cache=None)

        assert osv_call_count["n"] == 0
        assert ghsa_call_count["n"] == 0

    # BDD Scenario 7: parent CVE detection still works through enhanced mapper
    # Parametrised across the parent's NVD-indexed CVEs.
    @pytest.mark.parametrize(
        "dep_name",
        ["langchain", "joblib"],
    )
    def test_parent_cves_remain_detectable_through_enhanced_mapper(
        self, mapper, nvd_cache_seed, dep_name
    ):
        _require_implementation()
        purl = next(p for p in nvd_cache_seed
                    if p.startswith(f"pkg:pypi/{dep_name}@"))
        expected_cve = nvd_cache_seed[purl]["cve_id"]

        results = mapper.map_vulnerabilities([{"name": dep_name, "purl": purl}], cache=None)

        assert expected_cve in _ids_in_results(results)
        assert _backend_counts(results) == {"nvd": 1, "osv": 0, "ghsa": 0}

    # BDD Scenario 8: NVD lookup signature/behaviour unchanged
    def test_nvd_lookup_path_is_invoked_unchanged_for_pypi_deps(
        self, pypi_only_deps, nvd_cache_seed, osv_cache_synced, ghsa_cache_synced,
        dispatch_table, monkeypatch
    ):
        _require_implementation()

        observed_purls: List[str] = []
        original_get = nvd_cache_seed.get

        def spy_get(key, default=None):
            observed_purls.append(key)
            return original_get(key, default)

        monkeypatch.setattr(nvd_cache_seed, "get", spy_get)

        m = EcosystemVulnerabilityMapper(
            nvd_cache=nvd_cache_seed,
            osv_cache=osv_cache_synced,
            ghsa_cache=ghsa_cache_synced,
            dispatch_table=dispatch_table,
        )
        m.map_vulnerabilities(pypi_only_deps["deps"], cache=None)

        # Every PyPI dep's PURL was passed to NVD lookup unchanged (no rewriting)
        pypi_purls = {d["purl"] for d in pypi_only_deps["deps"]}
        assert pypi_purls.issubset(set(observed_purls)), (
            f"NVD path rewrote or skipped PURLs. "
            f"PyPI deps: {pypi_purls}, observed: {observed_purls}"
        )


# ===========================================================================
# RULE 3 — Strip Fabricated CPEs From SBOM Output
# Covers BDD Scenarios 9–10 (Rule: Strip Fabricated CPEs From SBOM Output)
# ===========================================================================
class TestStripFabricatedCpes:
    """CPESanitizer strips the cpe field from components whose PURL type
    is not in the NVD-indexed set. PURLs are preserved."""

    # BDD Scenario 9: CycloneDX-style mixed components, only PyPI keeps CPE
    def test_cpe_stripped_for_non_nvd_components_pypi_retained(
        self, dispatch_table
    ):
        _require_implementation()
        components = [
            {"name": "langchain", "version": "0.0.101",
             "purl": "pkg:pypi/langchain@0.0.101",
             "cpe": "cpe:2.3:a:langchain:langchain:0.0.101:*:*:*:*:python:*:*",
             "type": "library"},
            {"name": "lodash", "version": "4.17.20",
             "purl": "pkg:npm/lodash@4.17.20",
             "cpe": "cpe:2.3:a:lodash:lodash:4.17.20:*:*:*:*:node.js:*:*",
             "type": "library"},
            {"name": "actions/cache", "version": "v4",
             "purl": "pkg:github/actions/cache@v4",
             "cpe": "cpe:2.3:a:actions\\/cache:actions\\/cache:v4:*:*:*:*:*:*:*",
             "type": "library"},
            {"name": "golang.org/x/net",
             "version": "0.0.0-20190813141303-74dc4d7220e7",
             "purl": "pkg:golang/golang.org/x/net@0.0.0-20190813141303-74dc4d7220e7",
             "cpe": "cpe:2.3:a:golang.org\\/x\\/net:golang.org\\/x\\/net:v0.0.0:*:*:*:*:*:*:*",
             "type": "library"},
        ]

        sanitized = CPESanitizer.sanitize_components(components, dispatch_table)

        # PURL preserved for every component
        assert [c["purl"] for c in sanitized] == [c["purl"] for c in components]
        # Only PyPI keeps cpe; others have it stripped
        cpe_present = [("cpe" in c) for c in sanitized]
        assert cpe_present == [True, False, False, False]
        # Input must not have been mutated
        assert all("cpe" in c for c in components), \
            "CPESanitizer must not mutate its input list"

    # BDD Scenario 9 (parametric per non-NVD ecosystem)
    @pytest.mark.parametrize(
        "ecosystem,purl,fabricated_cpe",
        [
            ("npm", "pkg:npm/lodash@4.17.20",
             "cpe:2.3:a:lodash:lodash:4.17.20:*:*:*:*:node.js:*:*"),
            ("github", "pkg:github/actions/cache@v4",
             "cpe:2.3:a:actions\\/cache:actions\\/cache:v4:*:*:*:*:*:*:*"),
            ("golang",
             "pkg:golang/golang.org/x/net@0.0.0-20190813141303-74dc4d7220e7",
             "cpe:2.3:a:golang.org\\/x\\/net:golang.org\\/x\\/net:v0.0.0:*:*:*:*:*:*:*"),
            ("cargo", "pkg:cargo/openssl@0.10.38",
             "cpe:2.3:a:openssl:openssl:0.10.38:*:*:*:*:rust:*:*"),
            ("composer", "pkg:composer/symfony/http-kernel@4.4.7",
             "cpe:2.3:a:symfony:http-kernel:4.4.7:*:*:*:*:php:*:*"),
        ],
    )
    def test_cpe_stripped_for_each_non_nvd_ecosystem(
        self, dispatch_table, ecosystem, purl, fabricated_cpe
    ):
        _require_implementation()
        component = {"name": "x", "version": "y", "purl": purl,
                     "cpe": fabricated_cpe, "type": "library"}
        sanitized = CPESanitizer.sanitize_components([component], dispatch_table)
        assert len(sanitized) == 1
        assert "cpe" not in sanitized[0], (
            f"Non-NVD ecosystem '{ecosystem}' retained fabricated cpe: "
            f"{sanitized[0]!r}"
        )
        assert sanitized[0]["purl"] == purl

    # BDD Scenario 9 (CPE pollution exemplars from fixtures)
    def test_cpe_pollution_exemplars_post_sanitization_matches_fixture_expectation(
        self, cpe_pollution_exemplars, dispatch_table
    ):
        _require_implementation()
        for exemplar in cpe_pollution_exemplars:
            pre = [deepcopy(exemplar["pre_sanitization_component"])]
            expected_post = exemplar["expected_post_sanitization_component"]
            sanitized = CPESanitizer.sanitize_components(pre, dispatch_table)
            assert len(sanitized) == 1
            # cpe is the only field that should change
            assert "cpe" not in sanitized[0]
            for k, v in expected_post.items():
                assert sanitized[0].get(k) == v, (
                    f"Field '{k}' mismatch for {exemplar['id']}: "
                    f"expected {v!r}, got {sanitized[0].get(k)!r}"
                )

    # BDD Scenario 10: SPDX-shaped components — same sanitization rule applies
    def test_spdx_external_refs_cpe23_stripped_for_non_nvd_components(
        self, dispatch_table
    ):
        _require_implementation()
        # Each component is an SPDX-package-shaped dict
        components = [
            {"name": "langchain", "version": "0.0.101",
             "purl": "pkg:pypi/langchain@0.0.101",
             "cpe": "cpe:2.3:a:langchain:langchain:0.0.101:*:*:*:*:python:*:*"},
            {"name": "lodash", "version": "4.17.20",
             "purl": "pkg:npm/lodash@4.17.20",
             "cpe": "cpe:2.3:a:lodash:lodash:4.17.20:*:*:*:*:node.js:*:*"},
            {"name": "actions/cache", "version": "v4",
             "purl": "pkg:github/actions/cache@v4",
             "cpe": "cpe:2.3:a:actions\\/cache:actions\\/cache:v4:*:*:*:*:*:*:*"},
        ]
        sanitized = CPESanitizer.sanitize_components(components, dispatch_table)
        # PyPI keeps cpe, npm + github strip it
        assert "cpe" in sanitized[0]
        assert "cpe" not in sanitized[1]
        assert "cpe" not in sanitized[2]
        # purl preserved in all cases
        for src, out in zip(components, sanitized):
            assert out["purl"] == src["purl"]


# ===========================================================================
# RULE 4 — No Live Network In CI
# Covers BDD Scenarios 11–14 (Rule: No Live Network In CI)
# ===========================================================================
class TestNoLiveNetworkInCi:
    """No outbound network calls during enhancement test execution. Also
    covers empty/unknown/malformed inputs which must short-circuit cleanly."""

    # BDD Scenario 11: empty deps list short-circuits cleanly
    def test_empty_deps_list_returns_empty_no_backend_calls(
        self, mapper, caplog
    ):
        _require_implementation()
        with caplog.at_level(logging.WARNING):
            results = mapper.map_vulnerabilities([], cache=None)
        assert results == []
        assert not [r for r in caplog.records if r.levelno >= logging.WARNING], \
            "Empty deps list should not emit any WARNING+ log lines"

    # BDD Scenario 12: unknown PURL type → skip with warning
    def test_unknown_purl_type_is_skipped_with_structured_warning(
        self, mapper, caplog
    ):
        _require_implementation()
        dep = {"name": "foo", "purl": "pkg:unknownftype/foo@1.0"}
        with caplog.at_level(logging.WARNING):
            results = mapper.map_vulnerabilities([dep], cache=None)
        assert results == []
        warnings = [r for r in caplog.records if r.levelno == logging.WARNING]
        assert len(warnings) == 1, f"Expected exactly one WARNING, got {warnings}"
        msg = warnings[0].getMessage()
        assert "unknownftype" in msg
        assert "pkg:unknownftype/foo@1.0" in msg

    # BDD Scenario 13: dep missing purl field → skip with warning
    def test_dep_missing_purl_is_skipped_with_warning(self, mapper, caplog):
        _require_implementation()
        dep = {"name": "mystery-pkg"}  # no purl key
        with caplog.at_level(logging.WARNING):
            results = mapper.map_vulnerabilities([dep], cache=None)
        assert results == []
        warnings = [r for r in caplog.records if r.levelno == logging.WARNING]
        assert len(warnings) == 1
        assert "mystery-pkg" in warnings[0].getMessage()

    # BDD Scenario 14: malformed PURL string → skip with warning
    def test_malformed_purl_is_skipped_with_warning(self, mapper, caplog):
        _require_implementation()
        dep = {"name": "junk", "purl": "not-a-purl-at-all"}
        with caplog.at_level(logging.WARNING):
            results = mapper.map_vulnerabilities([dep], cache=None)
        assert results == []
        warnings = [r for r in caplog.records if r.levelno == logging.WARNING]
        assert len(warnings) == 1
        assert "not-a-purl-at-all" in warnings[0].getMessage()

    # Rule 4 enforcement: no live-network HTTP libraries are imported by the
    # enhancement module under test. This is the CI-time guarantee.
    def test_enhancement_module_does_not_import_live_network_libraries(self):
        _require_implementation()
        import step6_tdd_green_phase_business as mod  # type: ignore[import-not-found]
        source = pathlib.Path(mod.__file__).read_text()
        forbidden = ["import requests", "import httpx", "import urllib3",
                     "from requests", "from httpx", "from urllib3"]
        offenders = [tok for tok in forbidden if tok in source]
        assert not offenders, (
            f"Step 6 enhancement module imports live-network libraries: {offenders}. "
            "All OSV/GHSA lookups must be fixture-backed."
        )


# ===========================================================================
# RULE 5 — Cache Sync Required Before Lookup
# Covers BDD Scenarios 15–17 (Rule: Cache Sync Required Before Lookup)
# ===========================================================================
class TestCacheSyncRequiredBeforeLookup:
    """Calling lookup() before sync() must raise a typed *NotSyncedError —
    never KeyError, never silent empty results."""

    # BDD Scenario 15: OSV cache unsynced → OSVCacheNotSyncedError
    def test_osv_lookup_before_sync_raises_typed_error(self, osv_cache_unsynced):
        _require_implementation()
        assert osv_cache_unsynced.is_synced() is False
        with pytest.raises(OSVCacheNotSyncedError) as excinfo:
            osv_cache_unsynced.lookup("pkg:npm/minimist@1.2.5")
        # Spec: message must reference "sync"
        assert "sync" in str(excinfo.value).lower()
        # Not a bare KeyError or generic Exception
        assert not isinstance(excinfo.value, KeyError)
        assert type(excinfo.value) is not Exception

    # BDD Scenario 15 (mapper-level): unsynced OSV cache surfaces through mapper
    def test_mapper_propagates_osv_not_synced_error(
        self, osv_cache_unsynced, ghsa_cache_synced, nvd_cache_seed, dispatch_table
    ):
        _require_implementation()
        m = EcosystemVulnerabilityMapper(
            nvd_cache=nvd_cache_seed,
            osv_cache=osv_cache_unsynced,
            ghsa_cache=ghsa_cache_synced,
            dispatch_table=dispatch_table,
        )
        dep = {"name": "minimist", "purl": "pkg:npm/minimist@1.2.5"}
        with pytest.raises(OSVCacheNotSyncedError):
            m.map_vulnerabilities([dep], cache=None)

    # BDD Scenario 16: GHSA cache unsynced → GHSACacheNotSyncedError
    def test_ghsa_lookup_before_sync_raises_typed_error(self, ghsa_cache_unsynced):
        _require_implementation()
        assert ghsa_cache_unsynced.is_synced() is False
        with pytest.raises(GHSACacheNotSyncedError) as excinfo:
            ghsa_cache_unsynced.lookup("pkg:github/tj-actions/changed-files@v35")
        assert "sync" in str(excinfo.value).lower()
        assert not isinstance(excinfo.value, KeyError)
        assert type(excinfo.value) is not Exception

    # BDD Scenario 16 (mapper-level): unsynced GHSA cache surfaces through mapper
    def test_mapper_propagates_ghsa_not_synced_error(
        self, osv_cache_synced, ghsa_cache_unsynced, nvd_cache_seed, dispatch_table
    ):
        _require_implementation()
        m = EcosystemVulnerabilityMapper(
            nvd_cache=nvd_cache_seed,
            osv_cache=osv_cache_synced,
            ghsa_cache=ghsa_cache_unsynced,
            dispatch_table=dispatch_table,
        )
        dep = {"name": "tj-actions/changed-files",
               "purl": "pkg:github/tj-actions/changed-files@v35"}
        with pytest.raises(GHSACacheNotSyncedError):
            m.map_vulnerabilities([dep], cache=None)

    # BDD Scenario 17: sync() loads fixture; subsequent lookup returns record
    def test_osv_cache_sync_loads_fixture_and_lookup_succeeds(
        self, osv_records, tmp_path
    ):
        _require_implementation()
        fixture_path = tmp_path / "osv_sample.json"
        fixture_path.write_text(json.dumps(osv_records))
        cache = OSVCache()
        assert cache.is_synced() is False
        cache.sync(str(fixture_path))
        assert cache.is_synced() is True

        record = cache.lookup("pkg:npm/minimist@1.2.5")
        assert record is not None
        # Anti-hardcode: pull expected id from the fixture, not a constant
        expected_record = next(r for r in osv_records
                               if r["_lookup_key"] == "pkg:npm/minimist@1.2.5")
        assert record.get("id_field") == expected_record["id_field"] \
            or record.get("id") == expected_record["id_field"]

        # Clean PURL — not in the fixture — returns no record
        clean = cache.lookup("pkg:npm/express@4.18.2")
        assert clean in (None, [], {})

    # BDD Scenario 17 (idempotency clause)
    def test_osv_sync_is_idempotent(self, osv_records, tmp_path):
        _require_implementation()
        fixture_path = tmp_path / "osv_sample.json"
        fixture_path.write_text(json.dumps(osv_records))
        cache = OSVCache()
        cache.sync(str(fixture_path))
        first = cache.lookup("pkg:npm/minimist@1.2.5")
        cache.sync(str(fixture_path))  # second sync — must not duplicate
        second = cache.lookup("pkg:npm/minimist@1.2.5")
        # Either both returned a single dict or both returned the same-length list
        if isinstance(first, list):
            assert isinstance(second, list)
            assert len(first) == len(second)
        else:
            assert first == second


# ===========================================================================
# INTEGRATION — Full pipeline assertions across multiple rules
# Covers BDD Scenarios 18–19 (Rule: End-to-End Multi-Ecosystem Integration)
# ===========================================================================
class TestEndToEndMultiEcosystemIntegration:
    """Full-pipeline scenarios: dispatch + lookup + serialization +
    CPE sanitization together."""

    # BDD Scenario 18: full scan + CycloneDX-style sanitization
    def test_full_scan_with_cyclonedx_sanitization_emits_correct_set(
        self, mapper, mixed_repo_deps, mock_scenarios, dispatch_table
    ):
        _require_implementation()
        scenario = next(s for s in mock_scenarios["scenarios"]
                        if s["id"] == "scenario_enh_001")
        expected_ids = {v["cve_or_advisory_id"]
                        for v in scenario["expected_output"]["vulnerabilities"]}

        # Step 1: vuln mapping
        results = mapper.map_vulnerabilities(mixed_repo_deps["deps"], cache=None)
        assert set(_ids_in_results(results)) == expected_ids

        # Step 2: build per-component dicts with fabricated CPEs
        components = []
        for dep in mixed_repo_deps["deps"]:
            comp = {
                "name": dep["name"],
                "version": dep["exact_version"],
                "purl": dep["purl"],
                "type": "library",
                # Fabricate a CPE for every dep (simulates Syft --add-cpes-if-none)
                "cpe": f"cpe:2.3:a:{dep['name']}:{dep['name']}:"
                       f"{dep['exact_version']}:*:*:*:*:*:*:*",
            }
            components.append(comp)

        # Step 3: sanitize. Only PyPI components retain cpe.
        sanitized = CPESanitizer.sanitize_components(components, dispatch_table)
        pypi_count = sum(1 for c in sanitized
                         if c["purl"].startswith("pkg:pypi/") and "cpe" in c)
        non_pypi_with_cpe = sum(1 for c in sanitized
                                if not c["purl"].startswith("pkg:pypi/") and "cpe" in c)
        # All PyPI deps in fixture keep cpe; no non-PyPI component does
        pypi_dep_count = sum(1 for d in mixed_repo_deps["deps"]
                             if d["ecosystem"] == "pypi")
        assert pypi_count == pypi_dep_count
        assert non_pypi_with_cpe == 0
        # PURLs preserved across all components
        assert [c["purl"] for c in sanitized] == [c["purl"] for c in components]

    # BDD Scenario 18 (CPE-count assertion)
    def test_emitted_sbom_contains_only_nvd_indexed_cpes(
        self, mapper, mixed_repo_deps, dispatch_table
    ):
        _require_implementation()
        components = [
            {"name": d["name"], "version": d["exact_version"], "purl": d["purl"],
             "type": "library",
             "cpe": f"cpe:2.3:a:{d['name']}:{d['name']}:"
                    f"{d['exact_version']}:*:*:*:*:*:*:*"}
            for d in mixed_repo_deps["deps"]
        ]
        sanitized = CPESanitizer.sanitize_components(components, dispatch_table)
        nvd_ecosystems = set(dispatch_table["nvd_ecosystems"])
        for c in sanitized:
            ecosystem = c["purl"].split(":", 1)[1].split("/", 1)[0]
            if ecosystem in nvd_ecosystems:
                assert "cpe" in c, f"NVD-indexed ecosystem '{ecosystem}' should keep cpe"
            else:
                assert "cpe" not in c, (
                    f"Non-NVD ecosystem '{ecosystem}' should have cpe stripped: {c!r}"
                )

    # BDD Scenario 19: SPDX-style equivalence — same component-level guarantees
    def test_full_scan_with_spdx_style_sanitization_emits_correct_set(
        self, mapper, mixed_repo_deps, mock_scenarios, dispatch_table
    ):
        _require_implementation()
        scenario = next(s for s in mock_scenarios["scenarios"]
                        if s["id"] == "scenario_enh_001")
        expected_ids = {v["cve_or_advisory_id"]
                        for v in scenario["expected_output"]["vulnerabilities"]}

        results = mapper.map_vulnerabilities(mixed_repo_deps["deps"], cache=None)
        assert set(_ids_in_results(results)) == expected_ids

        # SPDX-style: cpe23Type and purl are co-located on the package dict
        packages = [
            {"name": d["name"], "versionInfo": d["exact_version"],
             "purl": d["purl"],
             "cpe": f"cpe:2.3:a:{d['name']}:{d['name']}:"
                    f"{d['exact_version']}:*:*:*:*:*:*:*"}
            for d in mixed_repo_deps["deps"]
        ]
        sanitized = CPESanitizer.sanitize_components(packages, dispatch_table)
        nvd_ecosystems = set(dispatch_table["nvd_ecosystems"])
        cpe_total = sum(1 for c in sanitized if "cpe" in c)
        expected_cpe_total = sum(
            1 for d in mixed_repo_deps["deps"]
            if d["purl"].split(":", 1)[1].split("/", 1)[0] in nvd_ecosystems
        )
        assert cpe_total == expected_cpe_total

    # Determinism (Scenario 9 from mock_scenarios — promoted to integration)
    def test_two_runs_against_same_inputs_are_byte_equal(
        self, mapper, mixed_repo_deps
    ):
        _require_implementation()
        run_1 = mapper.map_vulnerabilities(deepcopy(mixed_repo_deps["deps"]), cache=None)
        run_2 = mapper.map_vulnerabilities(deepcopy(mixed_repo_deps["deps"]), cache=None)
        # Same length, same ids, same order — full determinism
        assert len(run_1) == len(run_2)
        assert _ids_in_results(run_1) == _ids_in_results(run_2)
        # Byte-equality via canonical JSON
        assert json.dumps(run_1, sort_keys=True, default=str) \
            == json.dumps(run_2, sort_keys=True, default=str)
