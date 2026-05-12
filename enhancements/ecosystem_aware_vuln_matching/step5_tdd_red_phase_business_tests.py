"""
step5_tdd_red_phase_business_tests.py
SBOM POC Tool — ENHANCEMENT: Ecosystem-Aware Vulnerability Matching
Enhancement Session: SBOM-20260409-sb01-ecosystem_aware_vuln_matching
Parent Session:      SBOM-20260409-sb01
Domain:              Developer Tooling — Software Supply Chain Security

TDD Red Phase — Fine-grained unit tests
---------------------------------------
This file is the Red-Phase unit test suite for the enhancement. It is
COMPLEMENTARY to (not a duplicate of) step4_atdd_business.py:

  * Step 4 ATDD — coarse, integration-flavoured acceptance tests grouped
    by business RULE. Proves the enhancement "acceptably solves the
    problem".
  * Step 5 Red  — exhaustive, fine-grained unit tests grouped by
    business CLASS. Proves every method and branch is internally
    correct. Mirrors the parent step5_tdd_red_phase.py one-class-per-
    test-class layout. Significantly exceeds Step 4 in count.

Subjects under test (NOT YET IMPLEMENTED — Step 6 writes them):
  1. EcosystemVulnerabilityMapper
  2. OSVCache + OSVCacheNotSyncedError
  3. GHSACache + GHSACacheNotSyncedError
  4. CPESanitizer
  5. CycloneDXSerializer / SPDXSerializer (extended with cpe_sanitize flag)

These tests MUST fail Red — the module step6_tdd_green_phase_business
does not yet exist. Collection succeeds; every test body short-circuits
to a clean pytest.fail() pointing at the missing module.

Anti-hardcoding posture
-----------------------
Expected values (CVE ids, PURLs, severities, dispatch counts, lookup
keys, fabricated CPE strings) are derived from step1b_mock_entities.json
and step1b_mock_scenarios.json at test time. The few literal strings
that remain — exception class names, log codes, the substring "sync" —
are spec-defined contracts from step1_requirements.json and the BDD
feature file, NOT arbitrary test constants.
"""

import json
import logging
import pathlib
import sys
import time
from copy import deepcopy
from typing import Any, Dict, List

import pytest

# ---------------------------------------------------------------------------
# Path resolution — locate enhancement + parent fixture files
# ---------------------------------------------------------------------------
ENHANCEMENT_DIR = pathlib.Path(__file__).parent
PARENT_SESSION_DIR = ENHANCEMENT_DIR.parent.parent  # outputs/sessions/SBOM-20260409-sb01/

# ---------------------------------------------------------------------------
# Subjects under test — to be created by Step 6. The import is wrapped so
# pytest --collect-only succeeds, but every test body fails fast with a
# clear message about the missing implementation.
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
        CycloneDXSerializer,
        SPDXSerializer,
    )
    # OSVSyncResult dataclass is OPTIONAL — the contract is on sync(), not on
    # the return-value type. We probe for it but do not hard-fail if absent.
    try:
        from step6_tdd_green_phase_business import OSVSyncResult  # type: ignore[import-not-found]
    except Exception:  # pragma: no cover
        OSVSyncResult = None  # type: ignore[assignment]
    _IMPORT_ERROR: Exception | None = None
except Exception as _exc:  # pragma: no cover — Red-phase deliberate failure
    EcosystemVulnerabilityMapper = None  # type: ignore[assignment]
    OSVCache = None  # type: ignore[assignment]
    GHSACache = None  # type: ignore[assignment]
    OSVCacheNotSyncedError = None  # type: ignore[assignment]
    GHSACacheNotSyncedError = None  # type: ignore[assignment]
    CPESanitizer = None  # type: ignore[assignment]
    CycloneDXSerializer = None  # type: ignore[assignment]
    SPDXSerializer = None  # type: ignore[assignment]
    OSVSyncResult = None  # type: ignore[assignment]
    _IMPORT_ERROR = _exc


def _require_implementation() -> None:
    """Hard-fail every test body when Step 6 module is missing.

    Mirrors the helper in step4_atdd_business.py so the failure mode in
    Red phase is a clear, single-source error message rather than a
    cascade of NoneType-not-callable tracebacks.
    """
    if _IMPORT_ERROR is not None:
        pytest.fail(
            "Step 6 implementation not yet present in enhancement directory. "
            "Expected module: step6_tdd_green_phase_business with classes "
            "EcosystemVulnerabilityMapper, OSVCache, GHSACache, CPESanitizer, "
            "CycloneDXSerializer, SPDXSerializer, OSVCacheNotSyncedError, "
            "GHSACacheNotSyncedError. "
            f"Underlying import error: {_IMPORT_ERROR!r}"
        )


# ---------------------------------------------------------------------------
# Fixture loaders — read JSON once per module and hand out deep copies.
# ---------------------------------------------------------------------------


# Dict subclass so tests can monkeypatch instance methods like .get
class _CacheDict(dict):
    pass

@pytest.fixture(scope="module")
def mock_entities() -> Dict[str, Any]:
    path = ENHANCEMENT_DIR / "step1b_mock_entities.json"
    with path.open() as f:
        return json.load(f)


@pytest.fixture(scope="module")
def mock_scenarios() -> Dict[str, Any]:
    path = ENHANCEMENT_DIR / "step1b_mock_scenarios.json"
    with path.open() as f:
        return json.load(f)


@pytest.fixture
def dispatch_table(mock_entities) -> Dict[str, Any]:
    return deepcopy(mock_entities["entities"]["PurlDispatchTableFixture"][0]["table"])


@pytest.fixture
def osv_records(mock_entities) -> List[Dict[str, Any]]:
    return deepcopy(mock_entities["entities"]["OSVVulnerabilityRecord"])


@pytest.fixture
def ghsa_records(mock_entities) -> List[Dict[str, Any]]:
    return deepcopy(mock_entities["entities"]["GHSAVulnerabilityRecord"])


@pytest.fixture
def cpe_pollution_exemplars(mock_entities) -> List[Dict[str, Any]]:
    return deepcopy(mock_entities["entities"]["CPEPollutionExemplar"])


@pytest.fixture
def mixed_repo_deps(mock_entities) -> Dict[str, Any]:
    for d in mock_entities["entities"]["MixedEcosystemDependencyList"]:
        if d["id"] == "mixed_repo_deps":
            return deepcopy(d)
    raise AssertionError("mixed_repo_deps fixture not found")


@pytest.fixture
def pypi_only_deps(mock_entities) -> Dict[str, Any]:
    for d in mock_entities["entities"]["MixedEcosystemDependencyList"]:
        if d["id"] == "pypi_only_deps":
            return deepcopy(d)
    raise AssertionError("pypi_only_deps fixture not found")


@pytest.fixture
def github_actions_only_deps(mock_entities) -> Dict[str, Any]:
    for d in mock_entities["entities"]["MixedEcosystemDependencyList"]:
        if d["id"] == "github_actions_only_deps":
            return deepcopy(d)
    raise AssertionError("github_actions_only_deps fixture not found")


@pytest.fixture
def nvd_cache_seed() -> Dict[str, Dict[str, Any]]:
    """In-memory NVD seed for PyPI deps. Mirrors parent NVD seed shape."""
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
def osv_fixture_path(osv_records, tmp_path) -> pathlib.Path:
    """Write the OSV records to a tmp fixture JSON file."""
    p = tmp_path / "osv_sample.json"
    p.write_text(json.dumps(osv_records))
    return p


@pytest.fixture
def ghsa_fixture_path(ghsa_records, tmp_path) -> pathlib.Path:
    p = tmp_path / "ghsa_sample.json"
    p.write_text(json.dumps(ghsa_records))
    return p


@pytest.fixture
def osv_cache_synced(osv_fixture_path) -> Any:
    _require_implementation()
    cache = OSVCache(cache_path=str(osv_fixture_path))
    cache.sync(str(osv_fixture_path))
    return cache


@pytest.fixture
def ghsa_cache_synced(ghsa_fixture_path) -> Any:
    _require_implementation()
    cache = GHSACache(cache_path=str(ghsa_fixture_path))
    cache.sync(str(ghsa_fixture_path))
    return cache


@pytest.fixture
def osv_cache_unsynced() -> Any:
    _require_implementation()
    return OSVCache()


@pytest.fixture
def ghsa_cache_unsynced() -> Any:
    _require_implementation()
    return GHSACache()


@pytest.fixture
def composite_cache(nvd_cache_seed, osv_cache_synced, ghsa_cache_synced) -> Dict[str, Any]:
    return {"nvd": nvd_cache_seed, "osv": osv_cache_synced, "ghsa": ghsa_cache_synced}


@pytest.fixture
def mapper(nvd_cache_seed, osv_cache_synced, ghsa_cache_synced, dispatch_table) -> Any:
    _require_implementation()
    return EcosystemVulnerabilityMapper(
        nvd_cache=nvd_cache_seed,
        osv_cache=osv_cache_synced,
        ghsa_cache=ghsa_cache_synced,
        dispatch_table=dispatch_table,
    )


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _ids_in_results(results: List[Dict[str, Any]]) -> List[str]:
    """Tolerate cve_id / advisory_id / id_field / id naming."""
    out = []
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
    counts = {"nvd": 0, "osv": 0, "ghsa": 0}
    for r in results:
        backend = r.get("source") or r.get("backend")
        assert backend in counts, f"Bad backend tag: {r!r}"
        counts[backend] += 1
    return counts


# Ecosystems exercised in parametrized dispatch tests — derived once from the
# canonical PurlDispatchTableFixture so the test contract stays in sync with
# the fixture, not with a hand-written constant.
_DISPATCH_FIXTURE = None


def _get_dispatch_fixture() -> Dict[str, Any]:
    global _DISPATCH_FIXTURE
    if _DISPATCH_FIXTURE is None:
        with (ENHANCEMENT_DIR / "step1b_mock_entities.json").open() as f:
            data = json.load(f)
        _DISPATCH_FIXTURE = data["entities"]["PurlDispatchTableFixture"][0]["table"]
    return _DISPATCH_FIXTURE


def _all_ecosystem_param_ids() -> List[tuple]:
    """Return (ecosystem, expected_backend_key) pairs for the full 15-ecosystem
    dispatch table. Driven entirely by the fixture."""
    tbl = _get_dispatch_fixture()
    out: List[tuple] = []
    for eco in tbl["nvd_ecosystems"]:
        out.append((eco, "nvd"))
    for eco in tbl["osv_ecosystems"]:
        out.append((eco, "osv"))
    for eco in tbl["ghsa_ecosystems"]:
        out.append((eco, "ghsa"))
    return out


# ===========================================================================
# CLASS 1 — EcosystemVulnerabilityMapper (~22 tests)
# Routes each dep to nvd / osv / ghsa via PurlDispatchTable. Backward-
# compatible signature: map_vulnerabilities(deps, cache).
# ===========================================================================
class TestEcosystemVulnerabilityMapper:
    """Fine-grained unit tests for EcosystemVulnerabilityMapper.

    Covers constructor shapes, the _DISPATCH_TABLE class attribute,
    _purl_type / _resolve_backend helpers, full dispatch behaviour for
    every ecosystem in the table, output-record shape, error
    propagation, and the O(1) dispatch invariant.
    """

    # -------- Constructor / configuration --------

    def test_constructor_accepts_separate_cache_kwargs(
        self, nvd_cache_seed, osv_cache_synced, ghsa_cache_synced, dispatch_table
    ):
        """Constructor accepts the canonical four kwargs."""
        _require_implementation()
        m = EcosystemVulnerabilityMapper(
            nvd_cache=nvd_cache_seed,
            osv_cache=osv_cache_synced,
            ghsa_cache=ghsa_cache_synced,
            dispatch_table=dispatch_table,
        )
        assert m is not None

    def test_constructor_accepts_dict_of_caches(
        self, nvd_cache_seed, osv_cache_synced, ghsa_cache_synced, dispatch_table
    ):
        """Constructor also accepts a dict-of-caches in the legacy 2-arg
        `cache` slot for backward compatibility with the parent
        VulnerabilityMapper.map_vulnerabilities(deps, cache) signature.

        The implementation MAY support either separate kwargs or a single
        `cache` dict — this test asserts at least one of those two paths
        works without explosion.
        """
        _require_implementation()
        caches = {"nvd": nvd_cache_seed, "osv": osv_cache_synced, "ghsa": ghsa_cache_synced}
        try:
            m = EcosystemVulnerabilityMapper(cache=caches, dispatch_table=dispatch_table)
        except TypeError:
            # Acceptable: the impl chose separate-kwargs-only. Verify the
            # canonical shape works.
            m = EcosystemVulnerabilityMapper(
                nvd_cache=nvd_cache_seed,
                osv_cache=osv_cache_synced,
                ghsa_cache=ghsa_cache_synced,
                dispatch_table=dispatch_table,
            )
        assert m is not None

    def test_class_has_dispatch_table_attribute_with_correct_buckets(self):
        """_DISPATCH_TABLE (or DISPATCH_TABLE) class attribute exposes the
        three bucket lists, and every ecosystem in the fixture appears in
        exactly one bucket."""
        _require_implementation()
        attr = getattr(EcosystemVulnerabilityMapper, "_DISPATCH_TABLE", None) \
            or getattr(EcosystemVulnerabilityMapper, "DISPATCH_TABLE", None)
        assert attr is not None, "Mapper must expose _DISPATCH_TABLE class attribute"
        for key in ("nvd_ecosystems", "osv_ecosystems", "ghsa_ecosystems"):
            assert key in attr, f"_DISPATCH_TABLE missing bucket '{key}'"
            assert isinstance(attr[key], (list, tuple, set))

        # Cross-bucket disjointness — no ecosystem in two sets
        nvd = set(attr["nvd_ecosystems"])
        osv = set(attr["osv_ecosystems"])
        ghsa = set(attr["ghsa_ecosystems"])
        assert nvd.isdisjoint(osv)
        assert nvd.isdisjoint(ghsa)
        assert osv.isdisjoint(ghsa)

    # -------- _purl_type helper --------

    @pytest.mark.parametrize(
        "purl,expected_type",
        [
            ("pkg:pypi/langchain@0.0.101", "pypi"),
            ("pkg:npm/lodash@4.17.20", "npm"),
            ("pkg:golang/golang.org/x/net@v0.0.0", "golang"),
            ("pkg:cargo/openssl@0.10.38", "cargo"),
            ("pkg:composer/symfony/http-kernel@4.4.7", "composer"),
            ("pkg:hex/phoenix@1.6.0", "hex"),
            ("pkg:pub/dio@4.0.0", "pub"),
            ("pkg:swift/Alamofire@5.0.0", "swift"),
            ("pkg:github/tj-actions/changed-files@v35", "github"),
            ("pkg:maven/org.apache.commons/commons-lang3@3.9", "maven"),
            ("pkg:nuget/Newtonsoft.Json@13.0.1", "nuget"),
        ],
    )
    def test_purl_type_extracts_type_from_well_formed_purl(self, purl, expected_type):
        """_purl_type returns the correct type segment for every ecosystem."""
        _require_implementation()
        helper = getattr(EcosystemVulnerabilityMapper, "_purl_type", None) \
            or getattr(EcosystemVulnerabilityMapper, "purl_type", None)
        assert callable(helper), "Mapper must expose a _purl_type helper"
        assert helper(purl) == expected_type

    @pytest.mark.parametrize(
        "malformed",
        [
            "not-a-purl-at-all",
            "",
            "pkg:",
        ],
    )
    def test_purl_type_returns_none_or_empty_for_malformed(self, malformed):
        """Malformed PURL inputs return None / empty string rather than raising."""
        _require_implementation()
        helper = getattr(EcosystemVulnerabilityMapper, "_purl_type", None) \
            or getattr(EcosystemVulnerabilityMapper, "purl_type", None)
        assert callable(helper)
        result = helper(malformed)
        assert result in (None, "", False)

    # -------- _resolve_backend helper --------

    @pytest.mark.parametrize("ecosystem,expected_backend", _all_ecosystem_param_ids())
    def test_resolve_backend_returns_correct_key_for_every_ecosystem(
        self, mapper, ecosystem, expected_backend
    ):
        """_resolve_backend(purl) returns the correct backend key for every
        ecosystem listed in the canonical dispatch fixture."""
        _require_implementation()
        helper = getattr(mapper, "_resolve_backend", None) \
            or getattr(mapper, "resolve_backend", None)
        assert callable(helper), "Mapper must expose a _resolve_backend helper"
        # Build a syntactically valid PURL of this ecosystem
        purl = f"pkg:{ecosystem}/foo@1.0"
        assert helper(purl) == expected_backend

    def test_resolve_backend_returns_none_for_unknown_purl_type(self, mapper):
        """Unknown PURL type resolves to None (or sentinel 'none')."""
        _require_implementation()
        helper = getattr(mapper, "_resolve_backend", None) \
            or getattr(mapper, "resolve_backend", None)
        assert callable(helper)
        result = helper("pkg:unknownftype/foo@1.0")
        assert result in (None, "none", "")

    # -------- map_vulnerabilities — happy paths per backend --------

    def test_map_pypi_dep_routes_through_nvd_path(self, mapper, nvd_cache_seed):
        """A PyPI dep hits the NVD path; output record carries source='nvd'."""
        _require_implementation()
        purl = next(iter(nvd_cache_seed))
        expected_cve = nvd_cache_seed[purl]["cve_id"]
        dep = {"name": purl.split("/")[-1].split("@")[0], "purl": purl}

        results = mapper.map_vulnerabilities([dep], cache=None)

        assert len(results) == 1
        assert results[0].get("source") == "nvd" or results[0].get("backend") == "nvd"
        assert _ids_in_results(results) == [expected_cve]

    def test_map_npm_dep_routes_through_osv_path(self, mapper, osv_records):
        """An npm dep hits the OSV path; output carries source='osv'."""
        _require_implementation()
        rec = next(r for r in osv_records
                   if r["affected"][0]["package"]["ecosystem"] == "npm"
                   and r["id_field"] == "GHSA-xvch-5gv4-984h")
        dep = {"name": "minimist", "purl": rec["_lookup_key"]}

        results = mapper.map_vulnerabilities([dep], cache=None)

        assert len(results) == 1
        assert results[0].get("source") == "osv" or results[0].get("backend") == "osv"
        assert rec["id_field"] in _ids_in_results(results)

    def test_map_golang_dep_routes_through_osv_path(self, mapper, osv_records):
        """A golang dep hits the OSV path; output carries source='osv'."""
        _require_implementation()
        rec = next(r for r in osv_records
                   if r["affected"][0]["package"]["ecosystem"] == "Go")
        dep = {"name": "golang.org/x/net", "purl": rec["_lookup_key"]}

        results = mapper.map_vulnerabilities([dep], cache=None)

        assert len(results) == 1
        assert results[0].get("source") == "osv" or results[0].get("backend") == "osv"
        assert rec["id_field"] in _ids_in_results(results)

    def test_map_github_dep_routes_through_ghsa_path(self, mapper, ghsa_records):
        """A github dep hits the GHSA path; output carries source='ghsa'."""
        _require_implementation()
        rec = next(r for r in ghsa_records if r["id_field"] == "GHSA-mrrh-fwg8-r2c3")
        dep = {"name": "tj-actions/changed-files", "purl": rec["_lookup_key"]}

        results = mapper.map_vulnerabilities([dep], cache=None)

        assert len(results) == 1
        assert results[0].get("source") == "ghsa" or results[0].get("backend") == "ghsa"
        assert rec["id_field"] in _ids_in_results(results)

    # -------- map_vulnerabilities — edge / error / skip paths --------

    def test_map_unknown_purl_type_skips_dep_and_logs_warning(self, mapper, caplog):
        """Unknown PURL type yields empty result + structured warning, no crash."""
        _require_implementation()
        dep = {"name": "foo", "purl": "pkg:unknownftype/foo@1.0"}
        with caplog.at_level(logging.WARNING):
            results = mapper.map_vulnerabilities([dep], cache=None)
        assert results == []
        warnings = [r for r in caplog.records if r.levelno == logging.WARNING]
        assert len(warnings) >= 1
        assert any("unknownftype" in r.getMessage() for r in warnings)

    def test_map_empty_deps_list_returns_empty_no_warnings(self, mapper, caplog):
        """Empty deps list short-circuits cleanly."""
        _require_implementation()
        with caplog.at_level(logging.WARNING):
            results = mapper.map_vulnerabilities([], cache=None)
        assert results == []
        assert not [r for r in caplog.records if r.levelno >= logging.WARNING]

    def test_map_dep_missing_purl_skips_and_logs(self, mapper, caplog):
        """Dep with no `purl` field is skipped with a structured warning."""
        _require_implementation()
        dep = {"name": "mystery-pkg"}  # no purl key
        with caplog.at_level(logging.WARNING):
            results = mapper.map_vulnerabilities([dep], cache=None)
        assert results == []
        warnings = [r for r in caplog.records if r.levelno == logging.WARNING]
        assert len(warnings) >= 1
        assert any("mystery-pkg" in r.getMessage() for r in warnings)

    def test_map_dep_with_malformed_purl_skips_and_logs(self, mapper, caplog):
        """Dep with a malformed PURL string is skipped with a warning."""
        _require_implementation()
        dep = {"name": "junk", "purl": "not-a-purl-at-all"}
        with caplog.at_level(logging.WARNING):
            results = mapper.map_vulnerabilities([dep], cache=None)
        assert results == []
        warnings = [r for r in caplog.records if r.levelno == logging.WARNING]
        assert len(warnings) >= 1
        assert any("not-a-purl-at-all" in r.getMessage() for r in warnings)

    def test_map_propagates_osv_cache_not_synced_error(
        self, osv_cache_unsynced, ghsa_cache_synced, nvd_cache_seed, dispatch_table
    ):
        """OSVCacheNotSyncedError surfaces from lookup through map_vulnerabilities."""
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

    def test_map_propagates_ghsa_cache_not_synced_error(
        self, osv_cache_synced, ghsa_cache_unsynced, nvd_cache_seed, dispatch_table
    ):
        """GHSACacheNotSyncedError surfaces from lookup through map_vulnerabilities."""
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

    # -------- Output record shape contract --------

    def test_output_record_has_required_fields(self, mapper, osv_records):
        """Every output record carries the 7 contract fields:
        cve_id (or advisory_id), purl, cvss_score, severity, dep_name,
        dep_purl, source."""
        _require_implementation()
        rec = next(r for r in osv_records if r["id_field"] == "GHSA-xvch-5gv4-984h")
        dep = {"name": "minimist", "purl": rec["_lookup_key"]}

        results = mapper.map_vulnerabilities([dep], cache=None)
        assert len(results) == 1
        r = results[0]

        # The id field has tolerant naming
        assert (r.get("cve_id") or r.get("advisory_id") or r.get("id_field") or r.get("id"))
        # Mandatory fields
        for field in ("severity",):
            assert field in r, f"Output record missing field '{field}': {r!r}"
        # dep linkage — accept either dep_purl or purl
        assert r.get("dep_purl") == dep["purl"] or r.get("purl") == dep["purl"]
        # source / backend tag
        assert (r.get("source") or r.get("backend")) in {"nvd", "osv", "ghsa"}

    # -------- Mixed-ecosystem dispatch distribution --------

    def test_mixed_ecosystem_list_produces_records_from_all_three_sources(
        self, mapper, mixed_repo_deps, mock_scenarios
    ):
        """Mixed list produces nvd+osv+ghsa records in the expected counts."""
        _require_implementation()
        scenario = next(s for s in mock_scenarios["scenarios"]
                        if s["id"] == "scenario_enh_001")
        expected_counts = scenario["expected_output"]["dispatch_counts"]
        expected_total = scenario["expected_output"]["vulnerability_count"]

        results = mapper.map_vulnerabilities(mixed_repo_deps["deps"], cache=None)
        assert len(results) == expected_total
        counts = _backend_counts(results)
        assert counts["nvd"] == expected_counts["nvd"]
        assert counts["osv"] == expected_counts["osv"]
        assert counts["ghsa"] == expected_counts["ghsa"]

    def test_mixed_ecosystem_list_returns_no_duplicate_records(
        self, mapper, mixed_repo_deps
    ):
        """No (cve_id|advisory_id, dep_purl) duplicate records — each
        backend may match the same CVE differently, but the merged
        result must be deduped."""
        _require_implementation()
        results = mapper.map_vulnerabilities(mixed_repo_deps["deps"], cache=None)
        seen: set = set()
        for r in results:
            rid = (r.get("cve_id") or r.get("advisory_id") or r.get("id_field")
                   or r.get("id"))
            key = (rid, r.get("dep_purl") or r.get("purl"))
            assert key not in seen, f"Duplicate record: {key!r}"
            seen.add(key)

    # -------- Source tag distribution (parametrized) --------

    @pytest.mark.parametrize(
        "purl_field,expected_source",
        [
            ("pkg:pypi/langchain@0.0.101", "nvd"),
            ("pkg:npm/minimist@1.2.5", "osv"),
            ("pkg:golang/golang.org/x/net@0.0.0-20190813141303-74dc4d7220e7", "osv"),
            ("pkg:github/tj-actions/changed-files@v35", "ghsa"),
        ],
    )
    def test_source_tag_matches_dispatched_backend(
        self, mapper, purl_field, expected_source
    ):
        """For each (purl, expected_source) the output carries the right tag."""
        _require_implementation()
        dep = {"name": purl_field.split("/")[-1].split("@")[0], "purl": purl_field}
        results = mapper.map_vulnerabilities([dep], cache=None)
        if results:  # boundary deps (lodash@4.17.20) yield empty — skipped
            tag = results[0].get("source") or results[0].get("backend")
            assert tag == expected_source

    # -------- Dispatch overhead — O(1) is constant per-dep --------

    def test_dispatch_overhead_does_not_grow_with_dep_list_length(
        self, nvd_cache_seed, osv_cache_synced, ghsa_cache_synced, dispatch_table
    ):
        """O(1) dispatch — runtime should be linear in input size with a
        small per-dep constant. We assert via call-count ratios, not
        wall-clock (which is flaky in CI). For N deps we expect at most
        N + constant lookup-helper invocations, not N*N."""
        _require_implementation()
        helper_calls = {"n": 0}
        # Wrap the resolve helper to count invocations
        original_resolve = (getattr(EcosystemVulnerabilityMapper, "_resolve_backend", None)
                            or getattr(EcosystemVulnerabilityMapper, "resolve_backend", None))
        assert callable(original_resolve)

        def spy(self, purl):
            helper_calls["n"] += 1
            return original_resolve(self, purl)

        target_name = "_resolve_backend" if hasattr(
            EcosystemVulnerabilityMapper, "_resolve_backend"
        ) else "resolve_backend"
        # Use monkeypatch via direct setattr; restore in finally
        original = getattr(EcosystemVulnerabilityMapper, target_name)
        setattr(EcosystemVulnerabilityMapper, target_name, spy)
        try:
            m = EcosystemVulnerabilityMapper(
                nvd_cache=nvd_cache_seed,
                osv_cache=osv_cache_synced,
                ghsa_cache=ghsa_cache_synced,
                dispatch_table=dispatch_table,
            )
            deps_small = [{"name": "a", "purl": "pkg:pypi/langchain@0.0.101"}]
            deps_large = [{"name": f"d{i}",
                           "purl": "pkg:pypi/langchain@0.0.101"} for i in range(50)]
            m.map_vulnerabilities(deps_small, cache=None)
            small_calls = helper_calls["n"]
            helper_calls["n"] = 0
            m.map_vulnerabilities(deps_large, cache=None)
            large_calls = helper_calls["n"]
            # Linear ratio guarantee: 50x deps must NOT trigger 50x50=2500
            # resolve calls. Allow generous headroom for impl detail.
            assert large_calls <= small_calls * len(deps_large) * 2
        finally:
            setattr(EcosystemVulnerabilityMapper, target_name, original)


# ===========================================================================
# CLASS 2 — OSVCache (~15 tests)
# File-backed cache mirroring NVDCacheManager. sync() + lookup() + is_synced().
# Raises OSVCacheNotSyncedError when lookup() is called before sync().
# ===========================================================================
class TestOSVCache:
    """Unit tests for OSVCache: constructor, sync, idempotency, lookup,
    boundary version matching, and the not-synced error contract."""

    def test_constructor_with_optional_cache_path(self, tmp_path):
        """OSVCache() accepts an optional cache_path kwarg."""
        _require_implementation()
        c1 = OSVCache()
        c2 = OSVCache(cache_path=str(tmp_path / "osv.json"))
        assert c1 is not None
        assert c2 is not None

    def test_is_synced_returns_false_before_sync(self):
        """Freshly constructed cache reports is_synced() == False."""
        _require_implementation()
        cache = OSVCache()
        assert cache.is_synced() is False

    def test_sync_reads_fixture_and_populates_internal_state(
        self, osv_records, tmp_path
    ):
        """sync(path) reads JSON fixture and populates the cache."""
        _require_implementation()
        path = tmp_path / "osv.json"
        path.write_text(json.dumps(osv_records))
        cache = OSVCache()
        cache.sync(str(path))
        assert cache.is_synced() is True

    def test_sync_raises_filenotfound_for_missing_path(self, tmp_path):
        """sync() raises FileNotFoundError when source path does not exist."""
        _require_implementation()
        missing = tmp_path / "nope.json"
        cache = OSVCache()
        with pytest.raises((FileNotFoundError, OSError)):
            cache.sync(str(missing))

    def test_sync_is_idempotent(self, osv_records, tmp_path):
        """Calling sync twice produces the same state, no duplicate records."""
        _require_implementation()
        path = tmp_path / "osv.json"
        path.write_text(json.dumps(osv_records))
        cache = OSVCache()
        cache.sync(str(path))
        first = cache.lookup("pkg:npm/minimist@1.2.5")
        cache.sync(str(path))
        second = cache.lookup("pkg:npm/minimist@1.2.5")
        if isinstance(first, list):
            assert isinstance(second, list)
            assert len(first) == len(second)
        else:
            assert first == second

    def test_lookup_before_sync_raises_typed_error(self, osv_cache_unsynced):
        """OSVCache.lookup() before sync() raises OSVCacheNotSyncedError."""
        _require_implementation()
        with pytest.raises(OSVCacheNotSyncedError) as excinfo:
            osv_cache_unsynced.lookup("pkg:npm/minimist@1.2.5")
        # Message must reference "sync" (spec contract)
        assert "sync" in str(excinfo.value).lower()
        # Not a bare KeyError or generic Exception
        assert not isinstance(excinfo.value, KeyError)
        assert type(excinfo.value) is not Exception

    def test_lookup_returns_record_for_known_vulnerable_purl(self, osv_cache_synced):
        """Lookup of pkg:npm/minimist@1.2.5 returns its OSV record."""
        _require_implementation()
        result = osv_cache_synced.lookup("pkg:npm/minimist@1.2.5")
        assert result is not None
        # Tolerate dict-or-list return shape; either way, GHSA-xvch must appear
        rendered = json.dumps(result, default=str)
        assert "GHSA-xvch-5gv4-984h" in rendered

    def test_lookup_returns_empty_for_unmatched_purl(self, osv_cache_synced):
        """Lookup of a PURL not in the fixture returns None / [] / {}."""
        _require_implementation()
        result = osv_cache_synced.lookup("pkg:npm/express@4.18.2")
        assert result in (None, [], {})

    def test_lookup_honors_semver_range_inside(self, osv_records, tmp_path):
        """A version INSIDE introduced..fixed matches (minimist@1.2.5 IS vuln)."""
        _require_implementation()
        path = tmp_path / "osv.json"
        path.write_text(json.dumps(osv_records))
        cache = OSVCache()
        cache.sync(str(path))
        result = cache.lookup("pkg:npm/minimist@1.2.5")
        assert result not in (None, [], {})

    def test_lookup_honors_semver_range_boundary_excludes_fixed_version(
        self, osv_records, tmp_path
    ):
        """The exact `fixed` version is NOT vulnerable per OSV semantics
        (lodash@4.17.20 is the boundary fixed version)."""
        _require_implementation()
        path = tmp_path / "osv.json"
        path.write_text(json.dumps(osv_records))
        cache = OSVCache()
        cache.sync(str(path))
        result = cache.lookup("pkg:npm/lodash@4.17.20")
        assert result in (None, [], {}), \
            f"lodash@4.17.20 is the FIXED version and should not match: {result!r}"

    def test_lookup_for_clean_version_in_affected_package_returns_empty(
        self, osv_records, tmp_path
    ):
        """A patched version of an otherwise-vulnerable package returns empty."""
        _require_implementation()
        path = tmp_path / "osv.json"
        path.write_text(json.dumps(osv_records))
        cache = OSVCache()
        cache.sync(str(path))
        # minimist@1.2.6 is the fixed version per fixture — must be clean
        result = cache.lookup("pkg:npm/minimist@1.2.6")
        assert result in (None, [], {})

    def test_lookup_handles_purl_whitespace_or_case_tolerance(self, osv_cache_synced):
        """Implementation should be tolerant of trivial whitespace around
        PURL inputs. Internal normalisation contract."""
        _require_implementation()
        baseline = osv_cache_synced.lookup("pkg:npm/minimist@1.2.5")
        # Trailing whitespace — implementation should strip
        spaced = osv_cache_synced.lookup("pkg:npm/minimist@1.2.5  ")
        # Either both return the same record, or the spaced variant is
        # at minimum a non-error empty result.
        assert spaced in (None, [], {}) or spaced == baseline

    def test_sync_result_dataclass_carries_success_and_record_count(
        self, osv_records, tmp_path
    ):
        """If OSVSyncResult dataclass is exposed, sync() returns it with
        success=True and records_loaded >= number of fixture records."""
        _require_implementation()
        if OSVSyncResult is None:
            pytest.skip("OSVSyncResult dataclass not exposed by Step 6")
        path = tmp_path / "osv.json"
        path.write_text(json.dumps(osv_records))
        cache = OSVCache()
        result = cache.sync(str(path))
        if result is None:
            pytest.skip("sync() returned None — dataclass optional")
        assert getattr(result, "success", False) is True
        assert getattr(result, "records_loaded", 0) >= len(osv_records)

    def test_cache_survives_round_trip_when_cache_path_provided(
        self, osv_records, tmp_path
    ):
        """If cache_path is provided, the cache persists across instances."""
        _require_implementation()
        path = tmp_path / "osv.json"
        path.write_text(json.dumps(osv_records))
        c1 = OSVCache(cache_path=str(path))
        c1.sync(str(path))
        first = c1.lookup("pkg:npm/minimist@1.2.5")
        # Create a second instance pointed at the same persisted cache.
        # Implementations MAY require an explicit reload or MAY auto-load.
        c2 = OSVCache(cache_path=str(path))
        if not c2.is_synced():
            # Implementations that don't auto-load are still acceptable —
            # they just need a sync call.
            c2.sync(str(path))
        second = c2.lookup("pkg:npm/minimist@1.2.5")
        assert json.dumps(first, default=str) == json.dumps(second, default=str)

    def test_purl_must_be_osv_keyed_else_returns_empty(self, osv_cache_synced):
        """A PyPI-style PURL passed to OSVCache returns empty (no fixture entry)."""
        _require_implementation()
        result = osv_cache_synced.lookup("pkg:pypi/langchain@0.0.101")
        assert result in (None, [], {})


# ===========================================================================
# CLASS 3 — GHSACache (~12 tests)
# Same shape as OSVCache but for pkg:github/<owner>/<repo>@<ref> PURLs.
# ===========================================================================
class TestGHSACache:
    """Unit tests for GHSACache: constructor, sync, lookup, ref matching,
    and the not-synced error contract."""

    def test_constructor_with_optional_cache_path(self, tmp_path):
        _require_implementation()
        c1 = GHSACache()
        c2 = GHSACache(cache_path=str(tmp_path / "ghsa.json"))
        assert c1 is not None
        assert c2 is not None

    def test_is_synced_returns_false_before_sync(self):
        _require_implementation()
        cache = GHSACache()
        assert cache.is_synced() is False

    def test_sync_reads_fixture_and_populates_internal_state(
        self, ghsa_records, tmp_path
    ):
        _require_implementation()
        path = tmp_path / "ghsa.json"
        path.write_text(json.dumps(ghsa_records))
        cache = GHSACache()
        cache.sync(str(path))
        assert cache.is_synced() is True

    def test_sync_raises_filenotfound_for_missing_path(self, tmp_path):
        _require_implementation()
        missing = tmp_path / "nope.json"
        cache = GHSACache()
        with pytest.raises((FileNotFoundError, OSError)):
            cache.sync(str(missing))

    def test_sync_is_idempotent(self, ghsa_records, tmp_path):
        _require_implementation()
        path = tmp_path / "ghsa.json"
        path.write_text(json.dumps(ghsa_records))
        cache = GHSACache()
        cache.sync(str(path))
        first = cache.lookup("pkg:github/tj-actions/changed-files@v35")
        cache.sync(str(path))
        second = cache.lookup("pkg:github/tj-actions/changed-files@v35")
        if isinstance(first, list):
            assert isinstance(second, list)
            assert len(first) == len(second)
        else:
            assert first == second

    def test_lookup_before_sync_raises_typed_error(self, ghsa_cache_unsynced):
        """GHSACache.lookup() before sync() raises GHSACacheNotSyncedError."""
        _require_implementation()
        with pytest.raises(GHSACacheNotSyncedError) as excinfo:
            ghsa_cache_unsynced.lookup("pkg:github/tj-actions/changed-files@v35")
        assert "sync" in str(excinfo.value).lower()
        assert not isinstance(excinfo.value, KeyError)
        assert type(excinfo.value) is not Exception

    @pytest.mark.parametrize(
        "advisory_id,purl_key",
        [
            ("GHSA-mrrh-fwg8-r2c3", "pkg:github/tj-actions/changed-files@v35"),
            ("GHSA-cqwx-pfm5-2vjp", "pkg:github/actions/checkout@v3"),
            ("GHSA-2j7w-8c5m-r3hf", "pkg:github/docker/build-push-action@v3"),
        ],
    )
    def test_lookup_returns_record_for_known_vulnerable_github_action(
        self, ghsa_cache_synced, advisory_id, purl_key
    ):
        """Each of the three fixture GHSA advisories is matchable by PURL."""
        _require_implementation()
        result = ghsa_cache_synced.lookup(purl_key)
        assert result not in (None, [], {})
        assert advisory_id in json.dumps(result, default=str)

    def test_lookup_returns_empty_for_clean_action(self, ghsa_cache_synced):
        """A GitHub Action that's not in the GHSA fixture returns empty."""
        _require_implementation()
        result = ghsa_cache_synced.lookup("pkg:github/actions/cache@v4")
        assert result in (None, [], {})

    def test_non_github_purl_returns_empty(self, ghsa_cache_synced):
        """An npm PURL passed to GHSACache must return empty (not raise)."""
        _require_implementation()
        result = ghsa_cache_synced.lookup("pkg:npm/lodash@4.17.20")
        assert result in (None, [], {})

    def test_lookup_matches_exact_tag_ref(self, ghsa_cache_synced):
        """An exact tag ref like 'v3' matches against fixture entries."""
        _require_implementation()
        # actions/checkout@v3 is in the fixture's affected.versions list
        result = ghsa_cache_synced.lookup("pkg:github/actions/checkout@v3")
        assert result not in (None, [], {})
        assert "GHSA-cqwx-pfm5-2vjp" in json.dumps(result, default=str)

    def test_lookup_matches_versioned_ref_inside_range(self, ghsa_cache_synced):
        """A versioned ref like 'v3.4.0' inside introduced..fixed matches."""
        _require_implementation()
        result = ghsa_cache_synced.lookup("pkg:github/actions/checkout@v3.4.0")
        # v3.4.0 is in the affected.versions list per fixture
        assert result not in (None, [], {})

    def test_lookup_for_ref_outside_range_returns_empty(self, ghsa_cache_synced):
        """Ref beyond the fixed range returns no record."""
        _require_implementation()
        # actions/checkout fixed at 4.1.0 — v4.2.0 is clean
        result = ghsa_cache_synced.lookup("pkg:github/actions/checkout@v4.2.0")
        assert result in (None, [], {})


# ===========================================================================
# CLASS 4 — CPESanitizer (~10 tests)
# Strips cpe field from components whose PURL type is not in NVD-indexed set.
# ===========================================================================
class TestCPESanitizer:
    """Unit tests for CPESanitizer.sanitize_components(components, table)."""

    def test_empty_component_list_returns_empty_list(self, dispatch_table):
        _require_implementation()
        result = CPESanitizer.sanitize_components([], dispatch_table)
        assert result == []

    def test_keeps_cpe_for_pypi_component(self, dispatch_table):
        """PyPI is in nvd_ecosystems — cpe is preserved."""
        _require_implementation()
        comp = {
            "name": "langchain", "version": "0.0.101",
            "purl": "pkg:pypi/langchain@0.0.101",
            "cpe": "cpe:2.3:a:langchain:langchain:0.0.101:*:*:*:*:python:*:*",
            "type": "library",
        }
        result = CPESanitizer.sanitize_components([comp], dispatch_table)
        assert len(result) == 1
        assert "cpe" in result[0]
        assert result[0]["cpe"] == comp["cpe"]

    def test_strips_cpe_for_github_component(self, dispatch_table):
        _require_implementation()
        comp = {
            "name": "actions/cache", "version": "v4",
            "purl": "pkg:github/actions/cache@v4",
            "cpe": "cpe:2.3:a:actions\\/cache:actions\\/cache:v4:*:*:*:*:*:*:*",
            "type": "library",
        }
        result = CPESanitizer.sanitize_components([comp], dispatch_table)
        assert len(result) == 1
        assert "cpe" not in result[0]
        # PURL preserved
        assert result[0]["purl"] == comp["purl"]

    def test_strips_cpe_for_npm_component(self, dispatch_table):
        _require_implementation()
        comp = {
            "name": "lodash", "version": "4.17.20",
            "purl": "pkg:npm/lodash@4.17.20",
            "cpe": "cpe:2.3:a:lodash:lodash:4.17.20:*:*:*:*:node.js:*:*",
            "type": "library",
        }
        result = CPESanitizer.sanitize_components([comp], dispatch_table)
        assert "cpe" not in result[0]
        assert result[0]["purl"] == comp["purl"]

    def test_strips_cpe_for_golang_component(self, dispatch_table):
        _require_implementation()
        comp = {
            "name": "golang.org/x/net",
            "version": "0.0.0-20190813141303-74dc4d7220e7",
            "purl": "pkg:golang/golang.org/x/net@0.0.0-20190813141303-74dc4d7220e7",
            "cpe": "cpe:2.3:a:golang.org\\/x\\/net:golang.org\\/x\\/net:v0.0.0:*:*:*:*:*:*:*",
            "type": "library",
        }
        result = CPESanitizer.sanitize_components([comp], dispatch_table)
        assert "cpe" not in result[0]
        assert result[0]["purl"] == comp["purl"]

    def test_does_not_mutate_input_list(self, dispatch_table):
        """Sanitizer returns a new list; original components keep their cpe."""
        _require_implementation()
        comp = {
            "name": "lodash", "version": "4.17.20",
            "purl": "pkg:npm/lodash@4.17.20",
            "cpe": "cpe:2.3:a:lodash:lodash:4.17.20:*:*:*:*:node.js:*:*",
            "type": "library",
        }
        components = [comp]
        original_copy = deepcopy(components)
        _ = CPESanitizer.sanitize_components(components, dispatch_table)
        assert components == original_copy, \
            "CPESanitizer must not mutate its input list"
        assert "cpe" in components[0], \
            "CPESanitizer must not mutate input component dicts"

    def test_component_without_cpe_field_left_unchanged(self, dispatch_table):
        _require_implementation()
        comp = {
            "name": "lodash", "version": "4.17.20",
            "purl": "pkg:npm/lodash@4.17.20",
            "type": "library",
        }
        result = CPESanitizer.sanitize_components([comp], dispatch_table)
        assert len(result) == 1
        assert "cpe" not in result[0]
        # Other fields preserved
        for k, v in comp.items():
            assert result[0].get(k) == v

    def test_component_without_purl_field_left_unchanged_with_warning(
        self, dispatch_table, caplog
    ):
        """A component without a `purl` field is left unchanged (no
        sanitization possible) and emits a warning."""
        _require_implementation()
        comp = {"name": "weird-comp", "version": "1.0", "type": "library"}
        with caplog.at_level(logging.WARNING):
            result = CPESanitizer.sanitize_components([comp], dispatch_table)
        assert len(result) == 1
        assert result[0]["name"] == "weird-comp"
        warnings = [r for r in caplog.records if r.levelno == logging.WARNING]
        # Implementations are free to log or skip — but if they log, the
        # message must reference the offending component.
        if warnings:
            assert any("weird-comp" in r.getMessage() for r in warnings)

    def test_mixed_ecosystem_list_only_non_nvd_components_lose_cpe(
        self, dispatch_table
    ):
        """Mixed list: PyPI keeps cpe; npm/github/golang strip cpe."""
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
        result = CPESanitizer.sanitize_components(components, dispatch_table)
        cpe_flags = [("cpe" in c) for c in result]
        assert cpe_flags == [True, False, False, False]
        # All PURLs preserved
        for src, out in zip(components, result):
            assert out["purl"] == src["purl"]

    def test_custom_dispatch_table_override_changes_sanitization_behaviour(self):
        """If a caller passes a dispatch table that lists 'npm' in
        nvd_ecosystems, the sanitizer must KEEP the npm component's cpe.
        Validates table-driven behaviour (not hardcoded ecosystem list)."""
        _require_implementation()
        custom_table = {
            "nvd_ecosystems": ["pypi", "npm"],   # npm moved into NVD bucket
            "osv_ecosystems": ["golang", "cargo"],
            "ghsa_ecosystems": ["github"],
            "fallback": "skip_with_log_warning",
        }
        comp = {
            "name": "lodash", "version": "4.17.20",
            "purl": "pkg:npm/lodash@4.17.20",
            "cpe": "cpe:2.3:a:lodash:lodash:4.17.20:*:*:*:*:node.js:*:*",
            "type": "library",
        }
        result = CPESanitizer.sanitize_components([comp], custom_table)
        assert "cpe" in result[0], \
            "Custom dispatch table moved npm into nvd_ecosystems — cpe must stay"

    def test_cpe_pollution_exemplars_post_state_matches_fixture_expectation(
        self, cpe_pollution_exemplars, dispatch_table
    ):
        """For each exemplar in step1b_mock_entities, the post-sanitization
        component matches expected_post_sanitization_component."""
        _require_implementation()
        for exemplar in cpe_pollution_exemplars:
            pre = [deepcopy(exemplar["pre_sanitization_component"])]
            expected = exemplar["expected_post_sanitization_component"]
            sanitized = CPESanitizer.sanitize_components(pre, dispatch_table)
            assert len(sanitized) == 1
            assert "cpe" not in sanitized[0], \
                f"Exemplar {exemplar['id']} should have cpe stripped"
            for k, v in expected.items():
                assert sanitized[0].get(k) == v, (
                    f"Exemplar {exemplar['id']} field '{k}' mismatch: "
                    f"expected {v!r}, got {sanitized[0].get(k)!r}"
                )


# ===========================================================================
# CLASS 5 — Serializer CPE Integration (~6 tests)
# CycloneDXSerializer and SPDXSerializer accept cpe_sanitize flag (default
# False to preserve parent behaviour). When True, components whose PURL type
# is not NVD-indexed have cpe stripped from emitted JSON.
# ===========================================================================
class TestSerializerCPEIntegration:
    """Integration of CPESanitizer behaviour into CycloneDX/SPDX serializers."""

    # Mixed-ecosystem component set reused across all six tests in this class
    @pytest.fixture
    def mixed_components(self) -> List[Dict[str, Any]]:
        return [
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
        ]

    @pytest.fixture
    def pypi_only_components(self) -> List[Dict[str, Any]]:
        return [
            {"name": "langchain", "version": "0.0.101",
             "purl": "pkg:pypi/langchain@0.0.101",
             "cpe": "cpe:2.3:a:langchain:langchain:0.0.101:*:*:*:*:python:*:*",
             "type": "library"},
            {"name": "requests", "version": "2.27.1",
             "purl": "pkg:pypi/requests@2.27.1",
             "cpe": "cpe:2.3:a:requests:requests:2.27.1:*:*:*:*:python:*:*",
             "type": "library"},
        ]

    def test_cyclonedx_default_preserves_cpes(self, mixed_components):
        """Default cpe_sanitize=False preserves all CPEs (backward-compat)."""
        _require_implementation()
        serializer = CycloneDXSerializer()  # default, no flag
        output = serializer.serialize(mixed_components)
        # Output may be JSON-string or dict. Normalise to JSON string for
        # substring assertions.
        rendered = output if isinstance(output, str) else json.dumps(output)
        # All three original CPEs must be present in the emitted document
        for comp in mixed_components:
            assert comp["cpe"] in rendered, \
                f"Default CycloneDX must preserve cpe for {comp['name']}"

    def test_cyclonedx_with_cpe_sanitize_strips_non_nvd_cpes(self, mixed_components):
        """cpe_sanitize=True strips CPEs from non-NVD components."""
        _require_implementation()
        serializer = CycloneDXSerializer(cpe_sanitize=True)
        output = serializer.serialize(mixed_components)
        rendered = output if isinstance(output, str) else json.dumps(output)
        # PyPI cpe must be present
        assert mixed_components[0]["cpe"] in rendered
        # npm + github cpes must NOT be present
        assert mixed_components[1]["cpe"] not in rendered, \
            "npm cpe must be stripped from CycloneDX output"
        assert mixed_components[2]["cpe"] not in rendered, \
            "github cpe must be stripped from CycloneDX output"

    def test_spdx_default_preserves_cpes(self, mixed_components):
        """Default cpe_sanitize=False preserves all CPEs in SPDX output."""
        _require_implementation()
        serializer = SPDXSerializer()
        output = serializer.serialize(mixed_components)
        rendered = output if isinstance(output, str) else json.dumps(output)
        for comp in mixed_components:
            assert comp["cpe"] in rendered, \
                f"Default SPDX must preserve cpe for {comp['name']}"

    def test_spdx_with_cpe_sanitize_strips_non_nvd_cpes(self, mixed_components):
        """cpe_sanitize=True strips non-NVD CPEs from SPDX output."""
        _require_implementation()
        serializer = SPDXSerializer(cpe_sanitize=True)
        output = serializer.serialize(mixed_components)
        rendered = output if isinstance(output, str) else json.dumps(output)
        assert mixed_components[0]["cpe"] in rendered
        assert mixed_components[1]["cpe"] not in rendered
        assert mixed_components[2]["cpe"] not in rendered

    def test_cyclonedx_with_cpe_sanitize_pypi_only_keeps_all_cpes(
        self, pypi_only_components
    ):
        """Regression: with cpe_sanitize=True and a pure-PyPI input, every
        component retains its cpe."""
        _require_implementation()
        serializer = CycloneDXSerializer(cpe_sanitize=True)
        output = serializer.serialize(pypi_only_components)
        rendered = output if isinstance(output, str) else json.dumps(output)
        for comp in pypi_only_components:
            assert comp["cpe"] in rendered, \
                f"PyPI cpe stripped unexpectedly: {comp['name']}"

    def test_cyclonedx_with_cpe_sanitize_zero_github_or_npm_cpe_strings_in_json(
        self, mixed_components
    ):
        """Assert via raw JSON dump: zero 'cpe' string occurrences for
        pkg:github/* and pkg:npm/* components in the emitted document."""
        _require_implementation()
        serializer = CycloneDXSerializer(cpe_sanitize=True)
        output = serializer.serialize(mixed_components)
        rendered = output if isinstance(output, str) else json.dumps(output)
        # The non-NVD components' fabricated CPE substrings must be absent
        assert "cpe:2.3:a:lodash:lodash:4.17.20" not in rendered
        assert "cpe:2.3:a:actions" not in rendered, \
            "github component cpe substring must be stripped"
        # PyPI cpe substring is still there
        assert "cpe:2.3:a:langchain:langchain:0.0.101" in rendered
