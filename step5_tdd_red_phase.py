"""
step5_tdd_red_phase_batch1.py
SBOM POC Tool — TDD Red Phase, Batch 1 (Classes 1–5)
Session: SBOM-20260409-sb01

Classes under test (stubs — ALL tests must FAIL):
  1. CVSSSeverityClassifier   (sbom_tool.classifier)
  2. OSSToolAdapter            (sbom_tool.oss_adapter)
  3. VulnerabilityMapper       (sbom_tool.vulnerability_mapper)
  4. RemediationEnricher       (sbom_tool.remediation)
  5. NVDCacheManager           (sbom_tool.nvd_cache)

Stubs:
  - CVSSSeverityClassifier.classify()         -> None
  - OSSToolAdapter.normalise()                -> []
  - OSSToolAdapter.deduplicate()              -> []
  - VulnerabilityMapper.map_vulnerabilities() -> []
  - RemediationEnricher.enrich()              -> None
  - NVDCacheManager.is_stale()               -> False
  - NVDCacheManager.check_staleness()        -> {}
  - NVDCacheManager.sync()                   -> (raises nothing)

CVSS banding (CQ-1): High >= 7.0, Medium 4.0–6.9, Low < 4.0, null -> Unknown
"""

import pytest
import re
import uuid
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional
from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock, patch

# ---------------------------------------------------------------------------
# Stub implementations (replace with real imports once Green Phase begins)
# ---------------------------------------------------------------------------

class CVSSSeverityClassifier:
    """Stub — classify() always returns None so every test fails."""
    def classify(self, score):
        return None


class OSSToolAdapter:
    """Stub — normalise() returns [], deduplicate() returns []."""
    def normalise(self, raw):
        return []

    def deduplicate(self, records):
        return []


class VulnerabilityMapper:
    """Stub — map_vulnerabilities() returns []."""
    def map_vulnerabilities(self, deps, cache):
        return []


class RemediationEnricher:
    """Stub — enrich() returns None."""
    def enrich(self, vuln, cache_entry):
        return None


class NVDCacheManager:
    """Stub — is_stale() always False, check_staleness() returns {}, sync() raises nothing."""
    def is_stale(self, last_synced_at):
        return False

    def check_staleness(self):
        return {}

    def sync(self, source_path):
        pass


class NVDSyncError(Exception):
    """Raised when sync fails — not yet implemented."""
    pass


# ---------------------------------------------------------------------------
# Shared fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def clf():
    return CVSSSeverityClassifier()


@pytest.fixture
def adapter():
    return OSSToolAdapter()


@pytest.fixture
def mapper():
    return VulnerabilityMapper()


@pytest.fixture
def enricher():
    return RemediationEnricher()


@pytest.fixture
def cache_mgr():
    return NVDCacheManager()


@pytest.fixture
def nvd_cache():
    """Dict keyed by PURL — 8 seed records from step1b_mock_entities.json."""
    return {
        "pkg:pypi/langchain@0.0.101": {
            "cve_id": "CVE-2023-34540",
            "cvss_score": 9.8,
            "severity": "High",
            "fixed_version": "0.0.247",
            "advisory_url": "https://nvd.nist.gov/vuln/detail/CVE-2023-34540",
        },
        "pkg:pypi/joblib@0.14.1": {
            "cve_id": "CVE-2022-21797",
            "cvss_score": 9.8,
            "severity": "High",
            "fixed_version": "1.2.0",
            "advisory_url": "https://nvd.nist.gov/vuln/detail/CVE-2022-21797",
        },
        "pkg:pypi/numpy@1.22.0": {
            "cve_id": "CVE-2021-33430",
            "cvss_score": 5.5,
            "severity": "Medium",
            "fixed_version": "1.22.2",
            "advisory_url": "https://nvd.nist.gov/vuln/detail/CVE-2021-33430",
        },
        "pkg:pypi/scipy@1.6.0": {
            "cve_id": "CVE-2023-25399",
            "cvss_score": 5.5,
            "severity": "Medium",
            "fixed_version": "1.11.0",
            "advisory_url": "https://nvd.nist.gov/vuln/detail/CVE-2023-25399",
        },
        "pkg:pypi/requests@2.27.1": {
            "cve_id": "CVE-2023-32681",
            "cvss_score": 6.1,
            "severity": "Medium",
            "fixed_version": "2.31.0",
            "advisory_url": "https://nvd.nist.gov/vuln/detail/CVE-2023-32681",
        },
        "pkg:pypi/lxml@4.6.3": {
            "cve_id": "CVE-2018-19787",
            "cvss_score": 6.1,
            "severity": "Medium",
            "fixed_version": "4.7.1",
            "advisory_url": "https://nvd.nist.gov/vuln/detail/CVE-2018-19787",
        },
        "pkg:pypi/Pillow@9.0.1": {
            "cve_id": "CVE-2023-44271",
            "cvss_score": 7.5,
            "severity": "High",
            "fixed_version": "10.0.0",
            "advisory_url": "https://nvd.nist.gov/vuln/detail/CVE-2023-44271",
        },
        "pkg:pypi/tensorflow@1.15.5": {
            "cve_id": "CVE-2022-29216",
            "cvss_score": 8.8,
            "severity": "High",
            "fixed_version": "2.9.0",
            "advisory_url": "https://nvd.nist.gov/vuln/detail/CVE-2022-29216",
        },
    }


@pytest.fixture
def langchain_dep():
    return {
        "name": "langchain",
        "exact_version": "0.0.101",
        "purl": "pkg:pypi/langchain@0.0.101",
        "cpe": "cpe:2.3:a:langchain:langchain:0.0.101:*:*:*:*:python:*:*",
        "dependency_type": "direct",
        "transitive_via": None,
        "supplier": "LangChain, Inc.",
    }


@pytest.fixture
def joblib_dep():
    return {
        "name": "joblib",
        "exact_version": "0.14.1",
        "purl": "pkg:pypi/joblib@0.14.1",
        "cpe": "cpe:2.3:a:joblib:joblib:0.14.1:*:*:*:*:python:*:*",
        "dependency_type": "transitive",
        "transitive_via": "scikit-learn",
        "supplier": "Gael Varoquaux",
    }


@pytest.fixture
def clean_dep():
    return {
        "name": "flask",
        "exact_version": "3.0.0",
        "purl": "pkg:pypi/flask@3.0.0",
        "cpe": "cpe:2.3:a:palletsprojects:flask:3.0.0:*:*:*:*:python:*:*",
        "dependency_type": "direct",
        "transitive_via": None,
        "supplier": "Pallets",
    }


@pytest.fixture
def raw_syft_component():
    """Minimal Syft JSON component as emitted by Syft."""
    return {
        "name": "langchain",
        "version": "0.0.101",
        "type": "python",
        "foundBy": "python-package-cataloger",
        "locations": [{"path": "/req/requirements.txt"}],
        "language": "python",
        "purl": "pkg:pypi/langchain@0.0.101",
        "cpes": ["cpe:2.3:a:langchain:langchain:0.0.101:*:*:*:*:python:*:*"],
        "metadata": {"Author": "LangChain, Inc."},
    }


@pytest.fixture
def raw_trivy_component():
    """Minimal Trivy JSON package as emitted by Trivy."""
    return {
        "Name": "numpy",
        "Version": "1.22.0",
        "PkgType": "pip",
        "PkgID": "numpy@1.22.0",
        "InstalledVersion": "1.22.0",
        "PkgPath": "requirements.txt",
        "PkgRef": "pkg:pypi/numpy@1.22.0",
        "Identifier": {
            "PURL": "pkg:pypi/numpy@1.22.0",
            "CPEs": ["cpe:2.3:a:numpy:numpy:1.22.0:*:*:*:*:python:*:*"],
        },
    }


# ===========================================================================
# CLASS 1: CVSSSeverityClassifier (21 tests)
# ===========================================================================

class TestCVSSSeverityClassifier:

    # --- basic band tests ---

    def test_score_7_0_is_high(self, clf):
        assert clf.classify(7.0) == "High"

    def test_score_6_9_is_medium(self, clf):
        assert clf.classify(6.9) == "Medium"

    def test_score_4_0_is_medium(self, clf):
        assert clf.classify(4.0) == "Medium"

    def test_score_3_9_is_low(self, clf):
        assert clf.classify(3.9) == "Low"

    def test_score_9_8_is_high(self, clf):
        assert clf.classify(9.8) == "High"

    def test_score_0_0_is_low(self, clf):
        assert clf.classify(0.0) == "Low"

    def test_null_score_is_unknown(self, clf):
        assert clf.classify(None) == "Unknown"

    def test_negative_score_is_unknown(self, clf):
        # Out-of-range input — spec does not define it; Unknown is the safe default
        assert clf.classify(-1.0) == "Unknown"

    def test_score_10_1_is_high(self, clf):
        # Out-of-range high — still High by the >= 7.0 rule
        assert clf.classify(10.1) == "High"

    # --- parametrized boundary table ---

    @pytest.mark.parametrize("score,expected", [
        (10.0, "High"),
        (9.8,  "High"),
        (8.8,  "High"),
        (7.5,  "High"),
        (7.0,  "High"),
        (6.9,  "Medium"),
        (6.1,  "Medium"),
        (5.5,  "Medium"),
        (4.0,  "Medium"),
        (3.9,  "Low"),
        (0.1,  "Low"),
        (0.0,  "Low"),
    ])
    def test_boundary_table(self, clf, score, expected):
        assert clf.classify(score) == expected

    # --- return type ---

    def test_return_type_is_string(self, clf):
        result = clf.classify(5.5)
        assert isinstance(result, str)

    def test_return_value_not_none_for_valid_score(self, clf):
        assert clf.classify(5.0) is not None

    def test_classify_does_not_raise_on_float(self, clf):
        # Must not raise — any score, even weird floats
        clf.classify(4.999999)


# ===========================================================================
# CLASS 2: OSSToolAdapter (20 tests)
# ===========================================================================

class TestOSSToolAdapter:

    # --- normalise: Syft ---

    def test_syft_normalise_returns_non_empty_list(self, adapter, raw_syft_component):
        result = adapter.normalise({"tool": "syft", "components": [raw_syft_component]})
        assert len(result) > 0

    def test_syft_normalise_maps_name(self, adapter, raw_syft_component):
        result = adapter.normalise({"tool": "syft", "components": [raw_syft_component]})
        assert result[0]["name"] == "langchain"

    def test_syft_normalise_maps_version(self, adapter, raw_syft_component):
        result = adapter.normalise({"tool": "syft", "components": [raw_syft_component]})
        assert result[0]["exact_version"] == "0.0.101"

    def test_syft_normalise_maps_purl(self, adapter, raw_syft_component):
        result = adapter.normalise({"tool": "syft", "components": [raw_syft_component]})
        assert result[0]["purl"] == "pkg:pypi/langchain@0.0.101"

    def test_syft_normalise_extracts_supplier_from_metadata(self, adapter, raw_syft_component):
        result = adapter.normalise({"tool": "syft", "components": [raw_syft_component]})
        assert result[0]["supplier"] == "LangChain, Inc."

    def test_syft_missing_supplier_defaults_to_unknown(self, adapter):
        component = {
            "name": "somelib", "version": "1.0.0",
            "purl": "pkg:pypi/somelib@1.0.0",
            "cpes": [],
            "metadata": {},
        }
        result = adapter.normalise({"tool": "syft", "components": [component]})
        assert result[0]["supplier"] == "Unknown"

    # --- normalise: Trivy ---

    def test_trivy_normalise_returns_non_empty_list(self, adapter, raw_trivy_component):
        result = adapter.normalise({"tool": "trivy", "Results": [{"Packages": [raw_trivy_component]}]})
        assert len(result) > 0

    def test_trivy_normalise_maps_name(self, adapter, raw_trivy_component):
        result = adapter.normalise({"tool": "trivy", "Results": [{"Packages": [raw_trivy_component]}]})
        assert result[0]["name"] == "numpy"

    def test_trivy_normalise_maps_version(self, adapter, raw_trivy_component):
        result = adapter.normalise({"tool": "trivy", "Results": [{"Packages": [raw_trivy_component]}]})
        assert result[0]["exact_version"] == "1.22.0"

    def test_trivy_normalise_maps_purl(self, adapter, raw_trivy_component):
        result = adapter.normalise({"tool": "trivy", "Results": [{"Packages": [raw_trivy_component]}]})
        assert result[0]["purl"] == "pkg:pypi/numpy@1.22.0"

    def test_trivy_missing_supplier_defaults_to_unknown(self, adapter, raw_trivy_component):
        result = adapter.normalise({"tool": "trivy", "Results": [{"Packages": [raw_trivy_component]}]})
        assert result[0]["supplier"] == "Unknown"

    # --- deduplicate ---

    def test_dedup_by_purl_keeps_one_record(self, adapter):
        records = [
            {"purl": "pkg:pypi/langchain@0.0.101", "name": "langchain", "source": "syft"},
            {"purl": "pkg:pypi/langchain@0.0.101", "name": "langchain", "source": "trivy"},
        ]
        result = adapter.deduplicate(records)
        assert len(result) == 1

    def test_dedup_idempotent_on_unique_input(self, adapter):
        records = [
            {"purl": "pkg:pypi/langchain@0.0.101", "name": "langchain"},
            {"purl": "pkg:pypi/numpy@1.22.0",      "name": "numpy"},
        ]
        result = adapter.deduplicate(records)
        assert len(result) == 2

    def test_dedup_same_purl_two_tools_one_record(self, adapter):
        records = [
            {"purl": "pkg:pypi/requests@2.27.1", "name": "requests", "tool": "syft"},
            {"purl": "pkg:pypi/requests@2.27.1", "name": "requests", "tool": "trivy"},
        ]
        result = adapter.deduplicate(records)
        purls = [r["purl"] for r in result]
        assert purls.count("pkg:pypi/requests@2.27.1") == 1

    def test_dedup_preserves_all_fields_of_kept_record(self, adapter):
        records = [{"purl": "pkg:pypi/flask@3.0.0", "name": "flask", "supplier": "Pallets"}]
        result = adapter.deduplicate(records)
        assert result[0]["name"] == "flask"
        assert result[0]["supplier"] == "Pallets"

    def test_dedup_empty_input_returns_empty(self, adapter):
        assert adapter.deduplicate([]) == []

    def test_normalise_empty_components_returns_empty(self, adapter):
        result = adapter.normalise({"tool": "syft", "components": []})
        assert result == []

    def test_normalise_output_records_have_purl_key(self, adapter, raw_syft_component):
        result = adapter.normalise({"tool": "syft", "components": [raw_syft_component]})
        assert "purl" in result[0]

    def test_normalise_output_records_have_name_key(self, adapter, raw_syft_component):
        result = adapter.normalise({"tool": "syft", "components": [raw_syft_component]})
        assert "name" in result[0]

    def test_normalise_output_records_have_exact_version_key(self, adapter, raw_syft_component):
        result = adapter.normalise({"tool": "syft", "components": [raw_syft_component]})
        assert "exact_version" in result[0]


# ===========================================================================
# CLASS 3: VulnerabilityMapper (20 tests)
# ===========================================================================

class TestVulnerabilityMapper:

    def test_purl_match_returns_cve_record(self, mapper, langchain_dep, nvd_cache):
        result = mapper.map_vulnerabilities([langchain_dep], nvd_cache)
        assert len(result) == 1

    def test_purl_match_correct_cve_id(self, mapper, langchain_dep, nvd_cache):
        result = mapper.map_vulnerabilities([langchain_dep], nvd_cache)
        assert result[0]["cve_id"] == "CVE-2023-34540"

    def test_purl_match_correct_cvss_score(self, mapper, langchain_dep, nvd_cache):
        result = mapper.map_vulnerabilities([langchain_dep], nvd_cache)
        assert result[0]["cvss_score"] == 9.8

    def test_purl_match_correct_purl_in_result(self, mapper, langchain_dep, nvd_cache):
        result = mapper.map_vulnerabilities([langchain_dep], nvd_cache)
        assert result[0]["purl"] == "pkg:pypi/langchain@0.0.101"

    def test_cpe_fallback_when_purl_absent_in_cache(self, mapper, nvd_cache):
        # Dep with a PURL not in cache but CPE matches an entry
        dep = {
            "name": "joblib",
            "exact_version": "0.14.1",
            "purl": "pkg:pypi/joblib@0.14.1-NOPURL",  # won't match by PURL
            "cpe": "cpe:2.3:a:joblib:joblib:0.14.1:*:*:*:*:python:*:*",
            "dependency_type": "transitive",
            "transitive_via": "scikit-learn",
        }
        # Provide a cache indexed by CPE instead of PURL for this test
        cpe_cache = {e["cpe"]: e for e in [
            {"cpe": "cpe:2.3:a:joblib:joblib:0.14.1:*:*:*:*:python:*:*",
             "cve_id": "CVE-2022-21797", "cvss_score": 9.8,
             "fixed_version": "1.2.0",
             "advisory_url": "https://nvd.nist.gov/vuln/detail/CVE-2022-21797"},
        ]}
        result = mapper.map_vulnerabilities([dep], cpe_cache)
        assert len(result) == 1
        assert result[0]["cve_id"] == "CVE-2022-21797"

    def test_clean_package_returns_empty(self, mapper, clean_dep, nvd_cache):
        result = mapper.map_vulnerabilities([clean_dep], nvd_cache)
        assert result == []

    def test_transitive_dep_cve_attributed_to_transitive(self, mapper, joblib_dep, nvd_cache):
        result = mapper.map_vulnerabilities([joblib_dep], nvd_cache)
        assert len(result) == 1
        assert result[0]["dep_name"] == "joblib"

    def test_transitive_dep_cve_not_attributed_to_parent(self, mapper, joblib_dep, nvd_cache):
        result = mapper.map_vulnerabilities([joblib_dep], nvd_cache)
        # Parent is scikit-learn; result must reference joblib, not scikit-learn
        for r in result:
            assert r.get("dep_name") != "scikit-learn"

    def test_multiple_deps_multiple_vulns(self, mapper, nvd_cache):
        deps = [
            {"name": "langchain", "exact_version": "0.0.101",
             "purl": "pkg:pypi/langchain@0.0.101", "cpe": "", "dependency_type": "direct"},
            {"name": "Pillow", "exact_version": "9.0.1",
             "purl": "pkg:pypi/Pillow@9.0.1", "cpe": "", "dependency_type": "direct"},
        ]
        result = mapper.map_vulnerabilities(deps, nvd_cache)
        assert len(result) == 2

    def test_unknown_dep_no_fabricated_cve(self, mapper, nvd_cache):
        dep = {"name": "unknownlib", "exact_version": "9.9.9",
               "purl": "pkg:pypi/unknownlib@9.9.9", "cpe": "",
               "dependency_type": "direct"}
        result = mapper.map_vulnerabilities([dep], nvd_cache)
        assert result == []

    def test_result_record_contains_dep_purl(self, mapper, langchain_dep, nvd_cache):
        result = mapper.map_vulnerabilities([langchain_dep], nvd_cache)
        assert "purl" in result[0]

    def test_result_record_contains_cve_id(self, mapper, langchain_dep, nvd_cache):
        result = mapper.map_vulnerabilities([langchain_dep], nvd_cache)
        assert "cve_id" in result[0]

    def test_result_record_contains_cvss_score(self, mapper, langchain_dep, nvd_cache):
        result = mapper.map_vulnerabilities([langchain_dep], nvd_cache)
        assert "cvss_score" in result[0]

    def test_result_record_contains_severity(self, mapper, langchain_dep, nvd_cache):
        result = mapper.map_vulnerabilities([langchain_dep], nvd_cache)
        assert "severity" in result[0]

    def test_empty_dep_list_returns_empty(self, mapper, nvd_cache):
        assert mapper.map_vulnerabilities([], nvd_cache) == []

    def test_empty_cache_returns_empty(self, mapper, langchain_dep):
        assert mapper.map_vulnerabilities([langchain_dep], {}) == []

    def test_tensorflow_cve_mapped_correctly(self, mapper, nvd_cache):
        dep = {"name": "tensorflow", "exact_version": "1.15.5",
               "purl": "pkg:pypi/tensorflow@1.15.5", "cpe": "",
               "dependency_type": "direct"}
        result = mapper.map_vulnerabilities([dep], nvd_cache)
        assert result[0]["cve_id"] == "CVE-2022-29216"

    def test_pillow_cve_mapped_correctly(self, mapper, nvd_cache):
        dep = {"name": "Pillow", "exact_version": "9.0.1",
               "purl": "pkg:pypi/Pillow@9.0.1", "cpe": "",
               "dependency_type": "direct"}
        result = mapper.map_vulnerabilities([dep], nvd_cache)
        assert result[0]["cve_id"] == "CVE-2023-44271"

    def test_joblib_cve_is_high_severity(self, mapper, joblib_dep, nvd_cache):
        result = mapper.map_vulnerabilities([joblib_dep], nvd_cache)
        assert result[0]["severity"] == "High"

    def test_numpy_cve_is_medium_severity(self, mapper, nvd_cache):
        dep = {"name": "numpy", "exact_version": "1.22.0",
               "purl": "pkg:pypi/numpy@1.22.0", "cpe": "",
               "dependency_type": "direct"}
        result = mapper.map_vulnerabilities([dep], nvd_cache)
        assert result[0]["severity"] == "Medium"


# ===========================================================================
# CLASS 4: RemediationEnricher (20 tests)
# ===========================================================================

class TestRemediationEnricher:

    @pytest.fixture
    def vuln_langchain(self):
        return {
            "cve_id": "CVE-2023-34540",
            "purl": "pkg:pypi/langchain@0.0.101",
            "cvss_score": 9.8,
            "severity": "High",
            "dep_name": "langchain",
        }

    @pytest.fixture
    def cache_langchain(self):
        return {
            "cve_id": "CVE-2023-34540",
            "fixed_version": "0.0.247",
            "advisory_url": "https://nvd.nist.gov/vuln/detail/CVE-2023-34540",
            "cvss_score": 9.8,
            "severity": "High",
        }

    @pytest.fixture
    def cache_no_fix(self):
        return {
            "cve_id": "CVE-9999-99999",
            "advisory_url": "https://nvd.nist.gov/vuln/detail/CVE-9999-99999",
            "cvss_score": 5.0,
            "severity": "Medium",
            # fixed_version intentionally absent
        }

    @pytest.fixture
    def vuln_medium(self):
        return {
            "cve_id": "CVE-2021-33430",
            "purl": "pkg:pypi/numpy@1.22.0",
            "cvss_score": 5.5,
            "severity": "Medium",
            "dep_name": "numpy",
        }

    @pytest.fixture
    def cache_medium(self):
        return {
            "cve_id": "CVE-2021-33430",
            "fixed_version": "1.22.2",
            "advisory_url": "https://nvd.nist.gov/vuln/detail/CVE-2021-33430",
            "cvss_score": 5.5,
            "severity": "Medium",
        }

    def test_enrich_returns_non_none(self, enricher, vuln_langchain, cache_langchain):
        result = enricher.enrich(vuln_langchain, cache_langchain)
        assert result is not None

    def test_advisory_url_present_in_output(self, enricher, vuln_langchain, cache_langchain):
        result = enricher.enrich(vuln_langchain, cache_langchain)
        assert "advisory_url" in result

    def test_advisory_url_value_matches_cache(self, enricher, vuln_langchain, cache_langchain):
        result = enricher.enrich(vuln_langchain, cache_langchain)
        assert result["advisory_url"] == "https://nvd.nist.gov/vuln/detail/CVE-2023-34540"

    def test_fixed_version_present_when_in_cache(self, enricher, vuln_langchain, cache_langchain):
        result = enricher.enrich(vuln_langchain, cache_langchain)
        assert "fixed_version" in result
        assert result["fixed_version"] == "0.0.247"

    def test_fixed_version_none_when_absent_from_cache(self, enricher, vuln_langchain, cache_no_fix):
        result = enricher.enrich(vuln_langchain, cache_no_fix)
        assert "fixed_version" in result       # field must exist
        assert result["fixed_version"] is None # value must be None, not omitted

    def test_severity_applied_from_cvss(self, enricher, vuln_langchain, cache_langchain):
        result = enricher.enrich(vuln_langchain, cache_langchain)
        assert result["severity"] == "High"

    def test_severity_medium_applied(self, enricher, vuln_medium, cache_medium):
        result = enricher.enrich(vuln_medium, cache_medium)
        assert result["severity"] == "Medium"

    def test_high_severity_has_upgrade_command(self, enricher, vuln_langchain, cache_langchain):
        result = enricher.enrich(vuln_langchain, cache_langchain)
        assert "upgrade_command" in result
        assert result["upgrade_command"] is not None

    def test_high_severity_upgrade_command_references_package(self, enricher, vuln_langchain, cache_langchain):
        result = enricher.enrich(vuln_langchain, cache_langchain)
        assert "langchain" in result["upgrade_command"]

    def test_high_severity_upgrade_command_references_fixed_version(self, enricher, vuln_langchain, cache_langchain):
        result = enricher.enrich(vuln_langchain, cache_langchain)
        assert "0.0.247" in result["upgrade_command"]

    def test_cve_id_preserved_in_output(self, enricher, vuln_langchain, cache_langchain):
        result = enricher.enrich(vuln_langchain, cache_langchain)
        assert result["cve_id"] == "CVE-2023-34540"

    def test_purl_preserved_in_output(self, enricher, vuln_langchain, cache_langchain):
        result = enricher.enrich(vuln_langchain, cache_langchain)
        assert result["purl"] == "pkg:pypi/langchain@0.0.101"

    def test_cvss_score_preserved_in_output(self, enricher, vuln_langchain, cache_langchain):
        result = enricher.enrich(vuln_langchain, cache_langchain)
        assert result["cvss_score"] == 9.8

    def test_advisory_url_not_empty_string(self, enricher, vuln_langchain, cache_langchain):
        result = enricher.enrich(vuln_langchain, cache_langchain)
        assert result["advisory_url"] != ""

    def test_tensorflow_enrich(self, enricher):
        vuln = {"cve_id": "CVE-2022-29216", "purl": "pkg:pypi/tensorflow@1.15.5",
                "cvss_score": 8.8, "severity": "High", "dep_name": "tensorflow"}
        cache = {"cve_id": "CVE-2022-29216", "fixed_version": "2.9.0",
                 "advisory_url": "https://nvd.nist.gov/vuln/detail/CVE-2022-29216",
                 "cvss_score": 8.8, "severity": "High"}
        result = enricher.enrich(vuln, cache)
        assert result["fixed_version"] == "2.9.0"

    def test_pillow_enrich_advisory_url(self, enricher):
        vuln = {"cve_id": "CVE-2023-44271", "purl": "pkg:pypi/Pillow@9.0.1",
                "cvss_score": 7.5, "severity": "High", "dep_name": "Pillow"}
        cache = {"cve_id": "CVE-2023-44271", "fixed_version": "10.0.0",
                 "advisory_url": "https://nvd.nist.gov/vuln/detail/CVE-2023-44271",
                 "cvss_score": 7.5, "severity": "High"}
        result = enricher.enrich(vuln, cache)
        assert result["advisory_url"] == "https://nvd.nist.gov/vuln/detail/CVE-2023-44271"

    def test_medium_no_upgrade_command_required(self, enricher, vuln_medium, cache_medium):
        # Medium severity: upgrade_command is optional but fixed_version must still be present
        result = enricher.enrich(vuln_medium, cache_medium)
        assert result["fixed_version"] == "1.22.2"

    def test_result_is_dict(self, enricher, vuln_langchain, cache_langchain):
        result = enricher.enrich(vuln_langchain, cache_langchain)
        assert isinstance(result, dict)

    def test_enrich_does_not_mutate_input_vuln(self, enricher, vuln_langchain, cache_langchain):
        original_cve = vuln_langchain["cve_id"]
        enricher.enrich(vuln_langchain, cache_langchain)
        assert vuln_langchain["cve_id"] == original_cve


# ===========================================================================
# CLASS 5: NVDCacheManager (22 tests)
# ===========================================================================

class TestNVDCacheManager:

    def _ts(self, days_ago: int) -> datetime:
        return datetime.now(timezone.utc) - timedelta(days=days_ago)

    # --- is_stale ---

    def test_8_days_ago_is_stale(self, cache_mgr):
        assert cache_mgr.is_stale(self._ts(8)) is True

    def test_6_days_ago_is_not_stale(self, cache_mgr):
        assert cache_mgr.is_stale(self._ts(6)) is False

    def test_exactly_7_days_is_stale(self, cache_mgr):
        # Boundary: >= 7 days old → stale
        assert cache_mgr.is_stale(self._ts(7)) is True

    def test_1_day_ago_not_stale(self, cache_mgr):
        assert cache_mgr.is_stale(self._ts(1)) is False

    def test_0_days_ago_not_stale(self, cache_mgr):
        assert cache_mgr.is_stale(self._ts(0)) is False

    def test_30_days_ago_is_stale(self, cache_mgr):
        assert cache_mgr.is_stale(self._ts(30)) is True

    def test_is_stale_returns_bool(self, cache_mgr):
        result = cache_mgr.is_stale(self._ts(5))
        assert isinstance(result, bool)

    # --- check_staleness ---

    def test_check_staleness_returns_warning_when_stale(self, cache_mgr, monkeypatch):
        monkeypatch.setattr(cache_mgr, "is_stale", lambda ts: True)
        monkeypatch.setattr(cache_mgr, "_last_synced_at",
                            self._ts(8), raising=False)
        result = cache_mgr.check_staleness()
        assert "warning" in result or "stale" in str(result).lower()

    def test_check_staleness_warning_is_string(self, cache_mgr, monkeypatch):
        monkeypatch.setattr(cache_mgr, "is_stale", lambda ts: True)
        monkeypatch.setattr(cache_mgr, "_last_synced_at",
                            self._ts(8), raising=False)
        result = cache_mgr.check_staleness()
        warning = result.get("warning") or result.get("message") or ""
        assert isinstance(warning, str)

    def test_check_staleness_fresh_cache_no_warning(self, cache_mgr, monkeypatch):
        monkeypatch.setattr(cache_mgr, "is_stale", lambda ts: False)
        monkeypatch.setattr(cache_mgr, "_last_synced_at",
                            self._ts(2), raising=False)
        result = cache_mgr.check_staleness()
        # Either empty dict or a dict without a warning flag
        assert result == {} or result.get("stale") is False

    def test_check_staleness_returns_dict(self, cache_mgr):
        result = cache_mgr.check_staleness()
        assert isinstance(result, dict)

    # --- sync ---

    def test_sync_valid_path_returns_sync_result(self, cache_mgr, tmp_path):
        source = tmp_path / "nvd_feed.json"
        source.write_text('{"CVE_Items": []}')
        result = cache_mgr.sync(str(source))
        assert result is not None

    def test_sync_valid_path_result_has_records_added(self, cache_mgr, tmp_path):
        source = tmp_path / "nvd_feed.json"
        source.write_text('{"CVE_Items": []}')
        result = cache_mgr.sync(str(source))
        assert hasattr(result, "records_added") or "records_added" in result

    def test_sync_valid_path_result_has_records_updated(self, cache_mgr, tmp_path):
        source = tmp_path / "nvd_feed.json"
        source.write_text('{"CVE_Items": []}')
        result = cache_mgr.sync(str(source))
        assert hasattr(result, "records_updated") or "records_updated" in result

    def test_sync_missing_path_raises_nvd_sync_error(self, cache_mgr):
        with pytest.raises(NVDSyncError):
            cache_mgr.sync("/nonexistent/path/nvd.json")

    def test_sync_log_entry_created_after_sync(self, cache_mgr, tmp_path):
        source = tmp_path / "nvd_feed.json"
        source.write_text('{"CVE_Items": []}')
        cache_mgr.sync(str(source))
        assert cache_mgr.last_sync_log is not None

    def test_sync_log_contains_timestamp(self, cache_mgr, tmp_path):
        source = tmp_path / "nvd_feed.json"
        source.write_text('{"CVE_Items": []}')
        cache_mgr.sync(str(source))
        log = cache_mgr.last_sync_log
        assert "synced_at" in log or "timestamp" in log

    def test_sync_log_contains_source_path(self, cache_mgr, tmp_path):
        source = tmp_path / "nvd_feed.json"
        source.write_text('{"CVE_Items": []}')
        path_str = str(source)
        cache_mgr.sync(path_str)
        log = cache_mgr.last_sync_log
        assert log.get("source_path") == path_str or path_str in str(log)

    def test_duplicate_cve_purl_upsert_not_duplicate(self, cache_mgr, tmp_path):
        # Syncing the same CVE+PURL twice must not create two rows
        record = {
            "cve_id": "CVE-2023-34540",
            "purl": "pkg:pypi/langchain@0.0.101",
            "cvss_score": 9.8,
        }
        import json
        feed = json.dumps({"CVE_Items": [record, record]})
        source = tmp_path / "nvd_dup.json"
        source.write_text(feed)
        result = cache_mgr.sync(str(source))
        count = getattr(result, "records_added", None) or result.get("records_added", 0)
        count += getattr(result, "records_updated", None) or result.get("records_updated", 0)
        # Two identical inputs → 1 insert + 0 or 1 upsert, never 2 inserts
        inserts = getattr(result, "records_added", None) or result.get("records_added", 0)
        assert inserts <= 1

    def test_sync_does_not_raise_on_empty_feed(self, cache_mgr, tmp_path):
        source = tmp_path / "empty.json"
        source.write_text('{"CVE_Items": []}')
        # Must not raise
        cache_mgr.sync(str(source))

    def test_is_stale_with_naive_datetime_raises_or_handles(self, cache_mgr):
        # Passing a naive datetime (no tzinfo) — implementation must handle gracefully
        naive = datetime.now()
        try:
            result = cache_mgr.is_stale(naive)
            assert isinstance(result, bool)
        except (TypeError, ValueError):
            pass  # Also acceptable — raising is defensive behaviour


# ---------------------------------------------------------------------------
# STUBS — wrong-valued implementations (Red Phase)
# ---------------------------------------------------------------------------

class CycloneDXSerializer:
    def serialize(self, scan_result: Dict) -> Dict:
        return {}  # stub: empty dict — every assertion fails


class SPDXSerializer:
    def serialize(self, scan_result: Dict) -> Dict:
        return {}  # stub: empty dict — every assertion fails


@dataclass
class ValidationResult:
    valid: bool
    errors: List[str] = field(default_factory=list)


class ScanJobValidator:
    def validate(self, repo_path: str, env: str) -> ValidationResult:
        return ValidationResult(valid=True)  # stub: always valid — negative tests fail


@dataclass
class FilterResult:
    active: List[Dict]
    suppressed: List[Dict]


class VEXFilter:
    def apply(self, vulns: List[Dict], vex_statements: List[Dict]) -> FilterResult:
        return FilterResult(active=list(vulns), suppressed=[])  # stub: never suppresses


@dataclass
class DependencyRecord:
    name: str = ""
    version: str = ""
    purl: str = ""
    dependency_type: str = ""
    transitive_via: Optional[str] = None
    supplier: str = "Unknown"

    def __post_init__(self):
        pass  # stub: no validation


# ---------------------------------------------------------------------------
# Shared fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def taskmatrix_deps():
    return [
        {"name": "langchain", "version": "0.0.101",
         "purl": "pkg:pypi/langchain@0.0.101", "type": "library",
         "cpe": "cpe:2.3:a:langchain:langchain:0.0.101:*:*:*:*:python:*:*",
         "vulnerable": True, "cve_ids": ["CVE-2023-34540"]},
        {"name": "openai", "version": "0.27.2",
         "purl": "pkg:pypi/openai@0.27.2", "type": "library",
         "cpe": "cpe:2.3:a:openai:openai:0.27.2:*:*:*:*:python:*:*",
         "vulnerable": False, "cve_ids": []},
        {"name": "requests", "version": "2.27.1",
         "purl": "pkg:pypi/requests@2.27.1", "type": "library",
         "cpe": "cpe:2.3:a:python-requests:requests:2.27.1:*:*:*:*:python:*:*",
         "vulnerable": True, "cve_ids": ["CVE-2023-32681"]},
        {"name": "numpy", "version": "1.23.5",
         "purl": "pkg:pypi/numpy@1.23.5", "type": "library",
         "cpe": "cpe:2.3:a:numpy:numpy:1.23.5:*:*:*:*:python:*:*",
         "vulnerable": False, "cve_ids": []},
        {"name": "pydantic", "version": "1.10.4",
         "purl": "pkg:pypi/pydantic@1.10.4", "type": "library",
         "cpe": "cpe:2.3:a:pydantic:pydantic:1.10.4:*:*:*:*:python:*:*",
         "vulnerable": False, "cve_ids": []},
        {"name": "lxml", "version": "4.6.3",
         "purl": "pkg:pypi/lxml@4.6.3", "type": "library",
         "cpe": "cpe:2.3:a:lxml:lxml:4.6.3:*:*:*:*:python:*:*",
         "vulnerable": True, "cve_ids": ["CVE-2018-19787"]},
        {"name": "aiohttp", "version": "3.8.1",
         "purl": "pkg:pypi/aiohttp@3.8.1", "type": "library",
         "cpe": "cpe:2.3:a:aiohttp:aiohttp:3.8.1:*:*:*:*:python:*:*",
         "vulnerable": False, "cve_ids": []},
        {"name": "tenacity", "version": "8.1.0",
         "purl": "pkg:pypi/tenacity@8.1.0", "type": "library",
         "cpe": "cpe:2.3:a:tenacity_project:tenacity:8.1.0:*:*:*:*:python:*:*",
         "vulnerable": False, "cve_ids": []},
    ]


@pytest.fixture
def clean_api_deps():
    return [
        {"name": "flask", "version": "3.0.0",
         "purl": "pkg:pypi/flask@3.0.0", "type": "library",
         "cpe": "cpe:2.3:a:palletsprojects:flask:3.0.0:*:*:*:*:python:*:*",
         "vulnerable": False, "cve_ids": []},
        {"name": "click", "version": "8.1.7",
         "purl": "pkg:pypi/click@8.1.7", "type": "library",
         "cpe": "cpe:2.3:a:palletsprojects:click:8.1.7:*:*:*:*:python:*:*",
         "vulnerable": False, "cve_ids": []},
        {"name": "werkzeug", "version": "3.0.1",
         "purl": "pkg:pypi/werkzeug@3.0.1", "type": "library",
         "cpe": "cpe:2.3:a:palletsprojects:werkzeug:3.0.1:*:*:*:*:python:*:*",
         "vulnerable": False, "cve_ids": []},
        {"name": "itsdangerous", "version": "2.1.2",
         "purl": "pkg:pypi/itsdangerous@2.1.2", "type": "library",
         "cpe": "cpe:2.3:a:palletsprojects:itsdangerous:2.1.2:*:*:*:*:python:*:*",
         "vulnerable": False, "cve_ids": []},
    ]


@pytest.fixture
def handson_ml_deps():
    return [
        {"name": "numpy", "version": "1.22.0",
         "purl": "pkg:pypi/numpy@1.22.0", "type": "library",
         "cpe": "cpe:2.3:a:numpy:numpy:1.22.0:*:*:*:*:python:*:*",
         "vulnerable": True, "cve_ids": ["CVE-2021-33430"]},
        {"name": "pandas", "version": "1.2.2",
         "purl": "pkg:pypi/pandas@1.2.2", "type": "library",
         "cpe": "cpe:2.3:a:pandas:pandas:1.2.2:*:*:*:*:python:*:*",
         "vulnerable": False, "cve_ids": []},
        {"name": "scikit-learn", "version": "0.24.1",
         "purl": "pkg:pypi/scikit-learn@0.24.1", "type": "library",
         "cpe": "cpe:2.3:a:scikit-learn:scikit-learn:0.24.1:*:*:*:*:python:*:*",
         "vulnerable": False, "cve_ids": []},
        {"name": "scipy", "version": "1.6.0",
         "purl": "pkg:pypi/scipy@1.6.0", "type": "library",
         "cpe": "cpe:2.3:a:scipy:scipy:1.6.0:*:*:*:*:python:*:*",
         "vulnerable": True, "cve_ids": ["CVE-2023-25399"]},
        {"name": "matplotlib", "version": "3.3.4",
         "purl": "pkg:pypi/matplotlib@3.3.4", "type": "library",
         "cpe": "cpe:2.3:a:matplotlib:matplotlib:3.3.4:*:*:*:*:python:*:*",
         "vulnerable": False, "cve_ids": []},
        {"name": "Pillow", "version": "9.0.1",
         "purl": "pkg:pypi/Pillow@9.0.1", "type": "library",
         "cpe": "cpe:2.3:a:python:pillow:9.0.1:*:*:*:*:python:*:*",
         "vulnerable": True, "cve_ids": ["CVE-2023-44271"]},
        {"name": "joblib", "version": "0.14.1",
         "purl": "pkg:pypi/joblib@0.14.1", "type": "library",
         "cpe": "cpe:2.3:a:joblib:joblib:0.14.1:*:*:*:*:python:*:*",
         "vulnerable": True, "cve_ids": ["CVE-2022-21797"]},
        {"name": "threadpoolctl", "version": "2.1.0",
         "purl": "pkg:pypi/threadpoolctl@2.1.0", "type": "library",
         "cpe": "cpe:2.3:a:threadpoolctl:threadpoolctl:2.1.0:*:*:*:*:python:*:*",
         "vulnerable": False, "cve_ids": []},
        {"name": "tensorflow", "version": "1.15.5",
         "purl": "pkg:pypi/tensorflow@1.15.5", "type": "library",
         "cpe": "cpe:2.3:a:google:tensorflow:1.15.5:*:*:*:*:python:*:*",
         "vulnerable": True, "cve_ids": ["CVE-2022-29216"]},
    ]


@pytest.fixture
def taskmatrix_scan(taskmatrix_deps):
    return {
        "scan_id": "scan_001",
        "repo_name": "TaskMatrix",
        "dependencies": taskmatrix_deps,
        "vulnerabilities": [
            {"cve_id": "CVE-2023-34540", "purl": "pkg:pypi/langchain@0.0.101",
             "cvss_score": 9.8, "severity": "High"},
            {"cve_id": "CVE-2023-32681", "purl": "pkg:pypi/requests@2.27.1",
             "cvss_score": 6.1, "severity": "Medium"},
            {"cve_id": "CVE-2018-19787", "purl": "pkg:pypi/lxml@4.6.3",
             "cvss_score": 6.1, "severity": "Medium"},
        ],
    }


@pytest.fixture
def clean_scan(clean_api_deps):
    return {
        "scan_id": "scan_003",
        "repo_name": "clean-api",
        "dependencies": clean_api_deps,
        "vulnerabilities": [],
    }


@pytest.fixture
def handson_scan(handson_ml_deps):
    return {
        "scan_id": "scan_002",
        "repo_name": "handson-ml",
        "dependencies": handson_ml_deps,
        "vulnerabilities": [
            {"cve_id": "CVE-2021-33430", "purl": "pkg:pypi/numpy@1.22.0",
             "cvss_score": 5.5, "severity": "Medium"},
            {"cve_id": "CVE-2023-25399", "purl": "pkg:pypi/scipy@1.6.0",
             "cvss_score": 5.5, "severity": "Medium"},
            {"cve_id": "CVE-2023-44271", "purl": "pkg:pypi/Pillow@9.0.1",
             "cvss_score": 7.5, "severity": "High"},
            {"cve_id": "CVE-2022-21797", "purl": "pkg:pypi/joblib@0.14.1",
             "cvss_score": 9.8, "severity": "High"},
            {"cve_id": "CVE-2022-29216", "purl": "pkg:pypi/tensorflow@1.15.5",
             "cvss_score": 8.8, "severity": "High"},
        ],
    }


# ---------------------------------------------------------------------------
# 6. CycloneDXSerializer — 22 tests
# ---------------------------------------------------------------------------


class TestCycloneDXSerializer:

    @pytest.fixture
    def ser(self):
        return CycloneDXSerializer()

    def test_bom_format(self, ser, taskmatrix_scan):
        result = ser.serialize(taskmatrix_scan)
        assert result.get("bomFormat") == "CycloneDX"

    def test_spec_version(self, ser, taskmatrix_scan):
        result = ser.serialize(taskmatrix_scan)
        assert result.get("specVersion") == "1.4"

    def test_serial_number_present(self, ser, taskmatrix_scan):
        result = ser.serialize(taskmatrix_scan)
        assert "serialNumber" in result

    def test_serial_number_is_urn_uuid(self, ser, taskmatrix_scan):
        result = ser.serialize(taskmatrix_scan)
        sn = result.get("serialNumber", "")
        assert sn.startswith("urn:uuid:")

    def test_serial_number_uuid_valid(self, ser, taskmatrix_scan):
        result = ser.serialize(taskmatrix_scan)
        sn = result.get("serialNumber", "")
        raw = sn.replace("urn:uuid:", "")
        parsed = uuid.UUID(raw)  # raises ValueError on invalid UUID
        assert str(parsed) == raw

    def test_metadata_present(self, ser, taskmatrix_scan):
        result = ser.serialize(taskmatrix_scan)
        assert "metadata" in result

    def test_metadata_timestamp_present(self, ser, taskmatrix_scan):
        result = ser.serialize(taskmatrix_scan)
        assert "timestamp" in result.get("metadata", {})

    def test_metadata_timestamp_iso8601(self, ser, taskmatrix_scan):
        result = ser.serialize(taskmatrix_scan)
        ts = result.get("metadata", {}).get("timestamp", "")
        dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
        assert dt is not None

    def test_metadata_tools_contains_sbom_tool(self, ser, taskmatrix_scan):
        result = ser.serialize(taskmatrix_scan)
        tools = result.get("metadata", {}).get("tools", [])
        names = [t.get("name") for t in tools]
        assert "sbom-tool" in names

    def test_components_list_present(self, ser, taskmatrix_scan):
        result = ser.serialize(taskmatrix_scan)
        assert "components" in result

    def test_components_count_matches_deps(self, ser, taskmatrix_scan):
        result = ser.serialize(taskmatrix_scan)
        assert len(result.get("components", [])) == len(taskmatrix_scan["dependencies"])

    def test_each_component_has_name(self, ser, taskmatrix_scan):
        result = ser.serialize(taskmatrix_scan)
        components = result.get("components", [])
        assert len(components) == len(taskmatrix_scan["dependencies"]), "components list must be populated"
        for comp in components:
            assert "name" in comp and comp["name"]

    def test_each_component_has_version(self, ser, taskmatrix_scan):
        result = ser.serialize(taskmatrix_scan)
        components = result.get("components", [])
        assert len(components) == len(taskmatrix_scan["dependencies"]), "components list must be populated"
        for comp in components:
            assert "version" in comp and comp["version"]

    def test_each_component_has_purl(self, ser, taskmatrix_scan):
        result = ser.serialize(taskmatrix_scan)
        components = result.get("components", [])
        assert len(components) == len(taskmatrix_scan["dependencies"]), "components list must be populated"
        for comp in components:
            assert "purl" in comp and comp["purl"]

    def test_each_component_has_type(self, ser, taskmatrix_scan):
        result = ser.serialize(taskmatrix_scan)
        components = result.get("components", [])
        assert len(components) == len(taskmatrix_scan["dependencies"]), "components list must be populated"
        for comp in components:
            assert "type" in comp

    def test_component_purl_format(self, ser, taskmatrix_scan):
        result = ser.serialize(taskmatrix_scan)
        components = result.get("components", [])
        assert len(components) == len(taskmatrix_scan["dependencies"]), "components list must be populated"
        purl_re = re.compile(r"^pkg:pypi/[^@]+@.+$")
        for comp in components:
            assert purl_re.match(comp.get("purl", "")), comp.get("purl")

    def test_vulnerabilities_list_present(self, ser, taskmatrix_scan):
        result = ser.serialize(taskmatrix_scan)
        assert "vulnerabilities" in result

    def test_vuln_cve_id_in_vulnerabilities(self, ser, taskmatrix_scan):
        result = ser.serialize(taskmatrix_scan)
        ids = [v.get("id") for v in result.get("vulnerabilities", [])]
        assert "CVE-2023-34540" in ids

    def test_langchain_vuln_affects_correct_purl(self, ser, taskmatrix_scan):
        result = ser.serialize(taskmatrix_scan)
        langchain_vuln = next(
            (v for v in result.get("vulnerabilities", []) if v.get("id") == "CVE-2023-34540"),
            None,
        )
        assert langchain_vuln is not None
        affects_purls = [a.get("ref") for a in langchain_vuln.get("affects", [])]
        assert "pkg:pypi/langchain@0.0.101" in affects_purls

    def test_clean_scan_has_empty_vulnerabilities(self, ser, clean_scan):
        result = ser.serialize(clean_scan)
        assert result.get("vulnerabilities") == []

    def test_clean_scan_components_count(self, ser, clean_scan):
        result = ser.serialize(clean_scan)
        assert len(result.get("components", [])) == len(clean_scan["dependencies"])

    def test_metadata_tools_present(self, ser, taskmatrix_scan):
        result = ser.serialize(taskmatrix_scan)
        tools = result.get("metadata", {}).get("tools", [])
        assert len(tools) > 0


# ---------------------------------------------------------------------------
# 7. SPDXSerializer — 22 tests
# ---------------------------------------------------------------------------

class TestSPDXSerializer:

    @pytest.fixture
    def ser(self):
        return SPDXSerializer()

    def test_spdx_version(self, ser, handson_scan):
        result = ser.serialize(handson_scan)
        assert result.get("spdxVersion") == "SPDX-2.3"

    def test_data_license(self, ser, handson_scan):
        result = ser.serialize(handson_scan)
        assert result.get("dataLicense") == "CC0-1.0"

    def test_spdxid_document(self, ser, handson_scan):
        result = ser.serialize(handson_scan)
        assert result.get("SPDXID") == "SPDXRef-DOCUMENT"

    def test_document_namespace_present(self, ser, handson_scan):
        result = ser.serialize(handson_scan)
        assert "documentNamespace" in result

    def test_document_namespace_is_uri(self, ser, handson_scan):
        result = ser.serialize(handson_scan)
        ns = result.get("documentNamespace", "")
        assert ns.startswith("https://") or ns.startswith("http://")

    def test_packages_present(self, ser, handson_scan):
        result = ser.serialize(handson_scan)
        assert "packages" in result

    def test_packages_not_empty(self, ser, handson_scan):
        result = ser.serialize(handson_scan)
        assert len(result.get("packages", [])) > 0

    def test_packages_count_matches_deps(self, ser, handson_scan):
        result = ser.serialize(handson_scan)
        assert len(result.get("packages", [])) == len(handson_scan["dependencies"])

    def test_each_package_has_spdxid(self, ser, handson_scan):
        result = ser.serialize(handson_scan)
        packages = result.get("packages", [])
        assert len(packages) == len(handson_scan["dependencies"]), "packages list must be populated"
        for pkg in packages:
            assert "SPDXID" in pkg

    def test_each_spdxid_has_prefix(self, ser, handson_scan):
        result = ser.serialize(handson_scan)
        packages = result.get("packages", [])
        assert len(packages) == len(handson_scan["dependencies"]), "packages list must be populated"
        for pkg in packages:
            assert pkg.get("SPDXID", "").startswith("SPDXRef-"), pkg.get("SPDXID")

    def test_each_package_has_external_refs(self, ser, handson_scan):
        result = ser.serialize(handson_scan)
        packages = result.get("packages", [])
        assert len(packages) == len(handson_scan["dependencies"]), "packages list must be populated"
        for pkg in packages:
            assert "externalRefs" in pkg and len(pkg["externalRefs"]) > 0

    def test_purl_in_external_refs(self, ser, handson_scan):
        result = ser.serialize(handson_scan)
        packages = result.get("packages", [])
        assert len(packages) == len(handson_scan["dependencies"]), "packages list must be populated"
        for pkg in packages:
            refs = pkg.get("externalRefs", [])
            purl_refs = [r for r in refs if r.get("referenceCategory") == "PACKAGE-MANAGER"]
            assert len(purl_refs) > 0, f"No PACKAGE-MANAGER ref in {pkg.get('name')}"

    def test_purl_ref_type_is_purl(self, ser, handson_scan):
        result = ser.serialize(handson_scan)
        packages = result.get("packages", [])
        assert len(packages) == len(handson_scan["dependencies"]), "packages list must be populated"
        for pkg in packages:
            refs = pkg.get("externalRefs", [])
            purl_refs = [r for r in refs if r.get("referenceCategory") == "PACKAGE-MANAGER"]
            for r in purl_refs:
                assert r.get("referenceType") == "purl"

    def test_purl_locator_format(self, ser, handson_scan):
        result = ser.serialize(handson_scan)
        packages = result.get("packages", [])
        assert len(packages) == len(handson_scan["dependencies"]), "packages list must be populated"
        purl_re = re.compile(r"^pkg:pypi/[^@]+@.+$")
        for pkg in packages:
            refs = pkg.get("externalRefs", [])
            for r in refs:
                if r.get("referenceCategory") == "PACKAGE-MANAGER":
                    assert purl_re.match(r.get("referenceLocator", "")), r

    def test_vulnerable_pkg_has_security_ref(self, ser, handson_scan):
        result = ser.serialize(handson_scan)
        tf_pkg = next(
            (p for p in result.get("packages", []) if p.get("name") == "tensorflow"),
            None,
        )
        assert tf_pkg is not None
        sec_refs = [r for r in tf_pkg.get("externalRefs", [])
                    if r.get("referenceCategory") == "SECURITY"]
        assert len(sec_refs) > 0

    def test_security_ref_on_vulnerable_numpy(self, ser, handson_scan):
        result = ser.serialize(handson_scan)
        numpy_pkg = next(
            (p for p in result.get("packages", []) if p.get("name") == "numpy"),
            None,
        )
        assert numpy_pkg is not None
        sec_refs = [r for r in numpy_pkg.get("externalRefs", [])
                    if r.get("referenceCategory") == "SECURITY"]
        assert len(sec_refs) > 0

    def test_creation_info_present(self, ser, handson_scan):
        result = ser.serialize(handson_scan)
        assert "creationInfo" in result

    def test_creation_info_created_present(self, ser, handson_scan):
        result = ser.serialize(handson_scan)
        assert "created" in result.get("creationInfo", {})

    def test_creation_info_created_iso8601(self, ser, handson_scan):
        result = ser.serialize(handson_scan)
        created = result.get("creationInfo", {}).get("created", "")
        dt = datetime.fromisoformat(created.replace("Z", "+00:00"))
        assert dt is not None

    def test_clean_scan_packages_no_security_refs(self, ser, clean_scan):
        result = ser.serialize(clean_scan)
        packages = result.get("packages", [])
        assert len(packages) == len(clean_scan["dependencies"]), "clean scan packages must be populated"
        for pkg in packages:
            sec_refs = [r for r in pkg.get("externalRefs", [])
                        if r.get("referenceCategory") == "SECURITY"]
            assert len(sec_refs) == 0, f"{pkg.get('name')} should have no SECURITY refs"

    def test_clean_scan_spdx_version(self, ser, clean_scan):
        result = ser.serialize(clean_scan)
        assert result.get("spdxVersion") == "SPDX-2.3"

    def test_name_field_present(self, ser, handson_scan):
        result = ser.serialize(handson_scan)
        assert "name" in result


# ---------------------------------------------------------------------------
# 8. ScanJobValidator — 18 tests
# ---------------------------------------------------------------------------

class TestScanJobValidator:

    @pytest.fixture
    def val(self):
        return ScanJobValidator()

    def test_valid_python_repo_returns_valid_true(self, val, tmp_path):
        py_repo = tmp_path / "py_project"
        py_repo.mkdir()
        (py_repo / "requirements.txt").write_text("flask==3.0.0\n")
        result = val.validate(str(py_repo), "development")
        assert result.valid is True

    def test_valid_python_repo_no_errors(self, val, tmp_path):
        py_repo = tmp_path / "py_project_clean"
        py_repo.mkdir()
        (py_repo / "requirements.txt").write_text("flask==3.0.0\n")
        result = val.validate(str(py_repo), "development")
        assert result.errors == []

    def test_nonexistent_path_invalid(self, val):
        result = val.validate("/repos/does-not-exist-xyz", "development")
        assert result.valid is False

    def test_nonexistent_path_has_error_message(self, val):
        result = val.validate("/repos/does-not-exist-xyz", "development")
        assert len(result.errors) > 0

    def test_nonexistent_path_error_mentions_path(self, val):
        result = val.validate("/repos/does-not-exist-xyz", "development")
        assert any("path" in e.lower() or "exist" in e.lower() for e in result.errors)

    def test_go_repo_invalid_language(self, val, tmp_path):
        go_repo = tmp_path / "go_project"
        go_repo.mkdir()
        (go_repo / "go.mod").write_text("module example.com/mymodule\n\ngo 1.21\n")
        result = val.validate(str(go_repo), "development")
        assert result.valid is False

    def test_go_repo_error_mentions_unsupported_language(self, val, tmp_path):
        go_repo = tmp_path / "go_project2"
        go_repo.mkdir()
        (go_repo / "go.mod").write_text("module example.com/mymodule\n\ngo 1.21\n")
        result = val.validate(str(go_repo), "development")
        assert any(
            "language" in e.lower() or "unsupported" in e.lower() or "go" in e.lower()
            for e in result.errors
        )

    def test_multi_repo_list_invalid(self, val):
        result = val.validate("/repos/repo1,/repos/repo2", "development")
        assert result.valid is False

    def test_multi_repo_error_mentions_single_repo(self, val):
        result = val.validate("/repos/repo1,/repos/repo2", "development")
        assert any(
            "single" in e.lower() or "one" in e.lower() or "multiple" in e.lower()
            for e in result.errors
        )

    def test_empty_repo_path_invalid(self, val):
        result = val.validate("", "development")
        assert result.valid is False

    def test_empty_repo_path_has_error(self, val):
        result = val.validate("", "development")
        assert len(result.errors) > 0

    def test_development_environment_accepted(self, val, tmp_path):
        py_repo = tmp_path / "dev_repo"
        py_repo.mkdir()
        (py_repo / "requirements.txt").write_text("flask==3.0.0\n")
        result = val.validate(str(py_repo), "development")
        assert result.valid is True

    def test_staging_environment_accepted(self, val, tmp_path):
        py_repo = tmp_path / "staging_repo"
        py_repo.mkdir()
        (py_repo / "requirements.txt").write_text("flask==3.0.0\n")
        result = val.validate(str(py_repo), "staging")
        assert result.valid is True

    def test_production_environment_accepted(self, val, tmp_path):
        py_repo = tmp_path / "prod_repo"
        py_repo.mkdir()
        (py_repo / "requirements.txt").write_text("flask==3.0.0\n")
        result = val.validate(str(py_repo), "production")
        assert result.valid is True

    def test_unknown_environment_invalid(self, val, tmp_path):
        py_repo = tmp_path / "unknown_env_repo"
        py_repo.mkdir()
        (py_repo / "requirements.txt").write_text("flask==3.0.0\n")
        result = val.validate(str(py_repo), "banana")
        assert result.valid is False

    def test_unknown_environment_error_message(self, val, tmp_path):
        py_repo = tmp_path / "unknown_env_repo2"
        py_repo.mkdir()
        (py_repo / "requirements.txt").write_text("flask==3.0.0\n")
        result = val.validate(str(py_repo), "banana")
        assert any("environment" in e.lower() or "invalid" in e.lower() for e in result.errors)

    def test_validation_result_has_valid_field(self, val, tmp_path):
        py_repo = tmp_path / "struct_check_repo"
        py_repo.mkdir()
        (py_repo / "requirements.txt").write_text("flask==3.0.0\n")
        result = val.validate(str(py_repo), "development")
        assert hasattr(result, "valid")

    def test_validation_result_has_errors_field(self, val, tmp_path):
        py_repo = tmp_path / "struct_check_repo2"
        py_repo.mkdir()
        (py_repo / "requirements.txt").write_text("flask==3.0.0\n")
        result = val.validate(str(py_repo), "development")
        assert hasattr(result, "errors")


# ---------------------------------------------------------------------------
# 9. VEXFilter — 21 tests
# ---------------------------------------------------------------------------

@pytest.fixture
def langchain_vuln():
    return {
        "cve_id": "CVE-2023-34540",
        "purl": "pkg:pypi/langchain@0.0.101",
        "cvss_score": 9.8,
        "severity": "High",
    }


@pytest.fixture
def requests_vuln():
    return {
        "cve_id": "CVE-2023-32681",
        "purl": "pkg:pypi/requests@2.27.1",
        "cvss_score": 6.1,
        "severity": "Medium",
    }


@pytest.fixture
def lxml_vuln():
    return {
        "cve_id": "CVE-2018-19787",
        "purl": "pkg:pypi/lxml@4.6.3",
        "cvss_score": 6.1,
        "severity": "Medium",
    }


@pytest.fixture
def vex_langchain():
    return {
        "cve_id": "CVE-2023-34540",
        "purl": "pkg:pypi/langchain@0.0.101",
        "status": "not_affected",
        "justification": "vulnerable_code_not_in_execute_path",
    }


@pytest.fixture
def vex_lxml_wrong_version():
    """VEX for lxml@4.9.0 — must NOT suppress lxml@4.6.3."""
    return {
        "cve_id": "CVE-2018-19787",
        "purl": "pkg:pypi/lxml@4.9.0",
        "status": "not_affected",
        "justification": "component_not_present",
    }


@pytest.fixture
def vex_wrong_cve():
    """VEX for a different CVE on langchain — must NOT suppress CVE-2023-34540."""
    return {
        "cve_id": "CVE-9999-00001",
        "purl": "pkg:pypi/langchain@0.0.101",
        "status": "not_affected",
        "justification": "component_not_present",
    }


class TestVEXFilter:

    @pytest.fixture
    def vf(self):
        return VEXFilter()

    def test_matching_pair_is_suppressed(self, vf, langchain_vuln, vex_langchain):
        result = vf.apply([langchain_vuln], [vex_langchain])
        assert len(result.suppressed) == 1

    def test_matching_pair_not_in_active(self, vf, langchain_vuln, vex_langchain):
        result = vf.apply([langchain_vuln], [vex_langchain])
        assert len(result.active) == 0

    def test_wrong_version_not_suppressed(self, vf, lxml_vuln, vex_lxml_wrong_version):
        # lxml@4.9.0 VEX does NOT suppress lxml@4.6.3
        result = vf.apply([lxml_vuln], [vex_lxml_wrong_version])
        assert len(result.active) == 1

    def test_wrong_version_remains_active(self, vf, lxml_vuln, vex_lxml_wrong_version):
        result = vf.apply([lxml_vuln], [vex_lxml_wrong_version])
        assert result.active[0]["cve_id"] == "CVE-2018-19787"

    def test_wrong_cve_not_suppressed(self, vf, langchain_vuln, vex_wrong_cve):
        result = vf.apply([langchain_vuln], [vex_wrong_cve])
        assert len(result.active) == 1

    def test_wrong_cve_vuln_remains_active(self, vf, langchain_vuln, vex_wrong_cve):
        result = vf.apply([langchain_vuln], [vex_wrong_cve])
        assert result.active[0]["cve_id"] == "CVE-2023-34540"

    def test_empty_vex_list_all_active(self, vf, langchain_vuln, requests_vuln):
        result = vf.apply([langchain_vuln, requests_vuln], [])
        assert len(result.active) == 2

    def test_empty_vex_suppressed_empty(self, vf, langchain_vuln):
        result = vf.apply([langchain_vuln], [])
        assert result.suppressed == []

    def test_empty_vulns_empty_active(self, vf, vex_langchain):
        result = vf.apply([], [vex_langchain])
        assert result.active == []

    def test_empty_vulns_empty_suppressed(self, vf, vex_langchain):
        result = vf.apply([], [vex_langchain])
        assert result.suppressed == []

    def test_suppressed_list_populated(self, vf, langchain_vuln, requests_vuln, vex_langchain):
        result = vf.apply([langchain_vuln, requests_vuln], [vex_langchain])
        assert len(result.suppressed) == 1
        assert result.suppressed[0]["cve_id"] == "CVE-2023-34540"

    def test_non_matching_remains_active(self, vf, langchain_vuln, requests_vuln, vex_langchain):
        result = vf.apply([langchain_vuln, requests_vuln], [vex_langchain])
        assert len(result.active) == 1
        assert result.active[0]["cve_id"] == "CVE-2023-32681"

    def test_vex_filtered_flag_on_suppressed(self, vf, langchain_vuln, vex_langchain):
        result = vf.apply([langchain_vuln], [vex_langchain])
        assert result.suppressed[0].get("vex_filtered") is True

    def test_active_entries_have_no_vex_filtered_flag(self, vf, requests_vuln, vex_langchain):
        result = vf.apply([requests_vuln], [vex_langchain])
        assert not result.active[0].get("vex_filtered", False)

    def test_multiple_vex_applied_independently(
        self, vf, langchain_vuln, requests_vuln, lxml_vuln, vex_langchain
    ):
        vex_requests = {
            "cve_id": "CVE-2023-32681",
            "purl": "pkg:pypi/requests@2.27.1",
            "status": "not_affected",
            "justification": "vulnerable_code_not_in_execute_path",
        }
        result = vf.apply(
            [langchain_vuln, requests_vuln, lxml_vuln],
            [vex_langchain, vex_requests],
        )
        assert len(result.suppressed) == 2
        assert len(result.active) == 1

    def test_partial_match_only_matching_suppressed(
        self, vf, langchain_vuln, lxml_vuln, vex_langchain
    ):
        result = vf.apply([langchain_vuln, lxml_vuln], [vex_langchain])
        suppressed_ids = [s["cve_id"] for s in result.suppressed]
        assert "CVE-2023-34540" in suppressed_ids
        assert "CVE-2018-19787" not in suppressed_ids

    def test_filter_result_active_plus_suppressed_equals_total(
        self, vf, langchain_vuln, requests_vuln, lxml_vuln, vex_langchain
    ):
        result = vf.apply([langchain_vuln, requests_vuln, lxml_vuln], [vex_langchain])
        assert len(result.active) + len(result.suppressed) == 3

    def test_same_cve_wrong_purl_version_not_suppressed(self, vf, langchain_vuln):
        wrong_version_vex = {
            "cve_id": "CVE-2023-34540",
            "purl": "pkg:pypi/langchain@0.0.999",
            "status": "not_affected",
            "justification": "component_not_present",
        }
        result = vf.apply([langchain_vuln], [wrong_version_vex])
        assert len(result.active) == 1

    def test_exact_purl_version_match_suppresses(self, vf, lxml_vuln):
        exact_vex = {
            "cve_id": "CVE-2018-19787",
            "purl": "pkg:pypi/lxml@4.6.3",
            "status": "not_affected",
            "justification": "component_not_present",
        }
        result = vf.apply([lxml_vuln], [exact_vex])
        assert len(result.suppressed) == 1

    def test_suppressed_entry_preserves_cve_id(self, vf, langchain_vuln, vex_langchain):
        result = vf.apply([langchain_vuln], [vex_langchain])
        assert result.suppressed[0]["cve_id"] == "CVE-2023-34540"

    def test_suppressed_entry_preserves_purl(self, vf, langchain_vuln, vex_langchain):
        result = vf.apply([langchain_vuln], [vex_langchain])
        assert result.suppressed[0]["purl"] == "pkg:pypi/langchain@0.0.101"


# ---------------------------------------------------------------------------
# 10. DependencyRecord — 19 tests
# ---------------------------------------------------------------------------

class TestDependencyRecord:

    PURL_RE = re.compile(r"^pkg:pypi/[A-Za-z0-9._-]+@[A-Za-z0-9._\-+]+$")

    def test_valid_direct_construction(self):
        rec = DependencyRecord(
            name="langchain", version="0.0.101",
            purl="pkg:pypi/langchain@0.0.101", dependency_type="direct",
        )
        assert rec.name == "langchain"

    def test_valid_transitive_construction(self):
        rec = DependencyRecord(
            name="requests", version="2.27.1",
            purl="pkg:pypi/requests@2.27.1", dependency_type="transitive",
            transitive_via="langchain",
        )
        assert rec.version == "2.27.1"

    def test_purl_valid_format_accepted(self):
        rec = DependencyRecord(
            name="numpy", version="1.23.5",
            purl="pkg:pypi/numpy@1.23.5", dependency_type="direct",
        )
        assert self.PURL_RE.match(rec.purl)

    def test_purl_invalid_format_raises(self):
        with pytest.raises((ValueError, TypeError, Exception)):
            DependencyRecord(
                name="numpy", version="1.23.5",
                purl="invalid-purl-no-scheme", dependency_type="direct",
            )

    def test_purl_missing_version_raises(self):
        with pytest.raises((ValueError, TypeError, Exception)):
            DependencyRecord(
                name="numpy", version="1.23.5",
                purl="pkg:pypi/numpy",  # missing @version
                dependency_type="direct",
            )

    def test_purl_missing_package_name_raises(self):
        with pytest.raises((ValueError, TypeError, Exception)):
            DependencyRecord(
                name="numpy", version="1.23.5",
                purl="pkg:pypi/@1.23.5",
                dependency_type="direct",
            )

    def test_dependency_type_direct_accepted(self):
        rec = DependencyRecord(
            name="flask", version="3.0.0",
            purl="pkg:pypi/flask@3.0.0", dependency_type="direct",
        )
        assert rec.dependency_type == "direct"

    def test_dependency_type_transitive_accepted(self):
        rec = DependencyRecord(
            name="click", version="8.1.7",
            purl="pkg:pypi/click@8.1.7", dependency_type="transitive",
            transitive_via="flask",
        )
        assert rec.dependency_type == "transitive"

    def test_dependency_type_invalid_raises(self):
        with pytest.raises((ValueError, TypeError, Exception)):
            DependencyRecord(
                name="flask", version="3.0.0",
                purl="pkg:pypi/flask@3.0.0", dependency_type="optional",
            )

    def test_transitive_without_via_raises(self):
        with pytest.raises((ValueError, TypeError, Exception)):
            DependencyRecord(
                name="click", version="8.1.7",
                purl="pkg:pypi/click@8.1.7", dependency_type="transitive",
                transitive_via=None,
            )

    def test_direct_transitive_via_none_ok(self):
        rec = DependencyRecord(
            name="flask", version="3.0.0",
            purl="pkg:pypi/flask@3.0.0", dependency_type="direct",
            transitive_via=None,
        )
        assert rec.transitive_via is None

    def test_missing_name_raises(self):
        with pytest.raises((ValueError, TypeError, Exception)):
            DependencyRecord(
                name="", version="3.0.0",
                purl="pkg:pypi/flask@3.0.0", dependency_type="direct",
            )

    def test_missing_version_raises(self):
        with pytest.raises((ValueError, TypeError, Exception)):
            DependencyRecord(
                name="flask", version="",
                purl="pkg:pypi/flask@3.0.0", dependency_type="direct",
            )

    def test_supplier_defaults_to_unknown(self):
        rec = DependencyRecord(
            name="flask", version="3.0.0",
            purl="pkg:pypi/flask@3.0.0", dependency_type="direct",
        )
        assert rec.supplier == "Unknown"

    def test_supplier_explicit_value_stored(self):
        rec = DependencyRecord(
            name="flask", version="3.0.0",
            purl="pkg:pypi/flask@3.0.0", dependency_type="direct",
            supplier="Pallets",
        )
        assert rec.supplier == "Pallets"

    def test_purl_non_pypi_ecosystem_raises(self):
        with pytest.raises((ValueError, TypeError, Exception)):
            DependencyRecord(
                name="lodash", version="4.17.21",
                purl="pkg:npm/lodash@4.17.21", dependency_type="direct",
            )

    def test_langchain_real_cve_purl_valid(self):
        rec = DependencyRecord(
            name="langchain", version="0.0.101",
            purl="pkg:pypi/langchain@0.0.101",
            dependency_type="direct", supplier="LangChain, Inc.",
        )
        assert self.PURL_RE.match(rec.purl)

    def test_tensorflow_real_cve_purl_valid(self):
        rec = DependencyRecord(
            name="tensorflow", version="1.15.5",
            purl="pkg:pypi/tensorflow@1.15.5",
            dependency_type="direct", supplier="Google LLC",
        )
        assert self.PURL_RE.match(rec.purl)

    def test_hyphenated_name_purl_valid(self):
        rec = DependencyRecord(
            name="scikit-learn", version="0.24.1",
            purl="pkg:pypi/scikit-learn@0.24.1", dependency_type="direct",
        )
        assert self.PURL_RE.match(rec.purl)
