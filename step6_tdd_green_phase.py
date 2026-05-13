"""
step6_tdd_green_phase.py
SBOM POC Tool — TDD Green Phase (All 10 classes)
Session: SBOM-20260409-sb01

Implements all 10 business-logic classes so that every test in
step5_tdd_red_phase.py passes.

Design constraints:
  - OSS tools (Syft, Trivy, Grype, OpenVEX) are BLACK BOXES — we only wrap.
  - NVD data arrives as a pre-loaded dict (no live API calls at scan time).
  - NVDCacheManager uses an in-memory SQLite database for the sync tests.
  - CVSS v3.1 banding: High >= 7.0, Medium 4.0–6.9, Low < 4.0, null → Unknown.
  - Output formats: CycloneDX 1.4 JSON and SPDX 2.3 JSON.
  - PURL format: pkg:pypi/<name>@<version>
"""

import json
import re
import sqlite3
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

import pytest

# ---------------------------------------------------------------------------
# Shared test fixtures (identical to step5 so this file is self-contained)
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


# ---------------------------------------------------------------------------
# Scan-level fixtures
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


# VEX fixtures
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
    return {
        "cve_id": "CVE-2018-19787",
        "purl": "pkg:pypi/lxml@4.9.0",
        "status": "not_affected",
        "justification": "component_not_present",
    }


@pytest.fixture
def vex_wrong_cve():
    return {
        "cve_id": "CVE-9999-00001",
        "purl": "pkg:pypi/langchain@0.0.101",
        "status": "not_affected",
        "justification": "component_not_present",
    }


# ===========================================================================
# CLASS 1: CVSSSeverityClassifier
# ===========================================================================

class CVSSSeverityClassifier:
    """
    Maps a CVSS v3.1 base score to a severity band.

    Banding (CQ-1):
      High   >= 7.0
      Medium  4.0 – 6.9  (inclusive on both ends)
      Low     0.0 – 3.9  (inclusive on both ends)
      Unknown None or any value outside [0.0, 10.x]
    """

    def classify(self, score) -> str:
        if score is None:
            return "Unknown"
        try:
            score = float(score)
        except (TypeError, ValueError):
            return "Unknown"
        if score < 0.0:
            return "Unknown"
        if score >= 7.0:
            return "High"
        if score >= 4.0:
            return "Medium"
        return "Low"


# ===========================================================================
# CLASS 2: OSSToolAdapter
# ===========================================================================

class OSSToolAdapter:
    """
    Normalises raw output from Syft and Trivy into a common dict schema.

    Common output keys: name, exact_version, purl, supplier
    """

    def normalise(self, raw: dict) -> list:
        tool = raw.get("tool", "").lower()
        if tool == "syft":
            return self._normalise_syft(raw.get("components", []))
        if tool == "trivy":
            return self._normalise_trivy(raw.get("Results", []))
        return []

    def _normalise_syft(self, components: list) -> list:
        records = []
        for comp in components:
            purl = comp.get("purl", "")
            # Fall back to the PURL-ecosystem registry name (PyPI, GitHub, npm,
            # crates.io, …) instead of the old hardcoded "PyPI", so non-PyPI
            # components (github actions, npm, go) carry the correct supplier.
            # See CycloneDXSerializer._PURL_REGISTRY_SUPPLIER for the mapping.
            supplier = (
                comp.get("metadata", {}).get("Author")
                or comp.get("metadata", {}).get("author")
                or CycloneDXSerializer._supplier_from_purl(purl)
            )
            records.append({
                "name": comp.get("name", ""),
                "exact_version": comp.get("version", ""),
                "purl": purl,
                "supplier": supplier,
                "cpe": comp.get("cpe"),
            })
        return records

    def _normalise_trivy(self, results: list) -> list:
        records = []
        for result in results:
            for pkg in result.get("Packages", []):
                # PURL: prefer Identifier.PURL, fallback to PkgRef
                purl = (
                    pkg.get("Identifier", {}).get("PURL")
                    or pkg.get("PkgRef")
                    or ""
                )
                # version: prefer InstalledVersion, fallback to Version
                version = pkg.get("InstalledVersion") or pkg.get("Version", "")
                records.append({
                    "name": pkg.get("Name", pkg.get("pkgName", "")),
                    "exact_version": version,
                    "purl": purl,
                    "supplier": "Unknown",
                })
        return records

    def deduplicate(self, records: list) -> list:
        """Deduplicate by full PURL string, keeping the first occurrence."""
        seen_purls: set = set()
        result = []
        for record in records:
            purl = record.get("purl", "")
            if purl not in seen_purls:
                seen_purls.add(purl)
                result.append(record)
        return result


# ===========================================================================
# CLASS 3: VulnerabilityMapper
# ===========================================================================

class VulnerabilityMapper:
    """
    Maps dependency records to vulnerability records via NVD cache lookup.

    Lookup strategy:
      1. Primary: exact PURL key match in cache
      2. Fallback: CPE key match (for entries keyed by CPE rather than PURL)

    Never fabricates a CVE record — if no match, omit the dep silently.
    """

    def map_vulnerabilities(self, deps: list, cache: dict) -> list:
        records = []
        for dep in deps:
            purl = dep.get("purl", "")
            cpe = dep.get("cpe", "")

            entry = cache.get(purl) or cache.get(cpe)
            if entry is None:
                continue

            records.append({
                "cve_id": entry.get("cve_id", ""),
                "purl": purl if purl in cache else dep.get("purl", ""),
                "cvss_score": entry.get("cvss_score"),
                "severity": entry.get("severity", "Unknown"),
                "dep_name": dep.get("name", ""),
                "dep_purl": purl,
            })
        return records


# ===========================================================================
# CLASS 4: RemediationEnricher
# ===========================================================================

class RemediationEnricher:
    """
    Enriches a vulnerability record with advisory URL, fixed version,
    severity (re-applied from CVSS), and upgrade command for High severities.
    """

    def enrich(self, vuln: dict, cache_entry: dict) -> dict:
        # Do not mutate the input dict
        result = dict(vuln)

        # Apply advisory URL — always present (required)
        result["advisory_url"] = cache_entry.get("advisory_url", "")

        # Fixed version — None when absent, never omit the key
        result["fixed_version"] = cache_entry.get("fixed_version", None)

        # Severity from cache entry (authoritative), fallback to vuln
        severity = cache_entry.get("severity") or vuln.get("severity", "Unknown")
        result["severity"] = severity

        # Upgrade command — required for High severity when fixed_version is known
        if severity == "High" and result.get("fixed_version"):
            pkg_name = vuln.get("dep_name") or vuln.get("purl", "").split("/")[-1].split("@")[0]
            fixed_ver = result["fixed_version"]
            result["upgrade_command"] = f"pip install --upgrade {pkg_name}=={fixed_ver}"
        else:
            # For non-High severities or when no fixed version, still include key
            if "upgrade_command" not in result:
                result["upgrade_command"] = None

        return result


# ===========================================================================
# CLASS 5: NVDCacheManager
# ===========================================================================

class NVDSyncError(Exception):
    """Raised when NVD sync fails (e.g. source path missing)."""
    pass


class NVDSyncResult:
    """Holds the outcome of a sync operation."""

    def __init__(self, records_added: int = 0, records_updated: int = 0):
        self.records_added = records_added
        self.records_updated = records_updated

    def __contains__(self, item):
        return item in ("records_added", "records_updated")

    def get(self, key, default=None):
        if key == "records_added":
            return self.records_added
        if key == "records_updated":
            return self.records_updated
        return default


class StalenessResult(dict):
    """A dict that signals staleness via a 'warning' key."""
    pass


class NVDCacheManager:
    """
    SQLite-backed NVD cache manager.

    Responsibilities:
      - is_stale(): determine if the last sync is >= 7 days old
      - check_staleness(): return a warning dict when stale
      - sync(): upsert CVE records from a JSON feed file, update sync_log
    """

    _STALE_THRESHOLD_DAYS = 7

    def __init__(self, db_path: str = ":memory:"):
        self._conn = sqlite3.connect(db_path)
        self._setup_schema()
        self._last_synced_at: Optional[datetime] = None
        self.last_sync_log: Optional[dict] = None

    def _setup_schema(self):
        cur = self._conn.cursor()
        cur.execute("""
            CREATE TABLE IF NOT EXISTS vulnerabilities (
                cve_id                 TEXT PRIMARY KEY NOT NULL,
                purl                   TEXT,
                cpe                    TEXT,
                cvss_score             REAL NOT NULL,
                severity               TEXT NOT NULL,
                affected_version_range TEXT NOT NULL DEFAULT '',
                fixed_version          TEXT,
                advisory_url           TEXT,
                last_synced            TEXT NOT NULL DEFAULT ''
            )
        """)
        cur.execute("""
            CREATE TABLE IF NOT EXISTS sync_log (
                sync_id         INTEGER PRIMARY KEY AUTOINCREMENT,
                synced_at       TEXT NOT NULL,
                records_added   INTEGER DEFAULT 0,
                records_updated INTEGER DEFAULT 0,
                source          TEXT NOT NULL DEFAULT 'on_demand'
            )
        """)
        self._conn.commit()

    # --- public API ---

    def is_stale(self, last_synced_at) -> bool:
        """Return True if last_synced_at is >= 7 days ago."""
        if last_synced_at is None:
            return False
        # Normalise to UTC
        try:
            if hasattr(last_synced_at, "tzinfo") and last_synced_at.tzinfo is not None:
                now = datetime.now(timezone.utc)
            else:
                # naive datetime — treat as UTC for comparison
                now = datetime.now(timezone.utc)
                last_synced_at = last_synced_at.replace(tzinfo=timezone.utc)
            age = now - last_synced_at
            return age >= timedelta(days=self._STALE_THRESHOLD_DAYS)
        except (TypeError, AttributeError):
            return False

    def check_staleness(self) -> dict:
        """Return a dict indicating staleness. Uses self._last_synced_at."""
        last = getattr(self, "_last_synced_at", None)
        if last is None:
            # No sync timestamp recorded — treat as fresh / unknown
            return {}
        stale = self.is_stale(last)
        if stale:
            return {
                "stale": True,
                "warning": (
                    f"NVD cache is stale. Last synced at {last.isoformat()}. "
                    f"Please run a sync to refresh vulnerability data."
                ),
            }
        return {"stale": False}

    def sync(self, source_path: str) -> NVDSyncResult:
        """
        Upsert CVE records from a JSON feed file at source_path.

        Feed format: {"vulnerabilities": [{cve_id, purl, cpe, cvss_score,
                        severity, affected_version_range, fixed_version, advisory_url}]}

        Raises NVDSyncError if source_path does not exist or JSON is invalid.
        Returns NVDSyncResult with records_added and records_updated counts.
        """
        import os
        if not os.path.exists(source_path):
            raise NVDSyncError(
                f"NVD feed source not found: {source_path}"
            )

        with open(source_path, "r") as fh:
            try:
                feed = json.load(fh)
            except json.JSONDecodeError as exc:
                raise NVDSyncError(f"Invalid JSON in feed: {exc}") from exc

        items = feed.get("vulnerabilities", [])
        records_added = 0
        records_updated = 0

        cur = self._conn.cursor()
        seen: set = set()
        synced_at = datetime.now(timezone.utc)

        for item in items:
            cve_id = item.get("cve_id", "")
            if not cve_id:
                continue
            if cve_id in seen:
                records_updated += 1
                continue
            seen.add(cve_id)

            cur.execute("SELECT 1 FROM vulnerabilities WHERE cve_id = ?", (cve_id,))
            exists = cur.fetchone() is not None
            cur.execute(
                """INSERT OR REPLACE INTO vulnerabilities
                   (cve_id, purl, cpe, cvss_score, severity,
                    affected_version_range, fixed_version, advisory_url, last_synced)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    cve_id,
                    item.get("purl", ""),
                    item.get("cpe", ""),
                    item.get("cvss_score", 0.0),
                    item.get("severity", "Unknown"),
                    item.get("affected_version_range", ""),
                    item.get("fixed_version", ""),
                    item.get("advisory_url", ""),
                    synced_at.isoformat(),
                ),
            )
            if exists:
                records_updated += 1
            else:
                records_added += 1

        cur.execute(
            """INSERT INTO sync_log (synced_at, records_added, records_updated, source)
               VALUES (?, ?, ?, 'on_demand')""",
            (synced_at.isoformat(), records_added, records_updated),
        )
        self._conn.commit()

        self._last_synced_at = synced_at
        self.last_sync_log = {
            "synced_at": synced_at.isoformat(),
            "source_path": source_path,
            "records_added": records_added,
            "records_updated": records_updated,
        }
        return NVDSyncResult(records_added=records_added, records_updated=records_updated)


# ===========================================================================
# CLASS 6: CycloneDXSerializer
# ===========================================================================

class CycloneDXSerializer:
    """
    Serialises a scan result dict to a CycloneDX 1.4 JSON-compatible dict.

    Scan result schema (input):
      {
        "scan_id": str,
        "repo_name": str,
        "dependencies": [{"name", "version", "purl", "type", ...}],
        "vulnerabilities": [{"cve_id", "purl", "cvss_score", "severity"}],
      }
    """

    # Map purl ecosystem prefix to the canonical registry/supplier label used
    # as a fallback when a normalised supplier isn't available on the dep.
    _PURL_REGISTRY_SUPPLIER = {
        "pypi": "PyPI",
        "npm": "npm",
        "maven": "Maven Central",
        "golang": "Go modules",
        "cargo": "crates.io",
        "gem": "RubyGems",
        "nuget": "NuGet",
        "composer": "Packagist",
        "github": "GitHub",
        "githubactions": "GitHub",
        "docker": "Docker Hub",
        "oci": "OCI registry",
        "deb": "Debian",
        "rpm": "Red Hat",
        "apk": "Alpine",
        "hex": "Hex",
        "pub": "pub.dev",
        "swift": "Swift Package Index",
        "cocoapods": "CocoaPods",
        "conan": "Conan Center",
    }

    @classmethod
    def _supplier_from_purl(cls, purl: str) -> str:
        # pkg:<type>/<namespace>/<name>@<version>
        if not purl or not purl.startswith("pkg:"):
            return "Unknown"
        try:
            ptype = purl.split("pkg:", 1)[1].split("/", 1)[0].lower()
        except (IndexError, AttributeError):
            return "Unknown"
        return cls._PURL_REGISTRY_SUPPLIER.get(ptype, "Unknown")

    def serialize(self, scan_result: dict) -> dict:
        serial_number = f"urn:uuid:{uuid.uuid4()}"
        timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

        components = []
        for dep in scan_result.get("dependencies", []):
            purl = dep.get("purl", "")
            supplier = dep.get("supplier") or self._supplier_from_purl(purl)
            components.append({
                "type": dep.get("type", "library"),
                "name": dep.get("name", ""),
                "version": dep.get("version", dep.get("exact_version", "")),
                "purl": purl,
                "supplier": {"name": supplier},
            })

        vulnerabilities = []
        for vuln in scan_result.get("vulnerabilities", []):
            vuln_entry = {
                "id": vuln.get("cve_id", ""),
                "ratings": [
                    {
                        "score": vuln.get("cvss_score"),
                        "severity": vuln.get("severity", "").lower(),
                        "method": "CVSSv31",
                    }
                ],
                "affects": [
                    {"ref": vuln.get("purl", "")}
                ],
            }
            if vuln.get("advisory_url"):
                vuln_entry["advisories"] = [{"url": vuln["advisory_url"]}]
            if vuln.get("fixed_version"):
                vuln_entry["recommendation"] = f"Upgrade to {vuln['fixed_version']}"
            vulnerabilities.append(vuln_entry)

        repo_name = scan_result.get("repo_name") or scan_result.get("scan_id") or "unknown"
        subject_component = {
            "type": "application",
            "name": repo_name,
            "bom-ref": f"root:{repo_name}",
        }
        if scan_result.get("scan_id"):
            subject_component["version"] = str(scan_result["scan_id"])
        if scan_result.get("repo_url"):
            subject_component["externalReferences"] = [
                {"type": "vcs", "url": scan_result["repo_url"]}
            ]

        return {
            "bomFormat": "CycloneDX",
            "specVersion": "1.4",
            "serialNumber": serial_number,
            "version": 1,
            "metadata": {
                "timestamp": timestamp,
                "tools": [
                    {
                        "vendor": "SBOM POC",
                        "name": "sbom-tool",
                        "version": "1.0.0",
                    }
                ],
                "component": subject_component,
            },
            "components": components,
            "vulnerabilities": vulnerabilities,
        }


# ===========================================================================
# CLASS 7: SPDXSerializer
# ===========================================================================

class SPDXSerializer:
    """
    Serialises a scan result dict to an SPDX 2.3 JSON-compatible dict.

    Adds a SECURITY external ref (CPE) for packages that have known CVEs.
    """

    def serialize(self, scan_result: dict) -> dict:
        repo_name = scan_result.get("repo_name", scan_result.get("scan_id", "unknown"))
        scan_id = scan_result.get("scan_id", "unknown")
        created = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        doc_namespace = f"https://sbom-tool.example.com/spdx/{scan_id}"

        # Build map of vulnerable PURL → CPE from the vulnerabilities list
        vuln_purl_to_cpe: dict = {}
        for vuln in scan_result.get("vulnerabilities", []):
            purl = vuln.get("purl", "")
            if purl and purl not in vuln_purl_to_cpe:
                vuln_purl_to_cpe[purl] = vuln.get("cpe", "")

        packages = []
        for dep in scan_result.get("dependencies", []):
            dep_name = dep.get("name", "")
            dep_purl = dep.get("purl", "")
            dep_cpe = dep.get("cpe", "")
            spdx_id = f"SPDXRef-{dep_name}"

            external_refs = [
                {
                    "referenceCategory": "PACKAGE-MANAGER",
                    "referenceType": "purl",
                    "referenceLocator": dep_purl,
                }
            ]

            # Add SECURITY ref for vulnerable packages
            if dep_purl in vuln_purl_to_cpe:
                cpe_locator = dep_cpe or vuln_purl_to_cpe.get(dep_purl, "")
                if cpe_locator:
                    external_refs.append({
                        "referenceCategory": "SECURITY",
                        "referenceType": "cpe23Type",
                        "referenceLocator": cpe_locator,
                    })

            packages.append({
                "SPDXID": spdx_id,
                "name": dep_name,
                "versionInfo": dep.get("version", dep.get("exact_version", "")),
                "downloadLocation": "NOASSERTION",
                "filesAnalyzed": False,
                "externalRefs": external_refs,
            })

        return {
            "spdxVersion": "SPDX-2.3",
            "dataLicense": "CC0-1.0",
            "SPDXID": "SPDXRef-DOCUMENT",
            "name": repo_name,
            "documentNamespace": doc_namespace,
            "creationInfo": {
                "created": created,
                "creators": ["Tool: sbom-tool-1.0.0"],
                "licenseListVersion": "3.21",
            },
            "packages": packages,
        }


# ===========================================================================
# CLASS 8: ScanJobValidator
# ===========================================================================

@dataclass
class ValidationResult:
    valid: bool
    errors: List[str] = field(default_factory=list)


class ScanJobValidator:
    """
    Validates scan job parameters before dispatching to OSS scanning tools.

    Valid:
      - repo_path exists on disk
      - language detected is Python or JS/TS
      - environment is one of: development, staging, production

    Invalid:
      - empty or multi-repo path (contains comma)
      - non-existent path
      - Go, Java, Rust, etc.
      - unknown environment
    """

    _VALID_ENVIRONMENTS = {"development", "staging", "production"}

    # Mapping from filename indicator to language label
    _PYTHON_INDICATORS = {"requirements.txt", "setup.py", "setup.cfg", "pyproject.toml", "Pipfile"}
    _JS_INDICATORS = {"package.json"}
    _UNSUPPORTED_INDICATORS = {
        "go.mod": "Go",
        "go.sum": "Go",
        "Cargo.toml": "Rust",
        "Cargo.lock": "Rust",
        "pom.xml": "Java",
        "build.gradle": "Java",
        "build.gradle.kts": "Java",
    }

    def validate(self, repo_path: str, env: str) -> ValidationResult:
        errors: List[str] = []

        # 1. Empty path check
        if not repo_path:
            errors.append("Repository path must not be empty.")
            return ValidationResult(valid=False, errors=errors)

        # 2. Multi-repo check (comma present)
        if "," in repo_path:
            errors.append(
                "Only a single repository path is allowed. "
                "Multiple paths separated by commas are not supported."
            )
            return ValidationResult(valid=False, errors=errors)

        # 3. Path existence check
        import os
        if not os.path.exists(repo_path):
            errors.append(
                f"Repository path does not exist: '{repo_path}'. "
                "Please provide a valid local path."
            )
            return ValidationResult(valid=False, errors=errors)

        # 4. Language detection
        try:
            entries = set(os.listdir(repo_path))
        except PermissionError:
            errors.append(f"Cannot read directory: '{repo_path}'.")
            return ValidationResult(valid=False, errors=errors)

        # Check unsupported languages first
        for indicator, lang in self._UNSUPPORTED_INDICATORS.items():
            if indicator in entries:
                errors.append(
                    f"Unsupported language detected: {lang}. "
                    f"Only Python and JavaScript/TypeScript projects are supported. "
                    f"Found: {indicator}"
                )
                return ValidationResult(valid=False, errors=errors)

        has_python = bool(entries & self._PYTHON_INDICATORS)
        has_js = bool(entries & self._JS_INDICATORS)

        if not has_python and not has_js:
            errors.append(
                "Unsupported or undetected language. "
                "No Python (requirements.txt, pyproject.toml) or "
                "JavaScript/TypeScript (package.json) indicators found."
            )
            return ValidationResult(valid=False, errors=errors)

        # 5. Environment check
        if env not in self._VALID_ENVIRONMENTS:
            errors.append(
                f"Invalid environment: '{env}'. "
                f"Accepted values are: {', '.join(sorted(self._VALID_ENVIRONMENTS))}."
            )
            return ValidationResult(valid=False, errors=errors)

        return ValidationResult(valid=True, errors=[])


# ===========================================================================
# CLASS 9: VEXFilter
# ===========================================================================

@dataclass
class FilterResult:
    active: List[Dict]
    suppressed: List[Dict]


class VEXFilter:
    """
    Applies VEX (Vulnerability Exploitability eXchange) statements to suppress
    vulnerability records that are not exploitable in the given context.

    Suppression requires an exact match on both cve_id AND the full purl
    (including version).  A VEX statement for lxml@4.9.0 does NOT suppress
    a finding against lxml@4.6.3.
    """

    def apply(self, vulns: list, vex_statements: list) -> FilterResult:
        # Build a set of (cve_id, purl) pairs that are suppressed
        suppression_keys: set = set()
        for stmt in vex_statements:
            suppression_keys.add((stmt.get("cve_id", ""), stmt.get("purl", "")))

        active: list = []
        suppressed: list = []

        for vuln in vulns:
            key = (vuln.get("cve_id", ""), vuln.get("purl", ""))
            if key in suppression_keys:
                enriched = dict(vuln)
                enriched["vex_filtered"] = True
                suppressed.append(enriched)
            else:
                active.append(vuln)

        return FilterResult(active=active, suppressed=suppressed)


# ===========================================================================
# CLASS 10: DependencyRecord
# ===========================================================================

_PURL_REGEX = re.compile(r"^pkg:pypi/[A-Za-z0-9._-]+@[A-Za-z0-9._\-+]+$")


@dataclass
class DependencyRecord:
    """
    Canonical dependency record produced by OSSToolAdapter and consumed by
    VulnerabilityMapper and serializers.

    Validates on construction via __post_init__.
    """

    name: str = ""
    version: str = ""
    purl: str = ""
    dependency_type: str = ""
    transitive_via: Optional[str] = None
    supplier: str = "Unknown"

    def __post_init__(self):
        # name must be non-empty
        if not self.name:
            raise ValueError("DependencyRecord.name must not be empty.")

        # version must be non-empty
        if not self.version:
            raise ValueError("DependencyRecord.version must not be empty.")

        # purl format
        if not _PURL_REGEX.match(self.purl):
            raise ValueError(
                f"DependencyRecord.purl is invalid: '{self.purl}'. "
                f"Expected format: pkg:pypi/<name>@<version>"
            )

        # dependency_type
        if self.dependency_type not in ("direct", "transitive"):
            raise ValueError(
                f"DependencyRecord.dependency_type must be 'direct' or 'transitive', "
                f"got: '{self.dependency_type}'"
            )

        # transitive requires transitive_via
        if self.dependency_type == "transitive" and not self.transitive_via:
            raise ValueError(
                "DependencyRecord.transitive_via is required when dependency_type is 'transitive'."
            )


# ===========================================================================
# TEST CLASSES — Mirror of step5_tdd_red_phase.py
# Each test is identical so this file is a drop-in replacement.
# ===========================================================================

class TestCVSSSeverityClassifier:

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
        assert clf.classify(-1.0) == "Unknown"

    def test_score_10_1_is_high(self, clf):
        assert clf.classify(10.1) == "High"

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

    def test_return_type_is_string(self, clf):
        result = clf.classify(5.5)
        assert isinstance(result, str)

    def test_return_value_not_none_for_valid_score(self, clf):
        assert clf.classify(5.0) is not None

    def test_classify_does_not_raise_on_float(self, clf):
        clf.classify(4.999999)


class TestOSSToolAdapter:

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

    def test_syft_missing_supplier_falls_back_to_purl_registry(self, adapter):
        """When syft metadata.Author is absent, supplier is derived from the
        PURL ecosystem (PyPI / npm / GitHub / crates.io / …) rather than a
        hardcoded "PyPI" or "Unknown". Repairs the gap that left non-PyPI
        components carrying the wrong supplier in API responses."""
        # PyPI purl -> "PyPI"
        comp_py = {
            "name": "somelib", "version": "1.0.0",
            "purl": "pkg:pypi/somelib@1.0.0",
            "cpes": [], "metadata": {},
        }
        assert adapter.normalise({"tool": "syft", "components": [comp_py]})[0]["supplier"] == "PyPI"
        # GitHub Actions purl -> "GitHub"
        comp_gha = {
            "name": "actions/checkout", "version": "v4",
            "purl": "pkg:github/actions/checkout@v4",
            "cpes": [], "metadata": {},
        }
        assert adapter.normalise({"tool": "syft", "components": [comp_gha]})[0]["supplier"] == "GitHub"
        # npm purl -> "npm"
        comp_npm = {
            "name": "lodash", "version": "4.17.21",
            "purl": "pkg:npm/lodash@4.17.21",
            "cpes": [], "metadata": {},
        }
        assert adapter.normalise({"tool": "syft", "components": [comp_npm]})[0]["supplier"] == "npm"
        # Unknown ecosystem -> "Unknown"
        comp_x = {
            "name": "x", "version": "1.0",
            "purl": "pkg:weirdecosystem/x@1.0",
            "cpes": [], "metadata": {},
        }
        assert adapter.normalise({"tool": "syft", "components": [comp_x]})[0]["supplier"] == "Unknown"

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
        dep = {
            "name": "joblib",
            "exact_version": "0.14.1",
            "purl": "pkg:pypi/joblib@0.14.1-NOPURL",
            "cpe": "cpe:2.3:a:joblib:joblib:0.14.1:*:*:*:*:python:*:*",
            "dependency_type": "transitive",
            "transitive_via": "scikit-learn",
        }
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
        assert "fixed_version" in result
        assert result["fixed_version"] is None

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
        result = enricher.enrich(vuln_medium, cache_medium)
        assert result["fixed_version"] == "1.22.2"

    def test_result_is_dict(self, enricher, vuln_langchain, cache_langchain):
        result = enricher.enrich(vuln_langchain, cache_langchain)
        assert isinstance(result, dict)

    def test_enrich_does_not_mutate_input_vuln(self, enricher, vuln_langchain, cache_langchain):
        original_cve = vuln_langchain["cve_id"]
        enricher.enrich(vuln_langchain, cache_langchain)
        assert vuln_langchain["cve_id"] == original_cve


class TestNVDCacheManager:

    def _ts(self, days_ago: int) -> datetime:
        return datetime.now(timezone.utc) - timedelta(days=days_ago)

    def test_8_days_ago_is_stale(self, cache_mgr):
        assert cache_mgr.is_stale(self._ts(8)) is True

    def test_6_days_ago_is_not_stale(self, cache_mgr):
        assert cache_mgr.is_stale(self._ts(6)) is False

    def test_exactly_7_days_is_stale(self, cache_mgr):
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
        assert result == {} or result.get("stale") is False

    def test_check_staleness_returns_dict(self, cache_mgr):
        result = cache_mgr.check_staleness()
        assert isinstance(result, dict)

    def test_sync_valid_path_returns_sync_result(self, cache_mgr, tmp_path):
        source = tmp_path / "nvd_feed.json"
        source.write_text('{"vulnerabilities": []}')
        result = cache_mgr.sync(str(source))
        assert result is not None

    def test_sync_valid_path_result_has_records_added(self, cache_mgr, tmp_path):
        source = tmp_path / "nvd_feed.json"
        source.write_text('{"vulnerabilities": []}')
        result = cache_mgr.sync(str(source))
        assert hasattr(result, "records_added") or "records_added" in result

    def test_sync_valid_path_result_has_records_updated(self, cache_mgr, tmp_path):
        source = tmp_path / "nvd_feed.json"
        source.write_text('{"vulnerabilities": []}')
        result = cache_mgr.sync(str(source))
        assert hasattr(result, "records_updated") or "records_updated" in result

    def test_sync_missing_path_raises_nvd_sync_error(self, cache_mgr):
        with pytest.raises(NVDSyncError):
            cache_mgr.sync("/nonexistent/path/nvd.json")

    def test_sync_log_entry_created_after_sync(self, cache_mgr, tmp_path):
        source = tmp_path / "nvd_feed.json"
        source.write_text('{"vulnerabilities": []}')
        cache_mgr.sync(str(source))
        assert cache_mgr.last_sync_log is not None

    def test_sync_log_contains_timestamp(self, cache_mgr, tmp_path):
        source = tmp_path / "nvd_feed.json"
        source.write_text('{"vulnerabilities": []}')
        cache_mgr.sync(str(source))
        log = cache_mgr.last_sync_log
        assert "synced_at" in log or "timestamp" in log

    def test_sync_log_contains_source_path(self, cache_mgr, tmp_path):
        source = tmp_path / "nvd_feed.json"
        source.write_text('{"vulnerabilities": []}')
        path_str = str(source)
        cache_mgr.sync(path_str)
        log = cache_mgr.last_sync_log
        assert log.get("source_path") == path_str or path_str in str(log)

    def test_duplicate_cve_purl_upsert_not_duplicate(self, cache_mgr, tmp_path):
        record = {
            "cve_id": "CVE-2023-34540",
            "purl": "pkg:pypi/langchain@0.0.101",
            "cvss_score": 9.8,
            "severity": "High",
        }
        import json
        feed = json.dumps({"vulnerabilities": [record, record]})
        source = tmp_path / "nvd_dup.json"
        source.write_text(feed)
        result = cache_mgr.sync(str(source))
        count = getattr(result, "records_added", None) or result.get("records_added", 0)
        count += getattr(result, "records_updated", None) or result.get("records_updated", 0)
        inserts = getattr(result, "records_added", None) or result.get("records_added", 0)
        assert inserts <= 1

    def test_sync_does_not_raise_on_empty_feed(self, cache_mgr, tmp_path):
        source = tmp_path / "empty.json"
        source.write_text('{"vulnerabilities": []}')
        cache_mgr.sync(str(source))

    def test_is_stale_with_naive_datetime_raises_or_handles(self, cache_mgr):
        naive = datetime.now()
        try:
            result = cache_mgr.is_stale(naive)
            assert isinstance(result, bool)
        except (TypeError, ValueError):
            pass


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
        parsed = uuid.UUID(raw)
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
        assert len(components) == len(taskmatrix_scan["dependencies"])
        for comp in components:
            assert "name" in comp and comp["name"]

    def test_each_component_has_version(self, ser, taskmatrix_scan):
        result = ser.serialize(taskmatrix_scan)
        components = result.get("components", [])
        assert len(components) == len(taskmatrix_scan["dependencies"])
        for comp in components:
            assert "version" in comp and comp["version"]

    def test_each_component_has_purl(self, ser, taskmatrix_scan):
        result = ser.serialize(taskmatrix_scan)
        components = result.get("components", [])
        assert len(components) == len(taskmatrix_scan["dependencies"])
        for comp in components:
            assert "purl" in comp and comp["purl"]

    def test_each_component_has_type(self, ser, taskmatrix_scan):
        result = ser.serialize(taskmatrix_scan)
        components = result.get("components", [])
        assert len(components) == len(taskmatrix_scan["dependencies"])
        for comp in components:
            assert "type" in comp

    def test_component_purl_format(self, ser, taskmatrix_scan):
        result = ser.serialize(taskmatrix_scan)
        components = result.get("components", [])
        assert len(components) == len(taskmatrix_scan["dependencies"])
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
        assert len(packages) == len(handson_scan["dependencies"])
        for pkg in packages:
            assert "SPDXID" in pkg

    def test_each_spdxid_has_prefix(self, ser, handson_scan):
        result = ser.serialize(handson_scan)
        packages = result.get("packages", [])
        assert len(packages) == len(handson_scan["dependencies"])
        for pkg in packages:
            assert pkg.get("SPDXID", "").startswith("SPDXRef-"), pkg.get("SPDXID")

    def test_each_package_has_external_refs(self, ser, handson_scan):
        result = ser.serialize(handson_scan)
        packages = result.get("packages", [])
        assert len(packages) == len(handson_scan["dependencies"])
        for pkg in packages:
            assert "externalRefs" in pkg and len(pkg["externalRefs"]) > 0

    def test_purl_in_external_refs(self, ser, handson_scan):
        result = ser.serialize(handson_scan)
        packages = result.get("packages", [])
        assert len(packages) == len(handson_scan["dependencies"])
        for pkg in packages:
            refs = pkg.get("externalRefs", [])
            purl_refs = [r for r in refs if r.get("referenceCategory") == "PACKAGE-MANAGER"]
            assert len(purl_refs) > 0, f"No PACKAGE-MANAGER ref in {pkg.get('name')}"

    def test_purl_ref_type_is_purl(self, ser, handson_scan):
        result = ser.serialize(handson_scan)
        packages = result.get("packages", [])
        assert len(packages) == len(handson_scan["dependencies"])
        for pkg in packages:
            refs = pkg.get("externalRefs", [])
            purl_refs = [r for r in refs if r.get("referenceCategory") == "PACKAGE-MANAGER"]
            for r in purl_refs:
                assert r.get("referenceType") == "purl"

    def test_purl_locator_format(self, ser, handson_scan):
        result = ser.serialize(handson_scan)
        packages = result.get("packages", [])
        assert len(packages) == len(handson_scan["dependencies"])
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
        assert len(packages) == len(clean_scan["dependencies"])
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
                purl="pkg:pypi/numpy",
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
