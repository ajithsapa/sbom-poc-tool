"""
test_api.py — FastAPI integration tests for the SBOM POC Tool API.

Uses FastAPI TestClient (httpx-backed, synchronous) to exercise all five
endpoints against the real orchestration and business-logic layers.

Run from session root:
  pytest step11_api/test_api.py -v

Or from step11_api/:
  pytest test_api.py -v

Session: SBOM-20260409-sb01
Generated: Step 11 — FastAPI API Generation
"""

from __future__ import annotations

import json
import os
import sys

import pytest
from fastapi.testclient import TestClient

# Ensure session root is importable before importing the app.
_SESSION_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if _SESSION_ROOT not in sys.path:
    sys.path.insert(0, _SESSION_ROOT)

from step11_api.main import create_app  # noqa: E402


# ---------------------------------------------------------------------------
# Test fixtures
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module")
def client():
    """
    Create a TestClient backed by a fresh app instance.

    Dependencies use the same module-level singletons as production, so
    scan results persisted by POST /scans are visible to GET /scans/{id}.
    """
    app = create_app()
    with TestClient(app, raise_server_exceptions=False) as c:
        yield c


@pytest.fixture(scope="module")
def temp_repo(tmp_path_factory):
    """
    Create a temporary directory that looks like a Python project.

    ScanJobValidator.validate() requires the repo to contain at least one
    Python indicator (requirements.txt, setup.py, pyproject.toml, etc.)
    or a JavaScript indicator (package.json).  An empty directory fails
    validation with 'Unsupported or undetected language'.
    """
    repo = tmp_path_factory.mktemp("test_repo")
    # Create a minimal requirements.txt so ScanJobValidator accepts the path
    (repo / "requirements.txt").write_text("requests==2.31.0\nlangchain==0.0.247\n")
    return str(repo)


@pytest.fixture(scope="module")
def temp_nvd_feed(tmp_path_factory):
    """
    Write a minimal NVD JSON feed file that NVDCacheManager.sync() can ingest.
    """
    feed_dir = tmp_path_factory.mktemp("nvd_feed")
    feed_path = os.path.join(str(feed_dir), "vulnerability.db")
    feed_data = {
        "CVE_Items": [
            {
                "cve_id": "CVE-2023-99999",
                "purl": "pkg:pypi/test-pkg@1.0.0",
                "cvss_score": 7.5,
            }
        ]
    }
    with open(feed_path, "w") as fh:
        json.dump(feed_data, fh)
    return feed_path


# ---------------------------------------------------------------------------
# GET /api/v1/health
# ---------------------------------------------------------------------------

class TestHealthEndpoint:
    def test_health_returns_200(self, client):
        response = client.get("/api/v1/health")
        assert response.status_code == 200

    def test_health_response_has_required_fields(self, client):
        data = client.get("/api/v1/health").json()
        assert "status" in data
        assert "version" in data
        assert "cache_status" in data

    def test_health_status_is_valid_enum(self, client):
        status = client.get("/api/v1/health").json()["status"]
        assert status in ("ok", "degraded", "down")

    def test_health_cache_status_has_required_fields(self, client):
        cache = client.get("/api/v1/health").json()["cache_status"]
        assert "is_stale" in cache
        assert "record_count" in cache

    def test_health_version_matches_config(self, client):
        from step11_api.config import settings
        data = client.get("/api/v1/health").json()
        assert data["version"] == settings.VERSION


# ---------------------------------------------------------------------------
# GET /api/v1/cache/status
# ---------------------------------------------------------------------------

class TestCacheStatusEndpoint:
    def test_cache_status_returns_200(self, client):
        response = client.get("/api/v1/cache/status")
        assert response.status_code == 200

    def test_cache_status_has_required_fields(self, client):
        data = client.get("/api/v1/cache/status").json()
        assert "is_stale" in data
        assert "record_count" in data

    def test_cache_status_is_stale_bool(self, client):
        data = client.get("/api/v1/cache/status").json()
        assert isinstance(data["is_stale"], bool)

    def test_cache_status_record_count_nonnegative(self, client):
        data = client.get("/api/v1/cache/status").json()
        assert data["record_count"] >= 0


# ---------------------------------------------------------------------------
# POST /api/v1/sync
# ---------------------------------------------------------------------------

class TestSyncEndpoint:
    def test_sync_returns_404_for_missing_source(self, client):
        response = client.post(
            "/api/v1/sync",
            json={"source_path": "/nonexistent/path/vulnerability.db"},
        )
        assert response.status_code == 404

    def test_sync_404_error_code(self, client):
        data = client.post(
            "/api/v1/sync",
            json={"source_path": "/nonexistent/path/vulnerability.db"},
        ).json()
        assert data["error"] == "NVD_SOURCE_NOT_FOUND"

    def test_sync_returns_200_for_valid_feed(self, client, temp_nvd_feed):
        response = client.post(
            "/api/v1/sync",
            json={"source_path": temp_nvd_feed},
        )
        assert response.status_code == 200

    def test_sync_response_has_required_fields(self, client, temp_nvd_feed):
        data = client.post(
            "/api/v1/sync",
            json={"source_path": temp_nvd_feed},
        ).json()
        assert "records_added" in data
        assert "records_updated" in data
        assert "synced_at" in data
        assert "source_path" in data

    def test_sync_records_added_nonnegative(self, client, temp_nvd_feed):
        data = client.post(
            "/api/v1/sync",
            json={"source_path": temp_nvd_feed},
        ).json()
        assert data["records_added"] >= 0
        assert data["records_updated"] >= 0

    def test_sync_missing_source_path_field_returns_422(self, client):
        # Pydantic validation error — missing required field
        response = client.post("/api/v1/sync", json={})
        assert response.status_code == 422

    def test_sync_source_path_echoed_in_response(self, client, temp_nvd_feed):
        data = client.post(
            "/api/v1/sync",
            json={"source_path": temp_nvd_feed},
        ).json()
        assert data["source_path"] == temp_nvd_feed


# ---------------------------------------------------------------------------
# POST /api/v1/scans
# ---------------------------------------------------------------------------

class TestScanEndpoint:
    def test_scan_returns_422_for_missing_repo(self, client):
        """ScanJobValidator rejects nonexistent repo_path."""
        response = client.post(
            "/api/v1/scans",
            json={
                "repo_path": "/definitely/does/not/exist/12345",
                "format": "cyclonedx",
                "env": "development",
            },
        )
        assert response.status_code == 422

    def test_scan_422_error_code(self, client):
        data = client.post(
            "/api/v1/scans",
            json={
                "repo_path": "/definitely/does/not/exist/12345",
                "format": "cyclonedx",
                "env": "development",
            },
        ).json()
        assert data["error"] == "INVALID_REPO_PATH"

    def test_scan_returns_200_for_valid_repo(self, client, temp_repo):
        response = client.post(
            "/api/v1/scans",
            json={
                "repo_path": temp_repo,
                "format": "cyclonedx",
                "env": "development",
                "vex_statements": [],
            },
        )
        assert response.status_code == 200

    def test_scan_response_has_required_fields(self, client, temp_repo):
        data = client.post(
            "/api/v1/scans",
            json={"repo_path": temp_repo, "format": "cyclonedx", "env": "development"},
        ).json()
        required = {
            "scan_id", "repo_name", "output_format", "dependencies",
            "active_vulns", "suppressed_vulns", "warnings",
            "sbom_document", "workflow_states_visited",
        }
        assert required.issubset(set(data.keys()))

    def test_scan_result_scan_id_is_nonempty_string(self, client, temp_repo):
        data = client.post(
            "/api/v1/scans",
            json={"repo_path": temp_repo, "format": "cyclonedx", "env": "development"},
        ).json()
        assert isinstance(data["scan_id"], str)
        assert len(data["scan_id"]) > 0

    def test_scan_result_workflow_states_contains_idle(self, client, temp_repo):
        data = client.post(
            "/api/v1/scans",
            json={"repo_path": temp_repo, "format": "cyclonedx", "env": "staging"},
        ).json()
        assert "idle" in data["workflow_states_visited"]

    def test_scan_spdx_format(self, client, temp_repo):
        response = client.post(
            "/api/v1/scans",
            json={"repo_path": temp_repo, "format": "spdx", "env": "production"},
        )
        assert response.status_code == 200
        assert response.json()["output_format"] == "spdx"

    def test_scan_with_vex_statement(self, client, temp_repo):
        response = client.post(
            "/api/v1/scans",
            json={
                "repo_path": temp_repo,
                "format": "cyclonedx",
                "env": "development",
                "vex_statements": [
                    {
                        "cve_id": "CVE-2023-34540",
                        "purl": "pkg:pypi/langchain@0.0.101",
                        "status": "not_affected",
                        "justification": "vulnerable_code_not_in_execute_path",
                    }
                ],
            },
        )
        assert response.status_code == 200

    def test_scan_invalid_format_returns_422(self, client, temp_repo):
        """Pydantic enum validation rejects unknown format values."""
        response = client.post(
            "/api/v1/scans",
            json={"repo_path": temp_repo, "format": "unknown_format", "env": "development"},
        )
        assert response.status_code == 422

    def test_scan_invalid_env_returns_422(self, client, temp_repo):
        response = client.post(
            "/api/v1/scans",
            json={"repo_path": temp_repo, "format": "cyclonedx", "env": "invalid_env"},
        )
        assert response.status_code == 422

    def test_scan_warnings_is_list(self, client, temp_repo):
        data = client.post(
            "/api/v1/scans",
            json={"repo_path": temp_repo, "format": "cyclonedx", "env": "development"},
        ).json()
        assert isinstance(data["warnings"], list)

    def test_scan_sbom_document_is_dict(self, client, temp_repo):
        data = client.post(
            "/api/v1/scans",
            json={"repo_path": temp_repo, "format": "cyclonedx", "env": "development"},
        ).json()
        assert isinstance(data["sbom_document"], dict)

    def test_scan_cyclonedx_sbom_has_bom_format(self, client, temp_repo):
        data = client.post(
            "/api/v1/scans",
            json={"repo_path": temp_repo, "format": "cyclonedx", "env": "development"},
        ).json()
        # CycloneDX document should have bomFormat key
        assert "bomFormat" in data["sbom_document"]


# ---------------------------------------------------------------------------
# GET /api/v1/scans/{scan_id}
# ---------------------------------------------------------------------------

class TestGetScanEndpoint:
    def test_get_scan_returns_404_for_unknown_id(self, client):
        response = client.get("/api/v1/scans/00000000-0000-0000-0000-000000000000")
        assert response.status_code == 404

    def test_get_scan_404_error_code(self, client):
        data = client.get("/api/v1/scans/00000000-0000-0000-0000-000000000000").json()
        assert data["error"] == "SCAN_NOT_FOUND"

    def test_get_scan_retrieves_stored_result(self, client, temp_repo):
        """POST /scans stores result; GET /scans/{id} must return the same result."""
        post_data = client.post(
            "/api/v1/scans",
            json={"repo_path": temp_repo, "format": "cyclonedx", "env": "development"},
        ).json()
        scan_id = post_data["scan_id"]

        get_data = client.get(f"/api/v1/scans/{scan_id}").json()
        assert get_data["scan_id"] == scan_id

    def test_get_scan_returns_200_for_stored_id(self, client, temp_repo):
        scan_id = client.post(
            "/api/v1/scans",
            json={"repo_path": temp_repo, "format": "spdx", "env": "staging"},
        ).json()["scan_id"]

        response = client.get(f"/api/v1/scans/{scan_id}")
        assert response.status_code == 200

    def test_get_scan_matches_post_output_format(self, client, temp_repo):
        scan_id = client.post(
            "/api/v1/scans",
            json={"repo_path": temp_repo, "format": "spdx", "env": "production"},
        ).json()["scan_id"]

        get_data = client.get(f"/api/v1/scans/{scan_id}").json()
        assert get_data["output_format"] == "spdx"
