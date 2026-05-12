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


# ---------------------------------------------------------------------------
# Git URL clone feature — request validation + /api/v1/repos endpoints
# ---------------------------------------------------------------------------

class TestScanRequestUrlValidation:
    """ScanRequest validator must enforce exactly-one-of(repo_path, repo_url)."""

    def test_neither_repo_path_nor_repo_url_returns_422(self, client):
        response = client.post(
            "/api/v1/scans",
            json={"format": "cyclonedx", "env": "development"},
        )
        assert response.status_code == 422

    def test_both_repo_path_and_repo_url_returns_422(self, client, temp_repo):
        response = client.post(
            "/api/v1/scans",
            json={
                "repo_path": temp_repo,
                "repo_url": "https://github.com/example/example.git",
                "format": "cyclonedx",
                "env": "development",
            },
        )
        assert response.status_code == 422

    def test_invalid_url_scheme_returns_422(self, client):
        # Validator runs at the request layer; we never reach the cloner here.
        response = client.post(
            "/api/v1/scans",
            json={
                "repo_url": "file:///etc/passwd",
                "format": "cyclonedx",
                "env": "development",
            },
        )
        # The Pydantic model accepts any string; the cloner rejects the scheme.
        # Either is acceptable, but both must surface 422 with details.
        assert response.status_code == 422

    def test_url_with_embedded_credentials_returns_422(self, client):
        response = client.post(
            "/api/v1/scans",
            json={
                "repo_url": "https://user:token@github.com/example/repo.git",
                "format": "cyclonedx",
                "env": "development",
            },
        )
        assert response.status_code == 422
        assert response.json()["error"] in ("REPO_CLONE_FAILED", "VALIDATION_ERROR")


class TestReposEndpoint:
    """GET/DELETE/PUT /api/v1/repos exercised against the real CloneManager
    by populating the workspace directly (no network required)."""

    @pytest.fixture
    def populated_workspace(self):
        """Drop two fake clones into the active CloneManager's workspace."""
        from step11_api.dependencies import get_clone_manager
        mgr = get_clone_manager()
        names = ["test-clone-alpha", "test-clone-beta"]
        for name in names:
            target = os.path.join(str(mgr.workspace_dir), name)
            os.makedirs(target, exist_ok=True)
            # Make it scannable in case a downstream test runs it through Syft.
            with open(os.path.join(target, "requirements.txt"), "w") as fh:
                fh.write("requests==2.31.0\n")
            with open(os.path.join(target, ".sbom-clone.json"), "w") as fh:
                json.dump(
                    {"url": f"https://example.invalid/{name}.git", "cloned_at": "2026-05-12T00:00:00+00:00"},
                    fh,
                )
        yield names
        # Cleanup
        for name in names:
            target = os.path.join(str(mgr.workspace_dir), name)
            if os.path.isdir(target):
                import shutil
                shutil.rmtree(target, ignore_errors=True)

    def test_list_repos_returns_200(self, client):
        response = client.get("/api/v1/repos")
        assert response.status_code == 200
        assert "repos" in response.json()

    def test_list_repos_includes_populated_entries(self, client, populated_workspace):
        names_present = {r["name"] for r in client.get("/api/v1/repos").json()["repos"]}
        for name in populated_workspace:
            assert name in names_present

    def test_list_repos_includes_url_metadata(self, client, populated_workspace):
        repos = client.get("/api/v1/repos").json()["repos"]
        targeted = [r for r in repos if r["name"] == populated_workspace[0]]
        assert targeted, "expected populated clone to appear in listing"
        assert targeted[0]["url"].endswith(".git")
        assert targeted[0]["cloned_at"]

    def test_delete_repo_returns_200_and_removes_entry(self, client, populated_workspace):
        target_name = populated_workspace[0]
        response = client.delete(f"/api/v1/repos/{target_name}")
        assert response.status_code == 200
        assert response.json() == {"deleted": True, "name": target_name}
        names_after = {r["name"] for r in client.get("/api/v1/repos").json()["repos"]}
        assert target_name not in names_after

    def test_delete_repo_returns_404_for_unknown(self, client):
        response = client.delete("/api/v1/repos/this-clone-does-not-exist-9999")
        assert response.status_code == 404
        assert response.json()["error"] == "REPO_NOT_FOUND"

    def test_delete_repo_rejects_path_traversal(self, client):
        response = client.delete("/api/v1/repos/..")
        # FastAPI path normalization may catch ".." before the handler does;
        # either way, no traversal should succeed.
        assert response.status_code in (404, 422)


class TestGitClonerUnit:
    """Pure-unit tests for git_cloner helpers — no network, no subprocess."""

    def test_validate_url_rejects_empty(self):
        from git_cloner import GitCloneError, _validate_url
        with pytest.raises(GitCloneError):
            _validate_url("")

    def test_validate_url_rejects_file_scheme(self):
        from git_cloner import GitCloneError, _validate_url
        with pytest.raises(GitCloneError):
            _validate_url("file:///etc/passwd")

    def test_validate_url_rejects_embedded_creds(self):
        from git_cloner import GitCloneError, _validate_url
        with pytest.raises(GitCloneError):
            _validate_url("https://user:pw@github.com/x/y.git")

    def test_validate_url_accepts_https(self):
        from git_cloner import _validate_url
        # No exception means valid.
        _validate_url("https://github.com/anchore/syft.git")

    def test_repo_name_strips_dot_git(self):
        from git_cloner import repo_name_from_url
        assert repo_name_from_url("https://github.com/anchore/syft.git") == "syft"

    def test_repo_name_handles_trailing_slash(self):
        from git_cloner import repo_name_from_url
        assert repo_name_from_url("https://github.com/anchore/syft/") == "syft"

    def test_clone_collision_raises(self, tmp_path):
        from git_cloner import CloneManager, GitCloneError
        mgr = CloneManager(workspace_dir=str(tmp_path))
        # Pre-create a clone dir
        (tmp_path / "syft").mkdir()
        with pytest.raises(GitCloneError, match="already exists"):
            mgr.clone("https://github.com/anchore/syft.git")

    def test_validate_url_rejects_non_github_host(self):
        from git_cloner import HostNotAllowedError, _validate_url
        with pytest.raises(HostNotAllowedError, match="github.com"):
            _validate_url("https://gitlab.com/some-org/some-repo.git")

    def test_validate_url_rejects_github_subdomain(self):
        from git_cloner import HostNotAllowedError, _validate_url
        with pytest.raises(HostNotAllowedError):
            _validate_url("https://raw.githubusercontent.com/x/y/main")

    def test_validate_url_accepts_www_github(self):
        from git_cloner import _validate_url
        _validate_url("https://www.github.com/anchore/syft.git")


class TestRepoUrlHostAllowlistAPI:
    """POST /scans must reject non-github URLs with REPO_HOST_NOT_ALLOWED."""

    def test_gitlab_url_returns_422_host_not_allowed(self, client):
        response = client.post(
            "/api/v1/scans",
            json={
                "repo_url": "https://gitlab.com/some-org/some-repo.git",
                "format": "cyclonedx",
                "env": "development",
            },
        )
        assert response.status_code == 422
        assert response.json()["error"] == "REPO_HOST_NOT_ALLOWED"


class TestRepoSizeCap:
    """CloneManager must delete + raise when a clone exceeds the size cap."""

    def test_oversized_clone_raises_and_cleans_up(self, tmp_path, monkeypatch):
        """
        Simulate an oversized clone by mocking subprocess.run to drop a
        fake oversized blob into the target dir, then assert RepoTooLargeError.
        """
        import subprocess as _sp
        from git_cloner import CloneManager, RepoTooLargeError

        mgr = CloneManager(workspace_dir=str(tmp_path), max_bytes=1024)

        def fake_run(cmd, capture_output, text, env, timeout):
            # cmd[-1] is the target path; create it and stuff a 2 KB file in.
            target = cmd[-1]
            os.makedirs(target, exist_ok=True)
            with open(os.path.join(target, "blob.bin"), "wb") as fh:
                fh.write(b"x" * 2048)

            class _Result:
                returncode = 0
                stdout = ""
                stderr = ""
            return _Result()

        monkeypatch.setattr(_sp, "run", fake_run)

        with pytest.raises(RepoTooLargeError, match="exceeds the configured size cap"):
            mgr.clone("https://github.com/example/oversized.git")

        # Workspace must be empty after the failure — no orphaned dir left behind.
        assert not any(tmp_path.iterdir())


class TestApiKeyAuth:
    """X-API-Key enforcement when API_KEY is configured."""

    @pytest.fixture
    def authed_client(self, monkeypatch):
        """A separate TestClient with API_KEY set on the settings singleton."""
        monkeypatch.setenv("API_KEY", "test-secret-key")
        # Reload settings + reset the warned flag so the dependency re-reads env.
        from step11_api import config as _cfg
        from step11_api.dependencies import require_api_key
        _cfg.settings = _cfg.Settings()
        if hasattr(require_api_key, "_warned"):
            delattr(require_api_key, "_warned")
        from step11_api.main import create_app
        app = create_app()
        with TestClient(app, raise_server_exceptions=False) as c:
            yield c

    def test_health_is_open_without_key(self, authed_client):
        # /health must work even when auth is configured — used by liveness probes.
        assert authed_client.get("/api/v1/health").status_code == 200

    def test_scans_requires_key(self, authed_client, temp_repo):
        response = authed_client.post(
            "/api/v1/scans",
            json={"repo_path": temp_repo, "format": "cyclonedx", "env": "development"},
        )
        assert response.status_code == 401
        assert response.json()["detail"]["error"] == "INVALID_API_KEY"

    def test_scans_rejects_wrong_key(self, authed_client, temp_repo):
        response = authed_client.post(
            "/api/v1/scans",
            headers={"X-API-Key": "wrong"},
            json={"repo_path": temp_repo, "format": "cyclonedx", "env": "development"},
        )
        assert response.status_code == 401

    def test_scans_accepts_correct_key(self, authed_client, temp_repo):
        response = authed_client.post(
            "/api/v1/scans",
            headers={"X-API-Key": "test-secret-key"},
            json={"repo_path": temp_repo, "format": "cyclonedx", "env": "development"},
        )
        assert response.status_code == 200

    def test_repos_list_requires_key(self, authed_client):
        assert authed_client.get("/api/v1/repos").status_code == 401

    def test_cache_status_requires_key(self, authed_client):
        assert authed_client.get("/api/v1/cache/status").status_code == 401


class TestManifestDetection:
    """Unit tests for the Python/JS-only language gate."""

    def test_supported_python_manifest_only(self, tmp_path):
        from git_cloner import detect_manifests
        (tmp_path / "requirements.txt").write_text("requests==2.31.0\n")
        supported, foreign = detect_manifests(str(tmp_path))
        assert "requirements.txt" in supported
        assert foreign == []

    def test_supported_javascript_manifest_only(self, tmp_path):
        from git_cloner import detect_manifests
        (tmp_path / "package.json").write_text('{"name": "x"}')
        supported, foreign = detect_manifests(str(tmp_path))
        assert "package.json" in supported
        assert foreign == []

    def test_requirements_glob_matches_dev_variants(self, tmp_path):
        from git_cloner import detect_manifests
        (tmp_path / "requirements-dev.txt").write_text("")
        (tmp_path / "requirements-test.txt").write_text("")
        supported, foreign = detect_manifests(str(tmp_path))
        assert any("requirements-dev.txt" in s for s in supported)
        assert any("requirements-test.txt" in s for s in supported)

    def test_foreign_go_manifest_detected(self, tmp_path):
        from git_cloner import detect_manifests
        (tmp_path / "go.mod").write_text("module x\n")
        _, foreign = detect_manifests(str(tmp_path))
        assert "go.mod" in foreign

    def test_foreign_rust_manifest_detected(self, tmp_path):
        from git_cloner import detect_manifests
        (tmp_path / "Cargo.toml").write_text("[package]\n")
        _, foreign = detect_manifests(str(tmp_path))
        assert "Cargo.toml" in foreign

    def test_foreign_dotnet_csproj_detected(self, tmp_path):
        from git_cloner import detect_manifests
        (tmp_path / "MyApp.csproj").write_text("<Project/>")
        _, foreign = detect_manifests(str(tmp_path))
        assert any(p.endswith(".csproj") for p in foreign)

    def test_skip_dirs_are_ignored(self, tmp_path):
        from git_cloner import detect_manifests
        # A node_modules/Cargo.toml must not register as a foreign manifest.
        nm = tmp_path / "node_modules" / "some-pkg"
        nm.mkdir(parents=True)
        (nm / "Cargo.toml").write_text("")
        (tmp_path / "package.json").write_text("{}")
        supported, foreign = detect_manifests(str(tmp_path))
        assert foreign == []
        assert any("package.json" in s for s in supported)

    def test_mixed_repo_reports_both(self, tmp_path):
        from git_cloner import detect_manifests
        (tmp_path / "pyproject.toml").write_text("")
        (tmp_path / "go.mod").write_text("")
        supported, foreign = detect_manifests(str(tmp_path))
        assert "pyproject.toml" in supported
        assert "go.mod" in foreign


class TestRepoPathLanguageGateAPI:
    """POST /scans with a repo_path must enforce the language gate."""

    def test_unsupported_language_returns_422(self, client, tmp_path_factory):
        repo = tmp_path_factory.mktemp("empty_repo")
        # Drop a README so the dir isn't empty (still no manifest).
        (repo / "README.md").write_text("hello")
        response = client.post(
            "/api/v1/scans",
            json={
                "repo_path": str(repo),
                "format": "cyclonedx",
                "env": "development",
            },
        )
        assert response.status_code == 422
        assert response.json()["error"] == "REPO_UNSUPPORTED_LANGUAGE"

    def test_foreign_manifest_returns_422(self, client, tmp_path_factory):
        repo = tmp_path_factory.mktemp("mixed_repo")
        # Python manifest is present, but so is go.mod -> strict mode rejects.
        (repo / "requirements.txt").write_text("requests==2.31.0\n")
        (repo / "go.mod").write_text("module x\n")
        response = client.post(
            "/api/v1/scans",
            json={
                "repo_path": str(repo),
                "format": "cyclonedx",
                "env": "development",
            },
        )
        assert response.status_code == 422
        body = response.json()
        assert body["error"] == "REPO_FOREIGN_MANIFEST"
        assert "go.mod" in body.get("details", {}).get("foreign_manifests", [])


class TestCloneManagerLanguageGate:
    """CloneManager.clone() must reject + delete when language gate fails."""

    def _stub_clone(self, monkeypatch, layout_fn):
        """Replace subprocess.run with a fake that populates the clone target."""
        import subprocess as _sp

        def fake_run(cmd, capture_output, text, env, timeout):
            target = cmd[-1]
            os.makedirs(target, exist_ok=True)
            layout_fn(target)

            class _R:
                returncode = 0
                stdout = ""
                stderr = ""
            return _R()
        monkeypatch.setattr(_sp, "run", fake_run)

    def test_clone_rejects_repo_with_no_manifest(self, tmp_path, monkeypatch):
        from git_cloner import CloneManager, UnsupportedLanguageError

        def layout(target):
            with open(os.path.join(target, "README.md"), "w") as fh:
                fh.write("hello")

        self._stub_clone(monkeypatch, layout)
        mgr = CloneManager(workspace_dir=str(tmp_path), max_bytes=0)
        with pytest.raises(UnsupportedLanguageError):
            mgr.clone("https://github.com/example/no-manifest.git")
        assert not any(tmp_path.iterdir()), "clone must be cleaned up after rejection"

    def test_clone_rejects_repo_with_foreign_manifest(self, tmp_path, monkeypatch):
        from git_cloner import CloneManager, ForeignManifestError

        def layout(target):
            with open(os.path.join(target, "requirements.txt"), "w") as fh:
                fh.write("requests==2.31.0\n")
            with open(os.path.join(target, "go.mod"), "w") as fh:
                fh.write("module x\n")

        self._stub_clone(monkeypatch, layout)
        mgr = CloneManager(workspace_dir=str(tmp_path), max_bytes=0)
        with pytest.raises(ForeignManifestError, match="go.mod"):
            mgr.clone("https://github.com/example/mixed.git")
        assert not any(tmp_path.iterdir())
