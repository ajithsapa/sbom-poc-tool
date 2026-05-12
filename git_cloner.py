"""
git_cloner.py — Clone public git repositories into a managed workspace.

Used by the scan endpoint and CLI to accept a public git URL in addition to
a local filesystem path. Clones are shallow, single-branch, and non-interactive
(any prompt for credentials fails fast rather than blocking the request).

Public repos only: GIT_TERMINAL_PROMPT=0 and GIT_ASKPASS=echo prevent git from
ever blocking on an auth prompt. URLs containing embedded credentials are
rejected up front.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Optional
from urllib.parse import urlparse


class GitCloneError(Exception):
    """Raised when a clone fails for any reason — invalid URL, network, auth, etc."""


class HostNotAllowedError(GitCloneError):
    """Raised when the URL's host is outside the allowlist (currently github.com only)."""


class RepoTooLargeError(GitCloneError):
    """Raised when a successfully cloned repo exceeds the configured size cap."""


_ALLOWED_SCHEMES = {"https", "http", "git"}
# Host allowlist — public github.com only. Subdomains like gist.github.com or
# raw.githubusercontent.com are not git endpoints and are not accepted.
_ALLOWED_HOSTS = {"github.com", "www.github.com"}
_REPO_NAME_RE = re.compile(r"^[A-Za-z0-9._-]+$")
# Default clone timeout (seconds). Large repos with --depth=1 typically finish
# in well under 60s; this caps the request to avoid runaway clones.
_DEFAULT_TIMEOUT_SECONDS = 120
# Default size cap for a successful clone (bytes). 0 = unlimited.
_DEFAULT_MAX_BYTES = 50_000_000


@dataclass(frozen=True)
class ClonedRepo:
    """A repo cloned into the managed workspace."""
    name: str
    path: str
    url: str
    cloned_at: str  # ISO-8601 UTC
    size_bytes: int


def _validate_url(url: str) -> None:
    """
    Validate that the URL is plausibly a public git repo URL.
    Rejects: empty, non-http(s)/git schemes, embedded credentials, file:// paths.
    """
    if not url or not isinstance(url, str):
        raise GitCloneError("repo_url is required and must be a non-empty string")
    url = url.strip()
    if not url:
        raise GitCloneError("repo_url is required and must be a non-empty string")

    parsed = urlparse(url)
    if parsed.scheme not in _ALLOWED_SCHEMES:
        raise GitCloneError(
            f"Unsupported scheme '{parsed.scheme}'. Only https, http, and git URLs are allowed."
        )
    if "@" in parsed.netloc:
        # Reject https://user:token@host/... — public repos shouldn't carry creds,
        # and we don't want to log or persist them.
        raise GitCloneError("repo_url must not contain embedded credentials")
    if not parsed.netloc:
        raise GitCloneError("repo_url is missing a host")
    if not parsed.path or parsed.path in ("/", ""):
        raise GitCloneError("repo_url is missing a repository path")
    if parsed.netloc.lower() not in _ALLOWED_HOSTS:
        raise HostNotAllowedError(
            f"Only github.com URLs are accepted. Got host '{parsed.netloc}'. "
            f"Support for additional hosts is on the roadmap."
        )


def repo_name_from_url(url: str) -> str:
    """
    Derive a workspace directory name from a git URL.
    Strips a trailing '.git' and the leading path components, e.g.
        https://github.com/anchore/syft.git  -> 'syft'
    """
    path = urlparse(url).path.rstrip("/")
    base = path.rsplit("/", 1)[-1]
    if base.endswith(".git"):
        base = base[: -len(".git")]
    if not base or not _REPO_NAME_RE.match(base):
        raise GitCloneError(f"Could not derive a safe repo name from URL: {url!r}")
    return base


def _dir_size(path: Path) -> int:
    total = 0
    for root, _dirs, files in os.walk(path):
        for f in files:
            try:
                total += (Path(root) / f).stat().st_size
            except OSError:
                pass
    return total


class CloneManager:
    """
    Manages the workspace of cloned repos under a single root directory.
    Thread-safety: filesystem-level only; concurrent clones of the same name
    are prevented by checking existence before invoking git.
    """

    def __init__(
        self,
        workspace_dir: str,
        clone_timeout_seconds: int = _DEFAULT_TIMEOUT_SECONDS,
        max_bytes: int = _DEFAULT_MAX_BYTES,
    ):
        self.workspace_dir = Path(workspace_dir).resolve()
        self.workspace_dir.mkdir(parents=True, exist_ok=True)
        self.clone_timeout_seconds = clone_timeout_seconds
        # 0 disables the size cap.
        self.max_bytes = max_bytes

    def _resolve_safe(self, name: str) -> Path:
        """Resolve `name` inside the workspace, refusing path traversal."""
        if not _REPO_NAME_RE.match(name or ""):
            raise GitCloneError(f"Invalid repo name: {name!r}")
        target = (self.workspace_dir / name).resolve()
        # Ensure target is under workspace_dir (paranoia against symlink/traversal).
        if not str(target).startswith(str(self.workspace_dir) + os.sep) and target != self.workspace_dir:
            raise GitCloneError(f"Invalid repo name: {name!r}")
        return target

    def exists(self, name: str) -> bool:
        target = self._resolve_safe(name)
        return target.is_dir()

    def list_repos(self) -> List[ClonedRepo]:
        """List all cloned repos in the workspace."""
        repos: List[ClonedRepo] = []
        if not self.workspace_dir.is_dir():
            return repos
        for entry in sorted(self.workspace_dir.iterdir()):
            if not entry.is_dir():
                continue
            meta_path = entry / ".sbom-clone.json"
            url = ""
            cloned_at = ""
            if meta_path.is_file():
                try:
                    import json
                    data = json.loads(meta_path.read_text(encoding="utf-8"))
                    url = str(data.get("url", ""))
                    cloned_at = str(data.get("cloned_at", ""))
                except Exception:
                    pass
            repos.append(
                ClonedRepo(
                    name=entry.name,
                    path=str(entry),
                    url=url,
                    cloned_at=cloned_at,
                    size_bytes=_dir_size(entry),
                )
            )
        return repos

    def get(self, name: str) -> Optional[ClonedRepo]:
        for repo in self.list_repos():
            if repo.name == name:
                return repo
        return None

    def clone(self, url: str, name: Optional[str] = None) -> ClonedRepo:
        """
        Shallow-clone `url` into the workspace. Returns the resulting ClonedRepo.
        Raises GitCloneError if the name collides, the URL is invalid, or git fails.
        """
        _validate_url(url)
        repo_name = name or repo_name_from_url(url)
        target = self._resolve_safe(repo_name)

        if target.exists():
            raise GitCloneError(
                f"A clone named {repo_name!r} already exists. "
                f"Delete it first via DELETE /api/v1/repos/{repo_name}."
            )

        # Disable any interactive prompts — public repos only.
        env = os.environ.copy()
        env["GIT_TERMINAL_PROMPT"] = "0"
        env["GIT_ASKPASS"] = "echo"

        cmd = [
            "git", "clone",
            "--depth=1",
            "--single-branch",
            "--no-tags",
            url,
            str(target),
        ]

        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                env=env,
                timeout=self.clone_timeout_seconds,
            )
        except FileNotFoundError as exc:
            raise GitCloneError("git executable not found on PATH") from exc
        except subprocess.TimeoutExpired as exc:
            # Best-effort cleanup of any partial clone.
            if target.exists():
                shutil.rmtree(target)
            raise GitCloneError(
                f"git clone timed out after {self.clone_timeout_seconds}s"
            ) from exc

        if proc.returncode != 0:
            if target.exists():
                shutil.rmtree(target)
            stderr = (proc.stderr or "").strip().splitlines()
            # Surface the last meaningful stderr line; skip generic progress noise.
            last = stderr[-1] if stderr else "git clone failed"
            raise GitCloneError(f"git clone failed: {last}")

        # Enforce size cap. Clone is on disk by this point; measure, then
        # delete + raise if oversized so we never leave bloat behind.
        if self.max_bytes and self.max_bytes > 0:
            size = _dir_size(target)
            if size > self.max_bytes:
                shutil.rmtree(target)
                raise RepoTooLargeError(
                    f"Cloned repo is {size:,} bytes, which exceeds the configured "
                    f"size cap of {self.max_bytes:,} bytes. The clone has been deleted. "
                    f"This limit exists to keep scan workspaces small — large "
                    f"datasets/models in the repo will push it over the cap even "
                    f"though Syft only needs dependency manifests."
                )

        cloned_at = datetime.now(timezone.utc).isoformat()
        try:
            import json
            (target / ".sbom-clone.json").write_text(
                json.dumps({"url": url, "cloned_at": cloned_at}, indent=2),
                encoding="utf-8",
            )
        except OSError:
            pass

        return ClonedRepo(
            name=repo_name,
            path=str(target),
            url=url,
            cloned_at=cloned_at,
            size_bytes=_dir_size(target),
        )

    def delete(self, name: str) -> None:
        """Delete a cloned repo. Raises GitCloneError if it does not exist."""
        target = self._resolve_safe(name)
        if not target.is_dir():
            raise GitCloneError(f"No clone named {name!r}")
        shutil.rmtree(target)
