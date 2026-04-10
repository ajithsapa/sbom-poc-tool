"""
OSSToolRunner — subprocess wrapper for Syft.

Invokes `syft packages <repo> --output syft-json`, parses the output,
and returns a list of records in the format expected by
OSSToolAdapter.normalise().

This is the only place in the codebase that calls a real OSS binary.
All downstream logic (OSSToolAdapter, VulnerabilityMapper, etc.) remains
pure Python operating on the normalised dict shape.
"""
import json
import os
import subprocess
from typing import Any, Dict, List

# Default install location from the install script
_DEFAULT_SYFT = os.path.expanduser("~/.local/bin/syft")
_FALLBACK_SYFT = "syft"


class OSSToolRunnerError(Exception):
    """Raised when the OSS tool subprocess fails."""


class OSSToolRunner:
    """
    Runs Syft against a repository and returns raw artifacts ready
    for OSSToolAdapter.normalise().

    Each returned record has the shape:
        {
            "tool":    "syft",
            "name":    str,
            "version": str,
            "purl":    str,   # pkg:pypi/name@version
            "cpe":     str | None,
        }
    """

    def __init__(self, syft_path: str = _DEFAULT_SYFT, timeout: int = 120):
        # Fall back to PATH lookup if the default path does not exist
        if not os.path.isfile(syft_path):
            syft_path = _FALLBACK_SYFT
        self.syft_path = syft_path
        self.timeout = timeout

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def scan(self, repo_path: str) -> List[Dict[str, Any]]:
        """
        Scan *repo_path* with Syft and return a flat list of artifact dicts.

        Raises:
            OSSToolRunnerError: if syft exits non-zero or output is unparseable.
        """
        raw = self._run_syft(repo_path)
        return self._extract_artifacts(raw)

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    def _run_syft(self, repo_path: str) -> Dict[str, Any]:
        try:
            result = subprocess.run(
                [self.syft_path, "packages", repo_path, "--output", "syft-json"],
                capture_output=True,
                text=True,
                timeout=self.timeout,
            )
        except FileNotFoundError:
            raise OSSToolRunnerError(
                f"Syft binary not found at '{self.syft_path}'. "
                "Install via: curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh -s -- -b ~/.local/bin"
            )
        except subprocess.TimeoutExpired:
            raise OSSToolRunnerError(f"Syft timed out after {self.timeout}s scanning '{repo_path}'")

        if result.returncode != 0:
            raise OSSToolRunnerError(
                f"Syft exited {result.returncode} scanning '{repo_path}':\n{result.stderr[:500]}"
            )

        try:
            return json.loads(result.stdout)
        except json.JSONDecodeError as exc:
            raise OSSToolRunnerError(f"Syft produced invalid JSON: {exc}") from exc

    def _extract_artifacts(self, syft_json: Dict[str, Any]) -> List[Dict[str, Any]]:
        records = []
        for artifact in syft_json.get("artifacts", []):
            cpe = None
            cpes = artifact.get("cpes", [])
            if cpes:
                # Pick the most specific CPE (last entry tends to be vendor:product)
                cpe = cpes[-1].get("cpe")

            records.append({
                "tool": "syft",
                "name": artifact.get("name", ""),
                "version": artifact.get("version", ""),
                "purl": artifact.get("purl", ""),
                "cpe": cpe,
            })
        return records
