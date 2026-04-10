import json
import os
import sqlite3

import typer

from oss_tool_runner import OSSToolRunner, OSSToolRunnerError
from step9_tdd_green_phase_orchestration import CLIOrchestrator, ScanOrchestrator

app = typer.Typer(name="sbom-tool", help="SBOM POC Tool — scan codebases and sync NVD cache.")

# Default DB path: seeded file next to cli.py; override with SBOM_NVD_DB env var
_DEFAULT_DB = os.path.join(os.path.dirname(__file__), "step1b_nvd_cache.db")

_runner = OSSToolRunner()
_orchestrator = ScanOrchestrator()


def _load_nvd_cache(db_path: str) -> dict:
    """Load the NVD SQLite DB into the PURL-keyed dict expected by VulnerabilityMapper."""
    if not os.path.isfile(db_path):
        return {}
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    try:
        rows = conn.execute(
            "SELECT purl, cpe, cve_id, cvss_score, severity, fixed_version, advisory_url "
            "FROM vulnerabilities"
        ).fetchall()
    finally:
        conn.close()

    cache = {}
    for row in rows:
        entry = {
            "cve_id":       row["cve_id"],
            "cvss_score":   row["cvss_score"],
            "severity":     row["severity"],
            "fixed_version": row["fixed_version"],
            "advisory_url": row["advisory_url"],
        }
        if row["purl"]:
            cache[row["purl"]] = entry
        if row["cpe"]:
            cache[row["cpe"]] = entry
    return cache


@app.command()
def scan(
    repo: str = typer.Option(..., "--repo", help="Path to repository to scan"),
    format: str = typer.Option("cyclonedx", "--format", help="Output format: cyclonedx or spdx"),
    env: str = typer.Option("development", "--env", help="Runtime environment (development|staging|production)"),
    output: str = typer.Option(None, "--output", help="Write SBOM JSON to file instead of stdout"),
    db: str = typer.Option(None, "--db", help="Path to NVD cache SQLite DB (default: step1b_nvd_cache.db)"),
):
    """Scan a repository and produce an SBOM with vulnerability mapping."""
    db_path = db or os.environ.get("SBOM_NVD_DB", _DEFAULT_DB)

    # Run real Syft scan
    try:
        raw_artifacts = _runner.scan(repo)
    except OSSToolRunnerError as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(1)

    nvd_cache = _load_nvd_cache(db_path)
    if not nvd_cache:
        typer.echo(
            f"Warning: NVD cache is empty or not found at '{db_path}'. "
            "Vulnerability mapping will produce no results. Run 'sbom-tool sync' first.",
            err=True,
        )

    try:
        scan_result = _orchestrator.run(
            repo_path=repo,
            output_format=format,
            env=env,
            nvd_cache=nvd_cache,
            raw_tool_output={"tool": "syft", "components": raw_artifacts},
        )
    except (ValueError, RuntimeError) as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(1)

    for warning in getattr(scan_result, "warnings", []) or []:
        typer.echo(warning, err=True)

    sbom_json = json.dumps(scan_result.sbom_document, indent=2)

    if output:
        try:
            with open(output, "w") as f:
                f.write(sbom_json)
        except OSError as exc:
            typer.echo(f"Failed to write output file: {exc}", err=True)
            raise typer.Exit(1)
    else:
        typer.echo(sbom_json)

    raise typer.Exit(0)


@app.command()
def sync(
    source: str = typer.Option(..., "--source", help="Path to Grype DB for NVD cache sync"),
):
    """Sync the local NVD vulnerability cache from a Grype DB source."""
    cli = CLIOrchestrator()
    result = cli.invoke_sync(source)
    if result["stderr"]:
        typer.echo(result["stderr"], err=True)
    if result["stdout"]:
        typer.echo(result["stdout"])
    raise typer.Exit(result["exit_code"])


if __name__ == "__main__":
    app()
