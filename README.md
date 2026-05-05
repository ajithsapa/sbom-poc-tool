# SBOM POC Tool

A Software Bill of Materials engine for Python and JavaScript / TypeScript codebases. Scans dependency manifests, produces machine-readable SBOM output in **CycloneDX 1.4** or **SPDX 2.3** JSON, and maps each dependency against a local **NVD** (National Vulnerability Database) cache to surface CVEs with **CVSS** severity, fixed versions, and ready-to-run upgrade commands.

Ships with both a **REST API** (FastAPI) and a **CLI** wrapping the same engine.

---

## Architecture

```
   repository  ──►  Syft  ──►  OSSToolAdapter  ──►  VulnerabilityMapper  ──►  VEXFilter  ──►  RemediationEnricher  ──►  Serializer  ──►  CycloneDX / SPDX
                              (normalisation)        (PURL/CPE → NVD cache)    (suppress)     (fixed_version, etc.)         (output)
```

Roughly 60% of the pipeline is mature open source — Syft for cataloging, the NVD vulnerability data model, FastAPI / Pydantic / Typer for the surfaces. The novel layers are unified output across catalogers, PURL/CPE-based mapping against the local NVD cache, OpenVEX filtering, and remediation enrichment.

| Layer | OSS used | This tool's contribution |
|-------|----------|--------------------------|
| Dependency cataloging | [Syft](https://github.com/anchore/syft) | Unified output, deduplication |
| Vulnerability matching | NVD data model (Grype-compatible feeds) | PURL + CPE matching, case-insensitive PyPI normalisation |
| VEX filtering | [OpenVEX](https://github.com/openvex) statement schema | In-process filter, audit-preserved suppression |
| Output | [CycloneDX 1.4](https://cyclonedx.org/) / [SPDX 2.3](https://spdx.dev/) specs | Remediation enrichment, recommendation strings |
| CLI | [Typer](https://typer.tiangolo.com/) | — |
| API | [FastAPI](https://fastapi.tiangolo.com/) | — |

---

## Quickstart (REST API)

```bash
# 1. Clone + install
git clone https://github.com/ajithsapa/sbom-poc-tool.git
cd sbom-poc-tool
pip install -e .

# 2. Install Syft (one-time)
curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh -s -- -b ~/.local/bin

# 3. Seed the NVD cache (one-time, ~140 ms)
python create_nvd_cache_db.py

# 4. Boot the API pointed at the seeded cache
NVD_CACHE_DB_PATH=$(pwd)/step1b_nvd_cache.db \
  uvicorn step11_api.main:app --host 0.0.0.0 --port 8000
```

Then open **<http://localhost:8000/docs>**.

The default Swagger example for `POST /api/v1/scans` is pre-filled to scan `./examples/handson-ml-fixture`, which ships with this repo. Click "Try it out" then "Execute" — you should see 9 components, 4 active CVEs, and 1 suppressed CVE (joblib is suppressed by an inline VEX statement).

---

## REST API reference

| Method | Path | Purpose | POC requirement |
|--------|------|---------|-----------------|
| POST | `/api/v1/scans` | Run an SBOM scan against a repository, returns inventory + CVEs + SBOM document | Reqs 1–6 |
| GET | `/api/v1/scans/{scan_id}` | Retrieve a previously completed scan by UUID | — |
| POST | `/api/v1/sync` | Refresh the local NVD vulnerability cache from a feed file | Req 7 |
| GET | `/api/v1/cache/status` | Inspect NVD cache freshness (last sync, age, record count) | Req 7 |
| GET | `/api/v1/health` | Service liveness + cache health (returns `degraded` when stale) | — |

Full OpenAPI 3.1 contract: `/docs` (Swagger UI) or `/redoc` (ReDoc) when the server is running. Response shape, field-level scope tags, and acronym-expanded descriptions are all in the schema.

---

## CLI reference

After `pip install -e .` the `sbom-tool` console script is on `PATH`:

### `sbom-tool scan` — Scan a repository

```bash
sbom-tool scan --repo <path> [OPTIONS]
```

| Option | Default | Description |
|--------|---------|-------------|
| `--repo` | required | Path to repository to scan |
| `--format` | `cyclonedx` | Output format: `cyclonedx` or `spdx` |
| `--env` | `development` | Runtime environment: `development`, `staging`, `production` |
| `--output` | stdout | Write SBOM JSON to a file instead of stdout |
| `--db` | `step1b_nvd_cache.db` | Path to NVD cache SQLite DB |

### `sbom-tool sync` — Refresh the NVD cache

```bash
sbom-tool sync --source <path> [--db <path>]
```

| Option | Default | Description |
|--------|---------|-------------|
| `--source` | required | Path to NVD feed JSON or Grype DB to sync from |
| `--db` | `step1b_nvd_cache.db` | Cache DB to update |

If you haven't installed the package, both commands are also reachable via `python cli.py scan ...` and `python cli.py sync ...`.

---

## Configuration

All API configuration is environment-driven. Copy `step11_api/.env.template` to `step11_api/.env` and edit, or export inline.

| Variable | Default | Purpose |
|----------|---------|---------|
| `NVD_CACHE_DB_PATH` | `:memory:` | **Required for any non-trivial deployment.** Path to the SQLite NVD cache. Use `:memory:` for ephemeral testing; a file path (e.g. `/data/nvd_cache.db`) for persistence. |
| `HOST` | `0.0.0.0` | Bind address |
| `PORT` | `8000` | Bind port |
| `LOG_LEVEL` | `INFO` | One of `DEBUG`, `INFO`, `WARNING`, `ERROR`, `CRITICAL` |
| `ALLOWED_ORIGINS` | `["http://localhost:3000","http://localhost:5173","http://localhost:8080"]` | CORS allowlist (JSON-encoded array of origins) |
| `RELOAD` | `False` | Set `True` for development auto-reload |

For the CLI, `SBOM_NVD_DB` is an alternative to `--db`:

```bash
export SBOM_NVD_DB=/data/nvd_cache.db
sbom-tool scan --repo /path/to/repo
```

---

## Examples

The `examples/` directory ships two fixture projects with vulnerable dependency pins:

| Path | Components | CVEs | What it demonstrates |
|------|------------|------|----------------------|
| `examples/handson-ml-fixture/` | 9 | 5 (joblib 9.8, tensorflow 8.8, pillow 7.5, numpy 5.5, scipy 5.5) | Classic ML stack — high/medium severity range |
| `examples/TaskMatrix-fixture/` | 8 | 4 (langchain 9.8, pillow 7.5, requests 6.1, numpy 5.5) | LLM/agent project — surfaces an AI-ecosystem CVE |

Both fixtures contain only a `requirements.txt` with pinned versions. The SBOM tool inventories declared dependencies (not installed packages), so a manifest is sufficient for a complete scan — no actual source, datasets, or model files are needed.

To run the dogfood demo (scan the SBOM tool's own API layer — produces a clean SBOM with zero CVEs, since current pins are not in the seeded cache):

```bash
sbom-tool scan --repo ./step11_api --format cyclonedx
```

### Sample CycloneDX output

Scanning `./examples/TaskMatrix-fixture` (excerpt):

```json
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.4",
  "components": [
    { "type": "library", "name": "langchain", "version": "0.0.101", "purl": "pkg:pypi/langchain@0.0.101", "supplier": { "name": "PyPI" } },
    { "type": "library", "name": "torch",     "version": "1.13.1",  "purl": "pkg:pypi/torch@1.13.1",     "supplier": { "name": "PyPI" } }
  ],
  "vulnerabilities": [
    {
      "id": "CVE-2023-34540",
      "ratings": [{ "score": 9.8, "severity": "high", "method": "CVSSv31" }],
      "affects": [{ "ref": "pkg:pypi/langchain@0.0.101" }],
      "advisories": [{ "url": "https://nvd.nist.gov/vuln/detail/CVE-2023-34540" }],
      "recommendation": "Upgrade to 0.0.341"
    }
  ]
}
```

---

## VEX (Vulnerability Exploitability eXchange)

VEX is a spec for declaring that a CVE is **present** in your dependencies but **not actually exploitable** — for example, the vulnerable code path is never reached, or is sandboxed. It's how mature security programs reduce alert fatigue without losing audit trail.

The tool accepts inline OpenVEX statements on every scan request:

```json
{
  "repo_path": "./examples/handson-ml-fixture",
  "format": "cyclonedx",
  "env": "development",
  "vex_statements": [
    {
      "cve_id": "CVE-2022-21797",
      "purl": "pkg:pypi/joblib@0.14.1",
      "status": "not_affected",
      "justification": "vulnerable_code_not_in_execute_path"
    }
  ]
}
```

The matching CVE moves from `active_vulns[]` → `suppressed_vulns[]` in the response, with the justification preserved. The state machine visits a `filtering_vex` step that's recorded in `workflow_states_visited[]`. Both CycloneDX and SPDX outputs reflect the suppression, so downstream consumers see *why* a CVE was filtered.

Supported `status` values: `not_affected`, `affected`, `fixed`, `under_investigation`.

---

## Testing

The repository ships with 34 API integration tests. To verify a fresh deployment:

```bash
pytest step11_api/test_api.py
```

All 34 should pass. Tests cover scan happy-path + edge cases, sync, cache staleness, error responses, and contract conformance.

---

## Limitations (POC)

- **NVD cache ships pre-seeded with 8 representative CVEs** for demonstration. For production use, run `sbom-tool sync --source <grype.db>` on a schedule to populate from a [Grype](https://github.com/anchore/grype) feed.
- **Python and JavaScript / TypeScript only.** Go, Java, Rust, Ruby support is planned for Phase 1.5 and is largely an extension of Syft's cataloger coverage plus the upgrade-command synthesizer.
- **Single repository per scan.** Multi-repo / multi-target scanning is not supported in this phase.
- **No license detection.** License extraction from packages is deferred to Phase 1A+.
- **SPDX output omits `vulnerabilities[]`.** SPDX 2.3 expresses vulnerabilities via annotations or external doc references; this is on the Phase 1B roadmap. Use CycloneDX for vulnerability-driven workflows; SPDX for license/inventory workflows.

Stale-cache warnings (cache age > 7 days) are surfaced in the scan response's `warnings[]` field and via `GET /api/v1/health` (returns `degraded`). Stale cache does **not** abort a scan.

---

## Roadmap

| Phase | Scope |
|-------|-------|
| **1A** (this) | CLI + REST API, CycloneDX 1.4 + SPDX 2.3, NVD cache, CVSS classification, OpenVEX filtering, remediation enrichment |
| **1B** | AI BOM via [CycloneDX 1.5 ML-BOM](https://cyclonedx.org/capabilities/mlbom/) and [SPDX 3.0 AI Profile](https://spdx.dev/use/ai-profile/) — model fingerprinting, training-data lineage, agent topology, vector-DB inventory |
| **1C** | CI/CD integration (GitHub Actions / GitLab CI templates), Docker / docker-compose deployment, persistent scan store |
| **2** | Governance — RBAC, versioned central storage, graph-based BOM relationship view, automated update + alerting |

---

## Exit codes (CLI)

| Code | Meaning |
|------|---------|
| `0` | Success — SBOM written to stdout or file |
| `1` | Error — invalid repo path, unsupported language, Syft failure, or write error |

---

## License

See repository LICENSE file. The seeded NVD cache contains CVE records that are themselves public domain (NVD data); this tool's own code is the project's distribution license.
