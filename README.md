# SBOM POC Tool

A CLI-based Software Bill of Materials engine that scans a Python or JavaScript/TypeScript codebase, produces machine-readable SBOM output in CycloneDX or SPDX format, and maps dependencies against a local NVD vulnerability cache.

## Prerequisites

- Python 3.11+
- [Syft](https://github.com/anchore/syft) — dependency scanner

```bash
# Install Syft (macOS / Linux)
curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh -s -- -b ~/.local/bin

# Install Python dependencies
pip install typer
```

## Setup

```bash
cd outputs/sessions/SBOM-20260409-sb01

# Seed the local NVD vulnerability cache (run once)
python create_nvd_cache_db.py
```

This creates `step1b_nvd_cache.db` with 8 pre-seeded CVEs covering langchain, joblib, numpy, scipy, tensorflow, Pillow, requests, and lxml.

---

## Commands

### `scan` — Scan a repository

```
python cli.py scan --repo <path> [OPTIONS]
```

| Option | Default | Description |
|--------|---------|-------------|
| `--repo` | required | Path to repository to scan |
| `--format` | `cyclonedx` | Output format: `cyclonedx` or `spdx` |
| `--env` | `development` | Runtime environment: `development`, `staging`, `production` |
| `--output` | stdout | Write SBOM JSON to a file instead of stdout |
| `--db` | `step1b_nvd_cache.db` | Path to NVD cache SQLite DB |

### `sync` — Sync NVD vulnerability cache

```
python cli.py sync --source <path>
```

| Option | Default | Description |
|--------|---------|-------------|
| `--source` | required | Path to Grype DB file to sync from |

---

## Examples

### Scan a repo and print CycloneDX JSON to stdout

```bash
python cli.py scan --repo /path/to/my-project
```

### Scan and write SPDX output to a file

```bash
python cli.py scan --repo /path/to/my-project --format spdx --output sbom.json
```

### Scan with a custom NVD cache DB

```bash
python cli.py scan --repo /path/to/my-project --db /data/nvd_cache.db
```

### Real output — TaskMatrix (LLM/agent project)

```bash
python cli.py scan --repo /path/to/TaskMatrix
```

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

### Real output — handson-ml (classic ML project)

```bash
python cli.py scan --repo /path/to/handson-ml
```

Produces 19 components and 4 vulnerabilities:

| CVE | Package | CVSS | Severity |
|-----|---------|------|----------|
| CVE-2022-21797 | joblib@0.14.1 | 9.8 | HIGH |
| CVE-2022-29216 | tensorflow@1.15.5 | 8.8 | HIGH |
| CVE-2021-33430 | numpy@1.22.0 | 5.5 | MEDIUM |
| CVE-2023-25399 | scipy@1.6.0 | 5.5 | MEDIUM |

---

## Environment Variables

| Variable | Description |
|----------|-------------|
| `SBOM_NVD_DB` | Override the default NVD cache DB path (equivalent to `--db`) |

```bash
export SBOM_NVD_DB=/data/nvd_cache.db
python cli.py scan --repo /path/to/repo
```

---

## Exit Codes

| Code | Meaning |
|------|---------|
| `0` | Success — SBOM written to stdout or file |
| `1` | Error — invalid repo path, unsupported language, Syft failure, or write error |

Stale cache warnings are written to **stderr** and do not affect the exit code.

---

## REST API

A FastAPI server is available alongside the CLI:

```bash
pip install -r step11_api/requirements.txt
uvicorn step11_api.main:app --reload
```

Interactive docs at `http://localhost:8000/docs`.

Endpoints mirror the CLI:
- `POST /api/v1/scans` — run a scan
- `POST /api/v1/sync` — sync NVD cache
- `GET /api/v1/cache/status` — check cache staleness
- `GET /api/v1/health` — liveness probe

---

## Limitations (POC)

- **NVD cache is seeded** with 8 CVEs for demonstration. In production, populate it by running `sbom-tool sync` with a Grype DB after installing [Grype](https://github.com/anchore/grype).
- **Python and JavaScript/TypeScript only.** Go, Java, and Rust support is planned for Phase 1.5.
- **Single repository per scan.** Multi-repo scanning is not supported in this phase.
- **No license detection.** License analysis is deferred to post-POC.
