# CLAUDE.md — guidance for Claude Code (and other LLMs) in this repo

## Codegen drift: hand-edited "generated" file

`step7_5_pydantic_models.py` is labelled as auto-generated from
`step7_5_api_contract.yaml`, but it has been **hand-extended** with models
that do not exist in the YAML. The Python file is the runtime source of
truth for the FastAPI app in `step11_api/`; the YAML is a stale contract
artifact.

Before running any codegen step that overwrites `step7_5_pydantic_models.py`,
port the manual additions back into `step7_5_api_contract.yaml` first.
Current divergences (as of the git-clone-as-target feature):

- `ScanRequest`: added `repo_url: Optional[str]`, relaxed `repo_path` to
  `Optional[str]`, added a `model_validator` enforcing
  exactly-one-of(`repo_path`, `repo_url`).
- New models: `ClonedRepoRecord`, `ClonedRepoListResponse` — used by
  `GET /api/v1/repos`.

These back the feature implemented in `git_cloner.py` and
`step11_api/routers/repos.py`. Regenerating naively will delete the
git-URL scan path and the `/api/v1/repos` endpoints.

## Feature: scan-by-git-URL

`POST /api/v1/scans` accepts either `repo_path` (existing local-dir flow)
or `repo_url` (new — public git URL, https/http/git only, no embedded
creds). When `repo_url` is set, the handler shallow-clones into the
workspace (default `<session_root>/clones`, override via
`SBOM_CLONES_DIR`), then runs the existing Syft → mapper → VEX → enricher
→ serializer pipeline against the clone.

Clones persist after the scan and are managed via:

- `GET /api/v1/repos` — list workspace inventory
- `DELETE /api/v1/repos/{name}` — wipe a clone

CLI equivalents: `sbom-tool scan --repo-url <url>`,
`sbom-tool repos list`, `sbom-tool repos delete <name>`.

Public repos only — `GIT_TERMINAL_PROMPT=0` and `GIT_ASKPASS=echo` are
set in the clone subprocess so anything requiring auth fails fast rather
than hanging the request.
