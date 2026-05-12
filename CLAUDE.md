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

### Hardening: host allowlist + size cap (one branch with the URL feature)

- **Host allowlist**: `repo_url` must point at `github.com` (or
  `www.github.com`). Anything else returns `422 REPO_HOST_NOT_ALLOWED`.
  Defined as `_ALLOWED_HOSTS` in `git_cloner.py` — add hosts there.
- **Size cap**: a successful clone over `SBOM_MAX_CLONE_BYTES`
  (default 50 MB) is deleted and the request fails with
  `422 REPO_TOO_LARGE`. The 120s clone timeout is the first line of
  defense; the size cap catches large repos that finish under the
  timeout (e.g. monorepos with committed datasets).

## Auth: static API key

When `API_KEY` is set in the environment, every endpoint except
`/api/v1/health` requires an `X-API-Key` header matching that value.
401 with `INVALID_API_KEY` otherwise. When `API_KEY` is unset/empty,
auth is bypassed and a startup warning is logged — **POC dev mode only**.

Implementation: a single `Security(APIKeyHeader(...))` dependency in
`step11_api/dependencies.py` (`require_api_key`) wired via
`include_router(..., dependencies=[Depends(require_api_key)])` in
`main.py`. FastAPI auto-registers the security scheme so Swagger UI
shows an "Authorize" button and a lock icon on guarded routes.

To rotate the key: change `API_KEY` in the deployment env and restart.
