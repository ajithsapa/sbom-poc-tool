"""
routers/scans.py — Scan endpoints for the SBOM POC Tool API.

Endpoints:
  POST /api/v1/scans          — run a full SBOM scan pipeline (ScanOrchestrator)
  GET  /api/v1/scans/{scan_id} — retrieve a stored scan result by UUID

Import chain:
  - Request/response models from step7_5_pydantic_models (via sys.path)
  - Orchestration via injected ScanOrchestrator (from step9)
  - Business logic invoked transparently through the orchestrator

Session: SBOM-20260409-sb01
Generated: Step 11 — FastAPI API Generation
"""

from __future__ import annotations

import logging
import os
import sys
from typing import Any, Dict

from fastapi import APIRouter, Depends, HTTPException, Path
from fastapi.responses import JSONResponse

# Ensure session root is importable (dependencies.py also does this, but
# routers are imported before dependencies in some code paths).
_SESSION_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "../.."))
if _SESSION_ROOT not in sys.path:
    sys.path.insert(0, _SESSION_ROOT)

from git_cloner import (  # noqa: E402
    CloneManager,
    ForeignManifestError,
    GitCloneError,
    HostNotAllowedError,
    RepoTooLargeError,
    UnsupportedLanguageError,
    detect_manifests,
)
from oss_tool_runner import OSSToolRunner, OSSToolRunnerError  # noqa: E402
from step6_tdd_green_phase import NVDSyncError  # noqa: E402
from step7_5_pydantic_models import (  # noqa: E402
    DependencyRecord,
    DependencyType,
    EnrichedVulnerability,
    ErrorResponse,
    SbomFormat,
    ScanRequest,
    ScanResponse,
    Severity,
    VulnerabilityRecord,
)
from step9_tdd_green_phase_orchestration import ScanOrchestrator, ScanResult  # noqa: E402

_oss_runner = OSSToolRunner()

from ..dependencies import (  # noqa: E402
    get_clone_manager,
    get_nvd_cache_dict,
    get_nvd_cache_manager,
    get_scan_orchestrator,
    get_scan_store,
)

logger = logging.getLogger(__name__)

router = APIRouter()


# ---------------------------------------------------------------------------
# Conversion helpers — raw dicts from ScanResult → Pydantic response models
# ---------------------------------------------------------------------------

def _dep_dict_to_model(dep: Dict[str, Any]) -> DependencyRecord:
    """
    Convert an OSSToolAdapter output dict to a DependencyRecord Pydantic model.

    OSSToolAdapter produces: {name, exact_version, purl, supplier}.
    DependencyRecord requires: name, version, purl, dependency_type.
    """
    raw_dep_type = dep.get("dependency_type", "direct")
    try:
        dep_type = DependencyType(raw_dep_type)
    except ValueError:
        dep_type = DependencyType.direct

    return DependencyRecord(
        name=dep.get("name", ""),
        version=dep.get("version") or dep.get("exact_version", ""),
        purl=dep.get("purl", ""),
        cpe=dep.get("cpe") or None,
        supplier=dep.get("supplier") or None,
        dependency_type=dep_type,
        transitive_via=dep.get("transitive_via") or None,
    )


def _enriched_dict_to_model(vuln: Dict[str, Any]) -> EnrichedVulnerability:
    """
    Convert a RemediationEnricher output dict to an EnrichedVulnerability model.

    Enriched keys: cve_id, purl, dep_purl, cvss_score, severity, dep_name,
                   advisory_url, fixed_version, upgrade_command.
    """
    raw_severity = vuln.get("severity", "Unknown")
    try:
        severity = Severity(raw_severity)
    except ValueError:
        severity = Severity.Unknown

    cvss_raw = vuln.get("cvss_score")
    cvss_score = float(cvss_raw) if cvss_raw is not None else 0.0

    return EnrichedVulnerability(
        cve_id=vuln.get("cve_id", ""),
        purl=vuln.get("purl") or vuln.get("dep_purl", ""),
        cpe=vuln.get("cpe") or None,
        cvss_score=cvss_score,
        severity=severity,
        affected_version=vuln.get("affected_version") or None,
        fixed_version=vuln.get("fixed_version") or None,
        advisory_url=vuln.get("advisory_url") or None,
        upgrade_command=vuln.get("upgrade_command") or None,
        vex_filtered=bool(vuln.get("vex_filtered", False)),
    )


def _suppressed_dict_to_model(vuln: Dict[str, Any]) -> VulnerabilityRecord:
    """
    Convert a VEXFilter suppressed vulnerability dict to a VulnerabilityRecord.

    Suppressed entries have the same shape as mapped vulns (pre-enrichment).
    """
    raw_severity = vuln.get("severity", "Unknown")
    try:
        severity = Severity(raw_severity)
    except ValueError:
        severity = Severity.Unknown

    cvss_raw = vuln.get("cvss_score")
    cvss_score = float(cvss_raw) if cvss_raw is not None else 0.0

    return VulnerabilityRecord(
        cve_id=vuln.get("cve_id", ""),
        purl=vuln.get("purl") or vuln.get("dep_purl", ""),
        cpe=vuln.get("cpe") or None,
        cvss_score=cvss_score,
        severity=severity,
        affected_version=vuln.get("affected_version") or None,
        fixed_version=vuln.get("fixed_version") or None,
        advisory_url=vuln.get("advisory_url") or None,
    )


def _scan_result_to_response(result: ScanResult) -> ScanResponse:
    """
    Map a ScanResult dataclass (from step9 orchestration) to a ScanResponse
    Pydantic model (from step7_5_pydantic_models).
    """
    raw_format = result.output_format or "cyclonedx"
    try:
        output_format = SbomFormat(raw_format)
    except ValueError:
        output_format = SbomFormat.cyclonedx

    return ScanResponse(
        scan_id=result.scan_id,
        repo_name=result.repo_name,
        output_format=output_format,
        dependencies=[_dep_dict_to_model(d) for d in (result.dependencies or [])],
        active_vulns=[_enriched_dict_to_model(v) for v in (result.active_vulns or [])],
        suppressed_vulns=[_suppressed_dict_to_model(v) for v in (result.suppressed_vulns or [])],
        warnings=list(result.warnings or []),
        sbom_document=result.sbom_document or {},
        workflow_states_visited=list(result.workflow_states_visited or []),
    )


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@router.post(
    "",
    response_model=ScanResponse,
    status_code=200,
    summary="Run an SBOM scan against a repository (POC Reqs 1–6)",
    description=(
        "Scans a single source-code repository and produces a complete SBOM "
        "(Software Bill of Materials) with vulnerability mapping in one call. "
        "Covers all six POC requirements:\n\n"
        "- **Req 1**: CLI/API surface, suitable for CI/CD integration.\n"
        "- **Req 2**: Single runtime environment per scan (`env` field).\n"
        "- **Req 3**: Full dependency inventory — name, exact version, supplier, "
        "direct and transitive relationships.\n"
        "- **Req 4**: Output as machine-readable CycloneDX 1.4 or SPDX 2.3 "
        "(Software Package Data Exchange) JSON, returned in `sbom_document`.\n"
        "- **Req 5**: Vulnerability mapping against the local **NVD** "
        "(National Vulnerability Database, NIST) cache via **PURL** "
        "(Package URL) and **CPE** (Common Platform Enumeration) identifiers.\n"
        "- **Req 6**: **CVSS** (Common Vulnerability Scoring System) "
        "severity classification (High / Medium / Low) with `fixed_version` "
        "and `advisory_url` per **CVE** (Common Vulnerabilities and Exposures) "
        "entry in `active_vulns[]`.\n\n"
        "A stale NVD cache does NOT abort the scan — `warnings[]` flags it "
        "and the SBOM is still produced."
    ),
    responses={
        422: {"model": ErrorResponse, "description": "Validation error (invalid repo_path, format, or env)"},
        500: {"model": ErrorResponse, "description": "Unexpected internal error during scan pipeline"},
    },
)
async def create_scan(
    request: ScanRequest,
    orchestrator: ScanOrchestrator = Depends(get_scan_orchestrator),
    nvd_cache_dict: Dict[str, Any] = Depends(get_nvd_cache_dict),
    scan_store: Dict[str, Any] = Depends(get_scan_store),
    nvd_cache_manager=Depends(get_nvd_cache_manager),
    clone_manager: CloneManager = Depends(get_clone_manager),
) -> ScanResponse:
    """
    Execute the full SBOM scan pipeline and return results.

    The pipeline delegates to ScanOrchestrator (step9) which wires:
      ScanJobValidator -> NVDCacheManager.is_stale() -> OSSToolAdapter ->
      VulnerabilityMapper -> VEXFilter -> RemediationEnricher -> Serializer

    scan_id is stored in the in-memory store for subsequent GET /scans/{scan_id}.
    """
    vex_dicts = [vs.model_dump() for vs in request.vex_statements]

    # Resolve repo_url -> a local clone path. The clone persists across the
    # request lifecycle; remove it via DELETE /api/v1/repos/{name}.
    if request.repo_url:
        try:
            cloned = clone_manager.clone(request.repo_url)
        except HostNotAllowedError as exc:
            return JSONResponse(
                status_code=422,
                content=ErrorResponse(
                    error="REPO_HOST_NOT_ALLOWED",
                    message=str(exc),
                    details={"repo_url": request.repo_url},
                ).model_dump(),
            )
        except RepoTooLargeError as exc:
            return JSONResponse(
                status_code=422,
                content=ErrorResponse(
                    error="REPO_TOO_LARGE",
                    message=str(exc),
                    details={"repo_url": request.repo_url},
                ).model_dump(),
            )
        except ForeignManifestError as exc:
            return JSONResponse(
                status_code=422,
                content=ErrorResponse(
                    error="REPO_FOREIGN_MANIFEST",
                    message=str(exc),
                    details={"repo_url": request.repo_url},
                ).model_dump(),
            )
        except UnsupportedLanguageError as exc:
            return JSONResponse(
                status_code=422,
                content=ErrorResponse(
                    error="REPO_UNSUPPORTED_LANGUAGE",
                    message=str(exc),
                    details={"repo_url": request.repo_url},
                ).model_dump(),
            )
        except GitCloneError as exc:
            msg = str(exc)
            status = 409 if "already exists" in msg else 422
            return JSONResponse(
                status_code=status,
                content=ErrorResponse(
                    error="REPO_CLONE_FAILED" if status == 422 else "REPO_NAME_CONFLICT",
                    message=msg,
                    details={"repo_url": request.repo_url},
                ).model_dump(),
            )
        scan_target_path = cloned.path
        logger.info("Cloned repo from URL: name=%s path=%s", cloned.name, cloned.path)
    else:
        scan_target_path = request.repo_path

    # Validate repository path exists before invoking the OSS scanner, so we
    # return a precise INVALID_REPO_PATH 422 rather than a generic tool error.
    if not os.path.isdir(scan_target_path):
        return JSONResponse(
            status_code=422,
            content=ErrorResponse(
                error="INVALID_REPO_PATH",
                message=f"Repository path does not exist or is not a directory: {scan_target_path}",
                details={"repo_path": scan_target_path},
            ).model_dump(),
        )

    # Language gate. Applied here so that scans via `repo_path` are checked
    # identically to clones via `repo_url` (the clone path already validated
    # inside CloneManager.clone() but a second check is idempotent and keeps
    # the contract uniform for any future clone-bypass code path).
    supported, foreign = detect_manifests(scan_target_path)
    if foreign:
        sample = ", ".join(sorted(set(foreign))[:5])
        more = f" (and {len(set(foreign)) - 5} more)" if len(set(foreign)) > 5 else ""
        return JSONResponse(
            status_code=422,
            content=ErrorResponse(
                error="REPO_FOREIGN_MANIFEST",
                message=(
                    f"Repository contains dependency manifests for ecosystems "
                    f"this tool does not support: {sample}{more}. Only Python "
                    f"and JavaScript / TypeScript repos are scannable in this phase."
                ),
                details={"repo_path": scan_target_path, "foreign_manifests": sorted(set(foreign))},
            ).model_dump(),
        )
    if not supported:
        return JSONResponse(
            status_code=422,
            content=ErrorResponse(
                error="REPO_UNSUPPORTED_LANGUAGE",
                message=(
                    "No Python or JavaScript / TypeScript dependency manifest "
                    "was found in the repository. Looked for: requirements*.txt, "
                    "setup.py, setup.cfg, pyproject.toml, Pipfile, poetry.lock, "
                    "package.json, package-lock.json, yarn.lock, pnpm-lock.yaml."
                ),
                details={"repo_path": scan_target_path},
            ).model_dump(),
        )

    try:
        components = _oss_runner.scan(scan_target_path)
    except OSSToolRunnerError as exc:
        logger.warning("Syft scan failed: %s", exc)
        return JSONResponse(
            status_code=422,
            content=ErrorResponse(
                error="SCAN_TOOL_ERROR",
                message=str(exc),
                details={"repo_path": scan_target_path},
            ).model_dump(),
        )
    raw_tool_output: Dict[str, Any] = {"tool": "syft", "components": components}

    try:
        result: ScanResult = orchestrator.run(
            repo_path=scan_target_path,
            output_format=request.format.value,
            env=request.env.value,
            nvd_cache=nvd_cache_dict,
            raw_tool_output=raw_tool_output,
            vex_statements=vex_dicts,
            last_synced_at=nvd_cache_manager._last_synced_at,
        )
    except ValueError as exc:
        # Validation error from ScanJobValidator (missing/invalid repo_path, env)
        logger.warning("Scan validation failed: %s", exc)
        return JSONResponse(
            status_code=422,
            content=ErrorResponse(
                error="INVALID_REPO_PATH",
                message=str(exc),
                details={"repo_path": scan_target_path},
            ).model_dump(),
        )
    except NVDSyncError as exc:
        logger.error("NVD sync error during scan: %s", exc)
        return JSONResponse(
            status_code=500,
            content=ErrorResponse(
                error="NVD_CACHE_ERROR",
                message=str(exc),
                details=None,
            ).model_dump(),
        )
    except Exception as exc:
        logger.exception("Unexpected error during scan pipeline")
        return JSONResponse(
            status_code=500,
            content=ErrorResponse(
                error="INTERNAL_ERROR",
                message="Scan pipeline failed due to an unexpected error",
                details=None,
            ).model_dump(),
        )

    response = _scan_result_to_response(result)
    # Persist in-memory so GET /scans/{scan_id} can retrieve it
    scan_store[response.scan_id] = response
    logger.info("Scan completed: scan_id=%s repo=%s", response.scan_id, response.repo_name)
    return response


@router.get(
    "/{scan_id}",
    response_model=ScanResponse,
    status_code=200,
    summary="Retrieve a previously completed scan by ID",
    description=(
        "Looks up a scan result by the UUID returned from POST /scans. "
        "Useful for clients that poll for results or need to re-fetch an SBOM "
        "without re-running the scan. For the POC, results are kept in-memory "
        "for the lifetime of the API process; production deployments would "
        "back this with a persistent store."
    ),
    responses={
        404: {"model": ErrorResponse, "description": "No scan result found for the given scan_id"},
        500: {"model": ErrorResponse, "description": "Internal error while retrieving the scan result"},
    },
)
async def get_scan(
    scan_id: str = Path(
        ...,
        description="UUID returned by a prior POST /scans call (copy from the response).",
        examples=["a1b2c3d4-e5f6-7890-abcd-ef1234567890"],
    ),
    scan_store: Dict[str, Any] = Depends(get_scan_store),
) -> ScanResponse:
    """
    Retrieve a scan result from the in-memory store by its UUID.

    Returns HTTP 404 with SCAN_NOT_FOUND if no result exists for scan_id.
    """
    try:
        result = scan_store.get(scan_id)
    except Exception as exc:
        logger.exception("Unexpected error retrieving scan_id=%s", scan_id)
        return JSONResponse(
            status_code=500,
            content=ErrorResponse(
                error="INTERNAL_ERROR",
                message="Internal error while retrieving the scan result",
                details=None,
            ).model_dump(),
        )

    if result is None:
        return JSONResponse(
            status_code=404,
            content=ErrorResponse(
                error="SCAN_NOT_FOUND",
                message=f"No scan result found for ID: {scan_id}",
                details={"scan_id": scan_id},
            ).model_dump(),
        )

    return result
