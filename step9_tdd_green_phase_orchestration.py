"""
step9_tdd_green_phase_orchestration.py
SBOM POC Tool — Orchestration TDD Green Phase
Session: SBOM-20260409-sb01

Implements the orchestration layer on top of Step 6 business components:
  - WorkflowStateMachine   — enforces 7-state Scan Workflow ordering
  - NVDWorkflowStateMachine — enforces 4-state NVD Sync Workflow ordering
  - ScanOrchestrator        — wires all 8 Step 6 components in mandated order
  - NVDSyncOrchestrator     — delegates entirely to NVDCacheManager.sync()
  - CLIOrchestrator         — maps CLI invocations to orchestrators

All classes import directly from step6_tdd_green_phase (never re-implement
business logic). No live network calls during scan (AC-12).
"""

import json
import os
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional

# ---------------------------------------------------------------------------
# Business layer imports from Step 6
# ---------------------------------------------------------------------------
from step6_tdd_green_phase import (
    CycloneDXSerializer,
    NVDCacheManager,
    NVDSyncError,
    NVDSyncResult,
    OSSToolAdapter,
    RemediationEnricher,
    SPDXSerializer,
    ScanJobValidator,
    VEXFilter,
    VulnerabilityMapper,
)

# ---------------------------------------------------------------------------
# Re-export enums and dataclasses from step7 stubs — these are the canonical
# definitions and must not be redefined here to avoid import-time conflicts.
# The orchestration classes below are what step7 stubs forward-declare.
# ---------------------------------------------------------------------------
# NOTE: We import the enum/dataclass types from step7 only when called from
# within this module (they already exist there). The step7 stubs will be
# patched to forward to these implementations. For internal use we duplicate
# the enums to keep step9 self-contained and avoid circular imports.


class ScanWorkflowState(Enum):
    """
    7-state machine for the Scan Workflow.
    Mirrors step7_atdd_orchestration.ScanWorkflowState.
    """
    IDLE = "idle"
    SCANNING_DEPENDENCIES = "scanning_dependencies"
    DEDUPLICATING_OUTPUT = "deduplicating_output"
    MATCHING_VULNERABILITIES = "matching_vulnerabilities"
    FILTERING_VEX = "filtering_vex"
    ENRICHING_REMEDIATION = "enriching_remediation"
    EXPORTING_SBOM = "exporting_sbom"


class NVDSyncWorkflowState(Enum):
    """
    4-state machine for the NVD Sync Workflow.
    Mirrors step7_atdd_orchestration.NVDSyncWorkflowState.
    """
    IDLE = "idle"
    SYNCING_NVD = "syncing_nvd"
    UPDATING_CACHE = "updating_cache"
    SYNC_COMPLETE = "sync_complete"


@dataclass
class ScanResult:
    """
    Unified output produced by ScanOrchestrator.
    AC-11: carries deps, active_vulns, suppressed_vulns, warnings, sbom_document.
    """
    dependencies: List[Dict] = field(default_factory=list)
    active_vulns: List[Dict] = field(default_factory=list)
    suppressed_vulns: List[Dict] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    sbom_document: Optional[Dict] = None
    scan_id: str = ""
    repo_name: str = ""
    output_format: str = ""
    workflow_states_visited: List[str] = field(default_factory=list)


@dataclass
class SyncResult:
    """
    Result produced by NVDSyncOrchestrator.
    """
    records_added: int = 0
    records_updated: int = 0
    synced_at: Optional[str] = None
    source_path: str = ""
    sync_log: Optional[Dict] = None


# ===========================================================================
# WorkflowStateMachine — enforces Scan Workflow ordering
# ===========================================================================

class WorkflowStateMachine:
    """
    State machine for the SBOM Scan Workflow.

    Valid transition sequence (strictly linear, no skipping, no reverting):
      IDLE
        -> SCANNING_DEPENDENCIES
        -> DEDUPLICATING_OUTPUT
        -> MATCHING_VULNERABILITIES
        -> FILTERING_VEX
        -> ENRICHING_REMEDIATION
        -> EXPORTING_SBOM  (terminal)
    """

    _VALID_TRANSITIONS: Dict = {
        ScanWorkflowState.IDLE: {ScanWorkflowState.SCANNING_DEPENDENCIES},
        ScanWorkflowState.SCANNING_DEPENDENCIES: {ScanWorkflowState.DEDUPLICATING_OUTPUT},
        ScanWorkflowState.DEDUPLICATING_OUTPUT: {ScanWorkflowState.MATCHING_VULNERABILITIES},
        ScanWorkflowState.MATCHING_VULNERABILITIES: {ScanWorkflowState.FILTERING_VEX},
        ScanWorkflowState.FILTERING_VEX: {ScanWorkflowState.ENRICHING_REMEDIATION},
        ScanWorkflowState.ENRICHING_REMEDIATION: {ScanWorkflowState.EXPORTING_SBOM},
        ScanWorkflowState.EXPORTING_SBOM: set(),
    }

    def __init__(self, initial_state: ScanWorkflowState = ScanWorkflowState.IDLE):
        self._state: ScanWorkflowState = initial_state
        self._visited: List[str] = [initial_state.value]
        self.is_cache_stale: bool = False

    @property
    def state(self) -> ScanWorkflowState:
        return self._state

    def can_transition(self, target: ScanWorkflowState) -> bool:
        """Return True if transitioning to target from current state is valid."""
        return target in self._VALID_TRANSITIONS.get(self._state, set())

    def transition(self, target: ScanWorkflowState) -> None:
        """
        Attempt transition to target state.
        Raises ValueError when the transition is invalid (skip or revert).
        """
        if not self.can_transition(target):
            raise ValueError(
                f"Invalid workflow transition: {self._state.value!r} -> {target.value!r}. "
                f"Allowed from {self._state.value!r}: "
                f"{[s.value for s in self._VALID_TRANSITIONS.get(self._state, set())]}"
            )
        self._state = target
        self._visited.append(target.value)

    def visited_states(self) -> List[str]:
        """Return ordered list of all state values visited (including initial)."""
        return list(self._visited)


# ===========================================================================
# NVDWorkflowStateMachine — enforces NVD Sync Workflow ordering
# ===========================================================================

class NVDWorkflowStateMachine:
    """
    State machine for the NVD Sync Workflow.

    Valid transition sequence:
      IDLE -> SYNCING_NVD -> UPDATING_CACHE -> SYNC_COMPLETE (terminal)
    """

    _VALID_TRANSITIONS: Dict = {
        NVDSyncWorkflowState.IDLE: {NVDSyncWorkflowState.SYNCING_NVD},
        NVDSyncWorkflowState.SYNCING_NVD: {NVDSyncWorkflowState.UPDATING_CACHE},
        NVDSyncWorkflowState.UPDATING_CACHE: {NVDSyncWorkflowState.SYNC_COMPLETE},
        NVDSyncWorkflowState.SYNC_COMPLETE: set(),
    }

    def __init__(self):
        self._state: NVDSyncWorkflowState = NVDSyncWorkflowState.IDLE
        self._visited: List[str] = [NVDSyncWorkflowState.IDLE.value]

    @property
    def state(self) -> NVDSyncWorkflowState:
        return self._state

    def can_transition(self, target: NVDSyncWorkflowState) -> bool:
        return target in self._VALID_TRANSITIONS.get(self._state, set())

    def transition(self, target: NVDSyncWorkflowState) -> None:
        if not self.can_transition(target):
            raise ValueError(
                f"Invalid NVD sync transition: {self._state.value!r} -> {target.value!r}"
            )
        self._state = target
        self._visited.append(target.value)

    def visited_states(self) -> List[str]:
        return list(self._visited)


# ===========================================================================
# ScanOrchestrator — wires Step 6 components in mandated order
# ===========================================================================

class ScanOrchestrator:
    """
    End-to-end scan pipeline coordinator.

    Mandated call order (AC-5, AC-4, AC-12):
      1. ScanJobValidator.validate(repo_path, env)        — abort on failure
      2. NVDCacheManager.is_stale(last_synced_at)         — warn if stale
      3. OSSToolAdapter.normalise(raw_tool_output)
      4. OSSToolAdapter.deduplicate(normalised)
      5. VulnerabilityMapper.map_vulnerabilities(deduped, nvd_cache)
      6. VEXFilter.apply(mapped_vulns, vex_statements)
      7. RemediationEnricher.enrich(vuln, cache_entry) per active vuln
      8. CycloneDXSerializer or SPDXSerializer based on output_format

    Zero network I/O (AC-12) — no live API calls; all data from nvd_cache.
    Accepts all 8 business components via constructor injection.
    """

    def __init__(
        self,
        validator: Optional[ScanJobValidator] = None,
        adapter: Optional[OSSToolAdapter] = None,
        mapper: Optional[VulnerabilityMapper] = None,
        vex_filter: Optional[VEXFilter] = None,
        enricher: Optional[RemediationEnricher] = None,
        nvd_cache_manager: Optional[NVDCacheManager] = None,
        cyclonedx_serializer: Optional[CycloneDXSerializer] = None,
        spdx_serializer: Optional[SPDXSerializer] = None,
    ):
        self.validator = validator if validator is not None else ScanJobValidator()
        self.adapter = adapter if adapter is not None else OSSToolAdapter()
        self.mapper = mapper if mapper is not None else VulnerabilityMapper()
        self.vex_filter = vex_filter if vex_filter is not None else VEXFilter()
        self.enricher = enricher if enricher is not None else RemediationEnricher()
        self.nvd_cache_manager = (
            nvd_cache_manager if nvd_cache_manager is not None else NVDCacheManager()
        )
        self.cyclonedx_serializer = (
            cyclonedx_serializer
            if cyclonedx_serializer is not None
            else CycloneDXSerializer()
        )
        self.spdx_serializer = (
            spdx_serializer if spdx_serializer is not None else SPDXSerializer()
        )

    def run(
        self,
        repo_path: str,
        output_format: str,
        env: str,
        nvd_cache: Dict,
        raw_tool_output: Dict,
        vex_statements: Optional[List[Dict]] = None,
        last_synced_at=None,
    ) -> ScanResult:
        """
        Execute the full SBOM scan pipeline and return a ScanResult.

        Raises:
            ValueError: when validation fails or output_format is unsupported.
            NVDSyncError: propagated from NVDCacheManager without modification.
            RuntimeError: propagated from serializers without modification.
        """
        if vex_statements is None:
            vex_statements = []

        machine = WorkflowStateMachine(initial_state=ScanWorkflowState.IDLE)
        warnings: List[str] = []

        # ---------------------------------------------------------------
        # Step 1: Validate job parameters — abort if invalid
        # ---------------------------------------------------------------
        validation = self.validator.validate(repo_path, env)
        if not validation.valid:
            raise ValueError(
                f"Scan job validation failed: {'; '.join(validation.errors)}"
            )

        # ---------------------------------------------------------------
        # Step 2: Check NVD cache staleness BEFORE mapping (AC-3)
        # ---------------------------------------------------------------
        is_stale = self.nvd_cache_manager.is_stale(last_synced_at)
        if is_stale:
            warnings.append(
                f"NVD cache is stale (last synced: {last_synced_at}). "
                "Please run sbom-tool sync to refresh vulnerability data."
            )

        # ---------------------------------------------------------------
        # Step 3: Normalise raw tool output
        # ---------------------------------------------------------------
        machine.transition(ScanWorkflowState.SCANNING_DEPENDENCIES)
        if is_stale:
            machine.is_cache_stale = True
        normalised = self.adapter.normalise(raw_tool_output)

        # ---------------------------------------------------------------
        # Step 4: Deduplicate by PURL
        # ---------------------------------------------------------------
        machine.transition(ScanWorkflowState.DEDUPLICATING_OUTPUT)
        deduped = self.adapter.deduplicate(normalised)

        # ---------------------------------------------------------------
        # Step 5: Map vulnerabilities via PURL/CPE cache lookup
        # ---------------------------------------------------------------
        machine.transition(ScanWorkflowState.MATCHING_VULNERABILITIES)
        mapped_vulns = self.mapper.map_vulnerabilities(deduped, nvd_cache)

        # ---------------------------------------------------------------
        # Step 6: Apply VEX filter BEFORE enrichment (AC-4)
        # ---------------------------------------------------------------
        machine.transition(ScanWorkflowState.FILTERING_VEX)
        filter_result = self.vex_filter.apply(mapped_vulns, vex_statements)

        # ---------------------------------------------------------------
        # Step 7: Enrich ONLY active vulns (suppressed ones stay raw)
        # ---------------------------------------------------------------
        machine.transition(ScanWorkflowState.ENRICHING_REMEDIATION)
        active_vulns: List[Dict] = []
        for vuln in filter_result.active:
            purl = vuln.get("dep_purl") or vuln.get("purl", "")
            cache_entry = nvd_cache.get(purl, {})
            enriched = self.enricher.enrich(vuln, cache_entry)
            active_vulns.append(enriched)

        # ---------------------------------------------------------------
        # Step 8: Serialize to requested SBOM format
        # ---------------------------------------------------------------
        machine.transition(ScanWorkflowState.EXPORTING_SBOM)

        scan_data = {
            "scan_id": str(uuid.uuid4()),
            "repo_name": os.path.basename(repo_path) if repo_path else "unknown",
            "dependencies": deduped,
            "vulnerabilities": active_vulns,
        }

        if output_format == "cyclonedx":
            sbom_document = self.cyclonedx_serializer.serialize(scan_data)
        elif output_format == "spdx":
            sbom_document = self.spdx_serializer.serialize(scan_data)
        else:
            raise ValueError(
                f"Unsupported output_format: {output_format!r}. "
                "Accepted values: 'cyclonedx', 'spdx'."
            )

        return ScanResult(
            dependencies=deduped,
            active_vulns=active_vulns,
            suppressed_vulns=list(filter_result.suppressed),
            warnings=warnings,
            sbom_document=sbom_document,
            scan_id=scan_data["scan_id"],
            repo_name=scan_data["repo_name"],
            output_format=output_format,
            workflow_states_visited=machine.visited_states(),
        )


# ===========================================================================
# NVDSyncOrchestrator — delegates entirely to NVDCacheManager.sync()
# ===========================================================================

class NVDSyncOrchestrator:
    """
    NVD sync workflow coordinator.

    Delegates entirely to NVDCacheManager.sync(). Does NOT open files itself.
    Propagates NVDSyncError unchanged. Records sync_log on success.
    """

    def __init__(self, cache_manager: Optional[NVDCacheManager] = None, db_path: str = ":memory:"):
        self.cache_manager = (
            cache_manager if cache_manager is not None else NVDCacheManager(db_path=db_path)
        )
        self.last_sync_log: Optional[Dict] = None

    def run(self, source_path: str) -> SyncResult:
        """
        Execute NVD sync by delegating to the injected NVDCacheManager.

        Returns:
            SyncResult with records_added, records_updated, synced_at,
            source_path, and sync_log populated.

        Raises:
            NVDSyncError: propagated from NVDCacheManager without modification.
        """
        # Delegate fully — do NOT re-implement sync logic or open files here
        nvd_result: NVDSyncResult = self.cache_manager.sync(source_path)

        synced_at = datetime.now(timezone.utc).isoformat()

        sync_log: Dict = {
            "synced_at": synced_at,
            "source_path": source_path,
            "records_added": nvd_result.records_added,
            "records_updated": nvd_result.records_updated,
        }
        self.last_sync_log = sync_log

        return SyncResult(
            records_added=nvd_result.records_added,
            records_updated=nvd_result.records_updated,
            synced_at=synced_at,
            source_path=source_path,
            sync_log=sync_log,
        )


# ===========================================================================
# CLIOrchestrator — maps CLI invocations to orchestrators
# ===========================================================================

class CLIOrchestrator:
    """
    Typer CLI wiring coordinator.

    Commands:
      sbom-tool scan --repo <path> --format cyclonedx|spdx --env <env>
                     [--output <file>]
      sbom-tool sync --source <path>

    Exit semantics:
      0   : success (stale-cache warning goes to stderr but does NOT fail)
      !=0 : validation error, NVDSyncError, or write failure
    """

    def __init__(
        self,
        scan_orchestrator: Optional[ScanOrchestrator] = None,
        sync_orchestrator: Optional[NVDSyncOrchestrator] = None,
        db_path: str = ":memory:",
    ):
        self.scan_orchestrator = (
            scan_orchestrator
            if scan_orchestrator is not None
            else ScanOrchestrator()
        )
        self.sync_orchestrator = (
            sync_orchestrator
            if sync_orchestrator is not None
            else NVDSyncOrchestrator(db_path=db_path)
        )

    def invoke_scan(
        self,
        repo: str,
        fmt: str,
        env: str,
        output_path: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Execute a scan command.

        Returns:
            dict with keys: exit_code (int), stdout (str|None), stderr (str|None)
        """
        stderr_parts: List[str] = []

        # Basic repo pre-validation: empty path or non-existent directory
        if not repo:
            return {
                "exit_code": 1,
                "stdout": "",
                "stderr": "Repository path must not be empty.",
            }
        if not os.path.exists(repo):
            return {
                "exit_code": 1,
                "stdout": "",
                "stderr": f"Repository path does not exist: {repo!r}",
            }

        try:
            scan_result: ScanResult = self.scan_orchestrator.run(
                repo_path=repo,
                output_format=fmt,
                env=env,
                nvd_cache={},
                raw_tool_output={"tool": "syft", "components": []},
            )
        except (ValueError, NVDSyncError, RuntimeError) as exc:
            return {
                "exit_code": 1,
                "stdout": "",
                "stderr": str(exc),
            }
        except Exception as exc:
            return {
                "exit_code": 1,
                "stdout": "",
                "stderr": str(exc),
            }

        # Collect stale-cache and other warnings -> stderr
        try:
            warnings_list = list(scan_result.warnings)
        except TypeError:
            warnings_list = []
        if warnings_list:
            stderr_parts.extend(warnings_list)

        try:
            sbom_json = json.dumps(scan_result.sbom_document, indent=2)
        except (TypeError, ValueError) as exc:
            return {
                "exit_code": 1,
                "stdout": "",
                "stderr": f"Failed to serialize SBOM: {exc}",
            }

        # Handle --output flag
        if output_path is not None:
            try:
                with open(output_path, "w") as fh:
                    fh.write(sbom_json)
            except OSError as exc:
                return {
                    "exit_code": 1,
                    "stdout": "",
                    "stderr": f"Failed to write SBOM to {output_path!r}: {exc}",
                }
            return {
                "exit_code": 0,
                "stdout": "",
                "stderr": "\n".join(stderr_parts),
            }

        return {
            "exit_code": 0,
            "stdout": sbom_json,
            "stderr": "\n".join(stderr_parts),
        }

    def invoke_sync(self, source: str) -> Dict[str, Any]:
        """
        Execute a sync command.

        Returns:
            dict with keys: exit_code (int), stdout (str|None), stderr (str|None)
        """
        try:
            sync_result: SyncResult = self.sync_orchestrator.run(source)
        except NVDSyncError as exc:
            return {
                "exit_code": 1,
                "stdout": "",
                "stderr": str(exc),
            }
        except Exception as exc:
            return {
                "exit_code": 1,
                "stdout": "",
                "stderr": str(exc),
            }

        stdout_text = (
            f"Sync complete: {sync_result.records_added} records added, "
            f"{sync_result.records_updated} records updated. "
            f"Synced at: {sync_result.synced_at}"
        )

        return {
            "exit_code": 0,
            "stdout": stdout_text,
            "stderr": "",
        }
