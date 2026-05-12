# Enhancement: ecosystem_aware_vuln_matching

## Parent Session
- Session ID: SBOM-20260409-sb01
- Created: 2026-05-12T20:19:06Z

## Overview
This enhancement extends the parent session with new capabilities while maintaining backward compatibility.

## Directory Structure
```
outputs/sessions/SBOM-20260409-sb01/enhancements/ecosystem_aware_vuln_matching/
├── README.md                           # This file
├── enhancement_metadata.json           # Enhancement metadata
├── enhancement_context.json            # Context summary
├── import_parent.py                    # Helper for importing parent components
├── load_context.py                     # Dynamic context loader
├── step1_requirements.json             # Enhancement requirements (created in Step 1)
├── step1b_mock_entities.json           # Mock data (created in Step 1b)
├── step2_bdd_scenarios.feature         # BDD scenarios (created in Step 2)
└── ... (other pipeline files)
```

## How to Use

### 1. Import Parent Components
```python
from import_parent import get_parent_component, load_parent_requirements

# Import a specific component
AIContentGenerator = get_parent_component('AIContentGenerator', 'step6_tdd_green_phase_business')

# Load parent requirements
parent_req = load_parent_requirements()
```

### 2. Load Context Dynamically
```python
from load_context import EnhancementContext

context = EnhancementContext('.')
parent_components = context.get_parent_components()
parent_use_case = context.get_parent_use_case()
```

### 3. Run Enhancement Pipeline
```bash
# Step 1: Define requirements
@step1-agent-requirements --session SBOM-20260409-sb01 --enhancement "ecosystem_aware_vuln_matching"

# Continue through Steps 2-9...
```

## Integration Points
- Business Logic: 
- Orchestration: ScanWorkflowState NVDSyncWorkflowState ScanResult SyncResult WorkflowStateMachine NVDWorkflowStateMachine ScanOrchestrator NVDSyncOrchestrator CLIOrchestrator

## Notes
- All enhancement code should import from parent session
- Tests should validate integration with parent components
- Multiple integration strategies will be provided in Step 10
