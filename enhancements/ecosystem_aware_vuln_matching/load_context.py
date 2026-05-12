"""
Context loader for enhancement pipeline
Dynamically loads context from parent session and enhancement requirements
"""
import json
import os
from typing import Dict, List, Any

class EnhancementContext:
    def __init__(self, enhancement_dir: str):
        self.enhancement_dir = enhancement_dir
        self.parent_dir = os.path.dirname(os.path.dirname(enhancement_dir))
        self.context = self._load_all_context()
    
    def _load_all_context(self) -> Dict[str, Any]:
        """Load all available context"""
        context = {
            'enhancement': self._load_enhancement_metadata(),
            'parent': self._load_parent_context(),
            'requirements': None,  # Will be populated after Step 1
            'integration_points': self._identify_integration_points()
        }
        
        # Load enhancement requirements if they exist (after Step 1)
        req_file = os.path.join(self.enhancement_dir, 'step1_requirements.json')
        if os.path.exists(req_file):
            with open(req_file, 'r') as f:
                context['requirements'] = json.load(f)
        
        return context
    
    def _load_enhancement_metadata(self) -> Dict:
        """Load enhancement metadata"""
        meta_file = os.path.join(self.enhancement_dir, 'enhancement_metadata.json')
        if os.path.exists(meta_file):
            with open(meta_file, 'r') as f:
                return json.load(f)
        return {}
    
    def _load_parent_context(self) -> Dict:
        """Load parent session context"""
        parent_context = {}
        
        # Load parent requirements
        parent_req = os.path.join(self.parent_dir, 'step1_requirements.json')
        if os.path.exists(parent_req):
            with open(parent_req, 'r') as f:
                parent_context['requirements'] = json.load(f)
        
        # Identify available parent files
        parent_context['available_files'] = []
        for file in os.listdir(self.parent_dir):
            if file.endswith(('.py', '.json', '.feature')):
                parent_context['available_files'].append(file)
        
        return parent_context
    
    def _identify_integration_points(self) -> List[Dict]:
        """Identify specific integration points from parent code"""
        integration_points = []
        
        # Check business logic
        business_file = os.path.join(self.parent_dir, 'step6_tdd_green_phase_business.py')
        if os.path.exists(business_file):
            integration_points.append({
                'file': 'step6_tdd_green_phase_business.py',
                'type': 'business_logic',
                'integration_strategy': 'extension_or_composition'
            })
        
        # Check orchestration
        orch_file = os.path.join(self.parent_dir, 'step9_tdd_green_phase_orchestration.py')
        if os.path.exists(orch_file):
            integration_points.append({
                'file': 'step9_tdd_green_phase_orchestration.py',
                'type': 'orchestration',
                'integration_strategy': 'wrapper_or_mixin'
            })
        
        return integration_points
    
    def get_parent_components(self) -> Dict[str, List[str]]:
        """Get list of parent components"""
        return self.context.get('enhancement', {}).get('parent_components', {})
    
    def get_integration_targets(self) -> List[str]:
        """Get files that need integration"""
        return self.context.get('enhancement', {}).get('integration_targets', [])
    
    def get_parent_use_case(self) -> str:
        """Get parent use case name"""
        parent_req = self.context.get('parent', {}).get('requirements', {})
        return parent_req.get('agent_specification', {}).get('name', 'Unknown')
    
    def get_enhancement_requirements(self) -> Dict:
        """Get enhancement requirements (after Step 1)"""
        return self.context.get('requirements', {})
    
    def save_context_summary(self):
        """Save a summary of the current context"""
        summary_file = os.path.join(self.enhancement_dir, 'context_summary.json')
        with open(summary_file, 'w') as f:
            json.dump(self.context, f, indent=2)
        return summary_file

# Usage example
if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1:
        context = EnhancementContext(sys.argv[1])
        print(json.dumps(context.context, indent=2))
