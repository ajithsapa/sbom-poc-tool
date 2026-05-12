"""
Import helper for accessing parent session components
"""
import sys
import os
import json

def setup_parent_imports():
    """Setup sys.path to import from parent session"""
    current_dir = os.path.dirname(os.path.abspath(__file__))
    parent_session_dir = os.path.dirname(os.path.dirname(current_dir))
    
    # Add parent session to path
    if parent_session_dir not in sys.path:
        sys.path.insert(0, parent_session_dir)
    
    return parent_session_dir

def get_parent_component(component_name, module_name):
    """Import a specific component from parent session"""
    setup_parent_imports()
    module = __import__(module_name, fromlist=[component_name])
    return getattr(module, component_name)

def load_parent_requirements():
    """Load parent session requirements"""
    parent_dir = setup_parent_imports()
    req_file = os.path.join(parent_dir, 'step1_requirements.json')
    if os.path.exists(req_file):
        with open(req_file, 'r') as f:
            return json.load(f)
    return None

def load_parent_mock_data():
    """Load parent session mock data"""
    parent_dir = setup_parent_imports()
    mock_files = {
        'entities': os.path.join(parent_dir, 'step1b_mock_entities.json'),
        'scenarios': os.path.join(parent_dir, 'step1b_mock_scenarios.json')
    }
    
    mock_data = {}
    for key, filepath in mock_files.items():
        if os.path.exists(filepath):
            with open(filepath, 'r') as f:
                mock_data[key] = json.load(f)
    
    return mock_data

def get_parent_bdd_scenarios():
    """Load parent BDD scenarios"""
    parent_dir = setup_parent_imports()
    bdd_file = os.path.join(parent_dir, 'step2_bdd_scenarios.feature')
    if os.path.exists(bdd_file):
        with open(bdd_file, 'r') as f:
            return f.read()
    return None

# Setup imports on module load
PARENT_DIR = setup_parent_imports()
