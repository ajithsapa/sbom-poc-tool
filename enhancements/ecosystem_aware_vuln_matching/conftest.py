"""
conftest.py for the ecosystem_aware_vuln_matching enhancement.

The enhancement's Step 8 / Step 7 test files load the parent session by
file-path (importlib) AND prepend the parent session directory onto
``sys.path`` so the parent step9 module can resolve its own
``import step6_tdd_green_phase`` statement. A side-effect of that path
manipulation is that ``import step9_tdd_green_phase_orchestration``
resolves to the PARENT file rather than the enhancement file, because the
parent directory ends up at sys.path[0].

This conftest neutralises that ordering by re-inserting the enhancement
directory at the very front of ``sys.path`` BEFORE pytest imports any
test module. It is otherwise empty — no fixtures, no hooks, no plugins.
"""

from __future__ import annotations

import pathlib
import sys

_ENHANCEMENT_DIR = pathlib.Path(__file__).parent.resolve()
_PARENT_SESSION_DIR = _ENHANCEMENT_DIR.parent.parent

# Always keep the enhancement directory ahead of the parent directory on
# sys.path so that ``import step9_tdd_green_phase_orchestration`` (and
# ``import step6_tdd_green_phase_business``) resolve to the enhancement
# files rather than their parent-session namesakes.
_enh_str = str(_ENHANCEMENT_DIR)
_parent_str = str(_PARENT_SESSION_DIR)

# Remove any stale references so we don't grow sys.path on re-collection.
sys.path = [p for p in sys.path if p not in (_enh_str, _parent_str)]
# Parent goes in first so it's resolvable; enhancement goes on top so it
# wins lookups for shared module names.
sys.path.insert(0, _parent_str)
sys.path.insert(0, _enh_str)
