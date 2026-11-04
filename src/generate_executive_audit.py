"""Backward-compatibility facade for src/reporting/generate_executive_audit.py."""
import sys
import runpy
from pathlib import Path

_SRC = Path(__file__).resolve().parent
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))

from reporting.generate_executive_audit import *

if __name__ == "__main__":
    _target = _SRC / "reporting" / "generate_executive_audit.py"
    runpy.run_path(str(_target), run_name="__main__")
