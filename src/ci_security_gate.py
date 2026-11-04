"""Backward-compatibility facade for src/evaluation/ci_security_gate.py."""
import sys
import runpy
from pathlib import Path

_SRC = Path(__file__).resolve().parent
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))

from evaluation.ci_security_gate import *

if __name__ == "__main__":
    _target = _SRC / "evaluation" / "ci_security_gate.py"
    runpy.run_path(str(_target), run_name="__main__")
