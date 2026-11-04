"""Backward-compatibility facade for src/evaluation/security_chaos_testing.py."""
import sys
import runpy
from pathlib import Path

_SRC = Path(__file__).resolve().parent
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))

from evaluation.security_chaos_testing import *

if __name__ == "__main__":
    _target = _SRC / "evaluation" / "security_chaos_testing.py"
    runpy.run_path(str(_target), run_name="__main__")
