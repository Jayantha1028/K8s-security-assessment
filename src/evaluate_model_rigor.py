"""Backward-compatibility facade for src/evaluation/evaluate_model_rigor.py."""
import sys
import runpy
from pathlib import Path

_SRC = Path(__file__).resolve().parent
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))

from evaluation.evaluate_model_rigor import *

if __name__ == "__main__":
    _target = _SRC / "evaluation" / "evaluate_model_rigor.py"
    runpy.run_path(str(_target), run_name="__main__")
