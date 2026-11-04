"""Backward-compatibility facade for src/data/collect_cluster_features.py."""
import sys
import runpy
from pathlib import Path

_SRC = Path(__file__).resolve().parent
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))

from data.collect_cluster_features import *

if __name__ == "__main__":
    _target = _SRC / "data" / "collect_cluster_features.py"
    runpy.run_path(str(_target), run_name="__main__")
