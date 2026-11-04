"""Backward-compatibility facade for src/models/xai_threat_attribution.py."""
import sys
import runpy
from pathlib import Path

_SRC = Path(__file__).resolve().parent
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))

from models.xai_threat_attribution import *

if __name__ == "__main__":
    _target = _SRC / "models" / "xai_threat_attribution.py"
    runpy.run_path(str(_target), run_name="__main__")
