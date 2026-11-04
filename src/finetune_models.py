"""Backward-compatibility facade for src/models/finetune_models.py."""
import sys
import runpy
from pathlib import Path

_SRC = Path(__file__).resolve().parent
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))

from models.finetune_models import *

if __name__ == "__main__":
    _target = _SRC / "models" / "finetune_models.py"
    runpy.run_path(str(_target), run_name="__main__")
