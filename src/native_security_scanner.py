"""Backward-compatibility facade for src/scanners/native_security_scanner.py."""
import sys
import runpy
from pathlib import Path

_SRC = Path(__file__).resolve().parent
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))

from scanners.native_security_scanner import *

if __name__ == "__main__":
    _target = _SRC / "scanners" / "native_security_scanner.py"
    runpy.run_path(str(_target), run_name="__main__")
