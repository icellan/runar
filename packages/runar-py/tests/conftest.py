"""Ensure `runar_compiler` is importable for tests that exercise `compile_check`."""

import os
import sys


_REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", ".."))
_COMPILER_PATH = os.path.join(_REPO_ROOT, "compilers", "python")

if _COMPILER_PATH not in sys.path:
    sys.path.insert(0, _COMPILER_PATH)
