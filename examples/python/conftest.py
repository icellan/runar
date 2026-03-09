"""Import helper for .runar.py contract files."""

import importlib.util
import sys
from pathlib import Path


def load_contract(file_path: str):
    """Import a .runar.py file as a Python module."""
    path = Path(file_path).resolve()
    module_name = path.stem.replace('.', '_')
    spec = importlib.util.spec_from_file_location(module_name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    spec.loader.exec_module(module)
    return module
