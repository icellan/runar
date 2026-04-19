"""Test fixtures: load the contract .runar.py file as a Python module."""

import importlib.util
import sys
from pathlib import Path


def load_contract(file_path: str):
    path = Path(file_path).resolve()
    module_name = path.stem.replace(".", "_")
    spec = importlib.util.spec_from_file_location(module_name, str(path))
    if spec is None or spec.loader is None:
        raise RuntimeError(f"failed to build importlib spec for {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    spec.loader.exec_module(module)
    return module
