import pytest
from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).parent.parent))
from conftest import load_contract

contract_mod = load_contract(str(Path(__file__).parent / "ShiftOps.runar.py"))
ShiftOps = contract_mod.ShiftOps


def test_test_shift_runs():
    # Body asserts (x >= 0 or x < 0) which is always true.
    c = ShiftOps(a=64)
    c.test_shift()


def test_test_shift_zero():
    c = ShiftOps(a=0)
    c.test_shift()


def test_compile():
    from runar import compile_check
    source_path = str(Path(__file__).parent / "ShiftOps.runar.py")
    with open(source_path) as f:
        source = f.read()
    compile_check(source, "ShiftOps.runar.py")
