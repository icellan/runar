import pytest
from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).parent.parent))
from conftest import load_contract

contract_mod = load_contract(str(Path(__file__).parent / "BitwiseOps.runar.py"))
BitwiseOps = contract_mod.BitwiseOps


def test_test_shift_runs():
    c = BitwiseOps(a=12, b=10)
    c.test_shift()


def test_test_bitwise_runs():
    c = BitwiseOps(a=12, b=10)
    c.test_bitwise()


def test_test_bitwise_zeros():
    c = BitwiseOps(a=0, b=0)
    c.test_bitwise()


def test_compile():
    from runar import compile_check
    source_path = str(Path(__file__).parent / "BitwiseOps.runar.py")
    with open(source_path) as f:
        source = f.read()
    compile_check(source, "BitwiseOps.runar.py")
