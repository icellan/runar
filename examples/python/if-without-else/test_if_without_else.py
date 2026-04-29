import pytest
from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).parent.parent))
from conftest import load_contract

contract_mod = load_contract(str(Path(__file__).parent / "IfWithoutElse.runar.py"))
IfWithoutElse = contract_mod.IfWithoutElse


def test_check_both_above():
    c = IfWithoutElse(threshold=5)
    c.check(10, 20)


def test_check_one_above():
    c = IfWithoutElse(threshold=5)
    c.check(10, 1)


def test_check_neither_above_fails():
    c = IfWithoutElse(threshold=5)
    with pytest.raises(AssertionError):
        c.check(1, 2)


def test_compile():
    from runar import compile_check
    source_path = str(Path(__file__).parent / "IfWithoutElse.runar.py")
    with open(source_path) as f:
        source = f.read()
    compile_check(source, "IfWithoutElse.runar.py")
