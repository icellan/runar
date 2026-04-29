import pytest
from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).parent.parent))
from conftest import load_contract

contract_mod = load_contract(str(Path(__file__).parent / "IfElse.runar.py"))
IfElse = contract_mod.IfElse


def test_check_true_branch():
    # mode=True -> result = value + limit; require result > 0
    c = IfElse(limit=5)
    c.check(10, True)


def test_check_false_branch():
    # mode=False -> result = value - limit
    c = IfElse(limit=5)
    c.check(10, False)


def test_check_false_branch_underflows_fails():
    # value < limit, mode=False -> result negative -> assertion fails
    c = IfElse(limit=5)
    with pytest.raises(AssertionError):
        c.check(2, False)


def test_compile():
    from runar import compile_check
    source_path = str(Path(__file__).parent / "IfElse.runar.py")
    with open(source_path) as f:
        source = f.read()
    compile_check(source, "IfElse.runar.py")
