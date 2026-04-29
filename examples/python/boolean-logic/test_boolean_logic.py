import pytest
from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).parent.parent))
from conftest import load_contract

contract_mod = load_contract(str(Path(__file__).parent / "BooleanLogic.runar.py"))
BooleanLogic = contract_mod.BooleanLogic


def test_verify_both_above():
    # both above threshold => succeeds regardless of flag
    c = BooleanLogic(threshold=10)
    c.verify(20, 30, True)


def test_verify_either_above_with_not_flag():
    # only one above, flag False -> not_flag True -> either_above && not_flag
    c = BooleanLogic(threshold=10)
    c.verify(20, 1, False)


def test_verify_neither_above_fails():
    c = BooleanLogic(threshold=10)
    with pytest.raises(AssertionError):
        c.verify(1, 2, False)


def test_verify_either_above_with_flag_true_fails():
    # one above but flag True -> not_flag False -> branch fails, both_above also False
    c = BooleanLogic(threshold=10)
    with pytest.raises(AssertionError):
        c.verify(20, 1, True)


def test_compile():
    from runar import compile_check
    source_path = str(Path(__file__).parent / "BooleanLogic.runar.py")
    with open(source_path) as f:
        source = f.read()
    compile_check(source, "BooleanLogic.runar.py")
