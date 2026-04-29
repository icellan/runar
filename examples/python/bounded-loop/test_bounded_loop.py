import pytest
from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).parent.parent))
from conftest import load_contract

contract_mod = load_contract(str(Path(__file__).parent / "BoundedLoop.runar.py"))
BoundedLoop = contract_mod.BoundedLoop


# Loop computes: sum_{i=0..4} (start + i) = 5*start + (0+1+2+3+4) = 5*start + 10
def expected_sum(start: int) -> int:
    return 5 * start + 10


def test_verify_zero_start():
    c = BoundedLoop(expected_sum=expected_sum(0))
    c.verify(0)


def test_verify_positive_start():
    c = BoundedLoop(expected_sum=expected_sum(7))
    c.verify(7)


def test_verify_wrong_expected_fails():
    c = BoundedLoop(expected_sum=expected_sum(7) + 1)
    with pytest.raises(AssertionError):
        c.verify(7)


def test_compile():
    from runar import compile_check
    source_path = str(Path(__file__).parent / "BoundedLoop.runar.py")
    with open(source_path) as f:
        source = f.read()
    compile_check(source, "BoundedLoop.runar.py")
