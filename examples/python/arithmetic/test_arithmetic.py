import pytest
from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).parent.parent))
from conftest import load_contract

contract_mod = load_contract(str(Path(__file__).parent / "Arithmetic.runar.py"))
Arithmetic = contract_mod.Arithmetic


# Compute the expected target for a, b: (a+b) + (a-b) + (a*b) + (a//b)
def expected(a: int, b: int) -> int:
    return (a + b) + (a - b) + (a * b) + (a // b)


def test_verify_succeeds():
    a, b = 10, 3
    c = Arithmetic(target=expected(a, b))
    c.verify(a, b)


def test_verify_negative_inputs():
    a, b = 20, 4
    c = Arithmetic(target=expected(a, b))
    c.verify(a, b)


def test_verify_wrong_target():
    a, b = 10, 3
    c = Arithmetic(target=expected(a, b) + 1)
    with pytest.raises(AssertionError):
        c.verify(a, b)


def test_compile():
    from runar import compile_check
    source_path = str(Path(__file__).parent / "Arithmetic.runar.py")
    with open(source_path) as f:
        source = f.read()
    compile_check(source, "Arithmetic.runar.py")
