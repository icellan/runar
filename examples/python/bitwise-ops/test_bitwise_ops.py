import pytest
from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).parent.parent))
from conftest import load_contract

contract_mod = load_contract(str(Path(__file__).parent / "BitwiseOps.runar.py"))
BitwiseOps = contract_mod.BitwiseOps

# The caller supplies the expected results and the contract checks them
# (F-167: it used to assert only tautologies, so no input could fail). a = 12,
# b = 10 are 1-byte operands whose results stay below 0x80, so native Python
# agrees with the on-chain byte-array opcodes; the on-chain verdict for the
# same values is pinned by conformance/witnesses/real-crypto/bitwise-ops.json.


def test_test_shift_runs():
    c = BitwiseOps(a=12, b=10)
    c.test_shift(48, 6)


def test_test_shift_wrong_result_rejected():
    c = BitwiseOps(a=12, b=10)
    with pytest.raises(AssertionError):
        c.test_shift(49, 6)
    with pytest.raises(AssertionError):
        c.test_shift(48, 7)


def test_test_bitwise_runs():
    c = BitwiseOps(a=12, b=10)
    c.test_bitwise(8, 14, 6)


def test_test_bitwise_wrong_result_rejected():
    c = BitwiseOps(a=12, b=10)
    with pytest.raises(AssertionError):
        c.test_bitwise(14, 8, 6)
    with pytest.raises(AssertionError):
        c.test_bitwise(8, 14, 7)


def test_test_bitwise_zeros():
    c = BitwiseOps(a=0, b=0)
    c.test_bitwise(0, 0, 0)


def test_compile():
    from runar import compile_check
    source_path = str(Path(__file__).parent / "BitwiseOps.runar.py")
    with open(source_path) as f:
        source = f.read()
    compile_check(source, "BitwiseOps.runar.py")
