import pytest
from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).parent.parent))
from conftest import load_contract

contract_mod = load_contract(str(Path(__file__).parent / "ShiftOps.runar.py"))
ShiftOps = contract_mod.ShiftOps

# The caller supplies the expected shift results and the contract checks them
# (F-167: it used to assert only tautologies, so no input could fail). With
# a = 12 native Python agrees with the on-chain OP_LSHIFT / OP_RSHIFT; the
# on-chain verdict is pinned by conformance/witnesses/real-crypto/shift-ops.json.


def test_test_shift_runs():
    c = ShiftOps(a=12)
    c.test_shift(96, 3)


def test_test_shift_wrong_result_rejected():
    c = ShiftOps(a=12)
    with pytest.raises(AssertionError):
        c.test_shift(97, 3)
    with pytest.raises(AssertionError):
        c.test_shift(96, 2)


def test_test_shift_zero():
    c = ShiftOps(a=0)
    c.test_shift(0, 0)


def test_compile():
    from runar import compile_check
    source_path = str(Path(__file__).parent / "ShiftOps.runar.py")
    with open(source_path) as f:
        source = f.read()
    compile_check(source, "ShiftOps.runar.py")
