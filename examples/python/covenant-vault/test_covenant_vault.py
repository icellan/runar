"""Adversarial tests for CovenantVault — covers wrong output count, swapped
output order, and value-at-boundary attacks against the covenant rule.

The contract enforces:
    hash256(num2bin(min_amount, 8) || 1976a914 || recipient || 88ac)
        == extract_output_hash(tx_preimage)

The Python mock `extract_output_hash` returns the first 32 bytes of its
argument (`packages/runar-py/runar/builtins.py:555`). We drive adversarial
cases by setting `tx_preimage` to `hash256(adversarial_outputs)` and assert
that the contract raises AssertionError.
"""

from pathlib import Path
import hashlib
import sys

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))
from conftest import load_contract

contract_mod = load_contract(str(Path(__file__).parent / "CovenantVault.runar.py"))
CovenantVault = contract_mod.CovenantVault

from runar import ALICE, BOB, compile_check, num2bin


MIN_AMOUNT = 5000


def _hash256(b: bytes) -> bytes:
    return hashlib.sha256(hashlib.sha256(b).digest()).digest()


def _p2pkh_output(amount: int, pkh: bytes) -> bytes:
    """Canonical 34-byte P2PKH output: 8-byte LE amount || 1976a914 || pkh || 88ac."""
    assert len(pkh) == 20, "pkh must be 20 bytes"
    amt = num2bin(amount, 8)
    return amt + bytes.fromhex("1976a914") + pkh + bytes.fromhex("88ac")


def _preimage_for(outputs: bytes) -> bytes:
    """Build a 181-byte preimage whose first 32 bytes are hash256(outputs).
    The mock `extract_output_hash` returns exactly those 32 bytes."""
    p = bytearray(181)
    p[:32] = _hash256(outputs)
    return bytes(p)


def _new_vault() -> CovenantVault:
    return CovenantVault(
        owner=ALICE.pub_key,
        recipient=BOB.pub_key_hash,
        min_amount=MIN_AMOUNT,
    )


def test_compile():
    source_path = Path(__file__).parent / "CovenantVault.runar.py"
    with open(source_path) as f:
        source = f.read()
    compile_check(source, "CovenantVault.runar.py")


def test_happy_path():
    c = _new_vault()
    outputs = _p2pkh_output(MIN_AMOUNT, BOB.pub_key_hash)
    c.spend(ALICE.test_sig, _preimage_for(outputs))


# -- Adversarial: wrong output count -----------------------------------------

def test_rejects_zero_outputs():
    c = _new_vault()
    with pytest.raises(AssertionError):
        # hashOutputs commits to no outputs at all (n-1).
        c.spend(ALICE.test_sig, _preimage_for(b""))


def test_rejects_extra_output():
    c = _new_vault()
    required = _p2pkh_output(MIN_AMOUNT, BOB.pub_key_hash)
    extra = _p2pkh_output(1000, b"\xcc" * 20)
    with pytest.raises(AssertionError):
        c.spend(ALICE.test_sig, _preimage_for(required + extra))


# -- Adversarial: swapped output order ---------------------------------------

def test_rejects_reordered_outputs():
    c = _new_vault()
    required = _p2pkh_output(MIN_AMOUNT, BOB.pub_key_hash)
    other = _p2pkh_output(MIN_AMOUNT, b"\xcc" * 20)
    # Unauthorised output placed *before* the required one.
    with pytest.raises(AssertionError):
        c.spend(ALICE.test_sig, _preimage_for(other + required))


# -- Adversarial: value at boundary ------------------------------------------

def test_rejects_amount_minus_one():
    c = _new_vault()
    candidate = _p2pkh_output(MIN_AMOUNT - 1, BOB.pub_key_hash)
    with pytest.raises(AssertionError):
        c.spend(ALICE.test_sig, _preimage_for(candidate))


def test_rejects_amount_plus_one():
    c = _new_vault()
    candidate = _p2pkh_output(MIN_AMOUNT + 1, BOB.pub_key_hash)
    with pytest.raises(AssertionError):
        c.spend(ALICE.test_sig, _preimage_for(candidate))
