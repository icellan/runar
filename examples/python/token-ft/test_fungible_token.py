import pytest
from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).parent.parent))
from conftest import load_contract

contract_mod = load_contract(str(Path(__file__).parent / "FungibleTokenExample.runar.py"))
FungibleToken = contract_mod.FungibleToken

from runar import ALICE, BOB


def test_transfer():
    c = FungibleToken(owner=ALICE.pub_key, balance=1000, merge_balance=0, token_id=b'\xab' * 16)
    c.transfer(ALICE.test_sig, BOB.pub_key, 300, 546)
    assert len(c._outputs) == 2


def test_transfer_exceeds_balance_fails():
    c = FungibleToken(owner=ALICE.pub_key, balance=100, merge_balance=0, token_id=b'\xab' * 16)
    with pytest.raises(AssertionError):
        c.transfer(ALICE.test_sig, BOB.pub_key, 200, 546)


def test_send():
    c = FungibleToken(owner=ALICE.pub_key, balance=1000, merge_balance=0, token_id=b'\xab' * 16)
    c.send(ALICE.test_sig, BOB.pub_key, 546)
    assert len(c._outputs) == 1


def test_merge():
    c = FungibleToken(owner=ALICE.pub_key, balance=50, merge_balance=0, token_id=b'\xab' * 16)
    # allPrevouts = 72 zero bytes (two 36-byte zero outpoints),
    # consistent with mock extract_hash_prevouts and extract_outpoint.
    all_prevouts = b'\x00' * 72
    c.merge(ALICE.test_sig, 150, all_prevouts, 546)
    assert len(c._outputs) == 1


def test_merge_negative_other_balance_fails():
    c = FungibleToken(owner=ALICE.pub_key, balance=100, merge_balance=0, token_id=b'\xab' * 16)
    all_prevouts = b'\x00' * 72
    with pytest.raises(AssertionError):
        c.merge(ALICE.test_sig, -1, all_prevouts, 546)


def test_merge_tampered_prevouts_fails():
    c = FungibleToken(owner=ALICE.pub_key, balance=30, merge_balance=0, token_id=b'\xab' * 16)
    tampered_prevouts = b'\xff' * 72
    with pytest.raises(AssertionError):
        c.merge(ALICE.test_sig, 70, tampered_prevouts, 546)


def test_merge_with_pre_existing_merge_balance():
    c = FungibleToken(owner=ALICE.pub_key, balance=20, merge_balance=10, token_id=b'\xab' * 16)
    all_prevouts = b'\x00' * 72
    c.merge(ALICE.test_sig, 50, all_prevouts, 546)
    assert len(c._outputs) == 1


def test_transfer_exact_balance():
    c = FungibleToken(owner=ALICE.pub_key, balance=100, merge_balance=0, token_id=b'\xab' * 16)
    c.transfer(ALICE.test_sig, BOB.pub_key, 100, 546)
    assert len(c._outputs) == 1


def test_transfer_uses_merge_balance():
    c = FungibleToken(owner=ALICE.pub_key, balance=60, merge_balance=40, token_id=b'\xab' * 16)
    c.transfer(ALICE.test_sig, BOB.pub_key, 80, 546)
    assert len(c._outputs) == 2


def test_send_uses_merge_balance():
    c = FungibleToken(owner=ALICE.pub_key, balance=60, merge_balance=40, token_id=b'\xab' * 16)
    c.send(ALICE.test_sig, BOB.pub_key, 546)
    assert len(c._outputs) == 1


def test_transfer_zero_amount_fails():
    c = FungibleToken(owner=ALICE.pub_key, balance=1000, merge_balance=0, token_id=b'\xab' * 16)
    with pytest.raises(AssertionError):
        c.transfer(ALICE.test_sig, BOB.pub_key, 0, 546)


def test_compile():
    from pathlib import Path
    from runar import compile_check
    source_path = str(Path(__file__).parent / "FungibleTokenExample.runar.py")
    with open(source_path) as f:
        source = f.read()
    compile_check(source, "FungibleTokenExample.runar.py")
