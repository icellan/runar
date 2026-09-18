import pytest
from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).parent.parent))
from conftest import load_contract

contract_mod = load_contract(str(Path(__file__).parent / "FungibleTokenExample.runar.py"))
FungibleToken = contract_mod.FungibleToken

from runar import ALICE, BOB, hash256


def compact_size(value: int) -> bytes:
    if value < 0xfd:
        return value.to_bytes(1, 'little')
    if value <= 0xffff:
        return b'\xfd' + value.to_bytes(2, 'little')
    if value <= 0xffffffff:
        return b'\xfe' + value.to_bytes(4, 'little')
    return b'\xff' + value.to_bytes(8, 'little')


def merge_fixture(output_count: bytes = compact_size(253)):
    body = b'\x51' * 204 + ALICE.pub_key + (7).to_bytes(8, 'little') + (5).to_bytes(8, 'little')
    script = b'\x61\xab' + body
    parent = (
        (2).to_bytes(4, 'little') + b'\x01' + b'\x00' * 36 + b'\x00' + b'\xff' * 4
        + output_count
        + (1).to_bytes(8, 'little') + compact_size(len(script)) + script
        + (b'\x00' * 9) * 252 + b'\x00' * 4
    )
    mine = b'a' * 36
    all_prevouts = mine + hash256(parent) + b'\x00' * 4
    script_code = compact_size(len(body)) + body
    preimage = (
        (2).to_bytes(4, 'little') + hash256(all_prevouts) + b'\x00' * 32 + mine
        + script_code + b'\x00' * 8 + b'\xff' * 4 + b'\x00' * 32
        + b'\x00' * 4 + (0x41).to_bytes(4, 'little')
    )
    return parent, all_prevouts, preimage


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
    all_prevouts = b'\x00' * 72
    parent = b'\x00' * 64
    with pytest.raises(AssertionError):
        c.merge(ALICE.test_sig, 150, all_prevouts, parent, 546)


def test_merge_accepts_companion_parent_with_fd_output_count():
    c = FungibleToken(owner=ALICE.pub_key, balance=50, merge_balance=0, token_id=b'\xab' * 16)
    parent, all_prevouts, c.tx_preimage = merge_fixture()
    c.merge(ALICE.test_sig, 12, all_prevouts, parent, 546)
    assert len(c._outputs) == 1
    assert c._outputs[0]["values"] == [ALICE.pub_key, 50, 12]


def test_merge_rejects_noncanonical_fd_output_count():
    c = FungibleToken(owner=ALICE.pub_key, balance=50, merge_balance=0, token_id=b'\xab' * 16)
    parent, all_prevouts, c.tx_preimage = merge_fixture(b'\xfd\xfc\x00')
    with pytest.raises(AssertionError):
        c.merge(ALICE.test_sig, 12, all_prevouts, parent, 546)


def test_merge_negative_other_balance_fails():
    c = FungibleToken(owner=ALICE.pub_key, balance=100, merge_balance=0, token_id=b'\xab' * 16)
    all_prevouts = b'\x00' * 72
    with pytest.raises(AssertionError):
        c.merge(ALICE.test_sig, -1, all_prevouts, b'\x00' * 64, 546)


def test_merge_tampered_prevouts_fails():
    c = FungibleToken(owner=ALICE.pub_key, balance=30, merge_balance=0, token_id=b'\xab' * 16)
    tampered_prevouts = b'\xff' * 72
    with pytest.raises(AssertionError):
        c.merge(ALICE.test_sig, 70, tampered_prevouts, b'\x00' * 64, 546)


def test_merge_with_pre_existing_merge_balance():
    c = FungibleToken(owner=ALICE.pub_key, balance=20, merge_balance=10, token_id=b'\xab' * 16)
    all_prevouts = b'\x00' * 72
    with pytest.raises(AssertionError):
        c.merge(ALICE.test_sig, 50, all_prevouts, b'\x00' * 64, 546)


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
