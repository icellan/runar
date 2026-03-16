import pytest
from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).parent.parent))
from conftest import load_contract

contract_mod = load_contract(str(Path(__file__).parent / "FunctionPatterns.runar.py"))
FunctionPatterns = contract_mod.FunctionPatterns

from runar import ALICE


def test_deposit():
    c = FunctionPatterns(owner=ALICE.pub_key, balance=1000)
    c.deposit(ALICE.test_sig, 500)
    assert c.balance == 1500


def test_withdraw():
    c = FunctionPatterns(owner=ALICE.pub_key, balance=10000)
    # 100 bps = 1% fee on 1000 = 10
    c.withdraw(ALICE.test_sig, 1000, 100)
    assert c.balance == 8990


def test_scale():
    c = FunctionPatterns(owner=ALICE.pub_key, balance=100)
    c.scale(ALICE.test_sig, 3, 2)
    assert c.balance == 150


def test_normalize():
    c = FunctionPatterns(owner=ALICE.pub_key, balance=157)
    c.normalize(ALICE.test_sig, 0, 200, 10)
    assert c.balance == 150


# ---------------------------------------------------------------------------
# Deposit tests
# ---------------------------------------------------------------------------

def test_deposit_multiple():
    c = FunctionPatterns(owner=ALICE.pub_key, balance=10000)
    c.deposit(ALICE.test_sig, 100)
    c.deposit(ALICE.test_sig, 200)
    c.deposit(ALICE.test_sig, 300)
    assert c.balance == 10600


def test_deposit_rejects_zero():
    c = FunctionPatterns(owner=ALICE.pub_key, balance=10000)
    with pytest.raises(AssertionError):
        c.deposit(ALICE.test_sig, 0)


def test_deposit_rejects_negative():
    c = FunctionPatterns(owner=ALICE.pub_key, balance=10000)
    with pytest.raises(AssertionError):
        c.deposit(ALICE.test_sig, -100)


# ---------------------------------------------------------------------------
# Withdraw tests
# ---------------------------------------------------------------------------

def test_withdraw_no_fee():
    c = FunctionPatterns(owner=ALICE.pub_key, balance=10000)
    c.withdraw(ALICE.test_sig, 3000, 0)  # 0 bps = no fee
    assert c.balance == 7000


def test_withdraw_with_fee():
    c = FunctionPatterns(owner=ALICE.pub_key, balance=10000)
    # 1000 with 500 bps (5%) fee = 50, total = 1050
    c.withdraw(ALICE.test_sig, 1000, 500)
    assert c.balance == 8950


def test_withdraw_full_balance():
    c = FunctionPatterns(owner=ALICE.pub_key, balance=10000)
    c.withdraw(ALICE.test_sig, 10000, 0)
    assert c.balance == 0


def test_withdraw_insufficient_balance():
    c = FunctionPatterns(owner=ALICE.pub_key, balance=10000)
    with pytest.raises(AssertionError):
        c.withdraw(ALICE.test_sig, 20000, 0)


def test_withdraw_fee_exceeds_balance():
    c = FunctionPatterns(owner=ALICE.pub_key, balance=10000)
    # 10000 balance, withdraw 10000 with 100 bps fee = 100 -> total 10100 > 10000
    with pytest.raises(AssertionError):
        c.withdraw(ALICE.test_sig, 10000, 100)


# ---------------------------------------------------------------------------
# Scale tests
# ---------------------------------------------------------------------------

def test_scale_double():
    c = FunctionPatterns(owner=ALICE.pub_key, balance=10000)
    c.scale(ALICE.test_sig, 2, 1)
    assert c.balance == 20000


def test_scale_half():
    c = FunctionPatterns(owner=ALICE.pub_key, balance=10000)
    c.scale(ALICE.test_sig, 1, 2)
    assert c.balance == 5000


def test_scale_three_quarters():
    c = FunctionPatterns(owner=ALICE.pub_key, balance=10000)
    c.scale(ALICE.test_sig, 3, 4)
    assert c.balance == 7500


# ---------------------------------------------------------------------------
# Normalize tests
# ---------------------------------------------------------------------------

def test_normalize_clamps_and_rounds():
    c = FunctionPatterns(owner=ALICE.pub_key, balance=10000)
    # clamp to [0, 8000], round down to step=1000 -> 8000
    c.normalize(ALICE.test_sig, 0, 8000, 1000)
    assert c.balance == 8000


def test_normalize_rounds_down():
    c = FunctionPatterns(owner=ALICE.pub_key, balance=7777)
    # clamp to [0, 10000] (no effect), round down to step=1000 -> 7000
    c.normalize(ALICE.test_sig, 0, 10000, 1000)
    assert c.balance == 7000


def test_normalize_clamps_up():
    c = FunctionPatterns(owner=ALICE.pub_key, balance=50)
    # clamp to [1000, 10000] -> 1000, round down to step=500 -> 1000
    c.normalize(ALICE.test_sig, 1000, 10000, 500)
    assert c.balance == 1000


# ---------------------------------------------------------------------------
# Private helper unit tests
# ---------------------------------------------------------------------------

def test_is_positive():
    c = FunctionPatterns(owner=ALICE.pub_key, balance=0)
    # The private methods are accessible directly in unit tests
    assert c._compute_fee(1000, 500) == 50   # 5% of 1000
    assert c._compute_fee(1000, 0) == 0


def test_scale_value():
    c = FunctionPatterns(owner=ALICE.pub_key, balance=0)
    assert c._scale_value(1000, 3, 4) == 750
    assert c._scale_value(100, 1, 3) == 33


def test_clamp_value():
    c = FunctionPatterns(owner=ALICE.pub_key, balance=0)
    assert c._clamp_value(5, 10, 100) == 10
    assert c._clamp_value(200, 10, 100) == 100
    assert c._clamp_value(50, 10, 100) == 50


def test_round_down():
    c = FunctionPatterns(owner=ALICE.pub_key, balance=0)
    assert c._round_down(7777, 1000) == 7000
    assert c._round_down(5000, 1000) == 5000
    assert c._round_down(999, 500) == 500


# ---------------------------------------------------------------------------
# Composition tests
# ---------------------------------------------------------------------------

def test_deposit_then_withdraw_with_fee():
    c = FunctionPatterns(owner=ALICE.pub_key, balance=10000)
    c.deposit(ALICE.test_sig, 5000)   # 15000
    c.withdraw(ALICE.test_sig, 5000, 200)  # 2% fee = 100, total = 5100 -> 9900
    assert c.balance == 9900


def test_scale_then_normalize():
    c = FunctionPatterns(owner=ALICE.pub_key, balance=10000)
    c.scale(ALICE.test_sig, 3, 4)              # 10000 * 3/4 = 7500
    c.normalize(ALICE.test_sig, 0, 10000, 1000)  # clamp (no effect), round -> 7000
    assert c.balance == 7000


# ---------------------------------------------------------------------------
# Compile check
# ---------------------------------------------------------------------------

def test_compile():
    from pathlib import Path
    from runar import compile_check
    source_path = str(Path(__file__).parent / "FunctionPatterns.runar.py")
    with open(source_path) as f:
        source = f.read()
    compile_check(source, "FunctionPatterns.runar.py")
