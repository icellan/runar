"""Unit tests for the Python PriceBet contract.

Business-logic tests only -- no on-chain deployment. Uses the same
pre-computed Rabin signatures as `examples/python/oracle-price/` so we
don't reimplement Rabin keygen here.
"""

import pytest
from pathlib import Path

from conftest import load_contract
from runar import ALICE, BOB, compile_check


contract_mod = load_contract(str(Path(__file__).parent / "PriceBet.runar.py"))
PriceBet = contract_mod.PriceBet


# Same 130-bit demo Rabin key as used by OraclePriceFeed tests (TypeScript
# `rabin.ts` and integration/python/rabin). Modulus n = p * q.
_RABIN_N_BYTES = bytes.fromhex(
    "950b36f00000000000000000000000002863620200000000000000000000000010"
)

# Pre-computed Rabin signature for price = 60000 (num2bin(60000, 8)).
_RABIN_SIG_60000 = bytes.fromhex(
    "35f75f63384cae3c1f874e64d0d4692ea1cb595df52fe14930745c43e16f6eb001"
)
_RABIN_PAD_60000 = bytes.fromhex(
    "040000000000000000000000000000000000000000000000000000000000000000"
)


def _bet(strike_price: int) -> "PriceBet":
    return PriceBet(
        alice_pub_key=ALICE.pub_key,
        bob_pub_key=BOB.pub_key,
        oracle_pub_key=_RABIN_N_BYTES,
        strike_price=strike_price,
    )


def test_settle_above_strike_pays_alice():
    """price > strike → alice wins, alice_sig is checked, bob_sig ignored."""
    bet = _bet(strike_price=50_000)
    bet.settle(60_000, _RABIN_SIG_60000, _RABIN_PAD_60000, ALICE.test_sig, b"\x00" * 72)


def test_settle_at_or_below_strike_pays_bob():
    """price <= strike → bob wins, bob_sig is checked."""
    bet = _bet(strike_price=70_000)
    bet.settle(60_000, _RABIN_SIG_60000, _RABIN_PAD_60000, b"\x00" * 72, BOB.test_sig)


def test_settle_rejects_unsigned_price():
    """Price attested by the oracle signature does not match the argument price."""
    bet = _bet(strike_price=50_000)
    with pytest.raises(AssertionError):
        bet.settle(99_999, _RABIN_SIG_60000, _RABIN_PAD_60000, ALICE.test_sig, b"\x00" * 72)


def test_settle_rejects_non_positive_price():
    bet = _bet(strike_price=50_000)
    with pytest.raises(AssertionError):
        bet.settle(0, _RABIN_SIG_60000, _RABIN_PAD_60000, ALICE.test_sig, b"\x00" * 72)


def test_cancel_requires_both_parties():
    bet = _bet(strike_price=50_000)
    bet.cancel(ALICE.test_sig, BOB.test_sig)


def test_compile():
    compile_check(
        str(Path(__file__).parent / "PriceBet.runar.py"),
        "PriceBet.runar.py",
    )
