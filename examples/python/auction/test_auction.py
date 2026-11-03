import pytest
from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).parent.parent))
from conftest import load_contract

contract_mod = load_contract(str(Path(__file__).parent / "Auction.runar.py"))
Auction = contract_mod.Auction

from runar import ALICE, BOB, CHARLIE, DAVE, set_mock_continuation_amount


def bid_paying(c, sig, bidder, amount):
    """Bid with the continuation carrying the prior pot (extract_amount is
    10000 off-chain) plus the bid (N-027)."""
    prev = set_mock_continuation_amount(10000 + amount)
    try:
        c.bid(sig, bidder, amount)
    finally:
        set_mock_continuation_amount(prev)


def test_bid_higher():
    c = Auction(
        auctioneer=ALICE.pub_key,
        highest_bidder=BOB.pub_key,
        highest_bid=100,
        deadline=1000,
    )
    bid_paying(c, CHARLIE.test_sig, CHARLIE.pub_key, 200)
    assert c.highest_bidder == CHARLIE.pub_key
    assert c.highest_bid == 200


def test_bid_lower_fails():
    c = Auction(
        auctioneer=ALICE.pub_key,
        highest_bidder=BOB.pub_key,
        highest_bid=100,
        deadline=1000,
    )
    with pytest.raises(AssertionError):
        bid_paying(c, CHARLIE.test_sig, CHARLIE.pub_key, 50)


@pytest.mark.parametrize("amount", [10000, 10000 + 200 - 1])
def test_bid_must_be_paid(amount):
    """N-027: the bid must be paid into the pot. Carrying the pot forward
    unpaid (10000) passes F-024's `>= input` floor but not bid's rule."""
    c = Auction(
        auctioneer=ALICE.pub_key,
        highest_bidder=BOB.pub_key,
        highest_bid=100,
        deadline=1000,
    )
    prev = set_mock_continuation_amount(amount)
    try:
        with pytest.raises(AssertionError):
            c.bid(CHARLIE.test_sig, CHARLIE.pub_key, 200)
    finally:
        set_mock_continuation_amount(prev)
    assert c.highest_bid == 100


def test_close():
    c = Auction(
        auctioneer=ALICE.pub_key,
        highest_bidder=BOB.pub_key,
        highest_bid=100,
        deadline=0,  # deadline in the past
    )
    c.close(ALICE.test_sig)


def test_bid_must_be_higher():
    c = Auction(
        auctioneer=ALICE.pub_key,
        highest_bidder=BOB.pub_key,
        highest_bid=100,
        deadline=1000,
    )
    with pytest.raises(AssertionError):
        bid_paying(c, CHARLIE.test_sig, CHARLIE.pub_key, 50)


def test_multiple_bids():
    c = Auction(
        auctioneer=ALICE.pub_key,
        highest_bidder=BOB.pub_key,
        highest_bid=100,
        deadline=1000,
    )
    bid_paying(c, CHARLIE.test_sig, CHARLIE.pub_key, 200)
    assert c.highest_bid == 200
    bid_paying(c, DAVE.test_sig, DAVE.pub_key, 300)
    assert c.highest_bid == 300


def test_close_before_deadline_fails():
    c = Auction(
        auctioneer=ALICE.pub_key,
        highest_bidder=BOB.pub_key,
        highest_bid=100,
        deadline=1000,
    )
    with pytest.raises(AssertionError):
        c.close(ALICE.test_sig)


def test_compile():
    from pathlib import Path
    from runar import compile_check
    source_path = str(Path(__file__).parent / "Auction.runar.py")
    with open(source_path) as f:
        source = f.read()
    compile_check(source, "Auction.runar.py")
