import pytest
from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).parent.parent))
from conftest import load_contract

contract_mod = load_contract(str(Path(__file__).parent / "Auction.runar.py"))
Auction = contract_mod.Auction

from runar import ALICE, BOB, CHARLIE, DAVE


def test_bid_higher():
    c = Auction(
        auctioneer=ALICE.pub_key,
        highest_bidder=BOB.pub_key,
        highest_bid=100,
        deadline=1000,
    )
    c.bid(CHARLIE.test_sig, CHARLIE.pub_key, 200)
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
        c.bid(CHARLIE.test_sig, CHARLIE.pub_key, 50)


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
        c.bid(CHARLIE.test_sig, CHARLIE.pub_key, 50)


def test_multiple_bids():
    c = Auction(
        auctioneer=ALICE.pub_key,
        highest_bidder=BOB.pub_key,
        highest_bid=100,
        deadline=1000,
    )
    c.bid(CHARLIE.test_sig, CHARLIE.pub_key, 200)
    assert c.highest_bid == 200
    c.bid(DAVE.test_sig, DAVE.pub_key, 300)
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
