import pytest
from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).parent.parent))
from conftest import load_contract

contract_mod = load_contract(str(Path(__file__).parent / "Auction.runar.py"))
Auction = contract_mod.Auction

from runar import mock_sig, mock_pub_key


def test_bid_higher():
    c = Auction(
        auctioneer=mock_pub_key(),
        highest_bidder=mock_pub_key(),
        highest_bid=100,
        deadline=1000,
    )
    new_bidder = b'\x03' + b'\x01' * 32
    c.bid(mock_sig(), new_bidder, 200)
    assert c.highest_bidder == new_bidder
    assert c.highest_bid == 200


def test_bid_lower_fails():
    c = Auction(
        auctioneer=mock_pub_key(),
        highest_bidder=mock_pub_key(),
        highest_bid=100,
        deadline=1000,
    )
    with pytest.raises(AssertionError):
        c.bid(mock_sig(), mock_pub_key(), 50)


def test_close():
    c = Auction(
        auctioneer=mock_pub_key(),
        highest_bidder=mock_pub_key(),
        highest_bid=100,
        deadline=0,  # deadline in the past
    )
    c.close(mock_sig())


def test_bid_must_be_higher():
    c = Auction(
        auctioneer=mock_pub_key(),
        highest_bidder=mock_pub_key(),
        highest_bid=100,
        deadline=1000,
    )
    with pytest.raises(AssertionError):
        c.bid(mock_sig(), mock_pub_key(), 50)


def test_multiple_bids():
    c = Auction(
        auctioneer=mock_pub_key(),
        highest_bidder=mock_pub_key(),
        highest_bid=100,
        deadline=1000,
    )
    bidder1 = b'\x03' + b'\x01' * 32
    bidder2 = b'\x03' + b'\x02' * 32
    c.bid(mock_sig(), bidder1, 200)
    assert c.highest_bid == 200
    c.bid(mock_sig(), bidder2, 300)
    assert c.highest_bid == 300


def test_close_before_deadline_fails():
    c = Auction(
        auctioneer=mock_pub_key(),
        highest_bidder=mock_pub_key(),
        highest_bid=100,
        deadline=1000,
    )
    with pytest.raises(AssertionError):
        c.close(mock_sig())


def test_compile():
    from pathlib import Path
    from runar import compile_check
    source_path = str(Path(__file__).parent / "Auction.runar.py")
    with open(source_path) as f:
        source = f.read()
    compile_check(source, "Auction.runar.py")
