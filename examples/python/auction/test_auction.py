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
