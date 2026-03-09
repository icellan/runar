#[path = "Auction.runar.rs"]
mod contract;

use contract::*;
use runar::prelude::*;

fn new_auction() -> Auction {
    Auction {
        auctioneer: mock_pub_key(),
        highest_bidder: b"initial_bidder_placeholder_33b!x".to_vec(),
        highest_bid: 100,
        deadline: 1000,
        tx_preimage: mock_preimage(),
    }
}

#[test]
fn test_bid() {
    let mut c = new_auction();
    let bidder = b"new_bidder_placeholder_33bytes!x".to_vec();
    c.bid(&mock_sig(), bidder.clone(), 200);
    assert_eq!(c.highest_bidder, bidder);
    assert_eq!(c.highest_bid, 200);
}

#[test]
#[should_panic]
fn test_bid_must_be_higher() { new_auction().bid(&mock_sig(), mock_pub_key(), 50); }

#[test]
#[should_panic]
fn test_bid_equal_to_highest_fails() { new_auction().bid(&mock_sig(), mock_pub_key(), 100); }

#[test]
fn test_multiple_bids() {
    let mut c = new_auction();
    let bidder1 = b"bidder_one_33bytes_placeholder_!".to_vec();
    let bidder2 = b"bidder_two_33bytes_placeholder_!".to_vec();
    c.bid(&mock_sig(), bidder1, 200);
    c.bid(&mock_sig(), bidder2.clone(), 300);
    assert_eq!(c.highest_bid, 300);
    assert_eq!(c.highest_bidder, bidder2);
}

#[test]
fn test_close() {
    let mut c = new_auction();
    c.deadline = 0; // extract_locktime returns 0, so 0 >= 0 is true
    c.close(&mock_sig());
}

#[test]
#[should_panic]
fn test_close_before_deadline_fails() { new_auction().close(&mock_sig()); }

#[test]
fn test_compile() {
    runar::compile_check(include_str!("Auction.runar.rs"), "Auction.runar.rs").unwrap();
}
