#[path = "Auction.runar.rs"]
mod contract;

use contract::*;
use runar::prelude::*;

fn new_auction() -> Auction {
    Auction {
        auctioneer: ALICE.pub_key.to_vec(),
        highest_bidder: BOB.pub_key.to_vec(),
        highest_bid: 100,
        deadline: 1000,
        tx_preimage: mock_preimage(),
    }
}

#[test]
fn test_bid() {
    let mut c = new_auction();
    let bidder = BOB.pub_key.to_vec();
    c.bid(&BOB.sign_test_message(), bidder.clone(), 200);
    assert_eq!(c.highest_bidder, bidder);
    assert_eq!(c.highest_bid, 200);
}

#[test]
#[should_panic]
fn test_bid_must_be_higher() {
    new_auction().bid(&BOB.sign_test_message(), BOB.pub_key.to_vec(), 50);
}

#[test]
#[should_panic]
fn test_bid_equal_to_highest_fails() {
    new_auction().bid(&BOB.sign_test_message(), BOB.pub_key.to_vec(), 100);
}

#[test]
fn test_multiple_bids() {
    let mut c = new_auction();
    c.bid(&BOB.sign_test_message(), BOB.pub_key.to_vec(), 200);
    c.bid(&CHARLIE.sign_test_message(), CHARLIE.pub_key.to_vec(), 300);
    assert_eq!(c.highest_bid, 300);
    assert_eq!(c.highest_bidder, CHARLIE.pub_key.to_vec());
}

#[test]
fn test_close() {
    let mut c = new_auction();
    c.deadline = 0; // extract_locktime returns 0, so 0 >= 0 is true
    c.close(&ALICE.sign_test_message());
}

#[test]
#[should_panic]
fn test_close_before_deadline_fails() {
    new_auction().close(&ALICE.sign_test_message());
}

#[test]
fn test_compile() {
    runar::compile_check(include_str!("Auction.runar.rs"), "Auction.runar.rs").unwrap();
}
