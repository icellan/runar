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

/// Bid with the continuation carrying the prior pot (`extract_amount` is 10000
/// off-chain) plus the bid (N-027).
fn bid_paying(c: &mut Auction, sig: &Sig, bidder: PubKey, amount: Bigint) {
    let prev = set_mock_continuation_amount(10000 + amount);
    c.bid(sig, bidder, amount);
    set_mock_continuation_amount(prev);
}

#[test]
fn test_bid() {
    let mut c = new_auction();
    let bidder = BOB.pub_key.to_vec();
    bid_paying(&mut c, &BOB.sign_test_message(), bidder.clone(), 200);
    assert_eq!(c.highest_bidder, bidder);
    assert_eq!(c.highest_bid, 200);
}

#[test]
#[should_panic]
fn test_bid_must_be_higher() {
    bid_paying(&mut new_auction(), &BOB.sign_test_message(), BOB.pub_key.to_vec(), 50);
}

#[test]
#[should_panic]
fn test_bid_equal_to_highest_fails() {
    bid_paying(&mut new_auction(), &BOB.sign_test_message(), BOB.pub_key.to_vec(), 100);
}

/// N-027: the bid must be paid into the pot. Carrying the pot forward unpaid
/// (10000) passes F-024's `>= input` floor but not bid's rule.
#[test]
fn test_bid_must_be_paid() {
    for amount in [10000, 10000 + 200 - 1] {
        let caught = std::panic::catch_unwind(|| {
            set_mock_continuation_amount(amount);
            new_auction().bid(&BOB.sign_test_message(), BOB.pub_key.to_vec(), 200);
        });
        set_mock_continuation_amount(10000);
        assert!(caught.is_err(), "bid with continuation {amount} must be rejected");
    }
}

#[test]
fn test_multiple_bids() {
    let mut c = new_auction();
    bid_paying(&mut c, &BOB.sign_test_message(), BOB.pub_key.to_vec(), 200);
    bid_paying(&mut c, &CHARLIE.sign_test_message(), CHARLIE.pub_key.to_vec(), 300);
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
