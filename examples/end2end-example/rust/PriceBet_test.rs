#[path = "PriceBet.runar.rs"]
mod contract;

use contract::*;
use runar::prelude::*;

fn new_price_bet() -> PriceBet {
    PriceBet {
        alice_pub_key: mock_pub_key(),
        bob_pub_key: mock_pub_key(),
        oracle_pub_key: b"oracle_rabin_pk".to_vec(),
        strike_price: 50000,
    }
}

#[test]
fn test_settle_alice_wins() {
    new_price_bet().settle(60000, &b"sig".to_vec(), &b"pad".to_vec(), &mock_sig(), &mock_sig());
}

#[test]
fn test_settle_bob_wins() {
    new_price_bet().settle(30000, &b"sig".to_vec(), &b"pad".to_vec(), &mock_sig(), &mock_sig());
}

#[test]
fn test_settle_bob_wins_at_strike() {
    new_price_bet().settle(50000, &b"sig".to_vec(), &b"pad".to_vec(), &mock_sig(), &mock_sig());
}

#[test]
#[should_panic]
fn test_settle_zero_price_rejected() {
    new_price_bet().settle(0, &b"sig".to_vec(), &b"pad".to_vec(), &mock_sig(), &mock_sig());
}

#[test]
fn test_cancel() {
    new_price_bet().cancel(&mock_sig(), &mock_sig());
}

#[test]
fn test_compile() {
    runar::compile_check(
        include_str!("PriceBet.runar.rs"),
        "PriceBet.runar.rs",
    ).unwrap();
}
