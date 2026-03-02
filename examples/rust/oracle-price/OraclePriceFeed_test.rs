#[path = "OraclePriceFeed.runar.rs"]
mod contract;

use contract::*;
use runar::prelude::*;

fn new_oracle_feed() -> OraclePriceFeed {
    OraclePriceFeed {
        oracle_pub_key: b"oracle_rabin_pk".to_vec(),
        receiver: mock_pub_key(),
    }
}

#[test]
fn test_settle() {
    new_oracle_feed().settle(60000, &b"sig".to_vec(), &b"pad".to_vec(), &mock_sig());
}

#[test]
#[should_panic]
fn test_settle_price_too_low_fails() {
    new_oracle_feed().settle(50000, &b"sig".to_vec(), &b"pad".to_vec(), &mock_sig());
}

#[test]
fn test_settle_high_price() {
    new_oracle_feed().settle(100000, &b"sig".to_vec(), &b"pad".to_vec(), &mock_sig());
}

#[test]
fn test_compile() {
    runar::compile_check(
        include_str!("OraclePriceFeed.runar.rs"),
        "OraclePriceFeed.runar.rs",
    ).unwrap();
}
