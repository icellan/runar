#[path = "OraclePriceFeed.runar.rs"]
mod contract;

use contract::*;
use runar::prelude::*;

/// A small test Rabin modulus (a prime, so not a real Rabin key, but
/// sufficient for verifying the contract logic with the trivial signer).
const TEST_RABIN_PK: u64 = 997;

fn rabin_pk_bytes() -> Vec<u8> {
    TEST_RABIN_PK.to_le_bytes().to_vec()
}

fn new_oracle_feed() -> OraclePriceFeed {
    OraclePriceFeed {
        oracle_pub_key: rabin_pk_bytes(),
        receiver: ALICE.pub_key.to_vec(),
    }
}

#[test]
fn test_settle() {
    let price: Bigint = 60000;
    let msg = num2bin(&price, 8);
    let (sig, pad) = rabin_sign_trivial(&msg, &rabin_pk_bytes());
    new_oracle_feed().settle(price, &sig, &pad, &ALICE.sign_test_message());
}

#[test]
#[should_panic]
fn test_settle_price_too_low_fails() {
    let price: Bigint = 50000;
    let msg = num2bin(&price, 8);
    let (sig, pad) = rabin_sign_trivial(&msg, &rabin_pk_bytes());
    new_oracle_feed().settle(price, &sig, &pad, &ALICE.sign_test_message());
}

#[test]
fn test_settle_high_price() {
    let price: Bigint = 100000;
    let msg = num2bin(&price, 8);
    let (sig, pad) = rabin_sign_trivial(&msg, &rabin_pk_bytes());
    new_oracle_feed().settle(price, &sig, &pad, &ALICE.sign_test_message());
}

#[test]
fn test_compile() {
    runar::compile_check(
        include_str!("OraclePriceFeed.runar.rs"),
        "OraclePriceFeed.runar.rs",
    ).unwrap();
}
