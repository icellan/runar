#[path = "PriceBet.runar.rs"]
mod contract;

use contract::*;
use runar::prelude::*;

const ORACLE_PUB_KEY: &[u8] = b"oracle_rabin_pk";

fn new_price_bet() -> PriceBet {
    PriceBet {
        alice_pub_key: ALICE.pub_key.to_vec(),
        bob_pub_key: BOB.pub_key.to_vec(),
        oracle_pub_key: ORACLE_PUB_KEY.to_vec(),
        strike_price: 50000,
    }
}

/// Sign a price using the trivial Rabin scheme: sig=0, padding=SHA256(msg) mod n.
/// Mirrors `examples/end2end-example/go/PriceBet_test.go::signPrice`, which uses
/// `runar.RabinSignToBytes` against the real test Rabin key.
fn sign_price(price: i64) -> (Vec<u8>, Vec<u8>) {
    let msg = num2bin(&price, 8);
    rabin_sign_trivial(&msg, ORACLE_PUB_KEY)
}

#[test]
fn test_settle_alice_wins() {
    let (rabin_sig, pad) = sign_price(60000);
    let alice_sig = ALICE.sign_test_message();
    let bob_sig = BOB.sign_test_message();
    new_price_bet().settle(60000, &rabin_sig, &pad, &alice_sig, &bob_sig);
}

#[test]
fn test_settle_bob_wins() {
    let (rabin_sig, pad) = sign_price(30000);
    let alice_sig = ALICE.sign_test_message();
    let bob_sig = BOB.sign_test_message();
    new_price_bet().settle(30000, &rabin_sig, &pad, &alice_sig, &bob_sig);
}

#[test]
fn test_settle_bob_wins_at_strike() {
    let (rabin_sig, pad) = sign_price(50000);
    let alice_sig = ALICE.sign_test_message();
    let bob_sig = BOB.sign_test_message();
    new_price_bet().settle(50000, &rabin_sig, &pad, &alice_sig, &bob_sig);
}

#[test]
#[should_panic]
fn test_settle_zero_price_rejected() {
    let (rabin_sig, pad) = sign_price(0);
    let alice_sig = ALICE.sign_test_message();
    let bob_sig = BOB.sign_test_message();
    new_price_bet().settle(0, &rabin_sig, &pad, &alice_sig, &bob_sig);
}

#[test]
fn test_cancel() {
    let alice_sig = ALICE.sign_test_message();
    let bob_sig = BOB.sign_test_message();
    new_price_bet().cancel(&alice_sig, &bob_sig);
}

#[test]
fn test_compile() {
    runar::compile_check(
        include_str!("PriceBet.runar.rs"),
        "PriceBet.runar.rs",
    ).unwrap();
}
