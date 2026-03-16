#[path = "Escrow.runar.rs"]
mod contract;

use contract::*;
use runar::prelude::*;

fn new_escrow() -> Escrow {
    Escrow {
        buyer: ALICE.pub_key.to_vec(),
        seller: BOB.pub_key.to_vec(),
        arbiter: CHARLIE.pub_key.to_vec(),
    }
}

#[test]
fn test_release() {
    new_escrow().release(&BOB.sign_test_message(), &CHARLIE.sign_test_message());
}

#[test]
fn test_refund() {
    new_escrow().refund(&ALICE.sign_test_message(), &CHARLIE.sign_test_message());
}

#[test]
fn test_compile() {
    runar::compile_check(include_str!("Escrow.runar.rs"), "Escrow.runar.rs").unwrap();
}
