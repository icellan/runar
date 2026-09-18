//! TerminalVarlenRead as native Rust — the issue-#100 regression fixture.
//!
//! The contract calls `len`, which `packages/runar-rs` did not ship, so it had
//! never been compiled as Rust and `reveal` had never been executed off-chain.

#[path = "TerminalVarlenRead.runar.rs"]
mod contract;

use contract::*;
use runar::prelude::*;

fn subject(message: &str) -> TerminalVarlenRead {
    TerminalVarlenRead { message: message.as_bytes().to_vec() }
}

#[test]
fn post_replaces_the_message() {
    let mut c = subject("old");
    c.post(b"a longer message".to_vec());
    assert_eq!(c.message, b"a longer message".to_vec());
}

#[test]
fn reveal_accepts_a_message_longer_than_the_bound() {
    subject("hello").reveal(4);
}

/// The comparison is strict, so a message exactly at the bound must fail.
/// Without this the guard would pass for a `>=`.
#[test]
#[should_panic]
fn reveal_rejects_a_message_exactly_at_the_bound() {
    subject("hello").reveal(5);
}

#[test]
#[should_panic]
fn reveal_rejects_a_shorter_message() {
    subject("hi").reveal(5);
}

/// The empty value is the boundary `len` itself has to survive: `OP_SIZE` of an
/// empty element is 0, not a failure.
#[test]
fn len_of_the_empty_message_is_zero() {
    assert_eq!(len(&subject("").message), 0);
    subject("").reveal(-1);
}

/// 520 bytes is the largest element the emitted scripts are built around, and
/// a `len` that answered from anything narrower than the whole value would
/// still look right on the short cases above.
#[test]
fn len_of_a_520_byte_message() {
    let mut c = subject("");
    c.post(vec![0x41u8; 520]);
    assert_eq!(len(&c.message), 520);
    c.reveal(519);
}

#[test]
fn test_compile() {
    runar::compile_check(
        include_str!("TerminalVarlenRead.runar.rs"),
        "TerminalVarlenRead.runar.rs",
    )
    .unwrap();
}
