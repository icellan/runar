//! IntentPrevOutputScript as native Rust.
//!
//! The contract calls `len`, which `packages/runar-rs` did not ship, so it had
//! never been compiled as Rust.
//!
//! `bind()` still cannot be EXECUTED off-chain, and this file pins why rather
//! than asserting it in prose. `extract_prev_output_script` is a witness-bridge
//! intrinsic: on-chain the compiler emits `hash256(witness) ==
//! expected_script_hash` against an auto-injected method parameter carrying
//! another input's previous-output script. A mock in this crate has no other
//! inputs to read, so `packages/runar-rs` stubs it to the empty ByteString —
//! and the contract's own `assert!(len(&s) > 0)` is therefore unsatisfiable
//! here. The stub disagrees with the emitter by construction, which is worth
//! knowing and worth keeping visible: `the_stub_returns_empty_so_bind_cannot_
//! run_off_chain` fails the day the stub starts answering, instead of the
//! disagreement quietly persisting behind a compile-only test.

#[path = "IntentPrevOutputScript.runar.rs"]
mod contract;

use contract::*;
use runar::prelude::*;

fn subject() -> IntentPrevOutputScript {
    IntentPrevOutputScript { expected_hash: hash256(b"a previous output script"), count: 0 }
}

/// The stub, stated as an executed fact.
#[test]
fn the_intent_intrinsic_is_stubbed_to_the_empty_byte_string() {
    let c = subject();
    assert_eq!(
        len(&extract_prev_output_script(0, &c.expected_hash)),
        0,
        "extract_prev_output_script no longer returns the empty ByteString off-chain. \
         bind() may now be runnable — replace the should_panic below with a real call \
         rather than leaving a stale excuse in place."
    );
}

/// And the consequence, so the claim above is tied to the contract rather than
/// to the mock alone.
#[test]
#[should_panic]
fn the_stub_returns_empty_so_bind_cannot_run_off_chain() {
    subject().bind();
}

#[test]
fn test_compile() {
    runar::compile_check(
        include_str!("IntentPrevOutputScript.runar.rs"),
        "IntentPrevOutputScript.runar.rs",
    )
    .unwrap();
}
