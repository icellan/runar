//! ECUnit as native Rust.
//!
//! This file used to say the contract "breaks Rust-native compilation" because
//! the EC mocks take `&[u8]` where the contract passes an owned `Point`, and
//! concluded that `#[path]`-including it was impossible. Two things were wrong
//! with that. The mismatch is one `&` per call site and the `.runar.rs` parser
//! strips the borrow, so the emitted script is byte-identical either way
//! (checked: hex AND canonical ANF, fold-on and fold-off). And `len` — which
//! the contract also calls — was simply MISSING from `packages/runar-rs`, so
//! the file could not have compiled regardless of the borrows. A comment
//! asserting a checkable fact about another file, which was false, kept the
//! whole contract from ever running off-chain.
//!
//! It runs now. `test_ops` asserts nine EC identities; before this file, none
//! of them had ever been evaluated in this tier in any form.

#[path = "ECUnit.runar.rs"]
mod contract;

use contract::*;
use runar::ec::*;
use runar::prelude::*;

fn subject() -> ECUnit {
    ECUnit { pub_key: ec_encode_compressed(&ec_mul_gen(1)) }
}

/// The contract's own assertions, executed.
#[test]
fn ec_identities_hold() {
    subject().test_ops();
}

// The identities `test_ops` bundles, separated so a failure names which one
// broke. `test_ops` asserts them as one block, and one `assert!` firing in the
// middle of nine tells you very little.

#[test]
fn the_generator_is_on_the_curve() {
    assert!(ec_on_curve(&ec_mul_gen(1)));
}

#[test]
fn negation_stays_on_the_curve() {
    let g = ec_mul_gen(1);
    assert!(ec_on_curve(&ec_negate(&g)));
    // And it is an involution — a `negate` that returned its argument would
    // satisfy the on-curve check above.
    assert_eq!(ec_negate(&ec_negate(&g)), g);
}

#[test]
fn doubling_by_mul_equals_adding_to_itself() {
    let g = ec_mul_gen(1);
    assert_eq!(ec_mul(&g, 2), ec_add(&g, &g));
    assert_eq!(ec_mul(&g, 2), ec_mul_gen(2));
}

/// P + (-P) is the point at infinity. `ec_add` returns the all-zero blob from a
/// SUCCESSFUL script — there is no error channel in Script — so `ec_on_curve`
/// is what has to reject it. This is the identity the contract exists to pin.
#[test]
fn the_point_at_infinity_is_not_on_the_curve() {
    let g = ec_mul_gen(1);
    let inf = ec_add(&g, &ec_negate(&g));
    assert_eq!(inf, vec![0u8; 64], "P + (-P) is not the all-zero blob");
    assert!(!ec_on_curve(&inf));
}

#[test]
fn a_point_rebuilds_from_its_own_coordinates() {
    let g = ec_mul_gen(1);
    let rebuilt = ec_make_point(ec_point_x(&g), ec_point_y(&g));
    assert_eq!(rebuilt, g);
    assert!(ec_on_curve(&rebuilt));
}

#[test]
fn compressed_encoding_is_33_bytes() {
    let g = ec_mul_gen(1);
    assert_eq!(len(&ec_encode_compressed(&g)), 33);
    // The prefix carries the parity of y, so it is 02 or 03 and never 04.
    let enc = ec_encode_compressed(&g);
    assert!(enc[0] == 2 || enc[0] == 3, "prefix byte {} is not a compressed-point tag", enc[0]);
}

#[test]
fn test_compile() {
    runar::compile_check(include_str!("ECUnit.runar.rs"), "ECUnit.runar.rs").unwrap();
}
