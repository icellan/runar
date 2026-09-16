//! ByteBuiltins as native Rust.
//!
//! Until this file existed the contract could not be compiled as Rust at all:
//! `packages/runar-rs` shipped no `split`, no `int2str` and no `reverse_bytes`,
//! so the only thing that ever read `ByteBuiltins.runar.rs` was the Rúnar
//! frontend. The point of the `.runar.rs` surface is that a contract is BOTH
//! valid Rúnar and valid Rust — `cargo test` checks the business logic against
//! the mocks while `compile_check` checks it as Rúnar. Without the mocks only
//! the second half happened.
//!
//! The expected values here are computed by an encoder written for this file,
//! NOT by calling the mock under test: `split(data, i) == data[i..]` proves
//! nothing if both sides are the same function. Agreement between the mock and
//! the SCRIPT the compiler emits is a separate claim, and it is checked where
//! it can be checked — by spending the compiled lock, in
//! `packages/runar-rs/tests/mock_script_agreement.rs`.

#[path = "ByteBuiltins.runar.rs"]
mod contract;

use contract::*;
use runar::prelude::*;

fn subject() -> ByteBuiltins {
    ByteBuiltins {
        expectedDigest: sha256(b"runar"),
        expectedRipemd: ripemd160(b"runar"),
    }
}

/// `0102..10` — sixteen distinct bytes, so a cut at any position is visible.
fn sample() -> ByteString {
    (1u8..=16).collect()
}

// ---------------------------------------------------------------------------
// split — the RIGHT half of the cut
// ---------------------------------------------------------------------------

#[test]
fn split_binds_the_right_half() {
    let data = sample();
    // Written out rather than sliced, so this is an independent statement of
    // what `split(data, 5)` must return.
    let tail: ByteString = vec![6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];
    subject().checkSplit(data, 5, tail);
}

#[test]
fn split_at_zero_returns_the_whole_value() {
    let data = sample();
    subject().checkSplit(data.clone(), 0, data);
}

#[test]
fn split_at_the_length_returns_empty() {
    let data = sample();
    let n = data.len() as Int;
    subject().checkSplit(data, n, Vec::new());
}

#[test]
fn split_of_the_empty_value_at_zero_is_empty() {
    subject().checkSplit(Vec::new(), 0, Vec::new());
}

/// `OP_SPLIT` FAILS past the end of the element — it does not clamp — so the
/// mock must refuse rather than hand back a shorter answer the script can
/// never produce.
#[test]
#[should_panic(expected = "outside a 16-byte value")]
fn split_past_the_end_is_refused() {
    subject().checkSplit(sample(), 17, Vec::new());
}

#[test]
#[should_panic(expected = "outside a 16-byte value")]
fn split_at_a_negative_position_is_refused() {
    subject().checkSplit(sample(), -1, Vec::new());
}

// ---------------------------------------------------------------------------
// int2str — OP_NUM2BIN, despite the name; `width` is bytes, not a radix
// ---------------------------------------------------------------------------

#[test]
fn int2str_is_fixed_width_little_endian_sign_magnitude() {
    subject().checkInt2Str(1000, 4, vec![0xe8, 0x03, 0x00, 0x00]);
}

#[test]
fn int2str_of_zero_is_all_zero_bytes() {
    subject().checkInt2Str(0, 4, vec![0, 0, 0, 0]);
}

/// The sign is the top bit of the LAST byte, not a separate byte.
#[test]
fn int2str_of_a_negative_value_sets_the_high_bit_of_the_last_byte() {
    subject().checkInt2Str(-1000, 4, vec![0xe8, 0x03, 0x00, 0x80]);
}

/// 255 needs TWO bytes: the sign occupies the bit the magnitude would use.
#[test]
fn int2str_needs_a_byte_for_the_sign() {
    subject().checkInt2Str(255, 2, vec![0xff, 0x00]);
}

/// `OP_NUM2BIN` fails when the number does not fit the size; it has no
/// wrap-around. A mock that truncated would return bytes the script can never
/// produce — the defect `num2bin` carried until it was made to refuse.
#[test]
#[should_panic(expected = "cannot encode 1000 in 1 byte")]
fn int2str_refuses_a_width_too_small_for_the_value() {
    subject().checkInt2Str(1000, 1, Vec::new());
}

#[test]
#[should_panic(expected = "cannot encode 255 in 1 byte")]
fn int2str_refuses_a_width_that_leaves_no_room_for_the_sign() {
    subject().checkInt2Str(255, 1, Vec::new());
}

#[test]
#[should_panic(expected = "width -1 is negative")]
fn int2str_refuses_a_negative_width() {
    subject().checkInt2Str(1, -1, Vec::new());
}

/// Both spellings are the same builtin in every frontend, so both mocks must
/// answer identically. Nothing else in the crate compares them.
#[test]
fn int_2_str_is_the_same_function_as_int2str() {
    assert_eq!(int_2_str(-1000, 4), int2str(-1000, 4));
    assert_eq!(int_2_str(0, 1), int2str(0, 1));
}

// ---------------------------------------------------------------------------
// reverse_bytes
// ---------------------------------------------------------------------------

#[test]
fn reverse_bytes_reverses() {
    subject().checkReverse(vec![0xde, 0xad, 0xbe, 0xef], vec![0xef, 0xbe, 0xad, 0xde]);
}

#[test]
fn reverse_bytes_of_the_empty_value_is_empty() {
    subject().checkReverse(Vec::new(), Vec::new());
}

#[test]
fn reverse_bytes_of_one_byte_is_that_byte() {
    subject().checkReverse(vec![0x7f], vec![0x7f]);
}

/// An odd length has a fixed middle byte, which a reversal that pairs bytes
/// off the ends could drop or duplicate without an even-length case noticing.
#[test]
fn reverse_bytes_of_an_odd_length_keeps_the_middle_byte() {
    subject().checkReverse(vec![1, 2, 3, 4, 5], vec![5, 4, 3, 2, 1]);
}

/// 520 is the bound the emitted loop is unrolled to — every tier emits exactly
/// 520 peel-one-byte iterations — so it is the last length the script can
/// reverse in full.
#[test]
fn reverse_bytes_at_the_520_byte_bound() {
    let data: ByteString = (0..520).map(|i| (i % 251) as u8).collect();
    let mut want = data.clone();
    want.reverse();
    subject().checkReverse(data, want);
}

/// Past 520 bytes the SCRIPT returns the reverse of the first 520 bytes and
/// drops the rest. A mock that reversed the whole value would disagree with
/// every tier's emitter and say nothing about it.
#[test]
#[should_panic(expected = "cannot reverse 521 bytes")]
fn reverse_bytes_past_the_bound_is_refused() {
    subject().checkReverse(vec![0u8; 521], Vec::new());
}

// ---------------------------------------------------------------------------
// Hashes — the two the contract commits to in its locking script
// ---------------------------------------------------------------------------

#[test]
fn sha256_matches_the_baked_in_digest() {
    subject().checkSha256(b"runar".to_vec());
}

#[test]
#[should_panic]
fn sha256_rejects_a_different_preimage() {
    subject().checkSha256(b"runa".to_vec());
}

#[test]
fn ripemd160_matches_the_baked_in_digest() {
    subject().checkRipemd(b"runar".to_vec());
}

#[test]
#[should_panic]
fn ripemd160_rejects_a_different_preimage() {
    subject().checkRipemd(b"runa".to_vec());
}

// ---------------------------------------------------------------------------
// And the same source, read as Rúnar
// ---------------------------------------------------------------------------

#[test]
fn test_compile() {
    runar::compile_check(include_str!("ByteBuiltins.runar.rs"), "ByteBuiltins.runar.rs").unwrap();
}
