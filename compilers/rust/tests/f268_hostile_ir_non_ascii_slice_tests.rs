//! F-268 / CL-BUG-049 — `lower_load_const`'s `@ref:` alias check does
//! `s.len() > 5 && &s[..5] == "@ref:"` on an arbitrary `load_const` string
//! pulled straight from a hand-written `--ir` file, with no ASCII / char-
//! boundary check. `str::len()` counts BYTES, not chars, so a 7-byte string
//! whose 5th byte falls inside a multi-byte UTF-8 character (e.g.
//! "abcd\u{e9}!" — 'a','b','c','d' are 1 byte each, then 'é' is the 2-byte
//! UTF-8 sequence occupying bytes 4..6, then '!' is byte 6) panics Rust's
//! byte-slice indexing with "byte index 5 is not a char boundary" instead of
//! being refused as a diagnostic.
//!
//! The TS reference never hits this shape at all: `String.prototype.startsWith`
//! and `.slice()` index by UTF-16 code unit, not by byte, so they never panic
//! on a string that merely happens to contain a multi-byte character — for
//! this exact input TS's `startsWith('@ref:')` is simply `false` (the string
//! doesn't start with the ref marker) and lowering falls through to treat the
//! value as an ordinary (hex) byte-string constant, which then fails hex
//! decoding with a graceful `Error`. The fix below makes Rust take the same
//! PATH: a byte-boundary-safe `str::starts_with("@ref:")` check (which never
//! panics regardless of what bytes follow), falling through to the existing
//! hex decoding, which must itself refuse non-hex content gracefully rather
//! than panicking on it.
//!
//! The exact MESSAGE text is not expected to match TS byte-for-byte, and this
//! was verified empirically (`runar-cli compile --from-ir` on both inputs),
//! not assumed: `str::len()` in Rust counts UTF-8 bytes, `String.length` in
//! JS counts UTF-16 code units, so the two tiers can disagree on which of the
//! hex decoder's two checks (odd length vs. non-hex content) fires first for
//! the SAME string:
//!   - "abcd\u{e9}!" — TS (6 UTF-16 units, even) reaches the content check:
//!     `Invalid hex string: non-hex character at offset 4 in 'abcdé!'`; Rust
//!     (7 UTF-8 bytes, odd) stops at the length check: `invalid hex string
//!     length: 7`.
//!   - "a\u{e9}aaa" — swapped: TS (5 units, odd) hits the length check:
//!     `Invalid hex string length: 5`; Rust (6 bytes, even) reaches the
//!     content check: `invalid hex string: aéaaa`.
//! Both are refused gracefully either way, which is the only parity this fix
//! claims or needs — the repo already tolerates this class of per-tier
//! hex-decoder message divergence (see `anf_lower.rs:3630` and the
//! `r290_void_sentinel_tests.rs` header).

use runar_compiler_rust::compile_from_ir_str;

#[test]
fn a_non_ascii_load_const_at_the_ref_prefix_boundary_is_a_graceful_err_not_a_panic() {
    // "abcd\u{e9}!" is 7 bytes in UTF-8 (a,b,c,d = 1 byte each, 'é' = 2 bytes,
    // '!' = 1 byte). Byte offset 5 lands on the SECOND byte of 'é' — not a
    // char boundary — so `&s[..5]` panics today instead of refusing cleanly.
    let ir_json = r#"{
        "contractName": "HostileNonAsciiLoadConst",
        "properties": [],
        "methods": [{
            "name": "go",
            "params": [],
            "body": [
                {"name": "t1", "value": {"kind": "load_const", "value": "abcdé!"}},
                {"name": "t2", "value": {"kind": "assert", "value": "t1"}}
            ],
            "isPublic": true
        }]
    }"#;

    // This must come back as a graceful `Err` (a refusal diagnostic),
    // never as an unwind that `compile_from_ir_str` fails to convert.
    let err = compile_from_ir_str(ir_json).expect_err(
        "a non-hex, non-ASCII load_const string must be refused gracefully, not panic",
    );
    assert!(
        !err.is_empty(),
        "refusal must carry a diagnostic message, got empty string"
    );
    // Must NOT be the raw, unreadable byte-index panic message — that would
    // mean the char-boundary bug is still there, just no longer unwinding
    // past `catch_refusal` (or was never actually reaching it).
    assert!(
        !err.contains("is not a char boundary"),
        "refusal leaked the raw byte-slicing panic message instead of a clean diagnostic: {}",
        err
    );
    // Pins that the refusal came from the hex decoder (the same fall-through
    // path TS takes once `startsWith('@ref:')` / `starts_with("@ref:")` is
    // false), not from some unrelated refusal that happens to not mention
    // "char boundary".
    assert!(
        err.contains("invalid hex string"),
        "expected the hex-decoder refusal (byte length is odd: 7), got: {}",
        err
    );
}

#[test]
fn a_non_ascii_load_const_at_a_hex_pair_boundary_is_a_graceful_err_not_a_panic() {
    // "a\u{e9}aaa" is 6 bytes in UTF-8: 'a' (byte 0), then 'é' as the 2-byte
    // sequence 0xC3 0xA9 (bytes 1..3), then 'a','a','a' (bytes 3,4,5). This
    // string does not start with "@ref:", so it falls through to
    // `hex_to_bytes`, which decodes 2 bytes at a time starting at byte 0 —
    // `&hex_str[0..2]` lands on byte 2, the SECOND byte of 'é', not a char
    // boundary, so it panics today with the same "is not a char boundary"
    // shape as the `@ref:` site, just one call deeper (`hex_to_bytes`).
    let ir_json = r#"{
        "contractName": "HostileNonAsciiHexPair",
        "properties": [],
        "methods": [{
            "name": "go",
            "params": [],
            "body": [
                {"name": "t1", "value": {"kind": "load_const", "value": "aéaaa"}},
                {"name": "t2", "value": {"kind": "assert", "value": "t1"}}
            ],
            "isPublic": true
        }]
    }"#;

    let err = compile_from_ir_str(ir_json).expect_err(
        "a non-hex, non-ASCII load_const string must be refused gracefully, not panic",
    );
    assert!(
        !err.is_empty(),
        "refusal must carry a diagnostic message, got empty string"
    );
    assert!(
        !err.contains("is not a char boundary"),
        "refusal leaked the raw byte-slicing panic message instead of a clean diagnostic: {}",
        err
    );
    // Pins the refusal to the hex decoder's content check (byte length 6 is
    // even, so it gets past the length check and fails decoding the pair
    // straddling 'é' instead) — the same fall-through path TS takes.
    assert!(
        err.contains("invalid hex string"),
        "expected the hex-decoder refusal (non-hex byte in the 'é' pair), got: {}",
        err
    );
}
