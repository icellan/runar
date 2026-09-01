//! OP_PUSH_TX on-chain signature derivation (BUG-100 fix).
//!
//! The insecure legacy checkPreimage accepted a witness signature over the real
//! spending transaction and checked it against pubkey G, never reading the pushed
//! preimage — so the preimage was decoupled from the tx. This derives the ECDSA
//! signature FROM the preimage on-chain (s = (hash256(preimage) + r)*kinv mod n,
//! fixed nonce k=2, privkey d=1, low-S, minimal DER), so OP_CHECKSIG passes only
//! when hash256(preimage) equals the real tx sighash.
//!
//! The construction compiles to a FIXED byte sequence identical across all seven
//! tiers; it is the canonical output of the TypeScript reference
//! (packages/runar-compiler/src/passes/oppushtx-codegen.ts, validated end-to-end
//! against the BSV interpreter in oppushtx-binding.test.ts). Emitted as a single
//! opaque raw_bytes op (peephole barrier). The cross-tier conformance suite
//! guards that this constant matches every other tier byte-for-byte.
pub(crate) const CHECK_PREIMAGE_BINDING_HEX: &str = "76aa517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e01007e8100011f80517e9321414136d08c5ed2bf3ba048afe6dcaebafeffffffffffffffffffffffffffffff007d97785296789f527952798d9495937776927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e827c7e23022079be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798027c7e827c7e01307c7e01417e2102b405d7f0322a89d0f9f3a98e6f938fdc1c969a8d1382a2bf66a71ae74a1e83b0ad";

/// Decode the canonical binding construction into bytes. Panics only if the
/// compile-time constant is malformed (which the tests guard against).
pub(crate) fn check_preimage_binding_bytes() -> Vec<u8> {
    hex::decode(CHECK_PREIMAGE_BINDING_HEX).expect("invalid CHECK_PREIMAGE_BINDING_HEX")
}

/// Like [`check_preimage_binding_bytes`] but honours a declared non-default
/// `@sighash` mode (issue #123). The binding blob differs from the default in
/// exactly one byte: the sighash flag appended to the derived DER signature
/// (the reference `emitCheckPreimageBinding` only swaps `push(0x41)` for
/// `push(sighashFlag)`). The DER signature itself is derived from
/// hash256(preimage) and is independent of the flag byte, so no other byte
/// moves. `None` (or the default 0x41) returns the exact pinned constant, so
/// every existing contract stays byte-identical (zero golden churn).
pub(crate) fn check_preimage_binding_bytes_with_flag(flag: Option<i64>) -> Vec<u8> {
    let mut bytes = check_preimage_binding_bytes();
    let f = match flag {
        None => return bytes,
        Some(v) if (v & 0xff) as u8 == SIGHASH_FLAG_DEFAULT => return bytes,
        Some(v) => (v & 0xff) as u8,
    };
    // The sighash flag sits immediately before the `OP_PUSHBYTES_33 <pubkey>`
    // push that appends the OP_PUSH_TX pubkey (P = d*G for the Any-S key
    // d = 2^248 * Gx^-1 mod n): the tail is
    // `.. 01 <flag> 7e 21 02 b4 05 d7 f0 ..` (push-1 flag, OP_CAT, push-33 P).
    // Anchor on the unique pubkey-push prefix and rewrite the flag byte in place.
    const PUBKEY_ANCHOR: &[u8] = &[0x21, 0x02, 0xb4, 0x05, 0xd7, 0xf0, 0x32];
    let pos = find_subslice(&bytes, PUBKEY_ANCHOR)
        .expect("OP_PUSH_TX pubkey anchor not found in binding blob");
    assert!(pos >= 3, "unexpected binding blob layout (pubkey too early)");
    assert_eq!(
        bytes[pos - 2],
        SIGHASH_FLAG_DEFAULT,
        "expected 0x41 sighash flag before pubkey push"
    );
    assert_eq!(
        bytes[pos - 3],
        0x01,
        "expected single-byte push prefix for the sighash flag"
    );
    bytes[pos - 2] = f;
    bytes
}

/// SIGHASH_ALL | SIGHASH_FORKID — default when a method declares no @sighash.
const SIGHASH_FLAG_DEFAULT: u8 = 0x41;

/// Find the first index of `needle` within `haystack`.
fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || haystack.len() < needle.len() {
        return None;
    }
    haystack
        .windows(needle.len())
        .position(|w| w == needle)
}
