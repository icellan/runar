//! OP_PUSH_TX on-chain signature derivation (BUG-100 fix).
//!
//! The insecure legacy checkPreimage accepted a witness signature over the real
//! spending transaction and checked it against pubkey G, never reading the pushed
//! preimage — so the preimage was decoupled from the tx. This derives the ECDSA
//! signature FROM the preimage on-chain. Any-S: nonce k=1 so r = Gx needs no
//! k-inverse multiply and no sign pad; signing key d = Gx^-1 mod n (C = 1) so
//! r*d == 1 and the addend s = z + 1 is a single OP_1ADD (z = hash256(preimage)).
//! Both variants share the C=1 public key 038ff83d...9218 = d*G:
//!   - lowS (default): s = lowS((z + 1) mod n) — branchless low-S fixup, canonical
//!     s ≤ n/2, accepted under the LOW_S rule (nVersion = 1). 421 bytes.
//!   - all: s = z + 1 as-is (no mod-n, no low-S) — 376 bytes; valid only for
//!     spends with nVersion != 1, where LOW_S is not enforced.
//! OP_CHECKSIG passes only when hash256(preimage) equals the real tx sighash.
//!
//! Each construction compiles to a FIXED byte sequence identical across all seven
//! tiers; it is the canonical output of the TypeScript reference
//! (packages/runar-compiler/src/passes/oppushtx-codegen.ts, validated end-to-end
//! against the BSV interpreter in oppushtx-binding.test.ts). Emitted as a single
//! opaque raw_bytes op (peephole barrier). The cross-tier conformance suite
//! guards that these constants match every other tier byte-for-byte.
pub(crate) const CHECK_PREIMAGE_BINDING_HEX: &str = "76aa517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e01007e818b21414136d08c5ed2bf3ba048afe6dcaebafeffffffffffffffffffffffffffffff007d97785296789f527952798d9495937776927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e827c7e23022079be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798027c7e827c7e01307c7e01417e21038ff83d8cf12121491609c4939dc11c4aa35503508fe432dc5a5c1905608b9218ad";

/// The compact non-low-S ('all') construction: s = z + 1 without the mod-n +
/// low-S fixup. ~45 bytes smaller (376 bytes); valid only for spends with
/// nVersion != 0x01000000 (selected by the `@bindingVariant all` directive).
/// Shares the same C=1 pubkey tail (038ff83d...9218) as the default lowS blob.
pub(crate) const CHECK_PREIMAGE_BINDING_ALL_HEX: &str = "76aa517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e01007e8b76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e827c7e23022079be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798027c7e827c7e01307c7e01417e21038ff83d8cf12121491609c4939dc11c4aa35503508fe432dc5a5c1905608b9218ad";

/// Decode the canonical binding construction into bytes for the given variant
/// (`"all"` selects the compact non-low-S blob; any other value — including the
/// default `"lowS"` — selects the pinned low-S blob). Panics only if the
/// compile-time constant is malformed (which the tests guard against).
pub(crate) fn check_preimage_binding_bytes_variant(variant: &str) -> Vec<u8> {
    let h = if variant == "all" {
        CHECK_PREIMAGE_BINDING_ALL_HEX
    } else {
        CHECK_PREIMAGE_BINDING_HEX
    };
    hex::decode(h).expect("invalid CHECK_PREIMAGE_BINDING hex")
}

/// Like [`check_preimage_binding_bytes_variant`] but honours a declared
/// non-default `@sighash` mode (issue #123). The binding blob differs from the
/// default in exactly one byte: the sighash flag appended to the derived DER
/// signature (the reference `emitCheckPreimageBinding` only swaps `push(0x41)`
/// for `push(sighashFlag)`). The DER signature itself is derived from
/// hash256(preimage) and is independent of the flag byte, so no other byte
/// moves. `None` (or the default 0x41) returns the exact pinned constant for the
/// chosen `variant`, so every existing contract stays byte-identical (zero
/// golden churn). `variant` selects lowS (default) vs the compact `all` blob.
pub(crate) fn check_preimage_binding_bytes_with_flag(flag: Option<i64>, variant: &str) -> Vec<u8> {
    let mut bytes = check_preimage_binding_bytes_variant(variant);
    let f = match flag {
        None => return bytes,
        Some(v) if (v & 0xff) as u8 == SIGHASH_FLAG_DEFAULT => return bytes,
        Some(v) => (v & 0xff) as u8,
    };
    // The sighash flag sits immediately before the `OP_PUSHBYTES_33 <pubkey>`
    // push that appends the OP_PUSH_TX pubkey (P = d*G for the Any-S C=1 key
    // d = Gx^-1 mod n): the tail is
    // `.. 01 <flag> 7e 21 03 8f f8 3d 8c ..` (push-1 flag, OP_CAT, push-33 P).
    // The pubkey tail is shared by both variants. Anchor on the unique
    // pubkey-push prefix and rewrite the flag byte in place.
    const PUBKEY_ANCHOR: &[u8] = &[0x21, 0x03, 0x8f, 0xf8, 0x3d, 0x8c, 0xf1];
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
