//! Prelude — import everything needed for Rúnar contract development.
//!
//! ```ignore
//! use runar::prelude::*;
//! ```

use sha2::{Digest, Sha256 as Sha256Hasher};

// Re-export macros so `use runar::prelude::*` gets them too.
pub use runar_lang_macros::{contract, stateful_contract, unsafe_contract};

// ---------------------------------------------------------------------------
// Scalar types — type aliases so Rust arithmetic operators work directly
// ---------------------------------------------------------------------------

/// Rúnar integer (maps to Bitcoin Script numbers).
pub type Int = i64;

/// Alias for Int.
pub type Bigint = i64;

// ---------------------------------------------------------------------------
// Byte-string types
// ---------------------------------------------------------------------------

/// A public key (compressed or uncompressed).
pub type PubKey = Vec<u8>;

/// A DER-encoded signature.
pub type Sig = Vec<u8>;

/// A 20-byte address (typically hash160 of a public key).
pub type Addr = Vec<u8>;

/// An arbitrary byte sequence.
pub type ByteString = Vec<u8>;

/// A 32-byte SHA-256 hash.
pub type Sha256 = Vec<u8>;

/// A 32-byte SHA-256 hash digest. Alias of [`Sha256`] for cross-language
/// parity with Go, where the identifier `Sha256` must name a function
/// (mapped to OP_SHA256 in Script) and the TYPE is exposed as
/// `Sha256Digest` to avoid the type-vs-call ambiguity. Rust doesn't suffer
/// from the same ambiguity (the function is `sha256` in snake_case), so
/// both names remain available here and `Sha256` stays canonical.
pub type Sha256Digest = Sha256;

/// A 20-byte RIPEMD-160 hash.
pub type Ripemd160 = Vec<u8>;

/// Sighash preimage for transaction validation.
pub type SigHashPreimage = Vec<u8>;

/// A Rabin signature.
pub type RabinSig = Vec<u8>;

/// A Rabin public key.
pub type RabinPubKey = Vec<u8>;

/// A 64-byte EC point (x[32] || y[32], big-endian, no prefix).
pub type Point = Vec<u8>;

// ---------------------------------------------------------------------------
// Output snapshot (for stateful contracts with add_output)
// ---------------------------------------------------------------------------

/// A recorded output from `add_output`.
#[derive(Debug, Clone)]
pub struct OutputSnapshot {
    pub satoshis: Bigint,
    pub values: Vec<Vec<u8>>,
}

// ---------------------------------------------------------------------------
// Real crypto verification (ECDSA, Rabin) + mocked checkPreimage
// ---------------------------------------------------------------------------

/// Real ECDSA verification over the fixed TEST_MESSAGE.
///
/// Verifies the given DER-encoded signature against the compressed public
/// key using secp256k1 over the canonical test message
/// `"runar-test-message-v1"`. Handles optional trailing sighash byte.
pub fn check_sig(sig: &[u8], pk: &[u8]) -> bool {
    crate::ecdsa::ecdsa_verify(sig, pk)
}

/// Real ordered multi-sig ECDSA verification over the fixed TEST_MESSAGE.
///
/// Each signature in `sigs` must correspond to a public key in `pks`
/// (in order). All signatures must be valid.
pub fn check_multi_sig(sigs: &[&[u8]], pks: &[&[u8]]) -> bool {
    if sigs.len() != pks.len() {
        return false;
    }
    for (sig, pk) in sigs.iter().zip(pks.iter()) {
        if !crate::ecdsa::ecdsa_verify(sig, pk) {
            return false;
        }
    }
    true
}

/// Always returns `true` in test mode (preimage verification is mocked).
pub fn check_preimage(_preimage: &[u8]) -> bool {
    true
}

/// Real Rabin signature verification.
///
/// Equation: `(sig^2 + padding) mod n == SHA256(msg) mod n`
/// where all byte slices are interpreted as unsigned little-endian big integers.
pub fn verify_rabin_sig(msg: &[u8], sig: &[u8], padding: &[u8], pk: &[u8]) -> bool {
    crate::rabin::rabin_verify(msg, sig, padding, pk)
}

/// Real WOTS+ signature verification using SHA-256 hash chains.
pub fn verify_wots(msg: &[u8], sig: &[u8], pk: &[u8]) -> bool {
    crate::wots::wots_verify_impl(msg, sig, pk)
}

// SLH-DSA (SPHINCS+) SHA-256 variants — real FIPS 205 verification.

/// Real SLH-DSA-SHA2-128s verification (FIPS 205).
pub fn verify_slh_dsa_sha2_128s(msg: &[u8], sig: &[u8], pk: &[u8]) -> bool {
    crate::slh_dsa::slh_verify(&crate::slh_dsa::SLH_SHA2_128S, msg, sig, pk)
}

/// Real SLH-DSA-SHA2-128f verification (FIPS 205).
pub fn verify_slh_dsa_sha2_128f(msg: &[u8], sig: &[u8], pk: &[u8]) -> bool {
    crate::slh_dsa::slh_verify(&crate::slh_dsa::SLH_SHA2_128F, msg, sig, pk)
}

/// Real SLH-DSA-SHA2-192s verification (FIPS 205).
pub fn verify_slh_dsa_sha2_192s(msg: &[u8], sig: &[u8], pk: &[u8]) -> bool {
    crate::slh_dsa::slh_verify(&crate::slh_dsa::SLH_SHA2_192S, msg, sig, pk)
}

/// Real SLH-DSA-SHA2-192f verification (FIPS 205).
pub fn verify_slh_dsa_sha2_192f(msg: &[u8], sig: &[u8], pk: &[u8]) -> bool {
    crate::slh_dsa::slh_verify(&crate::slh_dsa::SLH_SHA2_192F, msg, sig, pk)
}

/// Real SLH-DSA-SHA2-256s verification (FIPS 205).
pub fn verify_slh_dsa_sha2_256s(msg: &[u8], sig: &[u8], pk: &[u8]) -> bool {
    crate::slh_dsa::slh_verify(&crate::slh_dsa::SLH_SHA2_256S, msg, sig, pk)
}

/// Real SLH-DSA-SHA2-256f verification (FIPS 205).
pub fn verify_slh_dsa_sha2_256f(msg: &[u8], sig: &[u8], pk: &[u8]) -> bool {
    crate::slh_dsa::slh_verify(&crate::slh_dsa::SLH_SHA2_256F, msg, sig, pk)
}

// ---------------------------------------------------------------------------
// EC (elliptic curve) functions — real secp256k1 arithmetic for testing.
// In compiled Bitcoin Script, these map to EC codegen opcodes.
// ---------------------------------------------------------------------------

pub use crate::ec::{
    ec_add, ec_encode_compressed, ec_make_point, ec_mod_reduce, ec_mul, ec_mul_gen,
    ec_negate, ec_on_curve, ec_point_x, ec_point_y,
};

pub use crate::wots::{wots_keygen, wots_sign, WotsKeyPair};

// ---------------------------------------------------------------------------
// P-256 (NIST P-256 / secp256r1) off-chain helpers for testing
// ---------------------------------------------------------------------------

pub use crate::p256::{p256_keygen, p256_sign, verify_ecdsa_p256, P256KeyPair};

// ---------------------------------------------------------------------------
// P-384 (NIST P-384 / secp384r1) off-chain helpers for testing
// ---------------------------------------------------------------------------

pub use crate::p384::{p384_keygen, p384_sign, verify_ecdsa_p384, P384KeyPair};

pub use crate::slh_dsa::{
    slh_keygen, slh_sign, slh_verify, SlhKeyPair, SlhParams,
    SLH_SHA2_128S, SLH_SHA2_128F, SLH_SHA2_192S, SLH_SHA2_192F,
    SLH_SHA2_256S, SLH_SHA2_256F,
};

pub use crate::ecdsa::{
    sign_test_message, pub_key_from_priv_key, ecdsa_verify,
    TEST_MESSAGE, TEST_MESSAGE_DIGEST,
};

pub use crate::test_keys::{TestKeyPair, ALICE, BOB, CHARLIE};

pub use crate::rabin::rabin_sign_trivial;

// ---------------------------------------------------------------------------
// Real hash functions
// ---------------------------------------------------------------------------

/// RIPEMD160(SHA256(data)) — produces a 20-byte address.
pub fn hash160(data: &[u8]) -> Addr {
    let sha = Sha256Hasher::digest(data);
    let mut hasher = ripemd::Ripemd160::new();
    hasher.update(&sha);
    hasher.finalize().to_vec()
}

/// SHA256(SHA256(data)) — produces a 32-byte hash.
pub fn hash256(data: &[u8]) -> Sha256 {
    let h1 = Sha256Hasher::digest(data);
    let h2 = Sha256Hasher::digest(&h1);
    h2.to_vec()
}

/// Single SHA-256 hash.
pub fn sha256(data: &[u8]) -> Sha256 {
    Sha256Hasher::digest(data).to_vec()
}

/// Alias for `sha256`. Provides the PascalCase / explicitly-named spelling
/// so cross-format contract sources that use the `Sha256Hash` identifier
/// (resolved by every parser back to the `sha256` builtin) have a matching
/// runtime function on the Rust side too.
pub fn sha256_hash(data: &[u8]) -> Sha256 {
    sha256(data)
}

/// Single RIPEMD-160 hash.
pub fn ripemd160(data: &[u8]) -> Ripemd160 {
    let mut hasher = ripemd::Ripemd160::new();
    hasher.update(data);
    hasher.finalize().to_vec()
}

// ---------------------------------------------------------------------------
// BLAKE3 single-block compression (real implementation)
// ---------------------------------------------------------------------------
//
// Matches the Rúnar codegen which hardcodes blockLen=64, counter=0,
// flags=11 (CHUNK_START | CHUNK_END | ROOT). All seven runtimes (TS, Go,
// Rust, Python, Zig, Ruby, Java) MUST produce byte-identical output for the
// same inputs — the cross-language test vectors are pinned in
// `packages/runar-py/tests/test_blake3.py` and mirrored in this crate's
// unit tests below.
//
// This is *not* a generic BLAKE3 hash of an arbitrary-length message: the
// emitted Bitcoin Script can only express a single compression invocation,
// so the off-chain runtime intentionally exposes the same restricted
// primitive. For message sizes ≤ 64 bytes `blake3_hash` applies zero-padding
// before calling the compression function with the IV as chaining value.

/// BLAKE3 initialization vector (8 u32 words, big-endian when serialized).
const BLAKE3_IV_WORDS: [u32; 8] = [
    0x6a09_e667, 0xbb67_ae85, 0x3c6e_f372, 0xa54f_f53a,
    0x510e_527f, 0x9b05_688c, 0x1f83_d9ab, 0x5be0_cd19,
];

/// BLAKE3 message word permutation between rounds.
const BLAKE3_MSG_PERM: [usize; 16] = [2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8];

#[inline]
fn blake3_rotr32(x: u32, n: u32) -> u32 {
    (x >> n) | (x << (32 - n))
}

#[inline]
fn blake3_g(s: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize, mx: u32, my: u32) {
    s[a] = s[a].wrapping_add(s[b]).wrapping_add(mx);
    s[d] = blake3_rotr32(s[d] ^ s[a], 16);
    s[c] = s[c].wrapping_add(s[d]);
    s[b] = blake3_rotr32(s[b] ^ s[c], 12);
    s[a] = s[a].wrapping_add(s[b]).wrapping_add(my);
    s[d] = blake3_rotr32(s[d] ^ s[a], 8);
    s[c] = s[c].wrapping_add(s[d]);
    s[b] = blake3_rotr32(s[b] ^ s[c], 7);
}

fn blake3_round(s: &mut [u32; 16], m: &[u32; 16]) {
    blake3_g(s, 0, 4, 8, 12, m[0], m[1]);
    blake3_g(s, 1, 5, 9, 13, m[2], m[3]);
    blake3_g(s, 2, 6, 10, 14, m[4], m[5]);
    blake3_g(s, 3, 7, 11, 15, m[6], m[7]);
    blake3_g(s, 0, 5, 10, 15, m[8], m[9]);
    blake3_g(s, 1, 6, 11, 12, m[10], m[11]);
    blake3_g(s, 2, 7, 8, 13, m[12], m[13]);
    blake3_g(s, 3, 4, 9, 14, m[14], m[15]);
}

fn blake3_iv_bytes() -> [u8; 32] {
    let mut out = [0u8; 32];
    for (i, w) in BLAKE3_IV_WORDS.iter().enumerate() {
        out[i * 4..i * 4 + 4].copy_from_slice(&w.to_be_bytes());
    }
    out
}

fn blake3_compress_impl(cv: &[u8], block: &[u8]) -> [u8; 32] {
    // Defensive: pad / truncate to the canonical sizes so a misuse doesn't
    // panic. Production code should always pass exactly 32 / 64 bytes.
    let mut cv_buf = [0u8; 32];
    let n = cv.len().min(32);
    cv_buf[..n].copy_from_slice(&cv[..n]);

    let mut blk_buf = [0u8; 64];
    let n = block.len().min(64);
    blk_buf[..n].copy_from_slice(&block[..n]);

    let mut h = [0u32; 8];
    for i in 0..8 {
        h[i] = u32::from_be_bytes([
            cv_buf[i * 4],
            cv_buf[i * 4 + 1],
            cv_buf[i * 4 + 2],
            cv_buf[i * 4 + 3],
        ]);
    }
    let mut m = [0u32; 16];
    for i in 0..16 {
        m[i] = u32::from_be_bytes([
            blk_buf[i * 4],
            blk_buf[i * 4 + 1],
            blk_buf[i * 4 + 2],
            blk_buf[i * 4 + 3],
        ]);
    }

    let mut state: [u32; 16] = [
        h[0], h[1], h[2], h[3],
        h[4], h[5], h[6], h[7],
        BLAKE3_IV_WORDS[0], BLAKE3_IV_WORDS[1], BLAKE3_IV_WORDS[2], BLAKE3_IV_WORDS[3],
        0,  // counter low
        0,  // counter high
        64, // blockLen
        11, // flags = CHUNK_START | CHUNK_END | ROOT
    ];

    let mut msg = m;
    for r in 0..7 {
        blake3_round(&mut state, &msg);
        if r < 6 {
            let mut permuted = [0u32; 16];
            for (i, &p) in BLAKE3_MSG_PERM.iter().enumerate() {
                permuted[i] = msg[p];
            }
            msg = permuted;
        }
    }

    let mut out = [0u8; 32];
    for i in 0..8 {
        let w = state[i] ^ state[i + 8];
        out[i * 4..i * 4 + 4].copy_from_slice(&w.to_be_bytes());
    }
    out
}

/// BLAKE3 single-block compression with hardcoded blockLen=64, counter=0,
/// flags=11. `chaining_value` should be 32 bytes and `block` 64 bytes; both
/// are interpreted as 8 / 16 big-endian u32 words. Output is 32 big-endian
/// bytes. Matches the on-chain codegen.
pub fn blake3_compress(chaining_value: &[u8], block: &[u8]) -> ByteString {
    blake3_compress_impl(chaining_value, block).to_vec()
}

/// BLAKE3 hash for messages up to 64 bytes. Equivalent to
/// `blake3_compress(IV, zero_pad(message, 64))`. Matches the on-chain
/// codegen.
pub fn blake3_hash(message: &[u8]) -> ByteString {
    let cv = blake3_iv_bytes();
    let mut padded = [0u8; 64];
    let n = message.len().min(64);
    padded[..n].copy_from_slice(&message[..n]);
    blake3_compress_impl(&cv, &padded).to_vec()
}

// ---------------------------------------------------------------------------
// Real SHA-256 compression (FIPS 180-4 Section 6.2.2)
// ---------------------------------------------------------------------------

const SHA256_K: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
    0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
    0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
    0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
    0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
    0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

/// Real SHA-256 single-block compression function (FIPS 180-4 Section 6.2.2).
///
/// Takes a 32-byte state (8 big-endian u32 words) and a 64-byte block,
/// returns the 32-byte updated state.
pub fn sha256_compress(state: &[u8], block: &[u8]) -> ByteString {
    assert!(state.len() == 32, "sha256_compress: state must be 32 bytes");
    assert!(block.len() == 64, "sha256_compress: block must be 64 bytes");

    // Parse state as 8 big-endian u32 words
    let mut h = [0u32; 8];
    for i in 0..8 {
        h[i] = u32::from_be_bytes(state[i * 4..i * 4 + 4].try_into().unwrap());
    }

    // Parse block as 16 big-endian u32 words
    let mut w = [0u32; 64];
    for i in 0..16 {
        w[i] = u32::from_be_bytes(block[i * 4..i * 4 + 4].try_into().unwrap());
    }

    // W-expansion for t = 16..64
    for t in 16..64 {
        let s0 = w[t - 15].rotate_right(7) ^ w[t - 15].rotate_right(18) ^ (w[t - 15] >> 3);
        let s1 = w[t - 2].rotate_right(17) ^ w[t - 2].rotate_right(19) ^ (w[t - 2] >> 10);
        w[t] = w[t - 16]
            .wrapping_add(s0)
            .wrapping_add(w[t - 7])
            .wrapping_add(s1);
    }

    // Initialize working variables
    let mut a = h[0];
    let mut b = h[1];
    let mut c = h[2];
    let mut d = h[3];
    let mut e = h[4];
    let mut f = h[5];
    let mut g = h[6];
    let mut hh = h[7];

    // 64 rounds
    for t in 0..64 {
        let big_s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
        let ch = (e & f) ^ ((!e) & g);
        let temp1 = hh
            .wrapping_add(big_s1)
            .wrapping_add(ch)
            .wrapping_add(SHA256_K[t])
            .wrapping_add(w[t]);
        let big_s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
        let maj = (a & b) ^ (a & c) ^ (b & c);
        let temp2 = big_s0.wrapping_add(maj);

        hh = g;
        g = f;
        f = e;
        e = d.wrapping_add(temp1);
        d = c;
        c = b;
        b = a;
        a = temp1.wrapping_add(temp2);
    }

    // Compute final hash values
    h[0] = h[0].wrapping_add(a);
    h[1] = h[1].wrapping_add(b);
    h[2] = h[2].wrapping_add(c);
    h[3] = h[3].wrapping_add(d);
    h[4] = h[4].wrapping_add(e);
    h[5] = h[5].wrapping_add(f);
    h[6] = h[6].wrapping_add(g);
    h[7] = h[7].wrapping_add(hh);

    // Encode as big-endian bytes
    let mut result = vec![0u8; 32];
    for i in 0..8 {
        result[i * 4..i * 4 + 4].copy_from_slice(&h[i].to_be_bytes());
    }
    result
}

/// Real SHA-256 finalize function.
///
/// Takes the current 32-byte state, remaining unprocessed bytes, and the
/// total message bit length. Applies SHA-256 padding (append 0x80, zero-pad,
/// append 64-bit big-endian bit length) and runs the final 1-2 compression rounds.
pub fn sha256_finalize(state: &[u8], remaining: &[u8], msg_bit_len: i64) -> ByteString {
    assert!(state.len() == 32, "sha256_finalize: state must be 32 bytes");
    assert!(remaining.len() <= 64, "sha256_finalize: remaining must be <= 64 bytes");

    let rem_len = remaining.len();

    // Build padded buffer: remaining + 0x80 + zeros + 8-byte big-endian bit length
    // If remaining + 1 (0x80) + 8 (bit length) <= 64, it fits in one block.
    // Otherwise we need two blocks.
    if rem_len < 56 {
        // Fits in one 64-byte block
        let mut block = [0u8; 64];
        block[..rem_len].copy_from_slice(remaining);
        block[rem_len] = 0x80;
        // Last 8 bytes = bit length in big-endian
        let bit_len = msg_bit_len as u64;
        block[56..64].copy_from_slice(&bit_len.to_be_bytes());
        sha256_compress(state, &block)
    } else {
        // Needs two blocks
        let mut block1 = [0u8; 64];
        block1[..rem_len].copy_from_slice(remaining);
        block1[rem_len] = 0x80;
        // First block: remaining + 0x80 + zeros (no room for bit length)
        let intermediate = sha256_compress(state, &block1);

        // Second block: all zeros except last 8 bytes = bit length
        let mut block2 = [0u8; 64];
        let bit_len = msg_bit_len as u64;
        block2[56..64].copy_from_slice(&bit_len.to_be_bytes());
        sha256_compress(&intermediate, &block2)
    }
}

// ---------------------------------------------------------------------------
// Mock preimage extraction functions
// ---------------------------------------------------------------------------

/// Returns 0 in test mode.
pub fn extract_locktime(_p: &[u8]) -> Int {
    0
}

/// Returns the first 32 bytes of the preimage in test mode.
/// Tests set `tx_preimage = hash256(expected_output_bytes)` so the assertion
/// `hash256(outputs) == extract_output_hash(tx_preimage)` passes.
/// Falls back to 32 zero bytes when the preimage is unset or shorter than 32 bytes.
pub fn extract_output_hash(p: &[u8]) -> ByteString {
    if p.len() >= 32 {
        p[..32].to_vec()
    } else {
        vec![0u8; 32]
    }
}

/// Returns `hash256([0u8; 72])` in test mode.
/// This is consistent with passing `all_prevouts = [0u8; 72]` in tests,
/// since `extract_outpoint` also returns 36 zero bytes.
pub fn extract_hash_prevouts(_p: &[u8]) -> Sha256 {
    hash256(&vec![0u8; 72])
}

/// Returns 36 zero bytes in test mode.
pub fn extract_outpoint(_p: &[u8]) -> ByteString {
    vec![0u8; 36]
}

/// Returns a mock state script (empty bytes).
pub fn get_state_script<T>(_contract: &T) -> ByteString {
    vec![]
}

// ---------------------------------------------------------------------------
// asm — the raw-script escape hatch (UnsafeSmartContract only)
// ---------------------------------------------------------------------------

/// Structured argument for the `asm` compiler intrinsic. The Rúnar Rust-DSL
/// frontend intercepts `asm(...)` calls at parse time and lowers them to a
/// `raw_script` ANF node; this struct only exists so native `cargo test`
/// compilation of contract source succeeds.
#[derive(Debug, Clone)]
pub struct AsmArgs {
    /// An even-length hex string of the raw Bitcoin Script opcode bytes to
    /// embed verbatim. The compiler does not re-encode or validate the
    /// semantics of these bytes — only that the string is valid hex with an
    /// even length.
    pub body: String,
    /// The number of stack items the embedded bytes consume on entry.
    pub in_arity: i64,
    /// The number of stack items the embedded bytes leave on exit.
    pub out_arity: i64,
}

/// Embeds a raw Bitcoin Script byte sequence in a contract method. Only
/// callable from inside a contract marked `#[runar::unsafe_contract]` — the
/// Rúnar compiler enforces this. The Rust-DSL surface spelling is the
/// positional form `asm(body, in_arity, out_arity)`; the compiler normalises
/// every frontend to the same `raw_script` ANF node.
///
/// This runtime stub panics: `asm` is a compile-time intrinsic and cannot be
/// executed off-chain.
pub fn asm(_body: &str, _in_arity: i64, _out_arity: i64) {
    panic!("asm() cannot be called at runtime — compile this contract with the Rúnar compiler");
}

// ---------------------------------------------------------------------------
// Utility functions
// ---------------------------------------------------------------------------

/// Returns a substring of a byte string starting at `start` with the given `length`.
pub fn substr(data: &[u8], start: i64, length: i64) -> ByteString {
    let s = start as usize;
    let l = length as usize;
    data[s..s + l].to_vec()
}

/// Converts an integer to a byte string of the specified length
/// using Bitcoin Script's little-endian signed magnitude encoding.
/// Accepts a reference to match Rúnar contract calling convention.
pub fn num2bin(v: &Bigint, length: usize) -> ByteString {
    let mut buf = vec![0u8; length];
    if *v == 0 || length == 0 {
        return buf;
    }
    let abs = v.unsigned_abs();
    let mut val = abs;
    for byte in buf.iter_mut() {
        if val == 0 {
            break;
        }
        *byte = (val & 0xff) as u8;
        val >>= 8;
    }
    if *v < 0 {
        buf[length - 1] |= 0x80;
    }
    buf
}

/// Converts a byte string (Bitcoin Script LE signed-magnitude) back to an integer.
/// Inverse of `num2bin`.
pub fn bin2num(data: &[u8]) -> Bigint {
    if data.is_empty() {
        return 0;
    }
    let last = data[data.len() - 1];
    let negative = (last & 0x80) != 0;
    let mut result: u64 = (last & 0x7f) as u64;
    for i in (0..data.len() - 1).rev() {
        result = (result << 8) | data[i] as u64;
    }
    if negative {
        -(result as i64)
    } else {
        result as i64
    }
}

/// Concatenates two byte strings.
pub fn cat(a: &[u8], b: &[u8]) -> ByteString {
    let mut result = a.to_vec();
    result.extend_from_slice(b);
    result
}

// ---------------------------------------------------------------------------
// Math functions
// ---------------------------------------------------------------------------

/// Safe division — panics if b is zero.
pub fn safediv(a: Int, b: Int) -> Int {
    assert!(b != 0, "safediv: division by zero");
    a / b
}

/// Safe modulo — panics if b is zero.
pub fn safemod(a: Int, b: Int) -> Int {
    assert!(b != 0, "safemod: modulo by zero");
    a % b
}

/// Clamp value to [lo, hi].
pub fn clamp(value: Int, lo: Int, hi: Int) -> Int {
    if value < lo { lo } else if value > hi { hi } else { value }
}

/// Sign of a number: -1, 0, or 1.
pub fn sign(n: Int) -> Int {
    if n > 0 { 1 } else if n < 0 { -1 } else { 0 }
}

/// Exponentiation for non-negative exponents. Panics on i64 overflow.
pub fn pow(base: Int, exp: Int) -> Int {
    assert!(exp >= 0, "pow: negative exponent");
    let mut result: Int = 1;
    for _ in 0..exp {
        result = result.checked_mul(base).unwrap_or_else(|| {
            panic!("runar: i64 overflow in {} * {} — Bitcoin Script supports arbitrary precision but Rust tests use i64", result, base)
        });
    }
    result
}

/// (a * b) / c — panics on i64 overflow in a*b.
pub fn mul_div(a: Int, b: Int, c: Int) -> Int {
    assert!(c != 0, "mulDiv: division by zero");
    let product = a.checked_mul(b).unwrap_or_else(|| {
        panic!("runar: i64 overflow in {} * {} — Bitcoin Script supports arbitrary precision but Rust tests use i64", a, b)
    });
    product / c
}

/// (amount * bps) / 10000 — basis point percentage. Panics on i64 overflow.
pub fn percent_of(amount: Int, bps: Int) -> Int {
    let product = amount.checked_mul(bps).unwrap_or_else(|| {
        panic!("runar: i64 overflow in {} * {} — Bitcoin Script supports arbitrary precision but Rust tests use i64", amount, bps)
    });
    product / 10000
}

/// Integer square root via Newton's method. Panics on i64 overflow.
pub fn sqrt(n: Int) -> Int {
    assert!(n >= 0, "sqrt: negative input");
    if n == 0 { return 0; }
    let mut guess = n;
    for _ in 0..256 {
        let sum = guess.checked_add(n / guess).unwrap_or_else(|| {
            panic!("runar: i64 overflow in sqrt — Bitcoin Script supports arbitrary precision but Rust tests use i64")
        });
        let next = sum / 2;
        if next >= guess { break; }
        guess = next;
    }
    guess
}

/// Greatest common divisor via Euclidean algorithm.
/// Panics if either argument is i64::MIN (|MIN| overflows i64).
pub fn gcd(mut a: Int, mut b: Int) -> Int {
    a = a.checked_abs().unwrap_or_else(|| {
        panic!("runar: i64 overflow in gcd — |i64::MIN| not representable; Bitcoin Script supports arbitrary precision but Rust tests use i64")
    });
    b = b.checked_abs().unwrap_or_else(|| {
        panic!("runar: i64 overflow in gcd — |i64::MIN| not representable; Bitcoin Script supports arbitrary precision but Rust tests use i64")
    });
    while b != 0 { let t = b; b = a % b; a = t; }
    a
}

/// Division returning quotient.
pub fn divmod(a: Int, b: Int) -> Int {
    assert!(b != 0, "divmod: division by zero");
    a / b
}

/// Approximate floor(log2(n)).
pub fn log2(n: Int) -> Int {
    if n <= 0 { return 0; }
    let mut bits: Int = 0;
    let mut val = n;
    while val > 1 { val >>= 1; bits += 1; }
    bits
}

/// Boolean cast — returns true if n is non-zero.
pub fn bool_cast(n: Int) -> bool {
    n != 0
}

// ---------------------------------------------------------------------------
// Baby Bear field arithmetic (p = 2^31 - 2^27 + 1 = 2013265921)
// ---------------------------------------------------------------------------

const BB_P: i64 = 2013265921;

/// Baby Bear field addition: (a + b) mod p.
pub fn bb_field_add(a: i64, b: i64) -> i64 {
    (a + b) % BB_P
}

/// Baby Bear field subtraction: (a - b + p) mod p.
pub fn bb_field_sub(a: i64, b: i64) -> i64 {
    ((a - b) % BB_P + BB_P) % BB_P
}

/// Baby Bear field multiplication: (a * b) mod p.
pub fn bb_field_mul(a: i64, b: i64) -> i64 {
    (a * b) % BB_P
}

/// Baby Bear field inverse via Fermat's little theorem: a^(p-2) mod p.
pub fn bb_field_inv(a: i64) -> i64 {
    let mut result: i64 = 1;
    let mut base = ((a % BB_P) + BB_P) % BB_P;
    let mut exp = BB_P - 2;
    while exp > 0 {
        if exp & 1 == 1 {
            result = (result * base) % BB_P;
        }
        base = (base * base) % BB_P;
        exp >>= 1;
    }
    result
}

// ---------------------------------------------------------------------------
// Baby Bear quartic extension field (x^4 - W, W = 11)
// ---------------------------------------------------------------------------
//
// Mirrors packages/runar-go/runar.go BbExt4Mul{0..3}/BbExt4Inv{0..3} and
// the compiler codegen used by the `babybear-ext4` conformance fixture.

const BB_EXT4_W: i64 = 11;

pub fn bb_ext4_mul0(
    a0: i64, a1: i64, a2: i64, a3: i64,
    b0: i64, b1: i64, b2: i64, b3: i64,
) -> i64 {
    let r = bb_field_mul(a0, b0);
    let t = bb_field_add(bb_field_mul(a1, b3),
        bb_field_add(bb_field_mul(a2, b2), bb_field_mul(a3, b1)));
    bb_field_add(r, bb_field_mul(BB_EXT4_W, t))
}

pub fn bb_ext4_mul1(
    a0: i64, a1: i64, a2: i64, a3: i64,
    b0: i64, b1: i64, b2: i64, b3: i64,
) -> i64 {
    let r = bb_field_add(bb_field_mul(a0, b1), bb_field_mul(a1, b0));
    let t = bb_field_add(bb_field_mul(a2, b3), bb_field_mul(a3, b2));
    bb_field_add(r, bb_field_mul(BB_EXT4_W, t))
}

pub fn bb_ext4_mul2(
    a0: i64, a1: i64, a2: i64, a3: i64,
    b0: i64, b1: i64, b2: i64, b3: i64,
) -> i64 {
    let r = bb_field_add(bb_field_mul(a0, b2),
        bb_field_add(bb_field_mul(a1, b1), bb_field_mul(a2, b0)));
    bb_field_add(r, bb_field_mul(BB_EXT4_W, bb_field_mul(a3, b3)))
}

pub fn bb_ext4_mul3(
    a0: i64, a1: i64, a2: i64, a3: i64,
    b0: i64, b1: i64, b2: i64, b3: i64,
) -> i64 {
    bb_field_add(
        bb_field_mul(a0, b3),
        bb_field_add(
            bb_field_mul(a1, b2),
            bb_field_add(bb_field_mul(a2, b1), bb_field_mul(a3, b0)),
        ),
    )
}

fn bb_ext4_inv_all(a0: i64, a1: i64, a2: i64, a3: i64) -> (i64, i64, i64, i64) {
    let (c0, c1, c2, c3) = (a0, bb_field_sub(0, a1), a2, bb_field_sub(0, a3));
    let p0 = bb_ext4_mul0(a0, a1, a2, a3, c0, c1, c2, c3);
    let p2 = bb_ext4_mul2(a0, a1, a2, a3, c0, c1, c2, c3);
    let norm_sq = bb_field_sub(bb_field_mul(p0, p0),
        bb_field_mul(BB_EXT4_W, bb_field_mul(p2, p2)));
    let norm_inv = bb_field_inv(norm_sq);
    let inv0 = bb_field_mul(p0, norm_inv);
    let inv2 = bb_field_sub(0, bb_field_mul(p2, norm_inv));
    (
        bb_field_add(bb_field_mul(c0, inv0), bb_field_mul(BB_EXT4_W, bb_field_mul(c2, inv2))),
        bb_field_add(bb_field_mul(c1, inv0), bb_field_mul(BB_EXT4_W, bb_field_mul(c3, inv2))),
        bb_field_add(bb_field_mul(c0, inv2), bb_field_mul(c2, inv0)),
        bb_field_add(bb_field_mul(c1, inv2), bb_field_mul(c3, inv0)),
    )
}

pub fn bb_ext4_inv0(a0: i64, a1: i64, a2: i64, a3: i64) -> i64 {
    bb_ext4_inv_all(a0, a1, a2, a3).0
}
pub fn bb_ext4_inv1(a0: i64, a1: i64, a2: i64, a3: i64) -> i64 {
    bb_ext4_inv_all(a0, a1, a2, a3).1
}
pub fn bb_ext4_inv2(a0: i64, a1: i64, a2: i64, a3: i64) -> i64 {
    bb_ext4_inv_all(a0, a1, a2, a3).2
}
pub fn bb_ext4_inv3(a0: i64, a1: i64, a2: i64, a3: i64) -> i64 {
    bb_ext4_inv_all(a0, a1, a2, a3).3
}

// ---------------------------------------------------------------------------
// Merkle proof verification
// ---------------------------------------------------------------------------

/// Compute a Merkle root using SHA-256 as the hash function.
///
/// `leaf` is a 32-byte hash, `proof` is `depth * 32` concatenated sibling
/// hashes, `index` determines left/right at each level.
pub fn merkle_root_sha256(leaf: &[u8], proof: &[u8], index: i64, depth: i64) -> ByteString {
    merkle_root_impl(leaf, proof, index, depth, sha256)
}

/// Compute a Merkle root using Hash256 (double SHA-256) as the hash function.
pub fn merkle_root_hash256(leaf: &[u8], proof: &[u8], index: i64, depth: i64) -> ByteString {
    merkle_root_impl(leaf, proof, index, depth, hash256)
}

fn merkle_root_impl(
    leaf: &[u8],
    proof: &[u8],
    index: i64,
    depth: i64,
    hash_fn: fn(&[u8]) -> ByteString,
) -> ByteString {
    let mut current = leaf.to_vec();
    for i in 0..depth {
        let start = (i as usize) * 32;
        let sibling = &proof[start..start + 32];
        let bit = (index >> i) & 1;
        let preimage = if bit == 1 {
            let mut p = sibling.to_vec();
            p.extend_from_slice(&current);
            p
        } else {
            let mut p = current.clone();
            p.extend_from_slice(sibling);
            p
        };
        current = hash_fn(&preimage);
    }
    current
}

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

/// Returns a dummy signature for testing.
pub fn mock_sig() -> Sig {
    vec![0u8; 72]
}

/// Returns a dummy compressed public key for testing.
pub fn mock_pub_key() -> PubKey {
    let mut pk = vec![0u8; 33];
    pk[0] = 0x02;
    pk
}

/// Returns a dummy sighash preimage for testing.
pub fn mock_preimage() -> SigHashPreimage {
    vec![0u8; 181]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_check_sig_real_ecdsa() {
        let sig = ALICE.sign_test_message();
        assert!(check_sig(&sig, ALICE.pub_key));
    }

    #[test]
    fn test_check_sig_rejects_wrong_key() {
        let sig = ALICE.sign_test_message();
        assert!(!check_sig(&sig, BOB.pub_key));
    }

    #[test]
    fn test_check_multi_sig_real() {
        let alice_sig = ALICE.sign_test_message();
        let bob_sig = BOB.sign_test_message();
        assert!(check_multi_sig(
            &[alice_sig.as_slice(), bob_sig.as_slice()],
            &[ALICE.pub_key, BOB.pub_key],
        ));
    }

    #[test]
    fn test_check_multi_sig_rejects_wrong_order() {
        let alice_sig = ALICE.sign_test_message();
        let bob_sig = BOB.sign_test_message();
        // Wrong order: alice sig checked against bob key
        assert!(!check_multi_sig(
            &[alice_sig.as_slice(), bob_sig.as_slice()],
            &[BOB.pub_key, ALICE.pub_key],
        ));
    }

    #[test]
    fn test_check_preimage_always_true() {
        assert!(check_preimage(&mock_preimage()));
    }

    #[test]
    fn test_hash160_produces_20_bytes() {
        assert_eq!(hash160(b"hello").len(), 20);
    }

    #[test]
    fn test_hash160_deterministic() {
        assert_eq!(hash160(b"test data"), hash160(b"test data"));
    }

    #[test]
    fn test_hash256_produces_32_bytes() {
        assert_eq!(hash256(b"hello").len(), 32);
    }

    #[test]
    fn test_hash256_deterministic() {
        assert_eq!(hash256(b"test data"), hash256(b"test data"));
    }

    #[test]
    fn test_sha256_produces_32_bytes() {
        assert_eq!(sha256(b"hello").len(), 32);
    }

    #[test]
    fn test_ripemd160_produces_20_bytes() {
        assert_eq!(ripemd160(b"hello").len(), 20);
    }

    #[test]
    fn test_num2bin_zero() {
        assert_eq!(num2bin(&0, 4), vec![0, 0, 0, 0]);
    }

    #[test]
    fn test_num2bin_positive() {
        assert_eq!(num2bin(&42, 4)[0], 42);
    }

    #[test]
    fn test_num2bin_negative() {
        let result = num2bin(&-42, 4);
        assert_eq!(result[0], 42);
        assert!(result[3] & 0x80 != 0);
    }

    #[test]
    fn test_mock_sig_length() {
        assert_eq!(mock_sig().len(), 72);
    }

    #[test]
    fn test_mock_pub_key_length() {
        let pk = mock_pub_key();
        assert_eq!(pk.len(), 33);
        assert_eq!(pk[0], 0x02);
    }

    // -----------------------------------------------------------------------
    // Overflow boundary tests — i64 limitation detection
    // -----------------------------------------------------------------------

    #[test]
    fn test_pow_small_values() {
        assert_eq!(pow(2, 10), 1024);
        assert_eq!(pow(3, 0), 1);
    }

    #[test]
    #[should_panic(expected = "i64 overflow")]
    fn test_pow_overflow() {
        pow(i64::MAX, 2);
    }

    #[test]
    fn test_mul_div_small_values() {
        assert_eq!(mul_div(100, 3, 2), 150);
    }

    #[test]
    #[should_panic(expected = "i64 overflow")]
    fn test_mul_div_overflow() {
        mul_div(i64::MAX, 2, 1);
    }

    #[test]
    fn test_percent_of_small_values() {
        assert_eq!(percent_of(10000, 2500), 2500);
    }

    #[test]
    #[should_panic(expected = "i64 overflow")]
    fn test_percent_of_overflow() {
        percent_of(i64::MAX, 5000);
    }

    #[test]
    fn test_gcd_small_values() {
        assert_eq!(gcd(12, 8), 4);
    }

    #[test]
    #[should_panic(expected = "i64 overflow")]
    fn test_gcd_min_panics() {
        gcd(i64::MIN, 1);
    }

    // -----------------------------------------------------------------------
    // safediv
    // -----------------------------------------------------------------------

    #[test]
    fn test_safediv_positive() {
        // 10 / 3 truncates toward zero in Rust
        assert_eq!(safediv(10, 3), 3);
    }

    #[test]
    fn test_safediv_truncates_toward_zero() {
        // Rust integer division truncates toward zero: -7 / 2 == -3 (not -4)
        assert_eq!(safediv(-7, 2), -3);
    }

    #[test]
    #[should_panic(expected = "safediv: division by zero")]
    fn test_safediv_by_zero_panics() {
        safediv(42, 0);
    }

    // -----------------------------------------------------------------------
    // safemod
    // -----------------------------------------------------------------------

    #[test]
    fn test_safemod_positive() {
        assert_eq!(safemod(10, 3), 1);
    }

    #[test]
    fn test_safemod_negative() {
        // Rust % follows the sign of the dividend: -7 % 2 == -1
        assert_eq!(safemod(-7, 2), -1);
    }

    // -----------------------------------------------------------------------
    // clamp
    // -----------------------------------------------------------------------

    #[test]
    fn test_clamp_within_range() {
        assert_eq!(clamp(5, 0, 10), 5);
    }

    #[test]
    fn test_clamp_below() {
        assert_eq!(clamp(-1, 0, 10), 0);
    }

    #[test]
    fn test_clamp_above() {
        assert_eq!(clamp(15, 0, 10), 10);
    }

    // -----------------------------------------------------------------------
    // sign
    // -----------------------------------------------------------------------

    #[test]
    fn test_sign_positive() {
        assert_eq!(sign(42), 1);
    }

    #[test]
    fn test_sign_negative() {
        assert_eq!(sign(-42), -1);
    }

    #[test]
    fn test_sign_zero() {
        assert_eq!(sign(0), 0);
    }

    // -----------------------------------------------------------------------
    // sqrt
    // -----------------------------------------------------------------------

    #[test]
    fn test_sqrt_perfect_square() {
        assert_eq!(sqrt(9), 3);
    }

    #[test]
    fn test_sqrt_non_perfect() {
        // floor(sqrt(10)) == 3
        assert_eq!(sqrt(10), 3);
    }

    // -----------------------------------------------------------------------
    // log2
    // -----------------------------------------------------------------------

    #[test]
    fn test_log2_power_of_two() {
        assert_eq!(log2(8), 3);
    }

    #[test]
    fn test_log2_non_power() {
        // floor(log2(9)) == 3
        assert_eq!(log2(9), 3);
    }

    // -----------------------------------------------------------------------
    // SHA-256 compress / finalize
    // -----------------------------------------------------------------------

    /// Decode a hex string to bytes.
    fn hex_decode(s: &str) -> Vec<u8> {
        assert!(s.len() % 2 == 0, "hex string must have even length");
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    /// Encode bytes as a lowercase hex string.
    fn hex_encode(data: &[u8]) -> String {
        data.iter().map(|b| format!("{:02x}", b)).collect()
    }

    #[test]
    fn test_sha256_compress_abc() {
        let state = hex_decode("6a09e667bb67ae853c6ef372a54ff53a510e527f9b05688c1f83d9ab5be0cd19");
        let block = hex_decode(
            "6162638000000000000000000000000000000000000000000000000000000000\
             0000000000000000000000000000000000000000000000000000000000000018"
        );
        let result = sha256_compress(&state, &block);
        assert_eq!(
            hex_encode(&result),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn test_sha256_finalize_abc() {
        let state = hex_decode("6a09e667bb67ae853c6ef372a54ff53a510e527f9b05688c1f83d9ab5be0cd19");
        let result = sha256_finalize(&state, b"abc", 24);
        assert_eq!(
            hex_encode(&result),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn test_sha256_finalize_empty() {
        let state = hex_decode("6a09e667bb67ae853c6ef372a54ff53a510e527f9b05688c1f83d9ab5be0cd19");
        let result = sha256_finalize(&state, b"", 0);
        assert_eq!(
            hex_encode(&result),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn test_sha256_finalize_cross_verify() {
        let state = hex_decode("6a09e667bb67ae853c6ef372a54ff53a510e527f9b05688c1f83d9ab5be0cd19");
        for msg in &["", "abc", "hello world"] {
            let finalized = sha256_finalize(&state, msg.as_bytes(), (msg.len() * 8) as i64);
            let hashed = sha256(msg.as_bytes());
            assert_eq!(finalized, hashed, "mismatch for {:?}", msg);
        }
    }

    // -- BLAKE3 single-block compression -------------------------------------
    //
    // The expected hex strings below are the cross-language reference vectors
    // pinned in `packages/runar-py/tests/test_blake3.py` and matched by the
    // Go runtime in `packages/runar-go/blake3_test.go`. Any divergence is a
    // cross-compiler regression.

    #[test]
    fn test_blake3_hash_matches_cross_language_reference() {
        let cases: &[(&[u8], &str)] = &[
            (b"", "7669004d96866a6330a609d9ad1a08a4f8507c4d04eefd1a50f00b02556aab86"),
            (b"abc", "6f9871b5d6e80fc882e7bb57857f8b279cdc229664eab9382d2838dbf7d8a20d"),
            (b"hello world", "47d3d7048c7ed47c986773cc1eefaa0b356bec676dd62cca3269a086999d65fc"),
        ];
        for (msg, expected) in cases {
            let got = blake3_hash(msg);
            assert_eq!(
                hex_encode(&got),
                *expected,
                "blake3_hash({:?}) mismatch",
                msg,
            );
        }
    }

    #[test]
    fn test_blake3_compress_not_zero_stub() {
        // Guards against regression back to the all-zero stub.
        let out = blake3_compress(&[0u8; 32], &[0u8; 64]);
        assert_eq!(out.len(), 32);
        assert_ne!(out, vec![0u8; 32], "blake3_compress(0,0) returned zero stub");
    }

    #[test]
    fn test_blake3_hash_equivalent_to_compression_with_iv() {
        // blake3_hash(msg) == blake3_compress(IV, zero-pad(msg, 64)).
        let cv = blake3_iv_bytes();
        for msg in &[&b""[..], &b"abc"[..], &b"hello world"[..], &[0x19, 0x76, 0xa9, 0x14][..]] {
            let mut padded = vec![0u8; 64];
            let n = msg.len().min(64);
            padded[..n].copy_from_slice(&msg[..n]);
            let direct = blake3_compress(&cv, &padded);
            let via_hash = blake3_hash(msg);
            assert_eq!(direct, via_hash, "mismatch for {:?}", msg);
        }
    }

    #[test]
    fn test_blake3_compress_determinism() {
        let cv: Vec<u8> = (0u8..32).collect();
        let block: Vec<u8> = (0u8..64).collect();
        let a = blake3_compress(&cv, &block);
        let b = blake3_compress(&cv, &block);
        assert_eq!(a, b);
        assert_eq!(a.len(), 32);
    }
}
