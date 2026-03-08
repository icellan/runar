//! Prelude — import everything needed for Rúnar contract development.
//!
//! ```ignore
//! use runar::prelude::*;
//! ```

use sha2::{Digest, Sha256 as Sha256Hasher};

// Re-export macros so `use runar::prelude::*` gets them too.
pub use runar_lang_macros::{contract, methods, public, stateful_contract};

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
// Mock crypto — always succeed for testing business logic
// ---------------------------------------------------------------------------

/// Always returns `true` in test mode.
pub fn check_sig(_sig: &[u8], _pk: &[u8]) -> bool {
    true
}

/// Always returns `true` in test mode.
pub fn check_multi_sig(_sigs: &[&[u8]], _pks: &[&[u8]]) -> bool {
    true
}

/// Always returns `true` in test mode.
pub fn check_preimage(_preimage: &[u8]) -> bool {
    true
}

/// Always returns `true` in test mode.
pub fn verify_rabin_sig(_msg: &[u8], _sig: &[u8], _padding: &[u8], _pk: &[u8]) -> bool {
    true
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

pub use crate::slh_dsa::{
    slh_keygen, slh_sign, slh_verify, SlhKeyPair, SlhParams,
    SLH_SHA2_128S, SLH_SHA2_128F, SLH_SHA2_192S, SLH_SHA2_192F,
    SLH_SHA2_256S, SLH_SHA2_256F,
};

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

/// Single RIPEMD-160 hash.
pub fn ripemd160(data: &[u8]) -> Ripemd160 {
    let mut hasher = ripemd::Ripemd160::new();
    hasher.update(data);
    hasher.finalize().to_vec()
}

// ---------------------------------------------------------------------------
// Mock preimage extraction functions
// ---------------------------------------------------------------------------

/// Returns 0 in test mode.
pub fn extract_locktime(_p: &[u8]) -> Int {
    0
}

/// Returns 32 zero bytes in test mode.
pub fn extract_output_hash(_p: &[u8]) -> ByteString {
    vec![0u8; 32]
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
    fn test_check_sig_always_true() {
        assert!(check_sig(&mock_sig(), &mock_pub_key()));
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
}
