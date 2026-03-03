//! Prelude — import everything needed for Rúnar contract development.
//!
//! ```ignore
//! use runar::prelude::*;
//! ```

use sha2::{Digest, Sha256 as Sha256Hasher};

// Re-export macros so `use runar::prelude::*` gets them too.
pub use runar_macros::{contract, methods, public, stateful_contract};

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
// Inductive smart contract support
// ---------------------------------------------------------------------------

/// Base struct for inductive Rúnar contracts.
///
/// Inductive contracts extend stateful contracts with chain-of-custody
/// tracking via parent transaction introspection. The compiler auto-injects
/// parentTx verification at method entry.
///
/// Fields:
/// - `genesis_outpoint`: The outpoint of the original deployment transaction.
/// - `parent_outpoint`: The outpoint of the immediate parent transaction.
/// - `grandparent_outpoint`: The outpoint of the parent's parent transaction.
/// - `outputs`: Recorded outputs from `add_output` calls.
/// - `tx_preimage`: The sighash preimage for transaction validation.
#[derive(Debug, Clone)]
pub struct InductiveSmartContract {
    pub genesis_outpoint: ByteString,
    pub parent_outpoint: ByteString,
    pub grandparent_outpoint: ByteString,
    pub outputs: Vec<OutputSnapshot>,
    pub tx_preimage: SigHashPreimage,
}

impl InductiveSmartContract {
    /// Create a new InductiveSmartContract with the given outpoints.
    pub fn new(
        genesis_outpoint: ByteString,
        parent_outpoint: ByteString,
        grandparent_outpoint: ByteString,
    ) -> Self {
        Self {
            genesis_outpoint,
            parent_outpoint,
            grandparent_outpoint,
            outputs: Vec::new(),
            tx_preimage: Vec::new(),
        }
    }

    /// Record a new output with the given satoshis and state values.
    pub fn add_output(&mut self, satoshis: Bigint, values: Vec<Vec<u8>>) {
        self.outputs.push(OutputSnapshot { satoshis, values });
    }

    /// Returns a mock state script (empty bytes in test mode).
    pub fn get_state_script(&self) -> ByteString {
        vec![]
    }

    /// Returns the recorded outputs.
    pub fn outputs(&self) -> &[OutputSnapshot] {
        &self.outputs
    }

    /// Clears recorded outputs (call between test method invocations).
    pub fn reset_outputs(&mut self) {
        self.outputs.clear();
    }
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

/// Always returns `true` in test mode.
/// Real WOTS+ verification happens in compiled Bitcoin Script.
pub fn verify_wots(_msg: &[u8], _sig: &[u8], _pk: &[u8]) -> bool {
    true
}

// SLH-DSA (SPHINCS+) SHA-256 variants — all return true in test mode.

pub fn verify_slh_dsa_sha2_128s(_msg: &[u8], _sig: &[u8], _pk: &[u8]) -> bool { true }
pub fn verify_slh_dsa_sha2_128f(_msg: &[u8], _sig: &[u8], _pk: &[u8]) -> bool { true }
pub fn verify_slh_dsa_sha2_192s(_msg: &[u8], _sig: &[u8], _pk: &[u8]) -> bool { true }
pub fn verify_slh_dsa_sha2_192f(_msg: &[u8], _sig: &[u8], _pk: &[u8]) -> bool { true }
pub fn verify_slh_dsa_sha2_256s(_msg: &[u8], _sig: &[u8], _pk: &[u8]) -> bool { true }
pub fn verify_slh_dsa_sha2_256f(_msg: &[u8], _sig: &[u8], _pk: &[u8]) -> bool { true }

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

/// Returns a mock state script (empty bytes).
pub fn get_state_script<T>(_contract: &T) -> ByteString {
    vec![]
}

// ---------------------------------------------------------------------------
// Utility functions
// ---------------------------------------------------------------------------

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

/// Exponentiation for non-negative exponents.
pub fn pow(base: Int, exp: Int) -> Int {
    assert!(exp >= 0, "pow: negative exponent");
    let mut result: Int = 1;
    for _ in 0..exp { result *= base; }
    result
}

/// (a * b) / c without intermediate overflow concern.
pub fn mul_div(a: Int, b: Int, c: Int) -> Int {
    assert!(c != 0, "mulDiv: division by zero");
    (a * b) / c
}

/// (amount * bps) / 10000 — basis point percentage.
pub fn percent_of(amount: Int, bps: Int) -> Int {
    (amount * bps) / 10000
}

/// Integer square root via Newton's method.
pub fn sqrt(n: Int) -> Int {
    assert!(n >= 0, "sqrt: negative input");
    if n == 0 { return 0; }
    let mut guess = n;
    for _ in 0..256 {
        let next = (guess + n / guess) / 2;
        if next >= guess { break; }
        guess = next;
    }
    guess
}

/// Greatest common divisor via Euclidean algorithm.
pub fn gcd(mut a: Int, mut b: Int) -> Int {
    a = a.abs();
    b = b.abs();
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
}
