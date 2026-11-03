//! Real Rabin signature verification for contract testing.
//!
//! Rabin verification: `(sig^2 + padding) mod n == SHA256(msg) mod n`
//! where `n` is the Rabin public key (product of two secret primes),
//! `sig` is the Rabin signature, and `padding` is chosen by the signer
//! to make the hash a quadratic residue mod n.
//!
//! All byte values (sig, padding, pubkey) are interpreted as unsigned
//! little-endian big integers, matching Bitcoin Script's OP_MOD / OP_ADD.

use sha2::{Digest, Sha256};

// ---------------------------------------------------------------------------
// Simple big integer arithmetic (unsigned, for Rabin verification only)
// ---------------------------------------------------------------------------
// We implement a minimal BigUint backed by Vec<u64> to avoid adding an
// external dependency. Only the operations needed for Rabin verification
// are implemented: from_le_bytes, mul, add, rem, eq, and comparisons.

/// Unsigned big integer backed by limbs in little-endian order (least
/// significant limb first). Each limb is a u64.
#[derive(Clone, Debug, PartialEq, Eq)]
struct BigUint {
    limbs: Vec<u64>,
}

impl BigUint {
    fn zero() -> Self {
        BigUint { limbs: vec![0] }
    }

    fn is_zero(&self) -> bool {
        self.limbs.iter().all(|&l| l == 0)
    }

    /// Construct from little-endian bytes.
    fn from_le_bytes(bytes: &[u8]) -> Self {
        if bytes.is_empty() {
            return Self::zero();
        }
        let mut limbs = Vec::new();
        let mut i = 0;
        while i < bytes.len() {
            let mut limb: u64 = 0;
            for j in 0..8 {
                if i + j < bytes.len() {
                    limb |= (bytes[i + j] as u64) << (j * 8);
                }
            }
            limbs.push(limb);
            i += 8;
        }
        // Trim trailing zero limbs (but keep at least one)
        while limbs.len() > 1 && limbs.last() == Some(&0) {
            limbs.pop();
        }
        BigUint { limbs }
    }

    /// Number of significant limbs.
    fn len(&self) -> usize {
        self.limbs.len()
    }

    /// Compare: returns Ordering.
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        let a_len = self.len();
        let b_len = other.len();
        if a_len != b_len {
            return a_len.cmp(&b_len);
        }
        for i in (0..a_len).rev() {
            let a = self.limbs[i];
            let b = other.limbs[i];
            if a != b {
                return a.cmp(&b);
            }
        }
        std::cmp::Ordering::Equal
    }

    /// Addition.
    fn add(&self, other: &Self) -> Self {
        let max_len = self.len().max(other.len());
        let mut result = Vec::with_capacity(max_len + 1);
        let mut carry: u64 = 0;
        for i in 0..max_len {
            let a = if i < self.len() { self.limbs[i] } else { 0 };
            let b = if i < other.len() { other.limbs[i] } else { 0 };
            let (s1, c1) = a.overflowing_add(b);
            let (s2, c2) = s1.overflowing_add(carry);
            result.push(s2);
            carry = (c1 as u64) + (c2 as u64);
        }
        if carry > 0 {
            result.push(carry);
        }
        while result.len() > 1 && result.last() == Some(&0) {
            result.pop();
        }
        BigUint { limbs: result }
    }

    /// Multiplication.
    fn mul(&self, other: &Self) -> Self {
        let n = self.len();
        let m = other.len();
        let mut result = vec![0u64; n + m];
        for i in 0..n {
            let mut carry: u64 = 0;
            for j in 0..m {
                let prod = (self.limbs[i] as u128) * (other.limbs[j] as u128)
                    + result[i + j] as u128
                    + carry as u128;
                result[i + j] = prod as u64;
                carry = (prod >> 64) as u64;
            }
            result[i + m] += carry;
        }
        while result.len() > 1 && result.last() == Some(&0) {
            result.pop();
        }
        BigUint { limbs: result }
    }

    /// Remainder (self % divisor). Panics if divisor is zero.
    fn rem(&self, divisor: &Self) -> Self {
        assert!(!divisor.is_zero(), "division by zero");
        if self.cmp(divisor) == std::cmp::Ordering::Less {
            return self.clone();
        }

        // Long division using base-2^64 digits
        let mut remainder = BigUint::zero();

        // Process bits from MSB to LSB
        let total_bits = self.len() * 64;
        for bit_idx in (0..total_bits).rev() {
            // Shift remainder left by 1 bit
            let mut carry = 0u64;
            for limb in remainder.limbs.iter_mut() {
                let new_carry = *limb >> 63;
                *limb = (*limb << 1) | carry;
                carry = new_carry;
            }
            if carry > 0 {
                remainder.limbs.push(carry);
            }

            // Set the lowest bit of remainder to the current bit of self
            let limb_idx = bit_idx / 64;
            let bit_pos = bit_idx % 64;
            if limb_idx < self.len() && (self.limbs[limb_idx] >> bit_pos) & 1 == 1 {
                remainder.limbs[0] |= 1;
            }

            // If remainder >= divisor, subtract
            if remainder.cmp(divisor) != std::cmp::Ordering::Less {
                remainder = remainder.sub(divisor);
            }
        }

        // Trim trailing zeros
        while remainder.limbs.len() > 1 && remainder.limbs.last() == Some(&0) {
            remainder.limbs.pop();
        }
        remainder
    }

    /// Subtraction (self - other). Panics on underflow.
    fn sub(&self, other: &Self) -> Self {
        assert!(
            self.cmp(other) != std::cmp::Ordering::Less,
            "BigUint subtraction underflow"
        );
        let mut result = Vec::with_capacity(self.len());
        let mut borrow: u64 = 0;
        for i in 0..self.len() {
            let a = self.limbs[i];
            let b = if i < other.len() { other.limbs[i] } else { 0 };
            let (s1, c1) = a.overflowing_sub(b);
            let (s2, c2) = s1.overflowing_sub(borrow);
            result.push(s2);
            borrow = (c1 as u64) + (c2 as u64);
        }
        while result.len() > 1 && result.last() == Some(&0) {
            result.pop();
        }
        BigUint { limbs: result }
    }
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Upper bound (exclusive) on the Rabin padding value.
///
/// Mirrors the on-chain OP_WITHIN bound `0 <= padding < 65536` enforced by the
/// Rabin codegen. Without this guard the off-chain verifier accepts a universal
/// forgery the deployed script rejects: setting `sig = 0` and
/// `padding = SHA256(msg)` trivially satisfies
/// `(0^2 + SHA256(msg)) mod n == SHA256(msg) mod n`. The on-chain script blocks
/// it because SHA256(msg) is a 256-bit value far larger than 65536.
const RABIN_PADDING_LIMIT: u64 = 65536;

/// Verify a Rabin signature.
///
/// Equation: `(sig^2 + padding) mod n == SHA256(msg) mod n`
///
/// All byte slices are interpreted as unsigned little-endian big integers.
///
/// # Arguments
/// * `msg` - The message bytes
/// * `sig` - Rabin signature bytes (unsigned LE)
/// * `padding` - Padding bytes (unsigned LE)
/// * `pubkey` - Rabin public key / modulus bytes (unsigned LE)
pub fn rabin_verify(msg: &[u8], sig: &[u8], padding: &[u8], pubkey: &[u8]) -> bool {
    let n = BigUint::from_le_bytes(pubkey);
    if n.is_zero() {
        return false;
    }

    let hash = Sha256::digest(msg);
    let hash_bn = BigUint::from_le_bytes(&hash);
    let sig_bn = BigUint::from_le_bytes(sig);
    let pad_bn = BigUint::from_le_bytes(padding);

    // Enforce the on-chain OP_WITHIN bound `0 <= padding < 65536`. BigUint is
    // unsigned so the lower bound is automatic; reject any padding at/above the
    // limit (more than one limb, or a single limb >= RABIN_PADDING_LIMIT). This
    // blocks the sig=0 / padding=SHA256(msg) universal forgery.
    let pad_limit = BigUint::from_le_bytes(&RABIN_PADDING_LIMIT.to_le_bytes());
    if pad_bn.cmp(&pad_limit) != std::cmp::Ordering::Less {
        return false;
    }

    // Enforce sig < n, mirroring the on-chain F-368 gate: sig + k*n squares to
    // the same residue but the deployed script aborts on it.
    if sig_bn.cmp(&n) != std::cmp::Ordering::Less {
        return false;
    }

    let sig_sq = sig_bn.mul(&sig_bn);
    let lhs_sum = sig_sq.add(&pad_bn);
    let lhs = lhs_sum.rem(&n);
    let rhs = hash_bn.rem(&n);

    lhs == rhs
}

/// Create a trivial Rabin "signature" for testing purposes.
///
/// Uses sig=0, padding = SHA256(msg) mod n. This satisfies the Rabin
/// verification equation: `(0^2 + padding) mod n == SHA256(msg) mod n`.
///
/// Returns `(sig_bytes, padding_bytes)` as little-endian unsigned byte vectors.
///
/// This is NOT cryptographically secure -- it's only for testing contracts
/// that use `verify_rabin_sig` without needing a real Rabin private key.
pub fn rabin_sign_trivial(msg: &[u8], pubkey: &[u8]) -> (Vec<u8>, Vec<u8>) {
    let n = BigUint::from_le_bytes(pubkey);
    assert!(!n.is_zero(), "Rabin pubkey cannot be zero");

    let hash = Sha256::digest(msg);
    let hash_bn = BigUint::from_le_bytes(&hash);
    let padding = hash_bn.rem(&n);

    // Convert padding back to LE bytes
    let mut pad_bytes = Vec::new();
    for &limb in &padding.limbs {
        pad_bytes.extend_from_slice(&limb.to_le_bytes());
    }
    // Trim trailing zeros but keep at least one byte
    while pad_bytes.len() > 1 && pad_bytes.last() == Some(&0) {
        pad_bytes.pop();
    }

    let sig_bytes = vec![0u8];
    (sig_bytes, pad_bytes)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_biguint_from_le_bytes() {
        let b = BigUint::from_le_bytes(&[1, 0, 0, 0]);
        assert_eq!(b.limbs, vec![1]);

        let b = BigUint::from_le_bytes(&[0xff, 0]);
        assert_eq!(b.limbs, vec![255]);
    }

    #[test]
    fn test_biguint_add() {
        let a = BigUint::from_le_bytes(&[255, 255, 255, 255, 255, 255, 255, 255]); // u64::MAX
        let b = BigUint::from_le_bytes(&[1]);
        let c = a.add(&b);
        assert_eq!(c.limbs, vec![0, 1]); // 2^64
    }

    #[test]
    fn test_biguint_mul() {
        let a = BigUint::from_le_bytes(&[10, 0, 0, 0]);
        let b = BigUint::from_le_bytes(&[20, 0, 0, 0]);
        let c = a.mul(&b);
        assert_eq!(c.limbs, vec![200]);
    }

    #[test]
    fn test_biguint_rem() {
        let a = BigUint::from_le_bytes(&[10, 0, 0, 0]);
        let b = BigUint::from_le_bytes(&[3, 0, 0, 0]);
        let c = a.rem(&b);
        assert_eq!(c.limbs, vec![1]);
    }

    #[test]
    fn test_rabin_verify_trivial() {
        // Construct a trivial Rabin verification:
        // msg such that SHA256(msg) = H
        // n = some modulus
        // sig = 0, padding = H mod n => (0 + H mod n) mod n == H mod n
        let msg = b"test message";
        let hash = Sha256::digest(msg);

        // Use a small modulus for testing (not cryptographically secure)
        let n_val: u64 = 997; // prime
        let n_bytes = n_val.to_le_bytes();

        // hash mod n
        let hash_bn = BigUint::from_le_bytes(&hash);
        let n_bn = BigUint::from_le_bytes(&n_bytes);
        let remainder = hash_bn.rem(&n_bn);

        // padding = hash mod n (so sig=0 works)
        let pad_val = remainder.limbs[0];
        let pad_bytes = pad_val.to_le_bytes();

        let sig_bytes = [0u8; 1]; // sig = 0
        assert!(rabin_verify(msg, &sig_bytes, &pad_bytes, &n_bytes));
    }

    #[test]
    fn test_rabin_verify_rejects_padding_forgery() {
        // Universal forgery: sig = 0, padding = SHA256(msg) (the *raw* 256-bit
        // hash, not reduced mod n). It satisfies the bare equation
        // (0^2 + SHA256(msg)) mod n == SHA256(msg) mod n, but SHA256(msg) is a
        // 256-bit value far above the on-chain OP_WITHIN limit of 65536, so the
        // off-chain verifier must reject it just like the deployed script does.
        let msg = b"test message";
        let hash = Sha256::digest(msg);

        let n_val: u64 = 997; // prime, same modulus family as other tests
        let n_bytes = n_val.to_le_bytes();

        let sig_bytes = [0u8; 1]; // sig = 0
        let pad_bytes = hash.to_vec(); // padding = raw SHA256(msg), >= 65536

        assert!(
            !rabin_verify(msg, &sig_bytes, &pad_bytes, &n_bytes),
            "padding=SHA256(msg) forgery must be rejected by the off-chain verifier"
        );
    }

    #[test]
    fn test_rabin_verify_accepts_honest_sig_under_padding_bound() {
        // An honestly-signed signature whose padding is within [0, 65536) must
        // still verify true. We search for a (sig, padding) pair satisfying
        // (sig^2 + padding) mod n == SHA256(msg) mod n with 0 <= padding < 65536.
        let msg = b"test message";
        let hash = Sha256::digest(msg);

        let n_val: u64 = 997;
        let n_bytes = n_val.to_le_bytes();

        let n_bn = BigUint::from_le_bytes(&n_bytes);
        let rhs = BigUint::from_le_bytes(&hash).rem(&n_bn).limbs[0];

        // Find sig such that padding = (rhs - sig^2 mod n) mod n stays < 65536.
        // With n = 997 every residue is < 997 < 65536, so any sig works; pick a
        // nonzero one to exercise the sig^2 term.
        let sig_val: u64 = 42;
        let sig_sq_mod = (sig_val * sig_val) % n_val;
        let padding_val = (rhs + n_val - sig_sq_mod) % n_val; // (rhs - sig^2) mod n
        assert!(padding_val < RABIN_PADDING_LIMIT);

        let sig_bytes = sig_val.to_le_bytes();
        let pad_bytes = padding_val.to_le_bytes();

        assert!(
            rabin_verify(msg, &sig_bytes, &pad_bytes, &n_bytes),
            "honestly-signed signature with padding < 65536 must verify true"
        );
    }

    // N-380 (F-368 follow-up): the script asserts sig < n, so sig + k*n aborts
    // on chain. Proves: canonical sig and n - sig accepted; sig + n, sig + 2n
    // rejected. Does not prove the verdict equals the consensus interpreter's.
    #[test]
    fn test_rabin_verify_rejects_non_canonical_sig_ge_n() {
        let msg = b"test message";
        let hash = Sha256::digest(msg);
        let n_val: u64 = 997;
        let n_bytes = n_val.to_le_bytes();
        let rhs = BigUint::from_le_bytes(&hash)
            .rem(&BigUint::from_le_bytes(&n_bytes))
            .limbs[0];
        let sig_val: u64 = 42;
        let padding_val = (rhs + n_val - (sig_val * sig_val) % n_val) % n_val;
        let pad_bytes = padding_val.to_le_bytes();

        for s in [sig_val, n_val - sig_val] {
            assert!(
                rabin_verify(msg, &s.to_le_bytes(), &pad_bytes, &n_bytes),
                "canonical sig {s} must verify"
            );
        }
        for k in 1..=2u64 {
            let s = sig_val + k * n_val;
            assert!(
                !rabin_verify(msg, &s.to_le_bytes(), &pad_bytes, &n_bytes),
                "sig + {k}*n must be rejected"
            );
        }
    }

    #[test]
    fn test_rabin_verify_rejects_wrong_sig() {
        let msg = b"test message";
        let n_val: u64 = 997;
        let n_bytes = n_val.to_le_bytes();
        let sig_bytes = [42u8, 0, 0, 0, 0, 0, 0, 0];
        let pad_bytes = [0u8; 1];
        // This should almost certainly fail
        assert!(!rabin_verify(msg, &sig_bytes, &pad_bytes, &n_bytes));
    }
}
