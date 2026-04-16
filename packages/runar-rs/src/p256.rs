//! P-256 (NIST P-256 / secp256r1) off-chain helpers for testing Rúnar contracts.
//!
//! These functions use the `p256` crate for real P-256 operations.
//! They are not compiled into Bitcoin Script — they exist so Rust contract tests
//! can generate keys, sign messages, and verify P-256 signatures.
//!
//! `P256KeyPair` holds a random P-256 key pair. `p256_sign` signs a message
//! (SHA-256 hashed internally). `verify_ecdsa_p256` verifies a raw r||s signature
//! against a 33-byte compressed public key.

use p256::ecdsa::{signature::DigestSigner, SigningKey, VerifyingKey, Signature};
use p256::ecdsa::signature::DigestVerifier;
use sha2::{Digest, Sha256};
use rand::rngs::OsRng;

/// A P-256 key pair.
pub struct P256KeyPair {
    sk: SigningKey,
    /// 64-byte uncompressed public key encoding: x[32] || y[32].
    pub pk: Vec<u8>,
    /// 33-byte compressed public key: (02/03) prefix + x[32].
    pub pk_compressed: Vec<u8>,
}

/// Generate a random P-256 key pair.
pub fn p256_keygen() -> P256KeyPair {
    let sk = SigningKey::random(&mut OsRng);
    let vk = sk.verifying_key();
    let point = vk.to_encoded_point(false); // uncompressed
    let coords = point.as_bytes();
    // uncompressed: 0x04 || x[32] || y[32] → strip prefix
    let pk = coords[1..].to_vec(); // 64 bytes

    let compressed_point = vk.to_encoded_point(true);
    let pk_compressed = compressed_point.as_bytes().to_vec();

    P256KeyPair { sk, pk, pk_compressed }
}

/// Sign `msg` with P-256 ECDSA. The message is SHA-256 hashed internally.
/// Returns a 64-byte raw signature: r[32] || s[32] (big-endian, zero-padded).
pub fn p256_sign(msg: &[u8], kp: &P256KeyPair) -> Vec<u8> {
    let digest = Sha256::new_with_prefix(msg);
    let sig: Signature = kp.sk.sign_digest(digest);
    let bytes = sig.to_bytes();
    bytes.to_vec()
}

/// Verify a P-256 ECDSA signature.
///
/// - `msg`: raw message (SHA-256 hashed internally).
/// - `sig`: 64-byte raw signature r[32] || s[32].
/// - `pubkey`: 33-byte compressed P-256 public key (02/03 prefix + x[32]).
pub fn verify_ecdsa_p256(msg: &[u8], sig: &[u8], pubkey: &[u8]) -> bool {
    if sig.len() != 64 {
        return false;
    }
    let vk = match VerifyingKey::from_sec1_bytes(pubkey) {
        Ok(k) => k,
        Err(_) => return false,
    };
    let sig = match Signature::from_slice(sig) {
        Ok(s) => s,
        Err(_) => return false,
    };
    let digest = Sha256::new_with_prefix(msg);
    vk.verify_digest(digest, &sig).is_ok()
}
