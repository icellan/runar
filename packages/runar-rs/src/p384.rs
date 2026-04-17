//! P-384 (NIST P-384 / secp384r1) off-chain helpers for testing Rúnar contracts.
//!
//! These functions use the `p384` crate for real P-384 operations.
//! They are not compiled into Bitcoin Script — they exist so Rust contract tests
//! can generate keys, sign messages, and verify P-384 signatures.
//!
//! `P384KeyPair` holds a random P-384 key pair. `p384_sign` signs a message
//! (SHA-256 hashed internally, matching the on-chain codegen which uses OP_SHA256
//! for both P-256 and P-384). `verify_ecdsa_p384` verifies a raw r||s signature
//! against a 49-byte compressed public key.
//!
//! Note: P-384 ECDSA normally uses SHA-384. The on-chain codegen uses OP_SHA256
//! for both P-256 and P-384 for script-size reasons, so these helpers mirror
//! that choice by hashing with SHA-256 and calling the prehash signing API.

use p384::ecdsa::{signature::hazmat::{PrehashSigner, PrehashVerifier}, SigningKey, VerifyingKey, Signature};
use sha2::{Digest, Sha256};
use rand::rngs::OsRng;

/// A P-384 key pair.
pub struct P384KeyPair {
    sk: SigningKey,
    /// 96-byte uncompressed public key encoding: x[48] || y[48].
    pub pk: Vec<u8>,
    /// 49-byte compressed public key: (02/03) prefix + x[48].
    pub pk_compressed: Vec<u8>,
}

/// Generate a random P-384 key pair.
pub fn p384_keygen() -> P384KeyPair {
    let sk = SigningKey::random(&mut OsRng);
    let vk = sk.verifying_key();
    let point = vk.to_encoded_point(false); // uncompressed
    let coords = point.as_bytes();
    // uncompressed: 0x04 || x[48] || y[48] → strip prefix
    let pk = coords[1..].to_vec(); // 96 bytes

    let compressed_point = vk.to_encoded_point(true);
    let pk_compressed = compressed_point.as_bytes().to_vec();

    P384KeyPair { sk, pk, pk_compressed }
}

/// Sign `msg` with P-384 ECDSA. The message is SHA-256 hashed internally
/// (matching the on-chain codegen which uses OP_SHA256 for both curves).
/// Returns a 96-byte raw signature: r[48] || s[48] (big-endian, zero-padded).
pub fn p384_sign(msg: &[u8], kp: &P384KeyPair) -> Vec<u8> {
    let digest = Sha256::digest(msg);
    let sig: Signature = kp.sk.sign_prehash(&digest)
        .expect("p384_sign: sign_prehash failed");
    let bytes = sig.to_bytes();
    bytes.to_vec()
}

/// Verify a P-384 ECDSA signature.
///
/// - `msg`: raw message (SHA-256 hashed internally).
/// - `sig`: 96-byte raw signature r[48] || s[48].
/// - `pubkey`: 49-byte compressed P-384 public key (02/03 prefix + x[48]).
pub fn verify_ecdsa_p384(msg: &[u8], sig: &[u8], pubkey: &[u8]) -> bool {
    if sig.len() != 96 {
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
    let digest = Sha256::digest(msg);
    vk.verify_prehash(&digest, &sig).is_ok()
}
