//! Real ECDSA signing and verification for contract testing.
//!
//! Instead of mocking `check_sig` to always return true, we use a fixed test
//! message so that signature verification is real ECDSA (secp256k1).
//!
//! `TEST_MESSAGE` is the UTF-8 encoding of `"runar-test-message-v1"`.
//! The k256 `Signer` trait internally SHA-256 hashes this before signing,
//! so the actual ECDSA digest is:
//!   SHA256("runar-test-message-v1") =
//!     ee5e6c74a298854942a9eadd789f2812b38936691230134ad50b884cc1f119fa

use k256::ecdsa::{
    signature::{Signer, Verifier},
    Signature, SigningKey, VerifyingKey,
};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// The raw test message bytes (UTF-8 encoding of "runar-test-message-v1").
pub const TEST_MESSAGE: &[u8] = b"runar-test-message-v1";

/// SHA256(TEST_MESSAGE) as a hex string, for cross-language reference.
pub const TEST_MESSAGE_DIGEST: &str =
    "ee5e6c74a298854942a9eadd789f2812b38936691230134ad50b884cc1f119fa";

// ---------------------------------------------------------------------------
// Signing helpers
// ---------------------------------------------------------------------------

/// Compute SHA256 of TEST_MESSAGE, returning 32 bytes.
pub fn test_message_digest() -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let hash = Sha256::digest(TEST_MESSAGE);
    let mut out = [0u8; 32];
    out.copy_from_slice(&hash);
    out
}

/// Sign the fixed test message with a hex-encoded private key.
/// Returns DER-encoded ECDSA signature bytes.
///
/// The k256 `Signer<Signature>` trait hashes the message with SHA-256
/// internally before signing (standard ECDSA for secp256k1), which
/// matches the TypeScript `@bsv/sdk` behavior.
pub fn sign_test_message(priv_key_hex: &str) -> Vec<u8> {
    let sk_bytes = hex_to_bytes(priv_key_hex);
    let signing_key = SigningKey::from_slice(&sk_bytes).expect("invalid private key");
    let sig: Signature = signing_key.sign(TEST_MESSAGE);
    sig.to_der().as_bytes().to_vec()
}

/// Derive the compressed public key from a hex-encoded private key.
/// Returns 33-byte SEC1 compressed encoding.
pub fn pub_key_from_priv_key(priv_key_hex: &str) -> Vec<u8> {
    let sk_bytes = hex_to_bytes(priv_key_hex);
    let signing_key = SigningKey::from_slice(&sk_bytes).expect("invalid private key");
    let verifying_key = VerifyingKey::from(&signing_key);
    verifying_key.to_sec1_bytes().to_vec()
}

// ---------------------------------------------------------------------------
// Verification
// ---------------------------------------------------------------------------

/// Verify an ECDSA signature against a public key over TEST_MESSAGE.
///
/// Handles:
///   - Raw DER signature bytes
///   - DER + trailing sighash byte (detected by DER envelope length)
///
/// Returns `true` if the signature is valid.
pub fn ecdsa_verify(sig_bytes: &[u8], pk_bytes: &[u8]) -> bool {
    if sig_bytes.len() < 8 || pk_bytes.is_empty() {
        return false;
    }

    // Parse the public key
    let vk = match VerifyingKey::from_sec1_bytes(pk_bytes) {
        Ok(vk) => vk,
        Err(_) => return false,
    };

    // Strip trailing sighash byte if present.
    // DER format: 0x30 [totalLen] ...
    // Pure DER length = bytes[1] + 2 (tag + length byte + content)
    // If actual length = pure DER + 1, strip the trailing byte.
    let der_bytes = strip_sighash(sig_bytes);

    let sig = match Signature::from_der(der_bytes) {
        Ok(s) => s,
        Err(_) => return false,
    };

    vk.verify(TEST_MESSAGE, &sig).is_ok()
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/// Strip trailing sighash byte from a DER-encoded signature if present.
fn strip_sighash(sig_bytes: &[u8]) -> &[u8] {
    if sig_bytes.len() < 2 || sig_bytes[0] != 0x30 {
        return sig_bytes;
    }
    let declared_len = sig_bytes[1] as usize;
    let expected_pure_der = declared_len + 2;
    if sig_bytes.len() == expected_pure_der + 1 {
        // Trailing sighash byte detected
        &sig_bytes[..expected_pure_der]
    } else {
        sig_bytes
    }
}

fn hex_to_bytes(hex: &str) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(hex.len() / 2);
    let mut i = 0;
    while i < hex.len() {
        let byte = u8::from_str_radix(&hex[i..i + 2], 16).expect("invalid hex");
        bytes.push(byte);
        i += 2;
    }
    bytes
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    const ALICE_PRIV: &str =
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
    const ALICE_PUB_HEX: &str =
        "03a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd";

    #[test]
    fn test_message_digest_matches() {
        let digest = test_message_digest();
        let hex: String = digest.iter().map(|b| format!("{:02x}", b)).collect();
        assert_eq!(hex, TEST_MESSAGE_DIGEST);
    }

    #[test]
    fn test_pub_key_derivation() {
        let pk = pub_key_from_priv_key(ALICE_PRIV);
        let hex: String = pk.iter().map(|b| format!("{:02x}", b)).collect();
        assert_eq!(hex, ALICE_PUB_HEX);
        assert_eq!(pk.len(), 33);
    }

    #[test]
    fn test_sign_and_verify() {
        let sig = sign_test_message(ALICE_PRIV);
        let pk = pub_key_from_priv_key(ALICE_PRIV);
        assert!(ecdsa_verify(&sig, &pk));
    }

    #[test]
    fn test_verify_rejects_wrong_key() {
        let sig = sign_test_message(ALICE_PRIV);
        let bob_priv = "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2";
        let bob_pk = pub_key_from_priv_key(bob_priv);
        assert!(!ecdsa_verify(&sig, &bob_pk));
    }

    #[test]
    fn test_verify_with_sighash_byte() {
        let mut sig = sign_test_message(ALICE_PRIV);
        sig.push(0x41); // Append SIGHASH_ALL|FORKID
        let pk = pub_key_from_priv_key(ALICE_PRIV);
        assert!(ecdsa_verify(&sig, &pk));
    }

    #[test]
    fn test_verify_rejects_garbage() {
        let pk = pub_key_from_priv_key(ALICE_PRIV);
        assert!(!ecdsa_verify(&[0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01], &pk));
    }

    #[test]
    fn test_deterministic_signatures() {
        // RFC 6979 should produce deterministic signatures
        let sig1 = sign_test_message(ALICE_PRIV);
        let sig2 = sign_test_message(ALICE_PRIV);
        assert_eq!(sig1, sig2);
    }

    #[test]
    fn test_known_alice_signature() {
        // Cross-check with TypeScript test-keys.ts ALICE.testSig
        let expected_hex = "3045022100e2aa1265ce57f54b981ffc6a5f3d229e908d7772fceb75a50c8c2d6076313df00220607dbca2f9f695438b49eefea4e445664c740163af8b62b1373f87d50eb64417";
        let sig = sign_test_message(ALICE_PRIV);
        let sig_hex: String = sig.iter().map(|b| format!("{:02x}", b)).collect();
        assert_eq!(sig_hex, expected_hex);
    }
}
