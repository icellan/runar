//! Pre-generated deterministic test keys for use across all Rust test suites.
//!
//! All derived values (public key, pubkey hash) match the TypeScript test-keys.ts
//! values exactly. Use these instead of generating random keys in tests for full
//! reproducibility.

/// A pre-computed test key pair with derived values.
pub struct TestKeyPair {
    /// Hex-encoded private key (64 chars).
    pub priv_key: &'static str,
    /// Compressed public key (33 bytes, SEC1).
    pub pub_key: &'static [u8],
    /// HASH160 of the compressed public key (20 bytes).
    pub pub_key_hash: &'static [u8],
}

impl TestKeyPair {
    /// Sign the fixed TEST_MESSAGE and return DER-encoded signature bytes.
    pub fn sign_test_message(&self) -> Vec<u8> {
        crate::ecdsa::sign_test_message(self.priv_key)
    }
}

/// Alice's test key pair.
/// privKey: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
/// pubKey: 03a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd
/// pubKeyHash: 9a1c78a507689f6f54b847ad1cef1e614ee23f1e
pub const ALICE: TestKeyPair = TestKeyPair {
    priv_key: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    pub_key: &[
        0x03, 0xa3, 0x4b, 0x99, 0xf2, 0x2c, 0x79, 0x0c, 0x4e, 0x36, 0xb2, 0xb3,
        0xc2, 0xc3, 0x5a, 0x36, 0xdb, 0x06, 0x22, 0x6e, 0x41, 0xc6, 0x92, 0xfc,
        0x82, 0xb8, 0xb5, 0x6a, 0xc1, 0xc5, 0x40, 0xc5, 0xbd,
    ],
    pub_key_hash: &[
        0x9a, 0x1c, 0x78, 0xa5, 0x07, 0x68, 0x9f, 0x6f, 0x54, 0xb8,
        0x47, 0xad, 0x1c, 0xef, 0x1e, 0x61, 0x4e, 0xe2, 0x3f, 0x1e,
    ],
};

/// Bob's test key pair.
/// privKey: a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2
/// pubKey: 03d6bfe100d1600c0d8f769501676fc74c3809500bd131c8a549f88cf616c21f35
/// pubKeyHash: 89b460e4e984ef496ff0b135712f3d9b9fc80482
pub const BOB: TestKeyPair = TestKeyPair {
    priv_key: "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2",
    pub_key: &[
        0x03, 0xd6, 0xbf, 0xe1, 0x00, 0xd1, 0x60, 0x0c, 0x0d, 0x8f, 0x76, 0x95,
        0x01, 0x67, 0x6f, 0xc7, 0x4c, 0x38, 0x09, 0x50, 0x0b, 0xd1, 0x31, 0xc8,
        0xa5, 0x49, 0xf8, 0x8c, 0xf6, 0x16, 0xc2, 0x1f, 0x35,
    ],
    pub_key_hash: &[
        0x89, 0xb4, 0x60, 0xe4, 0xe9, 0x84, 0xef, 0x49, 0x6f, 0xf0,
        0xb1, 0x35, 0x71, 0x2f, 0x3d, 0x9b, 0x9f, 0xc8, 0x04, 0x82,
    ],
};

/// Charlie's test key pair.
/// privKey: deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef
/// pubKey: 02c6b754b20826eb925e052ee2c25285b162b51fdca732bcf67e39d647fb6830ae
/// pubKeyHash: 66c1d8577d77be82e3e0e6ac0e14402e3fc67ff3
pub const CHARLIE: TestKeyPair = TestKeyPair {
    priv_key: "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
    pub_key: &[
        0x02, 0xc6, 0xb7, 0x54, 0xb2, 0x08, 0x26, 0xeb, 0x92, 0x5e, 0x05, 0x2e,
        0xe2, 0xc2, 0x52, 0x85, 0xb1, 0x62, 0xb5, 0x1f, 0xdc, 0xa7, 0x32, 0xbc,
        0xf6, 0x7e, 0x39, 0xd6, 0x47, 0xfb, 0x68, 0x30, 0xae,
    ],
    pub_key_hash: &[
        0x66, 0xc1, 0xd8, 0x57, 0x7d, 0x77, 0xbe, 0x82, 0xe3, 0xe0,
        0xe6, 0xac, 0x0e, 0x14, 0x40, 0x2e, 0x3f, 0xc6, 0x7f, 0xf3,
    ],
};

#[cfg(test)]
mod tests {
    use super::*;
    use crate::prelude::hash160;

    #[test]
    fn test_alice_pub_key_matches_priv_key() {
        let derived = crate::ecdsa::pub_key_from_priv_key(ALICE.priv_key);
        assert_eq!(derived, ALICE.pub_key);
    }

    #[test]
    fn test_bob_pub_key_matches_priv_key() {
        let derived = crate::ecdsa::pub_key_from_priv_key(BOB.priv_key);
        assert_eq!(derived, BOB.pub_key);
    }

    #[test]
    fn test_charlie_pub_key_matches_priv_key() {
        let derived = crate::ecdsa::pub_key_from_priv_key(CHARLIE.priv_key);
        assert_eq!(derived, CHARLIE.pub_key);
    }

    #[test]
    fn test_alice_pub_key_hash() {
        let h = hash160(ALICE.pub_key);
        assert_eq!(h.as_slice(), ALICE.pub_key_hash);
    }

    #[test]
    fn test_bob_pub_key_hash() {
        let h = hash160(BOB.pub_key);
        assert_eq!(h.as_slice(), BOB.pub_key_hash);
    }

    #[test]
    fn test_charlie_pub_key_hash() {
        let h = hash160(CHARLIE.pub_key);
        assert_eq!(h.as_slice(), CHARLIE.pub_key_hash);
    }

    #[test]
    fn test_alice_sign_and_verify() {
        let sig = ALICE.sign_test_message();
        assert!(crate::ecdsa::ecdsa_verify(&sig, ALICE.pub_key));
    }

    #[test]
    fn test_bob_sign_and_verify() {
        let sig = BOB.sign_test_message();
        assert!(crate::ecdsa::ecdsa_verify(&sig, BOB.pub_key));
    }

    #[test]
    fn test_cross_key_reject() {
        let alice_sig = ALICE.sign_test_message();
        assert!(!crate::ecdsa::ecdsa_verify(&alice_sig, BOB.pub_key));
    }
}
