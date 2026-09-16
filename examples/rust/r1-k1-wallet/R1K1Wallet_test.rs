//! Native-Rust tests for `R1K1Wallet.runar.rs`.
//!
//! This contract could not be compiled as Rust until `toByteString(<string
//! literal>)` folded to a ByteString literal in the IR. The sighash-suffix
//! check is spelled `to_byte_string("41000000")` here because the bare
//! `"41000000"` the other eight surfaces use is a `&str`, and `ByteString` is
//! `Vec<u8>` in this tier — `Vec<u8> == &str` does not compile, and no
//! `PartialEq` between them can be added from `packages/runar-rs` (orphan
//! rule). The wrapper is the ONLY spelling that is both valid Rust and valid
//! Rúnar, and `spec/grammar.md` section 11 makes it the ByteStringLiteral
//! production, so it now reaches the IR as a literal like every other surface.

#[path = "R1K1Wallet.runar.rs"]
mod contract;

use contract::*;
use runar::prelude::{
    cat, hash160, p256_keygen, p256_sign, sha256, P256KeyPair, ALICE, BOB,
};

/// A BIP-143 preimage ending in the four sighash-flag bytes the contract
/// pins: `41 00 00 00` (SIGHASH_ALL | SIGHASH_FORKID, 4-byte LE).
fn preimage_with_suffix(suffix: [u8; 4]) -> Vec<u8> {
    let mut p = vec![0xab; 60];
    p.extend_from_slice(&suffix);
    p
}

fn wallet(kp: &P256KeyPair, salt: &[u8]) -> R1K1Wallet {
    R1K1Wallet {
        r1_salted_pub_key_hash: hash160(&cat(&kp.pk_compressed, salt)),
        k1_pub_key_hash: hash160(ALICE.pub_key),
    }
}

fn salt32() -> Vec<u8> {
    vec![0x5a; 32]
}

// ---------------------------------------------------------------------------
// spendR1 — the P-256 path, and the sighash-suffix literal it pins
// ---------------------------------------------------------------------------

#[test]
fn spend_r1_accepts_a_valid_hardware_signature() {
    let kp = p256_keygen();
    let salt = salt32();
    let c = wallet(&kp, &salt);

    let preimage = preimage_with_suffix([0x41, 0x00, 0x00, 0x00]);
    // The contract verifies over sha256(preimage), and verify_ecdsa_p256
    // hashes its message argument once more internally.
    let sig = p256_sign(&sha256(&preimage), &kp);

    c.spend_r1(&sig, &kp.pk_compressed, &salt, &preimage);
}

/// The load-bearing case for the `toByteString` fold: the suffix comparison
/// must be a real BYTE comparison against `41 00 00 00`. A preimage carrying
/// any other sighash flag has to be rejected.
#[test]
#[should_panic(expected = "substr(tx_preimage, len(tx_preimage) - 4, 4) == to_byte_string(\"41000000\")")]
fn spend_r1_rejects_a_preimage_with_a_different_sighash_flag() {
    let kp = p256_keygen();
    let salt = salt32();
    let c = wallet(&kp, &salt);

    // SIGHASH_NONE | FORKID rather than SIGHASH_ALL | FORKID.
    let preimage = preimage_with_suffix([0x42, 0x00, 0x00, 0x00]);
    let sig = p256_sign(&sha256(&preimage), &kp);

    c.spend_r1(&sig, &kp.pk_compressed, &salt, &preimage);
}

/// The same four characters as ASCII TEXT rather than as the four bytes.
/// A literal read as a string instead of as bytes would accept this.
#[test]
#[should_panic(expected = "substr(tx_preimage, len(tx_preimage) - 4, 4) == to_byte_string(\"41000000\")")]
fn spend_r1_rejects_a_suffix_that_merely_looks_like_the_literal() {
    let kp = p256_keygen();
    let salt = salt32();
    let c = wallet(&kp, &salt);

    let mut preimage = vec![0xab; 60];
    preimage.extend_from_slice(b"4100"); // '4','1','0','0' — not 0x41,0x00,0x00,0x00
    let sig = p256_sign(&sha256(&preimage), &kp);

    c.spend_r1(&sig, &kp.pk_compressed, &salt, &preimage);
}

#[test]
#[should_panic(expected = "len(r1_salt) == 32")]
fn spend_r1_rejects_a_salt_that_is_not_32_bytes() {
    let kp = p256_keygen();
    let salt = vec![0x5a; 31];
    let c = wallet(&kp, &salt);

    let preimage = preimage_with_suffix([0x41, 0x00, 0x00, 0x00]);
    let sig = p256_sign(&sha256(&preimage), &kp);

    c.spend_r1(&sig, &kp.pk_compressed, &salt, &preimage);
}

#[test]
#[should_panic(expected = "hash160(&cat(r1_pub_key, r1_salt)) == self.r1_salted_pub_key_hash")]
fn spend_r1_rejects_a_salt_that_does_not_match_the_committed_hash() {
    let kp = p256_keygen();
    let c = wallet(&kp, &salt32());

    let preimage = preimage_with_suffix([0x41, 0x00, 0x00, 0x00]);
    let sig = p256_sign(&sha256(&preimage), &kp);

    // Right length, wrong bytes.
    c.spend_r1(&sig, &kp.pk_compressed, &vec![0x5b; 32], &preimage);
}

#[test]
#[should_panic(expected = "verify_ecdsa_p256(&sha256(tx_preimage), r1_sig, r1_pub_key)")]
fn spend_r1_rejects_a_tampered_p256_signature() {
    let kp = p256_keygen();
    let salt = salt32();
    let c = wallet(&kp, &salt);

    let preimage = preimage_with_suffix([0x41, 0x00, 0x00, 0x00]);
    let mut sig = p256_sign(&sha256(&preimage), &kp);
    sig[0] ^= 0xff;

    c.spend_r1(&sig, &kp.pk_compressed, &salt, &preimage);
}

// ---------------------------------------------------------------------------
// recoverK1 — the independent secp256k1 recovery path
// ---------------------------------------------------------------------------

#[test]
fn recover_k1_accepts_the_recovery_key() {
    let kp = p256_keygen();
    let c = wallet(&kp, &salt32());
    c.recover_k1(&ALICE.sign_test_message(), &ALICE.pub_key.to_vec());
}

#[test]
#[should_panic(expected = "hash160(k1_pub_key) == self.k1_pub_key_hash")]
fn recover_k1_rejects_a_different_key() {
    let kp = p256_keygen();
    let c = wallet(&kp, &salt32());
    c.recover_k1(&BOB.sign_test_message(), &BOB.pub_key.to_vec());
}

// ---------------------------------------------------------------------------
// Rúnar frontend
// ---------------------------------------------------------------------------

#[test]
fn test_compile() {
    runar::compile_check(include_str!("R1K1Wallet.runar.rs"), "R1K1Wallet.runar.rs").unwrap();
}
