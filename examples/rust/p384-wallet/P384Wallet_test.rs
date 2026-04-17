#[path = "P384Wallet.runar.rs"]
mod contract;

use contract::*;
use runar::prelude::{hash160, p384_keygen, p384_sign, ALICE};

fn setup_keys() -> (Vec<u8>, Vec<u8>, runar::prelude::P384KeyPair, Vec<u8>) {
    let ecdsa_pub_key = ALICE.pub_key.to_vec();
    let ecdsa_pub_key_hash = hash160(&ecdsa_pub_key);

    let kp = p384_keygen();
    let p384_pub_key_hash = hash160(&kp.pk_compressed);

    (ecdsa_pub_key, ecdsa_pub_key_hash, kp, p384_pub_key_hash)
}

#[test]
fn test_spend() {
    let (ecdsa_pub_key, ecdsa_pub_key_hash, kp, p384_pub_key_hash) = setup_keys();

    let c = P384Wallet {
        ecdsa_pub_key_hash,
        p384_pub_key_hash,
    };

    // Real secp256k1 signature (sig bytes ARE the P-384 message)
    let ecdsa_sig = ALICE.sign_test_message();

    // P-384-sign the secp256k1 signature bytes
    let p384_sig = p384_sign(&ecdsa_sig, &kp);

    c.spend(&p384_sig, &kp.pk_compressed, &ecdsa_sig, &ecdsa_pub_key);
}

#[test]
fn test_spend_tampered_p384_sig() {
    let (ecdsa_pub_key, ecdsa_pub_key_hash, kp, p384_pub_key_hash) = setup_keys();

    let c = P384Wallet {
        ecdsa_pub_key_hash,
        p384_pub_key_hash,
    };

    let ecdsa_sig = ALICE.sign_test_message();
    let mut p384_sig = p384_sign(&ecdsa_sig, &kp);
    p384_sig[0] ^= 0xff; // tamper

    let result = std::panic::catch_unwind(|| c.spend(&p384_sig, &kp.pk_compressed, &ecdsa_sig, &ecdsa_pub_key));
    assert!(result.is_err(), "expected spend to fail with tampered P-384 signature");
}

#[test]
fn test_spend_wrong_ecdsa_sig() {
    let (ecdsa_pub_key, ecdsa_pub_key_hash, kp, p384_pub_key_hash) = setup_keys();

    let c = P384Wallet {
        ecdsa_pub_key_hash,
        p384_pub_key_hash,
    };

    // P-384-sign one secp256k1 sig, but provide different sig to contract
    let ecdsa_sig1 = ALICE.sign_test_message();
    let p384_sig = p384_sign(&ecdsa_sig1, &kp);

    let ecdsa_sig2 = vec![0x30, 0xFF]; // different sig bytes

    let result = std::panic::catch_unwind(|| c.spend(&p384_sig, &kp.pk_compressed, &ecdsa_sig2, &ecdsa_pub_key));
    assert!(result.is_err(), "expected spend to fail when P-384 signed wrong secp256k1 sig");
}

#[test]
fn test_spend_wrong_ecdsa_pub_key_hash() {
    let (_, ecdsa_pub_key_hash, kp, p384_pub_key_hash) = setup_keys();

    let c = P384Wallet {
        ecdsa_pub_key_hash,
        p384_pub_key_hash,
    };

    // Different secp256k1 pubkey whose hash160 won't match
    let wrong_ecdsa_pub_key = {
        let mut k = vec![0x03u8];
        k.extend_from_slice(&[0xffu8; 32]);
        k
    };

    let ecdsa_sig = ALICE.sign_test_message();
    let p384_sig = p384_sign(&ecdsa_sig, &kp);

    let result = std::panic::catch_unwind(|| c.spend(&p384_sig, &kp.pk_compressed, &ecdsa_sig, &wrong_ecdsa_pub_key));
    assert!(result.is_err(), "expected spend to fail with wrong secp256k1 public key hash");
}

#[test]
fn test_spend_wrong_p384_pub_key_hash() {
    let (ecdsa_pub_key, ecdsa_pub_key_hash, _, p384_pub_key_hash) = setup_keys();

    let c = P384Wallet {
        ecdsa_pub_key_hash,
        p384_pub_key_hash,
    };

    // Different P-384 keypair whose hash160 won't match
    let wrong_kp = p384_keygen();

    let ecdsa_sig = ALICE.sign_test_message();
    let p384_sig = p384_sign(&ecdsa_sig, &wrong_kp);

    let result = std::panic::catch_unwind(|| c.spend(&p384_sig, &wrong_kp.pk_compressed, &ecdsa_sig, &ecdsa_pub_key));
    assert!(result.is_err(), "expected spend to fail with wrong P-384 public key hash");
}

#[test]
fn test_compile() {
    runar::compile_check(
        include_str!("P384Wallet.runar.rs"),
        "P384Wallet.runar.rs",
    )
    .unwrap();
}
