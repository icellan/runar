#[path = "PostQuantumWallet.runar.rs"]
mod contract;

use contract::*;
use runar::prelude::{hash160, wots_keygen, wots_sign, ALICE};

fn setup_keys() -> (Vec<u8>, Vec<u8>, runar::prelude::WotsKeyPair, Vec<u8>) {
    let ecdsa_pub_key = ALICE.pub_key.to_vec();
    let ecdsa_pub_key_hash = hash160(&ecdsa_pub_key);

    let seed = [0x42u8; 32];
    let pub_seed = [0x13u8; 32];
    let kp = wots_keygen(Some(&seed), Some(&pub_seed));
    let wots_pub_key_hash = hash160(&kp.pk);

    (ecdsa_pub_key, ecdsa_pub_key_hash, kp, wots_pub_key_hash)
}

#[test]
fn test_spend() {
    let (ecdsa_pub_key, ecdsa_pub_key_hash, kp, wots_pub_key_hash) = setup_keys();

    let c = PostQuantumWallet {
        ecdsa_pub_key_hash,
        wots_pub_key_hash,
    };

    // Real ECDSA signature
    let ecdsa_sig = ALICE.sign_test_message();

    // WOTS-sign the ECDSA signature bytes
    let wots_sig = wots_sign(&ecdsa_sig, &kp.sk, &kp.pub_seed);

    c.spend(&wots_sig, &kp.pk, &ecdsa_sig, &ecdsa_pub_key);
}

#[test]
fn test_spend_tampered_wots() {
    let (ecdsa_pub_key, ecdsa_pub_key_hash, kp, wots_pub_key_hash) = setup_keys();

    let c = PostQuantumWallet {
        ecdsa_pub_key_hash,
        wots_pub_key_hash,
    };

    let ecdsa_sig = ALICE.sign_test_message();
    let mut wots_sig = wots_sign(&ecdsa_sig, &kp.sk, &kp.pub_seed);
    wots_sig[100] ^= 0xff; // tamper

    let result = std::panic::catch_unwind(|| c.spend(&wots_sig, &kp.pk, &ecdsa_sig, &ecdsa_pub_key));
    assert!(result.is_err(), "expected spend to fail with tampered WOTS signature");
}

#[test]
fn test_spend_wrong_ecdsa_sig() {
    let (ecdsa_pub_key, ecdsa_pub_key_hash, kp, wots_pub_key_hash) = setup_keys();

    let c = PostQuantumWallet {
        ecdsa_pub_key_hash,
        wots_pub_key_hash,
    };

    // Sign one ECDSA sig with WOTS, but provide different ECDSA sig to contract
    let ecdsa_sig1 = ALICE.sign_test_message();
    let wots_sig = wots_sign(&ecdsa_sig1, &kp.sk, &kp.pub_seed);

    let ecdsa_sig2 = vec![0x30, 0xFF]; // different sig bytes

    let result = std::panic::catch_unwind(|| c.spend(&wots_sig, &kp.pk, &ecdsa_sig2, &ecdsa_pub_key));
    assert!(result.is_err(), "expected spend to fail when WOTS signed wrong ECDSA sig");
}

#[test]
fn test_spend_wrong_ecdsa_pub_key_hash() {
    let (_, ecdsa_pub_key_hash, kp, wots_pub_key_hash) = setup_keys();

    let c = PostQuantumWallet {
        ecdsa_pub_key_hash,
        wots_pub_key_hash,
    };

    // Different ECDSA pubkey whose hash160 won't match
    let wrong_ecdsa_pub_key = {
        let mut k = vec![0x03u8];
        k.extend_from_slice(&[0xffu8; 32]);
        k
    };

    let ecdsa_sig = ALICE.sign_test_message();
    let wots_sig = wots_sign(&ecdsa_sig, &kp.sk, &kp.pub_seed);

    let result = std::panic::catch_unwind(|| c.spend(&wots_sig, &kp.pk, &ecdsa_sig, &wrong_ecdsa_pub_key));
    assert!(result.is_err(), "expected spend to fail with wrong ECDSA public key hash");
}

#[test]
fn test_spend_wrong_wots_pub_key_hash() {
    let (ecdsa_pub_key, ecdsa_pub_key_hash, _, wots_pub_key_hash) = setup_keys();

    let c = PostQuantumWallet {
        ecdsa_pub_key_hash,
        wots_pub_key_hash,
    };

    // Different WOTS keypair whose hash160 won't match
    let wrong_kp = wots_keygen(Some(&[0x99u8; 32]), Some(&[0x77u8; 32]));

    let ecdsa_sig = ALICE.sign_test_message();
    let wots_sig = wots_sign(&ecdsa_sig, &wrong_kp.sk, &wrong_kp.pub_seed);

    let result = std::panic::catch_unwind(|| c.spend(&wots_sig, &wrong_kp.pk, &ecdsa_sig, &ecdsa_pub_key));
    assert!(result.is_err(), "expected spend to fail with wrong WOTS public key hash");
}

#[test]
fn test_compile() {
    runar::compile_check(
        include_str!("PostQuantumWallet.runar.rs"),
        "PostQuantumWallet.runar.rs",
    )
    .unwrap();
}
