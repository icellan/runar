#[path = "SPHINCSWallet.runar.rs"]
mod contract;

use contract::*;
use runar::prelude::{hash160, slh_keygen, slh_sign, SLH_SHA2_128S, ALICE, BOB};

fn setup_keys() -> (Vec<u8>, Vec<u8>, runar::prelude::SlhKeyPair, Vec<u8>) {
    let ecdsa_pub_key = ALICE.pub_key.to_vec();
    let ecdsa_pub_key_hash = hash160(&ecdsa_pub_key);

    let params = &SLH_SHA2_128S;
    let seed = vec![0x42u8; 3 * params.n];
    let kp = slh_keygen(params, Some(&seed));
    let slhdsa_pub_key_hash = hash160(&kp.pk);

    (ecdsa_pub_key, ecdsa_pub_key_hash, kp, slhdsa_pub_key_hash)
}



#[test]
fn test_spend() {
    let (ecdsa_pub_key, ecdsa_pub_key_hash, kp, slhdsa_pub_key_hash) = setup_keys();

    let c = SPHINCSWallet {
        ecdsa_pub_key_hash,
        slhdsa_pub_key_hash,
    };

    // Real ECDSA signature
    let ecdsa_sig = ALICE.sign_test_message();

    // SLH-DSA-sign the ECDSA signature bytes
    let slhdsa_sig = slh_sign(&SLH_SHA2_128S, &ecdsa_sig, &kp.sk);

    c.spend(&slhdsa_sig, &kp.pk, &ecdsa_sig, &ecdsa_pub_key);
}

#[test]
fn test_spend_multiple_messages() {
    // SLH-DSA is stateless — same SLH-DSA keypair can sign many ECDSA sigs.
    // We demonstrate this by spending with two different ECDSA keys (Alice, Bob),
    // each producing a distinct real ECDSA signature that the same SLH-DSA key signs.
    let params = &SLH_SHA2_128S;
    let seed = vec![0x42u8; 3 * params.n];
    let kp = slh_keygen(params, Some(&seed));
    let slhdsa_pub_key_hash = hash160(&kp.pk);

    // Spend 1: Alice's ECDSA key
    let alice_pk = ALICE.pub_key.to_vec();
    let alice_sig = ALICE.sign_test_message();
    let slhdsa_sig1 = slh_sign(&SLH_SHA2_128S, &alice_sig, &kp.sk);
    let c1 = SPHINCSWallet {
        ecdsa_pub_key_hash: hash160(&alice_pk),
        slhdsa_pub_key_hash: slhdsa_pub_key_hash.clone(),
    };
    c1.spend(&slhdsa_sig1, &kp.pk, &alice_sig, &alice_pk);

    // Spend 2: Bob's ECDSA key — different ECDSA sig, same SLH-DSA keypair
    let bob_pk = BOB.pub_key.to_vec();
    let bob_sig = BOB.sign_test_message();
    let slhdsa_sig2 = slh_sign(&SLH_SHA2_128S, &bob_sig, &kp.sk);
    let c2 = SPHINCSWallet {
        ecdsa_pub_key_hash: hash160(&bob_pk),
        slhdsa_pub_key_hash,
    };
    c2.spend(&slhdsa_sig2, &kp.pk, &bob_sig, &bob_pk);
}

#[test]
fn test_spend_tampered_slhdsa() {
    let (ecdsa_pub_key, ecdsa_pub_key_hash, kp, slhdsa_pub_key_hash) = setup_keys();

    let c = SPHINCSWallet {
        ecdsa_pub_key_hash,
        slhdsa_pub_key_hash,
    };

    let ecdsa_sig = ALICE.sign_test_message();
    let mut slhdsa_sig = slh_sign(&SLH_SHA2_128S, &ecdsa_sig, &kp.sk);
    slhdsa_sig[0] ^= 0xff; // tamper

    let result = std::panic::catch_unwind(|| c.spend(&slhdsa_sig, &kp.pk, &ecdsa_sig, &ecdsa_pub_key));
    assert!(result.is_err(), "expected spend to fail with tampered SLH-DSA signature");
}

#[test]
fn test_spend_wrong_ecdsa_sig() {
    let (ecdsa_pub_key, ecdsa_pub_key_hash, kp, slhdsa_pub_key_hash) = setup_keys();

    let c = SPHINCSWallet {
        ecdsa_pub_key_hash,
        slhdsa_pub_key_hash,
    };

    // Sign one ECDSA sig with SLH-DSA, but provide different ECDSA sig to contract
    let ecdsa_sig1 = ALICE.sign_test_message();
    let slhdsa_sig = slh_sign(&SLH_SHA2_128S, &ecdsa_sig1, &kp.sk);

    let ecdsa_sig2 = vec![0x30, 0xFF];

    let result = std::panic::catch_unwind(|| c.spend(&slhdsa_sig, &kp.pk, &ecdsa_sig2, &ecdsa_pub_key));
    assert!(result.is_err(), "expected spend to fail when SLH-DSA signed wrong ECDSA sig");
}

#[test]
fn test_spend_wrong_ecdsa_pub_key_hash() {
    let (_, ecdsa_pub_key_hash, kp, slhdsa_pub_key_hash) = setup_keys();

    let c = SPHINCSWallet {
        ecdsa_pub_key_hash,
        slhdsa_pub_key_hash,
    };

    // Different ECDSA pubkey whose hash160 won't match
    let wrong_ecdsa_pub_key = {
        let mut k = vec![0x03u8];
        k.extend_from_slice(&[0xffu8; 32]);
        k
    };

    let ecdsa_sig = ALICE.sign_test_message();
    let slhdsa_sig = slh_sign(&SLH_SHA2_128S, &ecdsa_sig, &kp.sk);

    let result = std::panic::catch_unwind(|| c.spend(&slhdsa_sig, &kp.pk, &ecdsa_sig, &wrong_ecdsa_pub_key));
    assert!(result.is_err(), "expected spend to fail with wrong ECDSA public key hash");
}

#[test]
fn test_spend_wrong_slhdsa_pub_key_hash() {
    let (ecdsa_pub_key, ecdsa_pub_key_hash, _, slhdsa_pub_key_hash) = setup_keys();

    let c = SPHINCSWallet {
        ecdsa_pub_key_hash,
        slhdsa_pub_key_hash,
    };

    // Different SLH-DSA keypair whose hash160 won't match
    let wrong_seed = vec![0xffu8; 3 * SLH_SHA2_128S.n];
    let wrong_kp = slh_keygen(&SLH_SHA2_128S, Some(&wrong_seed));

    let ecdsa_sig = ALICE.sign_test_message();
    let slhdsa_sig = slh_sign(&SLH_SHA2_128S, &ecdsa_sig, &wrong_kp.sk);

    let result = std::panic::catch_unwind(|| c.spend(&slhdsa_sig, &wrong_kp.pk, &ecdsa_sig, &ecdsa_pub_key));
    assert!(result.is_err(), "expected spend to fail with wrong SLH-DSA public key hash");
}

#[test]
fn test_compile() {
    runar::compile_check(
        include_str!("SPHINCSWallet.runar.rs"),
        "SPHINCSWallet.runar.rs",
    )
    .unwrap();
}
