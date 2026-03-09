#[path = "SPHINCSWallet.runar.rs"]
mod contract;

use contract::*;
use runar::prelude::{hash160, mock_pub_key, mock_sig, slh_keygen, slh_sign, SLH_SHA2_128S};

fn setup_keys() -> (Vec<u8>, Vec<u8>, runar::prelude::SlhKeyPair, Vec<u8>) {
    let ecdsa_pub_key = mock_pub_key();
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

    // Mock ECDSA signature (check_sig is mocked to true)
    let ecdsa_sig = mock_sig();

    // SLH-DSA-sign the ECDSA signature bytes
    let slhdsa_sig = slh_sign(&SLH_SHA2_128S, &ecdsa_sig, &kp.sk);

    c.spend(&slhdsa_sig, &kp.pk, &ecdsa_sig, &ecdsa_pub_key);
}

#[test]
fn test_spend_multiple_messages() {
    // SLH-DSA is stateless — same keypair can sign many messages
    let (ecdsa_pub_key, ecdsa_pub_key_hash, kp, slhdsa_pub_key_hash) = setup_keys();

    let c = SPHINCSWallet {
        ecdsa_pub_key_hash,
        slhdsa_pub_key_hash,
    };

    let ecdsa_sig1 = vec![0x30, 0x01];
    let slhdsa_sig1 = slh_sign(&SLH_SHA2_128S, &ecdsa_sig1, &kp.sk);
    c.spend(&slhdsa_sig1, &kp.pk, &ecdsa_sig1, &ecdsa_pub_key);

    let ecdsa_sig2 = vec![0x30, 0x02];
    let slhdsa_sig2 = slh_sign(&SLH_SHA2_128S, &ecdsa_sig2, &kp.sk);
    c.spend(&slhdsa_sig2, &kp.pk, &ecdsa_sig2, &ecdsa_pub_key);
}

#[test]
fn test_spend_tampered_slhdsa() {
    let (ecdsa_pub_key, ecdsa_pub_key_hash, kp, slhdsa_pub_key_hash) = setup_keys();

    let c = SPHINCSWallet {
        ecdsa_pub_key_hash,
        slhdsa_pub_key_hash,
    };

    let ecdsa_sig = mock_sig();
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
    let ecdsa_sig1 = mock_sig();
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

    let ecdsa_sig = mock_sig();
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

    let ecdsa_sig = mock_sig();
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
