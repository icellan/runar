//! OraclePriceFeed integration test — stateless contract with Rabin signature verification.
//!
//! ## How It Works
//!
//! OraclePriceFeed locks funds to an oracle's Rabin public key and a receiver's ECDSA
//! public key. To spend, the oracle must sign a price exceeding a threshold (50,000),
//! AND the receiver must provide their ECDSA signature.
//!
//! ### Constructor
//!   - oraclePubKey: RabinPubKey (bigint) — the Rabin modulus n = p*q
//!   - receiver: PubKey — the authorized receiver's ECDSA public key
//!
//! ### Method: settle(price: bigint, rabinSig: RabinSig, padding: ByteString, sig: Sig)
//!   1. Encode price as 8-byte LE (num2bin), hash it
//!   2. Verify: (rabinSig² + padding) mod n ≡ H(encoded_price) mod n
//!   3. Assert price > 50000
//!   4. Verify receiver's ECDSA signature (checkSig)
//!
//! ### How Rabin Signatures Work
//!   - Key: two primes p, q where p ≡ q ≡ 3 (mod 4), public key n = p*q
//!   - Sign: square root of H(msg) mod n using CRT (needs p, q)
//!   - Verify: sig² ≡ H(msg) + padding (mod n) — very cheap on-chain
//!   - Padding: tries 0..255 until H(msg)+padding is a quadratic residue
//!
//! ### Important Notes
//!   - Sig (ECDSA) is auto-computed by the SDK when SdkValue::Auto
//!   - Uses small test primes (7879, 7883) — real deployments need 1024+ bit primes

use crate::helpers::*;
use crate::helpers::crypto::{generate_rabin_key_pair, rabin_sign, bigint_to_script_num_hex};
use runar_lang::sdk::{DeployOptions, RunarContract, SdkValue};

/// Encode an integer as little-endian bytes of the given length.
/// Matches the contract's num2bin(price, 8) encoding.
fn num2bin_le(value: i64, length: usize) -> Vec<u8> {
    let mut buf = vec![0u8; length];
    let mut v = value;
    for byte in buf.iter_mut() {
        *byte = (v & 0xff) as u8;
        v >>= 8;
    }
    buf
}

#[test]
#[ignore]
fn test_oracle_price_feed_compile() {
    skip_if_no_node();

    let artifact = compile_contract("examples/ts/oracle-price/OraclePriceFeed.runar.ts");
    assert_eq!(artifact.contract_name, "OraclePriceFeed");
    assert!(!artifact.script.is_empty());
}

#[test]
#[ignore]
fn test_oracle_price_feed_deploy() {
    skip_if_no_node();

    let artifact = compile_contract("examples/ts/oracle-price/OraclePriceFeed.runar.ts");

    let mut provider = create_provider();
    let (signer, _wallet) = create_funded_wallet(&mut provider);

    let rabin_kp = generate_rabin_key_pair();
    let receiver = create_wallet();

    // Constructor: (oraclePubKey: RabinPubKey, receiver: PubKey)
    // RabinPubKey is bigint (n = p*q) — too large for i64, encode as script number hex
    let n_hex = bigint_to_script_num_hex(&rabin_kp.n);
    let mut contract = RunarContract::new(artifact, vec![
        SdkValue::Bytes(n_hex),
        SdkValue::Bytes(receiver.pub_key_hex),
    ]);

    let (deploy_txid, _tx) = contract
        .deploy(&mut provider, &*signer, &DeployOptions {
            satoshis: 5000,
            change_address: None,
        })
        .expect("deploy failed");
    assert!(!deploy_txid.is_empty());
    assert_eq!(deploy_txid.len(), 64);
}

#[test]
#[ignore]
fn test_oracle_price_feed_deploy_different_receiver() {
    skip_if_no_node();

    let artifact = compile_contract("examples/ts/oracle-price/OraclePriceFeed.runar.ts");

    let mut provider = create_provider();
    let (signer, _wallet) = create_funded_wallet(&mut provider);

    let rabin_kp = generate_rabin_key_pair();
    let receiver = create_wallet();

    let n_hex = bigint_to_script_num_hex(&rabin_kp.n);
    let mut contract = RunarContract::new(artifact, vec![
        SdkValue::Bytes(n_hex),
        SdkValue::Bytes(receiver.pub_key_hex),
    ]);

    let (deploy_txid, _tx) = contract
        .deploy(&mut provider, &*signer, &DeployOptions {
            satoshis: 5000,
            change_address: None,
        })
        .expect("deploy failed");
    assert!(!deploy_txid.is_empty());
}

/// Deploy and spend with a valid oracle price above the 50,000 threshold.
///
/// Steps:
///   1. Create Rabin keypair for the oracle (small test primes)
///   2. Create a funded receiver wallet (signer must match the constructor's receiver)
///   3. Deploy with (oracleN, receiverPubKey)
///   4. Oracle signs price=55001 as 8-byte LE using Rabin signature
///   5. Call settle(price, rabinSig, padding, Auto) — SDK auto-computes ECDSA sig
#[test]
#[ignore]
fn test_oracle_price_feed_spend_valid_price() {
    skip_if_no_node();

    let artifact = compile_contract("examples/ts/oracle-price/OraclePriceFeed.runar.ts");

    let mut provider = create_provider();

    // The receiver will be the signer — their ECDSA key must match the constructor
    let (receiver_signer, receiver_wallet) = create_funded_wallet(&mut provider);

    let rabin_kp = generate_rabin_key_pair();

    // Deploy: oracle Rabin pubkey + receiver's ECDSA pubkey
    let n_hex = bigint_to_script_num_hex(&rabin_kp.n);
    let mut contract = RunarContract::new(artifact, vec![
        SdkValue::Bytes(n_hex),
        SdkValue::Bytes(receiver_wallet.pub_key_hex.clone()),
    ]);
    contract
        .deploy(&mut provider, &*receiver_signer, &DeployOptions {
            satoshis: 5000,
            change_address: None,
        })
        .expect("deploy failed");

    // Oracle signs price=55001 (above 50000 threshold)
    let price: i64 = 55001;
    let msg_bytes = num2bin_le(price, 8);
    let rabin_result = rabin_sign(&msg_bytes, &rabin_kp);

    // Call settle(price, rabinSig, padding, sig=Auto)
    // rabinSig is a BigInt (260-bit) — encode as script number hex via Bytes
    // padding is small — use Int for MINIMALDATA compliance
    let sig_hex = bigint_to_script_num_hex(&rabin_result.sig);
    use num_traits::ToPrimitive;
    let padding_i64: i64 = rabin_result.padding.to_i64().expect("padding too large for i64");
    let (spend_txid, _tx) = contract
        .call(
            "settle",
            &[
                SdkValue::Int(price),
                SdkValue::Bytes(sig_hex),
                SdkValue::Int(padding_i64),
                SdkValue::Auto,  // ECDSA signature auto-computed from receiver's key
            ],
            &mut provider,
            &*receiver_signer,
            None,
        )
        .expect("spend failed");
    assert!(!spend_txid.is_empty());
    assert_eq!(spend_txid.len(), 64);
}

#[test]
#[ignore]
fn test_oracle_price_feed_below_threshold_rejected() {
    skip_if_no_node();

    let artifact = compile_contract("examples/ts/oracle-price/OraclePriceFeed.runar.ts");

    let mut provider = create_provider();
    let (receiver_signer, receiver_wallet) = create_funded_wallet(&mut provider);

    let rabin_kp = generate_rabin_key_pair();

    let n_hex = bigint_to_script_num_hex(&rabin_kp.n);
    let mut contract = RunarContract::new(artifact, vec![
        SdkValue::Bytes(n_hex),
        SdkValue::Bytes(receiver_wallet.pub_key_hex.clone()),
    ]);
    contract
        .deploy(&mut provider, &*receiver_signer, &DeployOptions {
            satoshis: 5000,
            change_address: None,
        })
        .expect("deploy failed");

    // Oracle signs price=49999 (below 50000 threshold)
    let price: i64 = 49999;
    let msg_bytes = num2bin_le(price, 8);
    let rabin_result = rabin_sign(&msg_bytes, &rabin_kp);

    let sig_hex = bigint_to_script_num_hex(&rabin_result.sig);
    use num_traits::ToPrimitive;
    let padding_i64: i64 = rabin_result.padding.to_i64().expect("padding too large for i64");

    let result = contract.call(
        "settle",
        &[
            SdkValue::Int(price),
            SdkValue::Bytes(sig_hex),
            SdkValue::Int(padding_i64),
            SdkValue::Auto,
        ],
        &mut provider,
        &*receiver_signer,
        None,
    );
    assert!(result.is_err(), "settle with price below threshold should be rejected");
}

#[test]
#[ignore]
fn test_oracle_price_feed_wrong_receiver_rejected() {
    skip_if_no_node();

    let artifact = compile_contract("examples/ts/oracle-price/OraclePriceFeed.runar.ts");

    let mut provider = create_provider();
    // Deploy with receiver=walletA
    let (signer_a, receiver_wallet) = create_funded_wallet(&mut provider);

    let rabin_kp = generate_rabin_key_pair();

    let n_hex = bigint_to_script_num_hex(&rabin_kp.n);
    let mut contract = RunarContract::new(artifact, vec![
        SdkValue::Bytes(n_hex),
        SdkValue::Bytes(receiver_wallet.pub_key_hex.clone()),
    ]);
    contract
        .deploy(&mut provider, &*signer_a, &DeployOptions {
            satoshis: 5000,
            change_address: None,
        })
        .expect("deploy failed");

    // Oracle signs price=55001 (above threshold) — valid price
    let price: i64 = 55001;
    let msg_bytes = num2bin_le(price, 8);
    let rabin_result = rabin_sign(&msg_bytes, &rabin_kp);

    let sig_hex = bigint_to_script_num_hex(&rabin_result.sig);
    use num_traits::ToPrimitive;
    let padding_i64: i64 = rabin_result.padding.to_i64().expect("padding too large for i64");

    // Call settle with a different signer — should be rejected
    let (signer_b, _wallet_b) = create_funded_wallet(&mut provider);
    let result = contract.call(
        "settle",
        &[
            SdkValue::Int(price),
            SdkValue::Bytes(sig_hex),
            SdkValue::Int(padding_i64),
            SdkValue::Auto,
        ],
        &mut provider,
        &*signer_b,
        None,
    );
    assert!(result.is_err(), "settle with wrong receiver should be rejected");
}
