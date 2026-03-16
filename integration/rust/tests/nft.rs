//! SimpleNFT integration test — stateful contract with addOutput (SDK Deploy path).
//!
//! Both methods require a Sig parameter (checkSig), so spending requires raw
//! transaction construction. We test compile + deploy via the SDK.

use crate::helpers::*;
use runar_lang::sdk::{CallOptions, DeployOptions, RunarContract, SdkValue};
use std::collections::HashMap;

fn hex_encode_str(s: &str) -> String {
    s.as_bytes().iter().map(|b| format!("{:02x}", b)).collect()
}

#[test]
#[ignore]
fn test_nft_compile() {
    skip_if_no_node();

    let artifact = compile_contract("examples/ts/token-nft/NFTExample.runar.ts");
    assert_eq!(artifact.contract_name, "SimpleNFT");
}

#[test]
#[ignore]
fn test_nft_deploy() {
    skip_if_no_node();

    let artifact = compile_contract("examples/ts/token-nft/NFTExample.runar.ts");

    let mut provider = create_provider();
    let owner = create_wallet();
    let (signer, _wallet) = create_funded_wallet(&mut provider);

    let token_id_hex = hex_encode_str("NFT-001");
    let metadata_hex = hex_encode_str("My First NFT");

    // Constructor: (owner: PubKey, tokenId: ByteString, metadata: ByteString)
    let mut contract = RunarContract::new(artifact, vec![
        SdkValue::Bytes(owner.pub_key_hex),
        SdkValue::Bytes(token_id_hex),
        SdkValue::Bytes(metadata_hex),
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
fn test_nft_deploy_different_owners() {
    skip_if_no_node();

    let artifact = compile_contract("examples/ts/token-nft/NFTExample.runar.ts");

    let mut provider = create_provider();
    let owner1 = create_wallet();
    let owner2 = create_wallet();
    let (signer, _wallet) = create_funded_wallet(&mut provider);

    let token_id_hex = hex_encode_str("NFT-MULTI");
    let metadata_hex = hex_encode_str("Unique Art Piece");

    let mut contract1 = RunarContract::new(artifact.clone(), vec![
        SdkValue::Bytes(owner1.pub_key_hex),
        SdkValue::Bytes(token_id_hex.clone()),
        SdkValue::Bytes(metadata_hex.clone()),
    ]);
    let (txid1, _) = contract1
        .deploy(&mut provider, &*signer, &DeployOptions {
            satoshis: 5000,
            change_address: None,
        })
        .expect("deploy 1 failed");

    let mut contract2 = RunarContract::new(artifact, vec![
        SdkValue::Bytes(owner2.pub_key_hex),
        SdkValue::Bytes(token_id_hex),
        SdkValue::Bytes(metadata_hex),
    ]);
    let (txid2, _) = contract2
        .deploy(&mut provider, &*signer, &DeployOptions {
            satoshis: 5000,
            change_address: None,
        })
        .expect("deploy 2 failed");

    assert_ne!(txid1, txid2);
}

#[test]
#[ignore]
fn test_nft_deploy_long_metadata() {
    skip_if_no_node();

    let artifact = compile_contract("examples/ts/token-nft/NFTExample.runar.ts");

    let mut provider = create_provider();
    let owner = create_wallet();
    let (signer, _wallet) = create_funded_wallet(&mut provider);

    let token_id_hex = hex_encode_str("NFT-LONG-META");
    // 256 bytes of metadata
    let metadata_hex = hex_encode_str(&"A".repeat(256));

    let mut contract = RunarContract::new(artifact, vec![
        SdkValue::Bytes(owner.pub_key_hex),
        SdkValue::Bytes(token_id_hex),
        SdkValue::Bytes(metadata_hex),
    ]);

    let (deploy_txid, _tx) = contract
        .deploy(&mut provider, &*signer, &DeployOptions {
            satoshis: 5000,
            change_address: None,
        })
        .expect("deploy failed");
    assert!(!deploy_txid.is_empty());
}

#[test]
#[ignore]
fn test_nft_transfer() {
    skip_if_no_node();

    let artifact = compile_contract("examples/ts/token-nft/NFTExample.runar.ts");

    let mut provider = create_provider();
    let (signer, owner_wallet) = create_funded_wallet(&mut provider);
    let new_owner = create_wallet();

    let token_id_hex = hex_encode_str("NFT-XFER");
    let metadata_hex = hex_encode_str("Transfer Test");

    // Owner is the funded signer
    let mut contract = RunarContract::new(artifact, vec![
        SdkValue::Bytes(owner_wallet.pub_key_hex.clone()),
        SdkValue::Bytes(token_id_hex),
        SdkValue::Bytes(metadata_hex),
    ]);

    contract
        .deploy(&mut provider, &*signer, &DeployOptions {
            satoshis: 5000,
            change_address: None,
        })
        .expect("deploy failed");

    // Transfer: sig=Auto, newOwner=explicit, outputSatoshis
    let (call_txid, _tx) = contract
        .call(
            "transfer",
            &[SdkValue::Auto, SdkValue::Bytes(new_owner.pub_key_hex), SdkValue::Int(5000)],
            &mut provider,
            &*signer,
            None,
        )
        .expect("transfer failed");
    assert!(!call_txid.is_empty());
}

#[test]
#[ignore]
fn test_nft_burn() {
    skip_if_no_node();

    let artifact = compile_contract("examples/ts/token-nft/NFTExample.runar.ts");

    let mut provider = create_provider();
    let (signer, owner_wallet) = create_funded_wallet(&mut provider);

    let token_id_hex = hex_encode_str("NFT-BURN");
    let metadata_hex = hex_encode_str("Burn Test");

    let mut contract = RunarContract::new(artifact, vec![
        SdkValue::Bytes(owner_wallet.pub_key_hex.clone()),
        SdkValue::Bytes(token_id_hex),
        SdkValue::Bytes(metadata_hex),
    ]);

    contract
        .deploy(&mut provider, &*signer, &DeployOptions {
            satoshis: 5000,
            change_address: None,
        })
        .expect("deploy failed");

    // Burn: sig=Auto, no state continuation
    let (call_txid, _tx) = contract
        .call(
            "burn",
            &[SdkValue::Auto],
            &mut provider,
            &*signer,
            None,
        )
        .expect("burn failed");
    assert!(!call_txid.is_empty());
}

#[test]
#[ignore]
fn test_nft_wrong_owner_rejected() {
    skip_if_no_node();

    let artifact = compile_contract("examples/ts/token-nft/NFTExample.runar.ts");

    let mut provider = create_provider();
    // Deploy with owner=walletA
    let (signer_a, owner_wallet) = create_funded_wallet(&mut provider);
    let new_owner = create_wallet();

    let token_id_hex = hex_encode_str("NFT-REJECT");
    let metadata_hex = hex_encode_str("Rejection Test");

    let mut contract = RunarContract::new(artifact, vec![
        SdkValue::Bytes(owner_wallet.pub_key_hex.clone()),
        SdkValue::Bytes(token_id_hex),
        SdkValue::Bytes(metadata_hex),
    ]);

    contract
        .deploy(&mut provider, &*signer_a, &DeployOptions {
            satoshis: 5000,
            change_address: None,
        })
        .expect("deploy failed");

    // Call transfer with a different signer — should be rejected
    let (signer_b, _wallet_b) = create_funded_wallet(&mut provider);
    let mut new_state = HashMap::new();
    new_state.insert("owner".to_string(), SdkValue::Bytes(new_owner.pub_key_hex.clone()));

    let result = contract.call(
        "transfer",
        &[SdkValue::Auto, SdkValue::Bytes(new_owner.pub_key_hex), SdkValue::Int(5000)],
        &mut provider,
        &*signer_b,
        Some(&CallOptions {
            new_state: Some(new_state),
            ..Default::default()
        }),
    );
    assert!(result.is_err(), "transfer with wrong owner should be rejected");
}
