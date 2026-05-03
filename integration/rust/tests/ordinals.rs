//! 1Sat Ordinals + BSV-20 / BSV-21 token integration tests.
//!
//! These contracts are simple P2PKH-style locking scripts with an inscription
//! envelope or token-protocol prefix in their unlocking-time data outputs.
//! The locking-script logic is identical to P2PKH (hash160 + checkSig), so
//! the integration coverage focuses on:
//!   - Compile success
//!   - Deploy succeeds on regtest under the `regtest` feature
//!
//! Mirrors `integration/ts/{bsv20-token,bsv21-token,ordinal-nft}.test.ts`.

use crate::helpers::*;
use runar_lang::sdk::{DeployOptions, RunarContract, SdkValue};

// ---------------------------------------------------------------------------
// BSV-20 token
// ---------------------------------------------------------------------------

#[test]
fn test_bsv20_token_compiles() {
    let artifact = compile_contract("examples/ts/bsv20-token/BSV20Token.runar.ts");
    assert_eq!(artifact.contract_name, "BSV20Token");
    assert!(!artifact.script.is_empty());
}

#[test]
#[cfg_attr(not(feature = "regtest"), ignore)]
fn test_bsv20_token_deploy() {
    skip_if_no_node();

    let artifact = compile_contract("examples/ts/bsv20-token/BSV20Token.runar.ts");

    let mut provider = create_provider();
    let (signer, wallet) = create_funded_wallet(&mut provider);

    let mut contract = RunarContract::new(
        artifact,
        vec![SdkValue::Bytes(wallet.pub_key_hash.clone())],
    );

    let (deploy_txid, _tx) = contract
        .deploy(&mut provider, &*signer, &DeployOptions {
            satoshis: 5_000,
            change_address: None,
        })
        .expect("BSV-20 deploy failed");
    assert!(!deploy_txid.is_empty());
    assert_eq!(deploy_txid.len(), 64);
}

// ---------------------------------------------------------------------------
// BSV-21 token
// ---------------------------------------------------------------------------

#[test]
fn test_bsv21_token_compiles() {
    let artifact = compile_contract("examples/ts/bsv21-token/BSV21Token.runar.ts");
    assert_eq!(artifact.contract_name, "BSV21Token");
    assert!(!artifact.script.is_empty());
}

#[test]
#[cfg_attr(not(feature = "regtest"), ignore)]
fn test_bsv21_token_deploy() {
    skip_if_no_node();

    let artifact = compile_contract("examples/ts/bsv21-token/BSV21Token.runar.ts");

    let mut provider = create_provider();
    let (signer, wallet) = create_funded_wallet(&mut provider);

    let mut contract = RunarContract::new(
        artifact,
        vec![SdkValue::Bytes(wallet.pub_key_hash.clone())],
    );

    let (deploy_txid, _tx) = contract
        .deploy(&mut provider, &*signer, &DeployOptions {
            satoshis: 5_000,
            change_address: None,
        })
        .expect("BSV-21 deploy failed");
    assert!(!deploy_txid.is_empty());
    assert_eq!(deploy_txid.len(), 64);
}

// ---------------------------------------------------------------------------
// 1Sat Ordinal NFT
// ---------------------------------------------------------------------------

#[test]
fn test_ordinal_nft_compiles() {
    let artifact = compile_contract("examples/ts/ordinal-nft/OrdinalNFT.runar.ts");
    assert_eq!(artifact.contract_name, "OrdinalNFT");
    assert!(!artifact.script.is_empty());
}

#[test]
#[cfg_attr(not(feature = "regtest"), ignore)]
fn test_ordinal_nft_deploy() {
    skip_if_no_node();

    let artifact = compile_contract("examples/ts/ordinal-nft/OrdinalNFT.runar.ts");

    let mut provider = create_provider();
    let (signer, wallet) = create_funded_wallet(&mut provider);

    let mut contract = RunarContract::new(
        artifact,
        vec![SdkValue::Bytes(wallet.pub_key_hash.clone())],
    );

    let (deploy_txid, _tx) = contract
        .deploy(&mut provider, &*signer, &DeployOptions {
            satoshis: 1_000,
            change_address: None,
        })
        .expect("OrdinalNFT deploy failed");
    assert!(!deploy_txid.is_empty());
    assert_eq!(deploy_txid.len(), 64);
}
