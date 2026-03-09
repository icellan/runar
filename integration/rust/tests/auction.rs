//! Auction integration test — stateful contract (SDK Deploy path).
//!
//! The bid() method checks extractLocktime, and close() requires a Sig.
//! We test compile + deploy via the SDK.

use crate::helpers::*;
use runar_lang::sdk::{DeployOptions, RunarContract, SdkValue};

#[test]
#[ignore]
fn test_auction_compile() {
    skip_if_no_node();

    let artifact = compile_contract("examples/ts/auction/Auction.runar.ts");
    assert_eq!(artifact.contract_name, "Auction");
}

#[test]
#[ignore]
fn test_auction_deploy() {
    skip_if_no_node();

    let artifact = compile_contract("examples/ts/auction/Auction.runar.ts");

    let mut provider = create_provider();
    let auctioneer = create_wallet();
    let initial_bidder = create_wallet();
    let (signer, _wallet) = create_funded_wallet(&mut provider);

    // Constructor: (auctioneer: PubKey, highestBidder: PubKey, highestBid: bigint, deadline: bigint)
    let mut contract = RunarContract::new(artifact, vec![
        SdkValue::Bytes(auctioneer.pub_key_hex),
        SdkValue::Bytes(initial_bidder.pub_key_hex),
        SdkValue::Int(1000),
        SdkValue::Int(1_000_000), // deadline far in the future
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
fn test_auction_deploy_zero_bid() {
    skip_if_no_node();

    let artifact = compile_contract("examples/ts/auction/Auction.runar.ts");

    let mut provider = create_provider();
    let auctioneer = create_wallet();
    let initial_bidder = create_wallet();
    let (signer, _wallet) = create_funded_wallet(&mut provider);

    let mut contract = RunarContract::new(artifact, vec![
        SdkValue::Bytes(auctioneer.pub_key_hex),
        SdkValue::Bytes(initial_bidder.pub_key_hex),
        SdkValue::Int(0),
        SdkValue::Int(500_000),
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
fn test_auction_deploy_same_key_both_roles() {
    skip_if_no_node();

    let artifact = compile_contract("examples/ts/auction/Auction.runar.ts");

    let mut provider = create_provider();
    let both = create_wallet();
    let (signer, _wallet) = create_funded_wallet(&mut provider);

    let mut contract = RunarContract::new(artifact, vec![
        SdkValue::Bytes(both.pub_key_hex.clone()),
        SdkValue::Bytes(both.pub_key_hex),
        SdkValue::Int(500),
        SdkValue::Int(999_999),
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
fn test_auction_close() {
    skip_if_no_node();

    let artifact = compile_contract("examples/ts/auction/Auction.runar.ts");
    let mut provider = create_provider();
    let (signer, auctioneer_wallet) = create_funded_wallet(&mut provider);
    let bidder = create_wallet();

    // Constructor: auctioneer, highestBidder, highestBid, deadline
    // deadline=0 so extractLocktime(txPreimage) >= deadline passes with nLocktime=0
    let mut contract = RunarContract::new(artifact, vec![
        SdkValue::Bytes(auctioneer_wallet.pub_key_hex.clone()),
        SdkValue::Bytes(bidder.pub_key_hex),
        SdkValue::Int(100),
        SdkValue::Int(0),  // deadline=0 so auction deadline has passed
    ]);

    contract
        .deploy(&mut provider, &*signer, &DeployOptions {
            satoshis: 5000,
            change_address: None,
        })
        .expect("deploy failed");

    let (call_txid, _tx) = contract
        .call(
            "close",
            &[SdkValue::Auto],
            &mut provider,
            &*signer,
            None,
        )
        .expect("close failed");
    assert!(!call_txid.is_empty());
}

#[test]
#[ignore]
fn test_auction_wrong_signer_rejected() {
    skip_if_no_node();

    let artifact = compile_contract("examples/ts/auction/Auction.runar.ts");
    let mut provider = create_provider();
    // Deploy with auctioneer=walletA
    let (signer_a, auctioneer_wallet) = create_funded_wallet(&mut provider);
    let bidder = create_wallet();

    let mut contract = RunarContract::new(artifact, vec![
        SdkValue::Bytes(auctioneer_wallet.pub_key_hex.clone()),
        SdkValue::Bytes(bidder.pub_key_hex),
        SdkValue::Int(100),
        SdkValue::Int(0), // deadline=0 so auction deadline has passed
    ]);

    contract
        .deploy(&mut provider, &*signer_a, &DeployOptions {
            satoshis: 5000,
            change_address: None,
        })
        .expect("deploy failed");

    // Call close with a different signer — should be rejected
    let (signer_b, _wallet_b) = create_funded_wallet(&mut provider);
    let result = contract.call(
        "close",
        &[SdkValue::Auto],
        &mut provider,
        &*signer_b,
        None,
    );
    assert!(result.is_err(), "close with wrong signer should be rejected");
}
