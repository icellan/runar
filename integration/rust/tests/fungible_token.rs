//! FungibleToken integration test — stateful contract with secure merge via addOutput.
//!
//! Tests compile, deploy, transfer (multi-output), and merge (additional
//! contract inputs with position-dependent balance verification) using the Rúnar SDK.

use crate::helpers::*;
use runar_lang::sdk::{
    CallOptions, DeployOptions, OutputSpec, RunarContract, SdkValue,
};
use std::collections::HashMap;

fn hex_encode_str(s: &str) -> String {
    s.as_bytes().iter().map(|b| format!("{:02x}", b)).collect()
}

fn ft_state(owner: &str, balance: i64, merge_balance: i64) -> HashMap<String, SdkValue> {
    let mut m = HashMap::new();
    m.insert("owner".to_string(), SdkValue::Bytes(owner.to_string()));
    m.insert("balance".to_string(), SdkValue::Int(balance));
    m.insert("mergeBalance".to_string(), SdkValue::Int(merge_balance));
    m
}

#[test]
#[ignore]
fn test_fungible_token_compile() {
    skip_if_no_node();

    let artifact = compile_contract("examples/ts/token-ft/FungibleTokenExample.runar.ts");
    assert_eq!(artifact.contract_name, "FungibleToken");
}

#[test]
#[ignore]
fn test_fungible_token_deploy() {
    skip_if_no_node();

    let artifact = compile_contract("examples/ts/token-ft/FungibleTokenExample.runar.ts");

    let mut provider = create_provider();
    let owner = create_wallet();
    let (signer, _wallet) = create_funded_wallet(&mut provider);

    let token_id_hex = hex_encode_str("TEST-TOKEN-001");

    // Constructor: (owner: PubKey, balance: bigint, mergeBalance: bigint, tokenId: ByteString)
    let mut contract = RunarContract::new(artifact, vec![
        SdkValue::Bytes(owner.pub_key_hex),
        SdkValue::Int(1000),
        SdkValue::Int(0),
        SdkValue::Bytes(token_id_hex),
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
fn test_fungible_token_deploy_zero_balance() {
    skip_if_no_node();

    let artifact = compile_contract("examples/ts/token-ft/FungibleTokenExample.runar.ts");

    let mut provider = create_provider();
    let owner = create_wallet();
    let (signer, _wallet) = create_funded_wallet(&mut provider);

    let token_id_hex = hex_encode_str("ZERO-BAL-TOKEN");

    let mut contract = RunarContract::new(artifact, vec![
        SdkValue::Bytes(owner.pub_key_hex),
        SdkValue::Int(0),
        SdkValue::Int(0),
        SdkValue::Bytes(token_id_hex),
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
fn test_fungible_token_deploy_large_balance() {
    skip_if_no_node();

    let artifact = compile_contract("examples/ts/token-ft/FungibleTokenExample.runar.ts");

    let mut provider = create_provider();
    let owner = create_wallet();
    let (signer, _wallet) = create_funded_wallet(&mut provider);

    let token_id_hex = hex_encode_str("BIG-TOKEN");

    let mut contract = RunarContract::new(artifact, vec![
        SdkValue::Bytes(owner.pub_key_hex),
        SdkValue::Int(2_100_000_000_000_000),
        SdkValue::Int(0),
        SdkValue::Bytes(token_id_hex),
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
fn test_fungible_token_send() {
    skip_if_no_node();

    let artifact = compile_contract("examples/ts/token-ft/FungibleTokenExample.runar.ts");
    let mut provider = create_provider();
    let (signer, owner_wallet) = create_funded_wallet(&mut provider);
    let recipient = create_wallet();

    let token_id_hex = "deadbeef".to_string();

    let mut contract = RunarContract::new(artifact, vec![
        SdkValue::Bytes(owner_wallet.pub_key_hex.clone()),
        SdkValue::Int(1000),
        SdkValue::Int(0),
        SdkValue::Bytes(token_id_hex),
    ]);

    contract
        .deploy(&mut provider, &*signer, &DeployOptions {
            satoshis: 5000,
            change_address: None,
        })
        .expect("deploy failed");

    let (call_txid, _tx) = contract
        .call(
            "send",
            &[SdkValue::Auto, SdkValue::Bytes(recipient.pub_key_hex), SdkValue::Int(5000)],
            &mut provider,
            &*signer,
            None,
        )
        .expect("send failed");
    assert!(!call_txid.is_empty());
}

#[test]
#[ignore]
fn test_fungible_token_wrong_owner_rejected() {
    skip_if_no_node();

    let artifact = compile_contract("examples/ts/token-ft/FungibleTokenExample.runar.ts");
    let mut provider = create_provider();
    let (signer_a, owner_wallet) = create_funded_wallet(&mut provider);
    let recipient = create_wallet();

    let token_id_hex = hex_encode_str("REJECT-TOKEN");

    let mut contract = RunarContract::new(artifact, vec![
        SdkValue::Bytes(owner_wallet.pub_key_hex.clone()),
        SdkValue::Int(1000),
        SdkValue::Int(0),
        SdkValue::Bytes(token_id_hex),
    ]);

    contract
        .deploy(&mut provider, &*signer_a, &DeployOptions {
            satoshis: 5000,
            change_address: None,
        })
        .expect("deploy failed");

    let (signer_b, _wallet_b) = create_funded_wallet(&mut provider);
    let mut new_state = HashMap::new();
    new_state.insert("owner".to_string(), SdkValue::Bytes(recipient.pub_key_hex.clone()));
    let call_opts = CallOptions {
        new_state: Some(new_state),
        ..Default::default()
    };
    let result = contract.call(
        "send",
        &[SdkValue::Auto, SdkValue::Bytes(recipient.pub_key_hex), SdkValue::Int(5000)],
        &mut provider,
        &*signer_b,
        Some(&call_opts),
    );
    assert!(result.is_err(), "send with wrong owner should be rejected");
}

// ---------------------------------------------------------------------------
// Transfer test — splits 1 UTXO into 2 outputs (SDK multi-output)
// ---------------------------------------------------------------------------

#[test]
#[ignore]
fn test_fungible_token_transfer() {
    skip_if_no_node();

    let artifact = compile_contract("examples/ts/token-ft/FungibleTokenExample.runar.ts");
    let mut provider = create_provider();
    let (signer, owner_wallet) = create_funded_wallet(&mut provider);
    let recipient = create_wallet();
    let token_id_hex = hex_encode_str("TRANSFER-TOKEN");

    let mut contract = RunarContract::new(artifact, vec![
        SdkValue::Bytes(owner_wallet.pub_key_hex.clone()),
        SdkValue::Int(1000),
        SdkValue::Int(0),
        SdkValue::Bytes(token_id_hex),
    ]);

    contract
        .deploy(&mut provider, &*signer, &DeployOptions {
            satoshis: 5000,
            change_address: None,
        })
        .expect("deploy failed");

    let call_opts = CallOptions {
        outputs: Some(vec![
            OutputSpec {
                satoshis: 2000,
                state: ft_state(&recipient.pub_key_hex, 300, 0),
            },
            OutputSpec {
                satoshis: 2000,
                state: ft_state(&owner_wallet.pub_key_hex, 700, 0),
            },
        ]),
        ..Default::default()
    };
    let (txid, _) = contract
        .call(
            "transfer",
            &[
                SdkValue::Auto,
                SdkValue::Bytes(recipient.pub_key_hex),
                SdkValue::Int(300),
                SdkValue::Int(2000),
            ],
            &mut provider,
            &*signer,
            Some(&call_opts),
        )
        .expect("transfer failed");
    assert!(!txid.is_empty());
    assert_eq!(txid.len(), 64);
}

// ---------------------------------------------------------------------------
// Merge test — consolidates 2 UTXOs into 1 output (SDK additional inputs)
// Uses position-dependent balance slots for anti-inflation security.
// ---------------------------------------------------------------------------

#[test]
#[ignore]
fn test_fungible_token_merge() {
    skip_if_no_node();

    let artifact = compile_contract("examples/ts/token-ft/FungibleTokenExample.runar.ts");
    let mut provider = create_provider();
    let (signer, owner_wallet) = create_funded_wallet(&mut provider);
    let token_id_hex = hex_encode_str("MERGE-TOKEN");

    // Deploy contract 1 (balance=400)
    let mut contract1 = RunarContract::new(artifact.clone(), vec![
        SdkValue::Bytes(owner_wallet.pub_key_hex.clone()),
        SdkValue::Int(400),
        SdkValue::Int(0),
        SdkValue::Bytes(token_id_hex.clone()),
    ]);
    contract1
        .deploy(&mut provider, &*signer, &DeployOptions {
            satoshis: 5000,
            change_address: None,
        })
        .expect("deploy contract1 failed");

    // Deploy contract 2 (balance=600)
    let mut contract2 = RunarContract::new(artifact.clone(), vec![
        SdkValue::Bytes(owner_wallet.pub_key_hex.clone()),
        SdkValue::Int(600),
        SdkValue::Int(0),
        SdkValue::Bytes(token_id_hex.clone()),
    ]);
    contract2
        .deploy(&mut provider, &*signer, &DeployOptions {
            satoshis: 5000,
            change_address: None,
        })
        .expect("deploy contract2 failed");

    let utxo2 = contract2.get_utxo().expect("contract2 has no UTXO").clone();

    // merge(sig, otherBalance, allPrevouts, outputSatoshis)
    // allPrevouts is auto-computed by SDK (null placeholder)
    let call_opts = CallOptions {
        additional_contract_inputs: Some(vec![utxo2]),
        additional_contract_input_args: Some(vec![
            vec![SdkValue::Auto, SdkValue::Int(400), SdkValue::Auto, SdkValue::Int(4000)],
        ]),
        outputs: Some(vec![
            OutputSpec {
                satoshis: 4000,
                state: ft_state(&owner_wallet.pub_key_hex, 400, 600),
            },
        ]),
        ..Default::default()
    };
    let (txid, _) = contract1
        .call(
            "merge",
            &[SdkValue::Auto, SdkValue::Int(600), SdkValue::Auto, SdkValue::Int(4000)],
            &mut provider,
            &*signer,
            Some(&call_opts),
        )
        .expect("merge failed");
    assert!(!txid.is_empty());
    assert_eq!(txid.len(), 64);
}

// ---------------------------------------------------------------------------
// Merge — attacker inflates otherBalance (hashOutputs mismatch rejects it)
// ---------------------------------------------------------------------------

#[test]
#[ignore]
fn test_fungible_token_merge_inflated_other_balance() {
    skip_if_no_node();

    let artifact = compile_contract("examples/ts/token-ft/FungibleTokenExample.runar.ts");
    let mut provider = create_provider();
    let (signer, owner_wallet) = create_funded_wallet(&mut provider);
    let token_id_hex = hex_encode_str("INFLATE-TOKEN");

    let mut contract1 = RunarContract::new(artifact.clone(), vec![
        SdkValue::Bytes(owner_wallet.pub_key_hex.clone()),
        SdkValue::Int(400),
        SdkValue::Int(0),
        SdkValue::Bytes(token_id_hex.clone()),
    ]);
    contract1
        .deploy(&mut provider, &*signer, &DeployOptions {
            satoshis: 5000,
            change_address: None,
        })
        .expect("deploy contract1 failed");

    let mut contract2 = RunarContract::new(artifact.clone(), vec![
        SdkValue::Bytes(owner_wallet.pub_key_hex.clone()),
        SdkValue::Int(600),
        SdkValue::Int(0),
        SdkValue::Bytes(token_id_hex.clone()),
    ]);
    contract2
        .deploy(&mut provider, &*signer, &DeployOptions {
            satoshis: 5000,
            change_address: None,
        })
        .expect("deploy contract2 failed");

    let utxo2 = contract2.get_utxo().expect("contract2 has no UTXO").clone();

    // Attacker lies: input 0 claims otherBalance=1600, input 1 claims otherBalance=1400
    // Outputs won't match → hashOutputs mismatch → rejected
    let call_opts = CallOptions {
        additional_contract_inputs: Some(vec![utxo2]),
        additional_contract_input_args: Some(vec![
            vec![SdkValue::Auto, SdkValue::Int(1400), SdkValue::Auto, SdkValue::Int(4000)],
        ]),
        outputs: Some(vec![
            OutputSpec {
                satoshis: 4000,
                state: ft_state(&owner_wallet.pub_key_hex, 400, 1600),
            },
        ]),
        ..Default::default()
    };
    let result = contract1.call(
        "merge",
        &[SdkValue::Auto, SdkValue::Int(1600), SdkValue::Auto, SdkValue::Int(4000)],
        &mut provider,
        &*signer,
        Some(&call_opts),
    );
    assert!(result.is_err(), "merge with inflated otherBalance should be rejected");
}

// ---------------------------------------------------------------------------
// Merge — negative otherBalance (fails assert >= 0)
// ---------------------------------------------------------------------------

#[test]
#[ignore]
fn test_fungible_token_merge_negative_other_balance() {
    skip_if_no_node();

    let artifact = compile_contract("examples/ts/token-ft/FungibleTokenExample.runar.ts");
    let mut provider = create_provider();
    let (signer, owner_wallet) = create_funded_wallet(&mut provider);
    let token_id_hex = hex_encode_str("DEFLATE-TOKEN");

    let mut contract1 = RunarContract::new(artifact.clone(), vec![
        SdkValue::Bytes(owner_wallet.pub_key_hex.clone()),
        SdkValue::Int(400),
        SdkValue::Int(0),
        SdkValue::Bytes(token_id_hex.clone()),
    ]);
    contract1
        .deploy(&mut provider, &*signer, &DeployOptions {
            satoshis: 5000,
            change_address: None,
        })
        .expect("deploy contract1 failed");

    let mut contract2 = RunarContract::new(artifact.clone(), vec![
        SdkValue::Bytes(owner_wallet.pub_key_hex.clone()),
        SdkValue::Int(600),
        SdkValue::Int(0),
        SdkValue::Bytes(token_id_hex.clone()),
    ]);
    contract2
        .deploy(&mut provider, &*signer, &DeployOptions {
            satoshis: 5000,
            change_address: None,
        })
        .expect("deploy contract2 failed");

    let utxo2 = contract2.get_utxo().expect("contract2 has no UTXO").clone();

    let call_opts = CallOptions {
        additional_contract_inputs: Some(vec![utxo2]),
        additional_contract_input_args: Some(vec![
            vec![SdkValue::Auto, SdkValue::Int(-1), SdkValue::Auto, SdkValue::Int(4000)],
        ]),
        outputs: Some(vec![
            OutputSpec {
                satoshis: 4000,
                state: ft_state(&owner_wallet.pub_key_hex, 100, 400),
            },
        ]),
        ..Default::default()
    };
    let result = contract1.call(
        "merge",
        &[SdkValue::Auto, SdkValue::Int(100), SdkValue::Auto, SdkValue::Int(4000)],
        &mut provider,
        &*signer,
        Some(&call_opts),
    );
    assert!(result.is_err(), "merge with negative otherBalance should be rejected");
}

// ---------------------------------------------------------------------------
// Merge — zero-balance UTXO (edge case, should succeed)
// ---------------------------------------------------------------------------

#[test]
#[ignore]
fn test_fungible_token_merge_zero_balance() {
    skip_if_no_node();

    let artifact = compile_contract("examples/ts/token-ft/FungibleTokenExample.runar.ts");
    let mut provider = create_provider();
    let (signer, owner_wallet) = create_funded_wallet(&mut provider);
    let token_id_hex = hex_encode_str("ZERO-MERGE-TK");

    let mut contract1 = RunarContract::new(artifact.clone(), vec![
        SdkValue::Bytes(owner_wallet.pub_key_hex.clone()),
        SdkValue::Int(0),
        SdkValue::Int(0),
        SdkValue::Bytes(token_id_hex.clone()),
    ]);
    contract1
        .deploy(&mut provider, &*signer, &DeployOptions {
            satoshis: 5000,
            change_address: None,
        })
        .expect("deploy contract1 failed");

    let mut contract2 = RunarContract::new(artifact.clone(), vec![
        SdkValue::Bytes(owner_wallet.pub_key_hex.clone()),
        SdkValue::Int(500),
        SdkValue::Int(0),
        SdkValue::Bytes(token_id_hex.clone()),
    ]);
    contract2
        .deploy(&mut provider, &*signer, &DeployOptions {
            satoshis: 5000,
            change_address: None,
        })
        .expect("deploy contract2 failed");

    let utxo2 = contract2.get_utxo().expect("contract2 has no UTXO").clone();

    let call_opts = CallOptions {
        additional_contract_inputs: Some(vec![utxo2]),
        additional_contract_input_args: Some(vec![
            vec![SdkValue::Auto, SdkValue::Int(0), SdkValue::Auto, SdkValue::Int(4000)],
        ]),
        outputs: Some(vec![
            OutputSpec {
                satoshis: 4000,
                state: ft_state(&owner_wallet.pub_key_hex, 0, 500),
            },
        ]),
        ..Default::default()
    };
    let (txid, _) = contract1
        .call(
            "merge",
            &[SdkValue::Auto, SdkValue::Int(500), SdkValue::Auto, SdkValue::Int(4000)],
            &mut provider,
            &*signer,
            Some(&call_opts),
        )
        .expect("merge with zero-balance UTXO should succeed");
    assert!(!txid.is_empty());
    assert_eq!(txid.len(), 64);
}

// ---------------------------------------------------------------------------
// Merge — wrong signer (checkSig should fail)
// ---------------------------------------------------------------------------

#[test]
#[ignore]
fn test_fungible_token_merge_wrong_signer() {
    skip_if_no_node();

    let artifact = compile_contract("examples/ts/token-ft/FungibleTokenExample.runar.ts");
    let mut provider = create_provider();
    let (signer_a, owner_wallet) = create_funded_wallet(&mut provider);
    let (signer_b, _wallet_b) = create_funded_wallet(&mut provider);
    let token_id_hex = hex_encode_str("MERGESIG-TOKEN");

    let mut contract1 = RunarContract::new(artifact.clone(), vec![
        SdkValue::Bytes(owner_wallet.pub_key_hex.clone()),
        SdkValue::Int(400),
        SdkValue::Int(0),
        SdkValue::Bytes(token_id_hex.clone()),
    ]);
    contract1
        .deploy(&mut provider, &*signer_a, &DeployOptions {
            satoshis: 5000,
            change_address: None,
        })
        .expect("deploy contract1 failed");

    let mut contract2 = RunarContract::new(artifact.clone(), vec![
        SdkValue::Bytes(owner_wallet.pub_key_hex.clone()),
        SdkValue::Int(600),
        SdkValue::Int(0),
        SdkValue::Bytes(token_id_hex.clone()),
    ]);
    contract2
        .deploy(&mut provider, &*signer_a, &DeployOptions {
            satoshis: 5000,
            change_address: None,
        })
        .expect("deploy contract2 failed");

    let utxo2 = contract2.get_utxo().expect("contract2 has no UTXO").clone();

    let call_opts = CallOptions {
        additional_contract_inputs: Some(vec![utxo2]),
        additional_contract_input_args: Some(vec![
            vec![SdkValue::Auto, SdkValue::Int(400), SdkValue::Auto, SdkValue::Int(4000)],
        ]),
        outputs: Some(vec![
            OutputSpec {
                satoshis: 4000,
                state: ft_state(&owner_wallet.pub_key_hex, 400, 600),
            },
        ]),
        ..Default::default()
    };
    let result = contract1.call(
        "merge",
        &[SdkValue::Auto, SdkValue::Int(600), SdkValue::Auto, SdkValue::Int(4000)],
        &mut provider,
        &*signer_b,
        Some(&call_opts),
    );
    assert!(result.is_err(), "merge with wrong signer should be rejected");
}

// ---------------------------------------------------------------------------
// Transfer — wrong signer (checkSig should fail)
// ---------------------------------------------------------------------------

#[test]
#[ignore]
fn test_fungible_token_transfer_wrong_signer() {
    skip_if_no_node();

    let artifact = compile_contract("examples/ts/token-ft/FungibleTokenExample.runar.ts");
    let mut provider = create_provider();
    let (signer_a, owner_wallet) = create_funded_wallet(&mut provider);
    let (signer_b, _wallet_b) = create_funded_wallet(&mut provider);
    let recipient = create_wallet();
    let token_id_hex = hex_encode_str("XFERSIG-TOKEN");

    let mut contract = RunarContract::new(artifact, vec![
        SdkValue::Bytes(owner_wallet.pub_key_hex.clone()),
        SdkValue::Int(1000),
        SdkValue::Int(0),
        SdkValue::Bytes(token_id_hex),
    ]);
    contract
        .deploy(&mut provider, &*signer_a, &DeployOptions {
            satoshis: 5000,
            change_address: None,
        })
        .expect("deploy failed");

    let call_opts = CallOptions {
        outputs: Some(vec![
            OutputSpec {
                satoshis: 2000,
                state: ft_state(&recipient.pub_key_hex, 300, 0),
            },
            OutputSpec {
                satoshis: 2000,
                state: ft_state(&owner_wallet.pub_key_hex, 700, 0),
            },
        ]),
        ..Default::default()
    };
    let result = contract.call(
        "transfer",
        &[
            SdkValue::Auto,
            SdkValue::Bytes(recipient.pub_key_hex),
            SdkValue::Int(300),
            SdkValue::Int(2000),
        ],
        &mut provider,
        &*signer_b,
        Some(&call_opts),
    );
    assert!(result.is_err(), "transfer with wrong signer should be rejected");
}

// ---------------------------------------------------------------------------
// Transfer — exact balance (1 output only, no change)
// ---------------------------------------------------------------------------

#[test]
#[ignore]
fn test_fungible_token_transfer_exact_balance() {
    skip_if_no_node();

    let artifact = compile_contract("examples/ts/token-ft/FungibleTokenExample.runar.ts");
    let mut provider = create_provider();
    let (signer, owner_wallet) = create_funded_wallet(&mut provider);
    let recipient = create_wallet();
    let token_id_hex = hex_encode_str("XFER-EXACT-TK");

    let mut contract = RunarContract::new(artifact, vec![
        SdkValue::Bytes(owner_wallet.pub_key_hex.clone()),
        SdkValue::Int(1000),
        SdkValue::Int(0),
        SdkValue::Bytes(token_id_hex),
    ]);
    contract
        .deploy(&mut provider, &*signer, &DeployOptions {
            satoshis: 5000,
            change_address: None,
        })
        .expect("deploy failed");

    // Transfer entire balance — produces only 1 output (no change)
    let call_opts = CallOptions {
        outputs: Some(vec![
            OutputSpec {
                satoshis: 5000,
                state: ft_state(&recipient.pub_key_hex, 1000, 0),
            },
        ]),
        ..Default::default()
    };
    let (txid, _) = contract
        .call(
            "transfer",
            &[
                SdkValue::Auto,
                SdkValue::Bytes(recipient.pub_key_hex),
                SdkValue::Int(1000),
                SdkValue::Int(5000),
            ],
            &mut provider,
            &*signer,
            Some(&call_opts),
        )
        .expect("transfer exact balance failed");
    assert!(!txid.is_empty());
    assert_eq!(txid.len(), 64);
}

// ---------------------------------------------------------------------------
// Transfer — zero amount (assert fails: amount > 0)
// ---------------------------------------------------------------------------

#[test]
#[ignore]
fn test_fungible_token_transfer_zero_amount_rejected() {
    skip_if_no_node();

    let artifact = compile_contract("examples/ts/token-ft/FungibleTokenExample.runar.ts");
    let mut provider = create_provider();
    let (signer, owner_wallet) = create_funded_wallet(&mut provider);
    let recipient = create_wallet();
    let token_id_hex = hex_encode_str("XFER-ZERO-TK");

    let mut contract = RunarContract::new(artifact, vec![
        SdkValue::Bytes(owner_wallet.pub_key_hex.clone()),
        SdkValue::Int(1000),
        SdkValue::Int(0),
        SdkValue::Bytes(token_id_hex),
    ]);
    contract
        .deploy(&mut provider, &*signer, &DeployOptions {
            satoshis: 5000,
            change_address: None,
        })
        .expect("deploy failed");

    let call_opts = CallOptions {
        outputs: Some(vec![
            OutputSpec {
                satoshis: 5000,
                state: ft_state(&owner_wallet.pub_key_hex, 1000, 0),
            },
        ]),
        ..Default::default()
    };
    let result = contract.call(
        "transfer",
        &[
            SdkValue::Auto,
            SdkValue::Bytes(recipient.pub_key_hex),
            SdkValue::Int(0),
            SdkValue::Int(5000),
        ],
        &mut provider,
        &*signer,
        Some(&call_opts),
    );
    assert!(result.is_err(), "transfer of zero amount should be rejected");
}

// ---------------------------------------------------------------------------
// Transfer — exceeds balance (assert fails: amount <= totalBalance)
// ---------------------------------------------------------------------------

#[test]
#[ignore]
fn test_fungible_token_transfer_exceeds_balance_rejected() {
    skip_if_no_node();

    let artifact = compile_contract("examples/ts/token-ft/FungibleTokenExample.runar.ts");
    let mut provider = create_provider();
    let (signer, owner_wallet) = create_funded_wallet(&mut provider);
    let recipient = create_wallet();
    let token_id_hex = hex_encode_str("XFER-EXCEED-TK");

    let mut contract = RunarContract::new(artifact, vec![
        SdkValue::Bytes(owner_wallet.pub_key_hex.clone()),
        SdkValue::Int(1000),
        SdkValue::Int(0),
        SdkValue::Bytes(token_id_hex),
    ]);
    contract
        .deploy(&mut provider, &*signer, &DeployOptions {
            satoshis: 5000,
            change_address: None,
        })
        .expect("deploy failed");

    let call_opts = CallOptions {
        outputs: Some(vec![
            OutputSpec {
                satoshis: 5000,
                state: ft_state(&recipient.pub_key_hex, 1001, 0),
            },
        ]),
        ..Default::default()
    };
    let result = contract.call(
        "transfer",
        &[
            SdkValue::Auto,
            SdkValue::Bytes(recipient.pub_key_hex),
            SdkValue::Int(1001),
            SdkValue::Int(5000),
        ],
        &mut provider,
        &*signer,
        Some(&call_opts),
    );
    assert!(result.is_err(), "transfer exceeding balance should be rejected");
}

// ---------------------------------------------------------------------------
// Transfer — attacker inflates output totals (hashOutputs mismatch)
// ---------------------------------------------------------------------------

#[test]
#[ignore]
fn test_fungible_token_transfer_inflated_balance() {
    skip_if_no_node();

    let artifact = compile_contract("examples/ts/token-ft/FungibleTokenExample.runar.ts");
    let mut provider = create_provider();
    let (signer, owner_wallet) = create_funded_wallet(&mut provider);
    let recipient = create_wallet();
    let token_id_hex = hex_encode_str("XFER-INFLATE-TK");

    let mut contract = RunarContract::new(artifact, vec![
        SdkValue::Bytes(owner_wallet.pub_key_hex.clone()),
        SdkValue::Int(1000),
        SdkValue::Int(0),
        SdkValue::Bytes(token_id_hex),
    ]);
    contract
        .deploy(&mut provider, &*signer, &DeployOptions {
            satoshis: 5000,
            change_address: None,
        })
        .expect("deploy failed");

    // Attacker claims outputs totaling 1300 from a 1000-balance UTXO.
    // The contract script does assert(amount <= totalBalance), but the
    // outputs claim inflated balances. hashOutputs mismatch rejects it.
    let call_opts = CallOptions {
        outputs: Some(vec![
            OutputSpec {
                satoshis: 2000,
                state: ft_state(&recipient.pub_key_hex, 800, 0),
            },
            OutputSpec {
                satoshis: 2000,
                state: ft_state(&owner_wallet.pub_key_hex, 500, 0),
            },
        ]),
        ..Default::default()
    };
    let result = contract.call(
        "transfer",
        &[
            SdkValue::Auto,
            SdkValue::Bytes(recipient.pub_key_hex),
            SdkValue::Int(300),
            SdkValue::Int(2000),
        ],
        &mut provider,
        &*signer,
        Some(&call_opts),
    );
    assert!(result.is_err(), "transfer with inflated output totals should be rejected");
}

// ---------------------------------------------------------------------------
// Transfer — attacker deflates output totals (hashOutputs mismatch)
// ---------------------------------------------------------------------------

#[test]
#[ignore]
fn test_fungible_token_transfer_deflated_balance() {
    skip_if_no_node();

    let artifact = compile_contract("examples/ts/token-ft/FungibleTokenExample.runar.ts");
    let mut provider = create_provider();
    let (signer, owner_wallet) = create_funded_wallet(&mut provider);
    let recipient = create_wallet();
    let token_id_hex = hex_encode_str("XFER-DEFLATE-TK");

    let mut contract = RunarContract::new(artifact, vec![
        SdkValue::Bytes(owner_wallet.pub_key_hex.clone()),
        SdkValue::Int(1000),
        SdkValue::Int(0),
        SdkValue::Bytes(token_id_hex),
    ]);
    contract
        .deploy(&mut provider, &*signer, &DeployOptions {
            satoshis: 5000,
            change_address: None,
        })
        .expect("deploy failed");

    // Attacker claims outputs totaling only 500 from a 1000-balance UTXO.
    // The contract creates correct outputs internally, but the declared
    // state doesn't match — hashOutputs mismatch rejects it.
    let call_opts = CallOptions {
        outputs: Some(vec![
            OutputSpec {
                satoshis: 2000,
                state: ft_state(&recipient.pub_key_hex, 200, 0),
            },
            OutputSpec {
                satoshis: 2000,
                state: ft_state(&owner_wallet.pub_key_hex, 300, 0),
            },
        ]),
        ..Default::default()
    };
    let result = contract.call(
        "transfer",
        &[
            SdkValue::Auto,
            SdkValue::Bytes(recipient.pub_key_hex),
            SdkValue::Int(300),
            SdkValue::Int(2000),
        ],
        &mut provider,
        &*signer,
        Some(&call_opts),
    );
    assert!(result.is_err(), "transfer with deflated output totals should be rejected");
}
