//! StateCovenant integration test -- stateful covenant combining Baby Bear
//! field arithmetic, Merkle proof verification, and hash256 batch data binding.
//!
//! Deploys and advances the covenant on a real regtest node. Tests both valid
//! state transitions and on-chain rejection of invalid inputs.

use crate::helpers::*;
use runar_lang::sdk::{DeployOptions, RunarContract, SdkValue};
use sha2::{Digest, Sha256};

const BB_PRIME: i64 = 2013265921;

fn bb_mul_field(a: i64, b: i64) -> i64 {
    (a * b) % BB_PRIME
}

fn hex_sha256(hex_data: &str) -> String {
    let data = hex_decode_bytes(hex_data);
    let hash = Sha256::digest(&data);
    hex_encode_bytes(&hash)
}

fn hex_hash256(hex_data: &str) -> String {
    hex_sha256(&hex_sha256(hex_data))
}

fn hex_state_root(n: usize) -> String {
    hex_sha256(&format!("{:02x}", n))
}

fn hex_zeros32() -> String {
    "00".repeat(32)
}

fn hex_decode_bytes(hex: &str) -> Vec<u8> {
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
        .collect()
}

fn hex_encode_bytes(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

struct HexMerkleTree {
    root: String,
    layers: Vec<Vec<String>>,
    leaves: Vec<String>,
}

fn build_hex_merkle_tree(leaves: &[String]) -> HexMerkleTree {
    let mut level: Vec<String> = leaves.to_vec();
    let mut layers: Vec<Vec<String>> = vec![level.clone()];

    while level.len() > 1 {
        let mut next = Vec::new();
        for i in (0..level.len()).step_by(2) {
            next.push(hex_sha256(&format!("{}{}", level[i], level[i + 1])));
        }
        level = next;
        layers.push(level.clone());
    }

    HexMerkleTree {
        root: level[0].clone(),
        layers,
        leaves: leaves.to_vec(),
    }
}

impl HexMerkleTree {
    fn get_proof(&self, index: usize) -> (String, String) {
        let mut siblings = Vec::new();
        let mut idx = index;
        for d in 0..self.layers.len() - 1 {
            siblings.push(self.layers[d][idx ^ 1].clone());
            idx >>= 1;
        }
        let proof: String = siblings.join("");
        (self.leaves[index].clone(), proof)
    }
}

const SC_LEAF_IDX: usize = 3;

fn build_test_tree() -> HexMerkleTree {
    let leaves: Vec<String> = (0..16)
        .map(|i| hex_sha256(&format!("{:02x}", i)))
        .collect();
    build_hex_merkle_tree(&leaves)
}

fn build_call_args(
    tree: &HexMerkleTree,
    pre_state_root: &str,
    new_block_number: i64,
) -> Vec<SdkValue> {
    let new_state_root = hex_state_root(new_block_number as usize);
    let batch_data_hash = hex_hash256(&format!("{}{}", pre_state_root, new_state_root));
    let proof_a: i64 = 1000000;
    let proof_b: i64 = 2000000;
    let proof_c = bb_mul_field(proof_a, proof_b);
    let (leaf, proof) = tree.get_proof(SC_LEAF_IDX);

    vec![
        SdkValue::Bytes(new_state_root),
        SdkValue::Int(new_block_number),
        SdkValue::Bytes(batch_data_hash),
        SdkValue::Bytes(pre_state_root.to_string()),
        SdkValue::Int(proof_a),
        SdkValue::Int(proof_b),
        SdkValue::Int(proof_c),
        SdkValue::Bytes(leaf),
        SdkValue::Bytes(proof),
        SdkValue::Int(SC_LEAF_IDX as i64),
    ]
}

fn deploy_state_covenant() -> (RunarContract, Box<dyn runar_lang::sdk::Signer>, TestWallet) {
    let artifact = compile_contract("examples/ts/state-covenant/StateCovenant.runar.ts");
    let tree = build_test_tree();

    let mut contract = RunarContract::new(artifact, vec![
        SdkValue::Bytes(hex_zeros32()),
        SdkValue::Int(0),
        SdkValue::Bytes(tree.root.clone()),
    ]);

    let mut provider = create_provider();
    let (signer, wallet) = create_funded_wallet(&mut provider);

    let (deploy_txid, _tx) = contract
        .deploy(
            &mut provider,
            &*signer,
            &DeployOptions {
                satoshis: 10000,
                change_address: None,
            },
        )
        .expect("deploy failed");
    assert!(!deploy_txid.is_empty());
    assert_eq!(deploy_txid.len(), 64);

    (contract, signer, wallet)
}

#[test]
#[ignore]
fn test_state_covenant_deploy() {
    skip_if_no_node();
    let (_contract, _signer, _wallet) = deploy_state_covenant();
}

#[test]
#[ignore]
fn test_state_covenant_advance_state() {
    skip_if_no_node();
    let (mut contract, signer, _wallet) = deploy_state_covenant();
    let mut provider = create_provider();
    let tree = build_test_tree();

    let args = build_call_args(&tree, &hex_zeros32(), 1);

    let (txid, _tx) = contract
        .call("advanceState", &args, &mut provider, &*signer, None)
        .expect("advanceState failed");
    assert!(!txid.is_empty());
}

#[test]
#[ignore]
fn test_state_covenant_chain_advances() {
    skip_if_no_node();
    let (mut contract, signer, _wallet) = deploy_state_covenant();
    let mut provider = create_provider();
    let tree = build_test_tree();

    let mut pre = hex_zeros32();
    for block in 1..=3i64 {
        let args = build_call_args(&tree, &pre, block);
        let (_txid, _tx) = contract
            .call("advanceState", &args, &mut provider, &*signer, None)
            .unwrap_or_else(|e| panic!("advance to block {}: {}", block, e));
        pre = hex_state_root(block as usize);
    }
}

#[test]
#[ignore]
fn test_state_covenant_wrong_pre_state_root_rejected() {
    skip_if_no_node();
    let (mut contract, signer, _wallet) = deploy_state_covenant();
    let mut provider = create_provider();
    let tree = build_test_tree();

    let mut args = build_call_args(&tree, &hex_zeros32(), 1);
    // Replace preStateRoot (index 3) with a wrong value
    let wrong_root = format!("ff{}", &hex_zeros32()[2..]);
    args[3] = SdkValue::Bytes(wrong_root);

    let result = contract.call("advanceState", &args, &mut provider, &*signer, None);
    assert!(result.is_err(), "expected rejection for wrong pre-state root");
}

#[test]
#[ignore]
fn test_state_covenant_invalid_block_number_rejected() {
    skip_if_no_node();
    let (mut contract, signer, _wallet) = deploy_state_covenant();
    let mut provider = create_provider();
    let tree = build_test_tree();

    // First advance to block 1
    let args1 = build_call_args(&tree, &hex_zeros32(), 1);
    contract
        .call("advanceState", &args1, &mut provider, &*signer, None)
        .expect("first advance");

    // Try to advance to block 0 (not increasing)
    let pre = hex_state_root(1);
    let mut args2 = build_call_args(&tree, &pre, 0);
    args2[1] = SdkValue::Int(0); // force block number 0

    let result = contract.call("advanceState", &args2, &mut provider, &*signer, None);
    assert!(
        result.is_err(),
        "expected rejection for non-increasing block number"
    );
}

#[test]
#[ignore]
fn test_state_covenant_invalid_babybear_proof_rejected() {
    skip_if_no_node();
    let (mut contract, signer, _wallet) = deploy_state_covenant();
    let mut provider = create_provider();
    let tree = build_test_tree();

    let mut args = build_call_args(&tree, &hex_zeros32(), 1);
    args[6] = SdkValue::Int(99999); // wrong proofFieldC

    let result = contract.call("advanceState", &args, &mut provider, &*signer, None);
    assert!(
        result.is_err(),
        "expected rejection for invalid Baby Bear proof"
    );
}

#[test]
#[ignore]
fn test_state_covenant_invalid_merkle_proof_rejected() {
    skip_if_no_node();
    let (mut contract, signer, _wallet) = deploy_state_covenant();
    let mut provider = create_provider();
    let tree = build_test_tree();

    let mut args = build_call_args(&tree, &hex_zeros32(), 1);
    // wrong merkleLeaf
    let wrong_leaf = format!("aa{}", &hex_zeros32()[2..]);
    args[7] = SdkValue::Bytes(wrong_leaf);

    let result = contract.call("advanceState", &args, &mut provider, &*signer, None);
    assert!(
        result.is_err(),
        "expected rejection for invalid Merkle proof"
    );
}
