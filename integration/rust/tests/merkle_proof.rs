//! Merkle proof verification integration tests -- inline contracts testing
//! merkleRootSha256 on a real regtest node.
//!
//! Each test compiles a minimal stateless contract with an unrolled Merkle path
//! verification, deploys it on regtest, and verifies the deployment + call succeed.
//!
//! **Gating**: all on-chain tests are gated with
//! `#[cfg_attr(not(feature = "regtest"), ignore)]`. They require a local Bitcoin
//! regtest node (see `integration/rust/README.md`). Run with:
//!     cargo test --features regtest
//! Tests without the gate (pure compile/script-size checks) run by default.

use crate::helpers::*;
use runar_lang::sdk::{DeployOptions, RunarContract, SdkValue};
use sha2::{Sha256, Digest};

// ---------------------------------------------------------------------------
// Hex utility helpers (no external hex crate dependency)
// ---------------------------------------------------------------------------

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

fn hex_decode(hex: &str) -> Vec<u8> {
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).expect("invalid hex"))
        .collect()
}

// ---------------------------------------------------------------------------
// Merkle tree helpers
// ---------------------------------------------------------------------------

fn sha256_hex(hex_str: &str) -> String {
    let bytes = hex_decode(hex_str);
    let hash = Sha256::digest(&bytes);
    hex_encode(&hash)
}

struct MerkleTree {
    root: String,
    leaves: Vec<String>,
    layers: Vec<Vec<String>>,
}

fn build_sha256_tree(leaves: &[String]) -> MerkleTree {
    let mut level: Vec<String> = leaves.to_vec();
    let mut layers: Vec<Vec<String>> = vec![level.clone()];
    while level.len() > 1 {
        let mut next = Vec::new();
        for i in (0..level.len()).step_by(2) {
            next.push(sha256_hex(&format!("{}{}", level[i], level[i + 1])));
        }
        level = next;
        layers.push(level.clone());
    }
    MerkleTree {
        root: level[0].clone(),
        leaves: leaves.to_vec(),
        layers,
    }
}

fn get_proof(tree: &MerkleTree, index: usize) -> (String, String) {
    let mut siblings = String::new();
    let mut idx = index;
    for d in 0..tree.layers.len() - 1 {
        siblings.push_str(&tree.layers[d][idx ^ 1]);
        idx >>= 1;
    }
    (siblings, tree.leaves[index].clone())
}

fn build_test_tree() -> MerkleTree {
    let leaves: Vec<String> = (0u8..16)
        .map(|i| sha256_hex(&hex_encode(&[i])))
        .collect();
    build_sha256_tree(&leaves)
}

// ---------------------------------------------------------------------------
// Contract source
// ---------------------------------------------------------------------------

const MERKLE_SHA256_SOURCE: &str = r#"
import { SmartContract, assert, merkleRootSha256 } from 'runar-lang';
import type { ByteString } from 'runar-lang';

class MerkleSha256Test extends SmartContract {
  readonly expectedRoot: ByteString;
  constructor(expectedRoot: ByteString) {
    super(expectedRoot);
    this.expectedRoot = expectedRoot;
  }
  public verify(leaf: ByteString, proof: ByteString, index: bigint) {
    const root = merkleRootSha256(leaf, proof, index, 4n);
    assert(root === this.expectedRoot);
  }
}
"#;

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[test]
#[cfg_attr(not(feature = "regtest"), ignore)]
fn test_merkle_sha256_leaf_index_0() {
    skip_if_no_node();

    let tree = build_test_tree();
    let (proof, leaf) = get_proof(&tree, 0);

    let artifact = compile_source(MERKLE_SHA256_SOURCE, "MerkleSha256Test.runar.ts");
    assert_eq!(artifact.contract_name, "MerkleSha256Test");

    let mut contract = RunarContract::new(artifact, vec![SdkValue::Bytes(tree.root.clone())]);

    let mut provider = create_provider();
    let (signer, _wallet) = create_funded_wallet(&mut provider);

    let (deploy_txid, _tx) = contract
        .deploy(&mut provider, &*signer, &DeployOptions {
            satoshis: 5000,
            change_address: None,
        })
        .expect("deploy failed");
    assert!(!deploy_txid.is_empty());

    let (spend_txid, _tx) = contract
        .call("verify", &[
            SdkValue::Bytes(leaf),
            SdkValue::Bytes(proof),
            SdkValue::Int(0),
        ], &mut provider, &*signer, None)
        .expect("call verify failed");
    assert!(!spend_txid.is_empty());
}

#[test]
#[cfg_attr(not(feature = "regtest"), ignore)]
fn test_merkle_sha256_leaf_index_7() {
    skip_if_no_node();

    let tree = build_test_tree();
    let (proof, leaf) = get_proof(&tree, 7);

    let artifact = compile_source(MERKLE_SHA256_SOURCE, "MerkleSha256Test.runar.ts");

    let mut contract = RunarContract::new(artifact, vec![SdkValue::Bytes(tree.root.clone())]);

    let mut provider = create_provider();
    let (signer, _wallet) = create_funded_wallet(&mut provider);

    let (deploy_txid, _tx) = contract
        .deploy(&mut provider, &*signer, &DeployOptions {
            satoshis: 5000,
            change_address: None,
        })
        .expect("deploy failed");
    assert!(!deploy_txid.is_empty());

    let (spend_txid, _tx) = contract
        .call("verify", &[
            SdkValue::Bytes(leaf),
            SdkValue::Bytes(proof),
            SdkValue::Int(7),
        ], &mut provider, &*signer, None)
        .expect("call verify failed");
    assert!(!spend_txid.is_empty());
}

#[test]
#[cfg_attr(not(feature = "regtest"), ignore)]
fn test_merkle_sha256_wrong_leaf_rejected() {
    skip_if_no_node();

    let tree = build_test_tree();
    let (proof, _leaf) = get_proof(&tree, 0);
    let wrong_leaf = sha256_hex("ff");

    let artifact = compile_source(MERKLE_SHA256_SOURCE, "MerkleSha256Test.runar.ts");

    let mut contract = RunarContract::new(artifact, vec![SdkValue::Bytes(tree.root.clone())]);

    let mut provider = create_provider();
    let (signer, _wallet) = create_funded_wallet(&mut provider);

    let (deploy_txid, _tx) = contract
        .deploy(&mut provider, &*signer, &DeployOptions {
            satoshis: 5000,
            change_address: None,
        })
        .expect("deploy failed");
    assert!(!deploy_txid.is_empty());

    let result = contract
        .call("verify", &[
            SdkValue::Bytes(wrong_leaf),
            SdkValue::Bytes(proof),
            SdkValue::Int(0),
        ], &mut provider, &*signer, None);
    assert!(result.is_err(), "expected wrong leaf to be rejected on-chain");
}
