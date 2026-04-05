#[path = "StateCovenant.runar.rs"]
mod contract;

use contract::*;
use runar::prelude::*;

/// Baby Bear field prime: p = 2^31 - 2^27 + 1 = 2013265921
const BB_P: i64 = 2013265921;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn bb_field_mul_helper(a: i64, b: i64) -> i64 {
    ((a as i128 * b as i128) % BB_P as i128) as i64
}

fn make_state_root(n: u8) -> ByteString {
    sha256(&[n])
}

struct MerkleTree {
    root: ByteString,
    leaves: Vec<ByteString>,
    layers: Vec<Vec<ByteString>>,
}

fn build_merkle_tree(leaves: &[ByteString]) -> MerkleTree {
    let mut level: Vec<ByteString> = leaves.to_vec();
    let mut layers: Vec<Vec<ByteString>> = vec![level.clone()];

    while level.len() > 1 {
        let mut next = Vec::new();
        for i in (0..level.len()).step_by(2) {
            let mut preimage = level[i].clone();
            preimage.extend_from_slice(&level[i + 1]);
            next.push(sha256(&preimage));
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

fn get_proof(tree: &MerkleTree, index: usize) -> (ByteString, ByteString) {
    let mut siblings = Vec::new();
    let mut idx = index;
    for d in 0..tree.layers.len() - 1 {
        let sibling_idx = idx ^ 1;
        siblings.push(tree.layers[d][sibling_idx].clone());
        idx >>= 1;
    }
    let mut proof = Vec::new();
    for s in &siblings {
        proof.extend_from_slice(s);
    }
    (tree.leaves[index].clone(), proof)
}

fn make_leaves() -> Vec<ByteString> {
    (0u8..16).map(|i| sha256(&[i])).collect()
}

fn genesis_state_root() -> ByteString {
    vec![0u8; 32]
}

const LEAF_INDEX: usize = 3;

struct AdvanceArgs {
    new_state_root: ByteString,
    new_block_number: i64,
    batch_data_hash: ByteString,
    pre_state_root: ByteString,
    proof_field_a: i64,
    proof_field_b: i64,
    proof_field_c: i64,
    merkle_leaf: ByteString,
    merkle_proof: ByteString,
    merkle_index: i64,
}

fn build_advance_args(tree: &MerkleTree, pre_state_root: &ByteString, new_block_number: i64) -> AdvanceArgs {
    let new_state_root = make_state_root(new_block_number as u8);
    let mut cat_data = pre_state_root.clone();
    cat_data.extend_from_slice(&new_state_root);
    let batch_data_hash = hash256(&cat_data);
    let proof_field_a: i64 = 1000000;
    let proof_field_b: i64 = 2000000;
    let proof_field_c = bb_field_mul_helper(proof_field_a, proof_field_b);
    let (leaf, proof) = get_proof(tree, LEAF_INDEX);

    AdvanceArgs {
        new_state_root,
        new_block_number,
        batch_data_hash,
        pre_state_root: pre_state_root.clone(),
        proof_field_a,
        proof_field_b,
        proof_field_c,
        merkle_leaf: leaf,
        merkle_proof: proof,
        merkle_index: LEAF_INDEX as i64,
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[test]
fn test_starts_with_initial_state() {
    let leaves = make_leaves();
    let tree = build_merkle_tree(&leaves);
    let c = StateCovenant {
        state_root: genesis_state_root(),
        block_number: 0,
        verifying_key_hash: tree.root,
    };
    assert_eq!(c.state_root, genesis_state_root());
    assert_eq!(c.block_number, 0);
}

#[test]
fn test_advances_state_with_valid_proof() {
    let leaves = make_leaves();
    let tree = build_merkle_tree(&leaves);
    let mut c = StateCovenant {
        state_root: genesis_state_root(),
        block_number: 0,
        verifying_key_hash: tree.root.clone(),
    };
    let args = build_advance_args(&tree, &genesis_state_root(), 1);
    c.advance_state(
        args.new_state_root.clone(),
        args.new_block_number,
        args.batch_data_hash,
        args.pre_state_root,
        args.proof_field_a,
        args.proof_field_b,
        args.proof_field_c,
        args.merkle_leaf,
        args.merkle_proof,
        args.merkle_index,
    );
    assert_eq!(c.state_root, args.new_state_root);
    assert_eq!(c.block_number, 1);
}

#[test]
fn test_chains_multiple_advances() {
    let leaves = make_leaves();
    let tree = build_merkle_tree(&leaves);
    let mut c = StateCovenant {
        state_root: genesis_state_root(),
        block_number: 0,
        verifying_key_hash: tree.root.clone(),
    };

    let mut pre = genesis_state_root();
    for block in 1i64..=3 {
        let args = build_advance_args(&tree, &pre, block);
        c.advance_state(
            args.new_state_root.clone(),
            args.new_block_number,
            args.batch_data_hash,
            args.pre_state_root,
            args.proof_field_a,
            args.proof_field_b,
            args.proof_field_c,
            args.merkle_leaf,
            args.merkle_proof,
            args.merkle_index,
        );
        assert_eq!(c.block_number, block);
        pre = args.new_state_root;
    }
}

#[test]
#[should_panic]
fn test_rejects_wrong_pre_state_root() {
    let leaves = make_leaves();
    let tree = build_merkle_tree(&leaves);
    let mut c = StateCovenant {
        state_root: genesis_state_root(),
        block_number: 0,
        verifying_key_hash: tree.root.clone(),
    };
    let mut args = build_advance_args(&tree, &genesis_state_root(), 1);
    args.pre_state_root = vec![0xffu8; 32];
    c.advance_state(
        args.new_state_root,
        args.new_block_number,
        args.batch_data_hash,
        args.pre_state_root,
        args.proof_field_a,
        args.proof_field_b,
        args.proof_field_c,
        args.merkle_leaf,
        args.merkle_proof,
        args.merkle_index,
    );
}

#[test]
#[should_panic]
fn test_rejects_non_increasing_block_number() {
    let leaves = make_leaves();
    let tree = build_merkle_tree(&leaves);
    let mut c = StateCovenant {
        state_root: genesis_state_root(),
        block_number: 5,
        verifying_key_hash: tree.root.clone(),
    };
    let args = build_advance_args(&tree, &genesis_state_root(), 3);
    c.advance_state(
        args.new_state_root,
        3,
        args.batch_data_hash,
        args.pre_state_root,
        args.proof_field_a,
        args.proof_field_b,
        args.proof_field_c,
        args.merkle_leaf,
        args.merkle_proof,
        args.merkle_index,
    );
}

#[test]
#[should_panic]
fn test_rejects_invalid_baby_bear_proof() {
    let leaves = make_leaves();
    let tree = build_merkle_tree(&leaves);
    let mut c = StateCovenant {
        state_root: genesis_state_root(),
        block_number: 0,
        verifying_key_hash: tree.root.clone(),
    };
    let mut args = build_advance_args(&tree, &genesis_state_root(), 1);
    args.proof_field_c = 99999;
    c.advance_state(
        args.new_state_root,
        args.new_block_number,
        args.batch_data_hash,
        args.pre_state_root,
        args.proof_field_a,
        args.proof_field_b,
        args.proof_field_c,
        args.merkle_leaf,
        args.merkle_proof,
        args.merkle_index,
    );
}

#[test]
#[should_panic]
fn test_rejects_invalid_merkle_proof() {
    let leaves = make_leaves();
    let tree = build_merkle_tree(&leaves);
    let mut c = StateCovenant {
        state_root: genesis_state_root(),
        block_number: 0,
        verifying_key_hash: tree.root.clone(),
    };
    let mut args = build_advance_args(&tree, &genesis_state_root(), 1);
    args.merkle_leaf = vec![0xaau8; 32];
    c.advance_state(
        args.new_state_root,
        args.new_block_number,
        args.batch_data_hash,
        args.pre_state_root,
        args.proof_field_a,
        args.proof_field_b,
        args.proof_field_c,
        args.merkle_leaf,
        args.merkle_proof,
        args.merkle_index,
    );
}

#[test]
#[should_panic]
fn test_rejects_wrong_batch_data_hash() {
    let leaves = make_leaves();
    let tree = build_merkle_tree(&leaves);
    let mut c = StateCovenant {
        state_root: genesis_state_root(),
        block_number: 0,
        verifying_key_hash: tree.root.clone(),
    };
    let mut args = build_advance_args(&tree, &genesis_state_root(), 1);
    args.batch_data_hash = vec![0xbbu8; 32];
    c.advance_state(
        args.new_state_root,
        args.new_block_number,
        args.batch_data_hash,
        args.pre_state_root,
        args.proof_field_a,
        args.proof_field_b,
        args.proof_field_c,
        args.merkle_leaf,
        args.merkle_proof,
        args.merkle_index,
    );
}

#[test]
fn test_compile() {
    runar::compile_check(
        include_str!("StateCovenant.runar.rs"),
        "StateCovenant.runar.rs",
    )
    .unwrap();
}
