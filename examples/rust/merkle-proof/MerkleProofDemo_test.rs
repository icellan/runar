#[path = "MerkleProofDemo.runar.rs"]
mod contract;

use contract::*;
use runar::prelude::*;

// ---------------------------------------------------------------------------
// Merkle tree helper -- builds a depth-4 tree (16 leaves)
// ---------------------------------------------------------------------------

struct MerkleTree {
    root: ByteString,
    leaves: Vec<ByteString>,
    layers: Vec<Vec<ByteString>>,
}

fn build_merkle_tree(
    leaves: &[ByteString],
    hash_fn: fn(&[u8]) -> ByteString,
) -> MerkleTree {
    let mut level: Vec<ByteString> = leaves.to_vec();
    let mut layers: Vec<Vec<ByteString>> = vec![level.clone()];

    while level.len() > 1 {
        let mut next = Vec::new();
        for i in (0..level.len()).step_by(2) {
            let mut preimage = level[i].clone();
            preimage.extend_from_slice(&level[i + 1]);
            next.push(hash_fn(&preimage));
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

// ---------------------------------------------------------------------------
// verify_sha256 (merkle_root_sha256, depth=4)
// ---------------------------------------------------------------------------

#[test]
fn test_verify_sha256_index0() {
    let leaves = make_leaves();
    let tree = build_merkle_tree(&leaves, sha256);
    let (leaf, proof) = get_proof(&tree, 0);

    let c = MerkleProofDemo { expected_root: tree.root };
    c.verify_sha256(leaf, proof, 0);
}

#[test]
fn test_verify_sha256_index7() {
    let leaves = make_leaves();
    let tree = build_merkle_tree(&leaves, sha256);
    let (leaf, proof) = get_proof(&tree, 7);

    let c = MerkleProofDemo { expected_root: tree.root };
    c.verify_sha256(leaf, proof, 7);
}

#[test]
fn test_verify_sha256_index15() {
    let leaves = make_leaves();
    let tree = build_merkle_tree(&leaves, sha256);
    let (leaf, proof) = get_proof(&tree, 15);

    let c = MerkleProofDemo { expected_root: tree.root };
    c.verify_sha256(leaf, proof, 15);
}

#[test]
#[should_panic]
fn test_verify_sha256_wrong_leaf() {
    let leaves = make_leaves();
    let tree = build_merkle_tree(&leaves, sha256);
    let (_, proof) = get_proof(&tree, 0);
    let wrong_leaf = sha256(&[0xff]);

    let c = MerkleProofDemo { expected_root: tree.root };
    c.verify_sha256(wrong_leaf, proof, 0);
}

#[test]
#[should_panic]
fn test_verify_sha256_wrong_index() {
    let leaves = make_leaves();
    let tree = build_merkle_tree(&leaves, sha256);
    let (leaf, proof) = get_proof(&tree, 0);

    let c = MerkleProofDemo { expected_root: tree.root };
    c.verify_sha256(leaf, proof, 1); // wrong index
}

// ---------------------------------------------------------------------------
// verify_hash256 (merkle_root_hash256, depth=4)
// ---------------------------------------------------------------------------

#[test]
fn test_verify_hash256_index0() {
    let leaves = make_leaves();
    let tree = build_merkle_tree(&leaves, hash256);
    let (leaf, proof) = get_proof(&tree, 0);

    let c = MerkleProofDemo { expected_root: tree.root };
    c.verify_hash256(leaf, proof, 0);
}

#[test]
fn test_verify_hash256_index10() {
    let leaves = make_leaves();
    let tree = build_merkle_tree(&leaves, hash256);
    let (leaf, proof) = get_proof(&tree, 10);

    let c = MerkleProofDemo { expected_root: tree.root };
    c.verify_hash256(leaf, proof, 10);
}

// ---------------------------------------------------------------------------
// Compile check
// ---------------------------------------------------------------------------

#[test]
fn test_compile() {
    runar::compile_check(
        include_str!("MerkleProofDemo.runar.rs"),
        "MerkleProofDemo.runar.rs",
    )
    .unwrap();
}
