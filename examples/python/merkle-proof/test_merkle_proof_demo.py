import pytest
from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).parent.parent))
from conftest import load_contract

contract_mod = load_contract(str(Path(__file__).parent / "MerkleProofDemo.runar.py"))
MerkleProofDemo = contract_mod.MerkleProofDemo

from runar import sha256, hash256


# ---------------------------------------------------------------------------
# Merkle tree helper -- builds a depth-4 tree (16 leaves)
# ---------------------------------------------------------------------------

def build_merkle_tree(leaves, hash_fn):
    level = list(leaves)
    layers = [level]

    while len(level) > 1:
        next_level = []
        for i in range(0, len(level), 2):
            next_level.append(hash_fn(level[i] + level[i + 1]))
        level = next_level
        layers.append(level)

    root = level[0]
    return root, layers


def get_proof(layers, leaves, index):
    siblings = []
    idx = index
    for d in range(len(layers) - 1):
        sibling_idx = idx ^ 1
        siblings.append(layers[d][sibling_idx])
        idx >>= 1
    proof = b"".join(siblings)
    return leaves[index], proof


def make_leaves():
    return [sha256(bytes([i])) for i in range(16)]


# ---------------------------------------------------------------------------
# verify_sha256 (merkle_root_sha256, depth=4)
# ---------------------------------------------------------------------------

def test_verify_sha256_index0():
    leaves = make_leaves()
    root, layers = build_merkle_tree(leaves, sha256)
    leaf, proof = get_proof(layers, leaves, 0)

    c = MerkleProofDemo(expected_root=root)
    c.verify_sha256(leaf, proof, 0)


def test_verify_sha256_index7():
    leaves = make_leaves()
    root, layers = build_merkle_tree(leaves, sha256)
    leaf, proof = get_proof(layers, leaves, 7)

    c = MerkleProofDemo(expected_root=root)
    c.verify_sha256(leaf, proof, 7)


def test_verify_sha256_index15():
    leaves = make_leaves()
    root, layers = build_merkle_tree(leaves, sha256)
    leaf, proof = get_proof(layers, leaves, 15)

    c = MerkleProofDemo(expected_root=root)
    c.verify_sha256(leaf, proof, 15)


def test_verify_sha256_wrong_leaf():
    leaves = make_leaves()
    root, layers = build_merkle_tree(leaves, sha256)
    _, proof = get_proof(layers, leaves, 0)
    wrong_leaf = sha256(b"\xff")

    c = MerkleProofDemo(expected_root=root)
    with pytest.raises(AssertionError):
        c.verify_sha256(wrong_leaf, proof, 0)


def test_verify_sha256_wrong_index():
    leaves = make_leaves()
    root, layers = build_merkle_tree(leaves, sha256)
    leaf, proof = get_proof(layers, leaves, 0)

    c = MerkleProofDemo(expected_root=root)
    with pytest.raises(AssertionError):
        c.verify_sha256(leaf, proof, 1)  # wrong index


# ---------------------------------------------------------------------------
# verify_hash256 (merkle_root_hash256, depth=4)
# ---------------------------------------------------------------------------

def test_verify_hash256_index0():
    leaves = make_leaves()
    root, layers = build_merkle_tree(leaves, hash256)
    leaf, proof = get_proof(layers, leaves, 0)

    c = MerkleProofDemo(expected_root=root)
    c.verify_hash256(leaf, proof, 0)


def test_verify_hash256_index10():
    leaves = make_leaves()
    root, layers = build_merkle_tree(leaves, hash256)
    leaf, proof = get_proof(layers, leaves, 10)

    c = MerkleProofDemo(expected_root=root)
    c.verify_hash256(leaf, proof, 10)


# ---------------------------------------------------------------------------
# Compile check
# ---------------------------------------------------------------------------

def test_compile():
    from runar import compile_check
    source_path = str(Path(__file__).parent / "MerkleProofDemo.runar.py")
    with open(source_path) as f:
        source = f.read()
    compile_check(source, "MerkleProofDemo.runar.py")
