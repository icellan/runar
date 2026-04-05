import pytest
from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).parent.parent))
from conftest import load_contract

contract_mod = load_contract(str(Path(__file__).parent / "StateCovenant.runar.py"))
StateCovenant = contract_mod.StateCovenant

from runar import bb_field_mul, merkle_root_sha256, hash256, cat
import hashlib

# Baby Bear field prime: p = 2^31 - 2^27 + 1 = 2013265921
BB_P = 2013265921


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def bb_field_mul_helper(a, b):
    return (a * b) % BB_P


def sha256_hex(hex_str):
    data = bytes.fromhex(hex_str)
    return hashlib.sha256(data).hexdigest()


def hash256_hex(hex_str):
    return sha256_hex(sha256_hex(hex_str))


def make_state_root(n):
    return sha256_hex(format(n, '02x'))


def build_merkle_tree(leaves):
    level = list(leaves)
    layers = [level[:]]
    while len(level) > 1:
        next_level = []
        for i in range(0, len(level), 2):
            next_level.append(sha256_hex(level[i] + level[i + 1]))
        level = next_level
        layers.append(level[:])
    return level[0], layers


def get_proof(layers, index, leaves):
    siblings = []
    idx = index
    for d in range(len(layers) - 1):
        siblings.append(layers[d][idx ^ 1])
        idx >>= 1
    return ''.join(siblings), leaves[index]


MERKLE_LEAVES = [sha256_hex(format(i, '02x')) for i in range(16)]
MERKLE_ROOT, MERKLE_LAYERS = build_merkle_tree(MERKLE_LEAVES)
VERIFYING_KEY_HASH = MERKLE_ROOT
LEAF_INDEX = 3
GENESIS_STATE_ROOT = '00' * 32


def build_advance_args(pre_state_root, new_block_number):
    new_state_root = make_state_root(new_block_number)
    batch_data_hash = hash256_hex(pre_state_root + new_state_root)
    proof_field_a = 1000000
    proof_field_b = 2000000
    proof_field_c = bb_field_mul_helper(proof_field_a, proof_field_b)
    proof, leaf = get_proof(MERKLE_LAYERS, LEAF_INDEX, MERKLE_LEAVES)
    return dict(
        new_state_root=new_state_root,
        new_block_number=new_block_number,
        batch_data_hash=batch_data_hash,
        pre_state_root=pre_state_root,
        proof_field_a=proof_field_a,
        proof_field_b=proof_field_b,
        proof_field_c=proof_field_c,
        merkle_leaf=leaf,
        merkle_proof=proof,
        merkle_index=LEAF_INDEX,
    )


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

def test_starts_with_initial_state():
    c = StateCovenant(
        state_root=GENESIS_STATE_ROOT,
        block_number=0,
        verifying_key_hash=VERIFYING_KEY_HASH,
    )
    assert c.state_root == GENESIS_STATE_ROOT
    assert c.block_number == 0


def test_advances_state_with_valid_proof():
    c = StateCovenant(
        state_root=GENESIS_STATE_ROOT,
        block_number=0,
        verifying_key_hash=VERIFYING_KEY_HASH,
    )
    args = build_advance_args(GENESIS_STATE_ROOT, 1)
    c.advance_state(**args)
    assert c.state_root == args['new_state_root']
    assert c.block_number == 1


def test_chains_multiple_advances():
    c = StateCovenant(
        state_root=GENESIS_STATE_ROOT,
        block_number=0,
        verifying_key_hash=VERIFYING_KEY_HASH,
    )
    pre = GENESIS_STATE_ROOT
    for block in range(1, 4):
        args = build_advance_args(pre, block)
        c.advance_state(**args)
        assert c.block_number == block
        pre = args['new_state_root']


def test_rejects_wrong_pre_state_root():
    c = StateCovenant(
        state_root=GENESIS_STATE_ROOT,
        block_number=0,
        verifying_key_hash=VERIFYING_KEY_HASH,
    )
    args = build_advance_args(GENESIS_STATE_ROOT, 1)
    args['pre_state_root'] = 'ff' * 32
    with pytest.raises(AssertionError):
        c.advance_state(**args)


def test_rejects_non_increasing_block_number():
    c = StateCovenant(
        state_root=GENESIS_STATE_ROOT,
        block_number=5,
        verifying_key_hash=VERIFYING_KEY_HASH,
    )
    args = build_advance_args(GENESIS_STATE_ROOT, 3)
    with pytest.raises(AssertionError):
        c.advance_state(**args)


def test_rejects_invalid_baby_bear_proof():
    c = StateCovenant(
        state_root=GENESIS_STATE_ROOT,
        block_number=0,
        verifying_key_hash=VERIFYING_KEY_HASH,
    )
    args = build_advance_args(GENESIS_STATE_ROOT, 1)
    args['proof_field_c'] = 99999
    with pytest.raises(AssertionError):
        c.advance_state(**args)


def test_rejects_invalid_merkle_proof():
    c = StateCovenant(
        state_root=GENESIS_STATE_ROOT,
        block_number=0,
        verifying_key_hash=VERIFYING_KEY_HASH,
    )
    args = build_advance_args(GENESIS_STATE_ROOT, 1)
    args['merkle_leaf'] = 'aa' * 32
    with pytest.raises(AssertionError):
        c.advance_state(**args)


def test_rejects_wrong_batch_data_hash():
    c = StateCovenant(
        state_root=GENESIS_STATE_ROOT,
        block_number=0,
        verifying_key_hash=VERIFYING_KEY_HASH,
    )
    args = build_advance_args(GENESIS_STATE_ROOT, 1)
    args['batch_data_hash'] = 'bb' * 32
    with pytest.raises(AssertionError):
        c.advance_state(**args)


def test_compile():
    from runar import compile_check
    source_path = str(Path(__file__).parent / "StateCovenant.runar.py")
    with open(source_path) as f:
        source = f.read()
    compile_check(source, "StateCovenant.runar.py")
