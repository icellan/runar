"""
StateCovenant integration test -- stateful covenant combining Baby Bear field
arithmetic, Merkle proof verification, and hash256 batch data binding.

Deploys and advances the covenant on a real regtest node. Tests both valid
state transitions and on-chain rejection of invalid inputs.
"""

import hashlib
import pytest

from conftest import (
    assert_node_rejected,
    compile_contract, create_provider, create_funded_wallet,
)
from runar.sdk import RunarContract, DeployOptions


BB_PRIME = 2013265921


def bb_mul_field(a: int, b: int) -> int:
    return (a * b) % BB_PRIME


def hex_sha256(hex_data: str) -> str:
    data = bytes.fromhex(hex_data)
    return hashlib.sha256(data).hexdigest()


def hex_hash256(hex_data: str) -> str:
    return hex_sha256(hex_sha256(hex_data))


def hex_state_root(n: int) -> str:
    return hex_sha256(f'{n:02x}')


def hex_zeros32() -> str:
    return '00' * 32


def build_merkle_tree(leaves: list[str]):
    level = list(leaves)
    layers = [level]
    while len(level) > 1:
        next_level = []
        for i in range(0, len(level), 2):
            next_level.append(hex_sha256(level[i] + level[i + 1]))
        level = next_level
        layers.append(level)

    root = level[0]

    def get_proof(index: int):
        siblings = []
        idx = index
        for d in range(len(layers) - 1):
            siblings.append(layers[d][idx ^ 1])
            idx >>= 1
        proof = ''.join(siblings)
        return leaves[index], proof

    return root, get_proof


SC_LEAF_IDX = 3


def _build_test_tree():
    leaves = [hex_sha256(f'{i:02x}') for i in range(16)]
    return build_merkle_tree(leaves), leaves


def build_call_args(tree_root, get_proof, pre_state_root: str, new_block_number: int) -> list:
    new_state_root = hex_state_root(new_block_number)
    batch_data_hash = hex_hash256(pre_state_root + new_state_root)
    proof_a = 1000000
    proof_b = 2000000
    proof_c = bb_mul_field(proof_a, proof_b)
    leaf, proof = get_proof(SC_LEAF_IDX)

    return [
        new_state_root,      # newStateRoot
        new_block_number,    # newBlockNumber
        batch_data_hash,     # batchDataHash
        pre_state_root,      # preStateRoot
        proof_a,             # proofFieldA
        proof_b,             # proofFieldB
        proof_c,             # proofFieldC
        leaf,                # merkleLeaf
        proof,               # merkleProof
        SC_LEAF_IDX,         # merkleIndex
    ]


def deploy_state_covenant():
    artifact = compile_contract('examples/ts/state-covenant/StateCovenant.runar.ts')
    (tree_root, get_proof), _leaves = _build_test_tree()

    contract = RunarContract(artifact, [hex_zeros32(), 0, tree_root])

    provider = create_provider()
    wallet = create_funded_wallet(provider)

    txid, _ = contract.deploy(provider, wallet['signer'], DeployOptions(satoshis=10000))
    assert txid
    assert len(txid) == 64

    return contract, wallet, tree_root, get_proof


class TestStateCovenant:

    def test_deploy(self):
        """Should deploy StateCovenant with initial state."""
        _contract, _wallet, _root, _get_proof = deploy_state_covenant()

    def test_advance_state(self):
        """Should advance state with valid inputs."""
        contract, wallet, tree_root, get_proof = deploy_state_covenant()
        provider = create_provider()

        args = build_call_args(tree_root, get_proof, hex_zeros32(), 1)
        txid, _ = contract.call('advanceState', args, provider, wallet['signer'])
        assert txid

    def test_chain_advances(self):
        """Should chain multiple state advances: 0 -> 1 -> 2 -> 3."""
        contract, wallet, tree_root, get_proof = deploy_state_covenant()
        provider = create_provider()

        pre = hex_zeros32()
        for block in range(1, 4):
            args = build_call_args(tree_root, get_proof, pre, block)
            txid, _ = contract.call('advanceState', args, provider, wallet['signer'])
            assert txid
            pre = hex_state_root(block)

    def test_wrong_pre_state_root_rejected(self):
        """Should reject wrong pre-state root."""
        contract, wallet, tree_root, get_proof = deploy_state_covenant()
        provider = create_provider()

        args = build_call_args(tree_root, get_proof, hex_zeros32(), 1)
        # Replace preStateRoot (index 3) with a wrong value
        args[3] = 'ff' + hex_zeros32()[2:]

        # A negative test must prove the NODE refused this spend, and why:
        # an accepted tx whose confirming mine fails also raises after a
        # broadcast (GK-BUG-004). See conftest.assert_node_rejected.
        with assert_node_rejected(provider):
            contract.call('advanceState', args, provider, wallet['signer'])

    def test_invalid_block_number_rejected(self):
        """Should reject non-increasing block number."""
        contract, wallet, tree_root, get_proof = deploy_state_covenant()
        provider = create_provider()

        # First advance to block 1
        args1 = build_call_args(tree_root, get_proof, hex_zeros32(), 1)
        contract.call('advanceState', args1, provider, wallet['signer'])

        # Try to advance to block 0 (not increasing)
        pre = hex_state_root(1)
        args2 = build_call_args(tree_root, get_proof, pre, 0)
        args2[1] = 0  # force block number 0

        # A negative test must prove the NODE refused this spend, and why:
        # an accepted tx whose confirming mine fails also raises after a
        # broadcast (GK-BUG-004). See conftest.assert_node_rejected.
        with assert_node_rejected(provider):
            contract.call('advanceState', args2, provider, wallet['signer'])

    def test_invalid_babybear_proof_rejected(self):
        """Should reject invalid Baby Bear proof."""
        contract, wallet, tree_root, get_proof = deploy_state_covenant()
        provider = create_provider()

        args = build_call_args(tree_root, get_proof, hex_zeros32(), 1)
        args[6] = 99999  # wrong proofFieldC

        # A negative test must prove the NODE refused this spend, and why:
        # an accepted tx whose confirming mine fails also raises after a
        # broadcast (GK-BUG-004). See conftest.assert_node_rejected.
        with assert_node_rejected(provider):
            contract.call('advanceState', args, provider, wallet['signer'])

    def test_invalid_merkle_proof_rejected(self):
        """Should reject invalid Merkle proof."""
        contract, wallet, tree_root, get_proof = deploy_state_covenant()
        provider = create_provider()

        args = build_call_args(tree_root, get_proof, hex_zeros32(), 1)
        # wrong merkleLeaf
        args[7] = 'aa' + hex_zeros32()[2:]

        # A negative test must prove the NODE refused this spend, and why:
        # an accepted tx whose confirming mine fails also raises after a
        # broadcast (GK-BUG-004). See conftest.assert_node_rejected.
        with assert_node_rejected(provider):
            contract.call('advanceState', args, provider, wallet['signer'])
