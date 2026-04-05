"""StateCovenant -- A stateful UTXO chain covenant that guards a state root.

Demonstrates the core pattern for a validity-proof-based state covenant:
each spend advances the state by providing a new state root, a block number,
and proof data. The covenant verifies the proof and enforces monotonic
block number progression.

This contract exercises the key primitives needed for STARK/FRI verification
on BSV: Baby Bear field arithmetic, SHA-256 Merkle proof verification, and
hash256 batch data binding -- without implementing the full FRI verifier.

State fields (persisted across UTXO spends via OP_PUSH_TX):
  - state_root: 32-byte hash representing the current state
  - block_number: monotonically increasing block counter

Readonly property (baked into locking script at compile time):
  - verifying_key_hash: commitment to the proof system's verifying key;
    also used as the expected Merkle root for commitment verification
"""

from runar import (
    StatefulSmartContract, Bigint, ByteString, Readonly,
    public, assert_,
    bb_field_mul, merkle_root_sha256, hash256, cat,
)


class StateCovenant(StatefulSmartContract):
    """A stateful UTXO chain covenant that guards a state root."""

    state_root: ByteString
    block_number: Bigint
    verifying_key_hash: Readonly[ByteString]

    def __init__(self, state_root: ByteString, block_number: Bigint,
                 verifying_key_hash: ByteString):
        super().__init__(state_root, block_number, verifying_key_hash)
        self.state_root = state_root
        self.block_number = block_number
        self.verifying_key_hash = verifying_key_hash

    @public
    def advance_state(
        self,
        new_state_root: ByteString,
        new_block_number: Bigint,
        batch_data_hash: ByteString,
        pre_state_root: ByteString,
        proof_field_a: Bigint,
        proof_field_b: Bigint,
        proof_field_c: Bigint,
        merkle_leaf: ByteString,
        merkle_proof: ByteString,
        merkle_index: Bigint,
    ):
        """Advance the covenant state. Verifies proof data and updates state
        root and block number."""
        # 1. Block number must strictly increase
        assert_(new_block_number > self.block_number)

        # 2. Pre-state root must match current covenant state
        assert_(pre_state_root == self.state_root)

        # 3. Verify Baby Bear field multiplication (simplified proof check)
        assert_(bb_field_mul(proof_field_a, proof_field_b) == proof_field_c)

        # 4. Verify Merkle commitment: the leaf must be in a SHA-256 tree
        #    whose root matches the verifying key hash
        computed_root = merkle_root_sha256(merkle_leaf, merkle_proof, merkle_index, 4)
        assert_(computed_root == self.verifying_key_hash)

        # 5. Batch data hash binding: verify the caller provided the correct
        #    hash256 of the state transition
        expected_batch_hash = hash256(cat(pre_state_root, new_state_root))
        assert_(batch_data_hash == expected_batch_hash)

        # 6. Update state -- compiler auto-enforces output carries new state
        self.state_root = new_state_root
        self.block_number = new_block_number
