pragma runar ^0.1.0;

/// @title StateCovenant
/// @notice A stateful UTXO chain covenant that guards a state root.
/// @dev Demonstrates the core pattern for a validity-proof-based state covenant:
/// each spend advances the state by providing a new state root, a block number,
/// and proof data. The covenant verifies the proof and enforces monotonic
/// block number progression.
///
/// This contract exercises the key primitives needed for STARK/FRI verification
/// on BSV: Baby Bear field arithmetic, SHA-256 Merkle proof verification, and
/// hash256 batch data binding — without implementing the full FRI verifier.
///
/// State fields (persisted across UTXO spends via OP_PUSH_TX):
///   - stateRoot: 32-byte hash representing the current state
///   - blockNumber: monotonically increasing block counter
///
/// Readonly property (baked into locking script at compile time):
///   - verifyingKeyHash: commitment to the proof system's verifying key;
///     also used as the expected Merkle root for commitment verification
contract StateCovenant is StatefulSmartContract {
    bytes stateRoot;
    bigint blockNumber;
    bytes immutable verifyingKeyHash;

    constructor(bytes _stateRoot, bigint _blockNumber, bytes _verifyingKeyHash) {
        stateRoot = _stateRoot;
        blockNumber = _blockNumber;
        verifyingKeyHash = _verifyingKeyHash;
    }

    /// @notice Advance the covenant state. Verifies proof data and updates
    /// state root and block number.
    /// @param newStateRoot The new 32-byte state root after execution
    /// @param newBlockNumber The new block number (must be > current)
    /// @param batchDataHash hash256 of the batch data (binding check)
    /// @param preStateRoot Claimed pre-state root (must match current state)
    /// @param proofFieldA Baby Bear field element (simplified proof element)
    /// @param proofFieldB Baby Bear field element (simplified proof element)
    /// @param proofFieldC Expected bbFieldMul(A, B) result
    /// @param merkleLeaf Leaf hash for commitment tree verification
    /// @param merkleProof Concatenated 32-byte sibling hashes (depth 4 = 128 bytes)
    /// @param merkleIndex Leaf position in the commitment tree
    function advanceState(
        bytes newStateRoot,
        bigint newBlockNumber,
        bytes batchDataHash,
        bytes preStateRoot,
        bigint proofFieldA,
        bigint proofFieldB,
        bigint proofFieldC,
        bytes merkleLeaf,
        bytes merkleProof,
        bigint merkleIndex
    ) public {
        // 1. Block number must strictly increase
        require(newBlockNumber > this.blockNumber);

        // 2. Pre-state root must match current covenant state
        require(preStateRoot == this.stateRoot);

        // 3. Verify Baby Bear field multiplication (simplified proof check)
        require(bbFieldMul(proofFieldA, proofFieldB) == proofFieldC);

        // 4. Verify Merkle commitment: the leaf must be in a SHA-256 tree
        //    whose root matches the verifying key hash
        bytes computedRoot = merkleRootSha256(merkleLeaf, merkleProof, merkleIndex, 4);
        require(computedRoot == this.verifyingKeyHash);

        // 5. Batch data hash binding: verify the caller provided the correct
        //    hash256 of the state transition
        bytes expectedBatchHash = hash256(cat(preStateRoot, newStateRoot));
        require(batchDataHash == expectedBatchHash);

        // 6. Update state — compiler auto-enforces output carries new state
        this.stateRoot = newStateRoot;
        this.blockNumber = newBlockNumber;
    }
}
