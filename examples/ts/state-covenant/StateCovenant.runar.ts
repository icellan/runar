import {
  StatefulSmartContract, assert,
  bbFieldMul, merkleRootSha256, hash256, cat,
} from 'runar-lang';
import type { ByteString } from 'runar-lang';

/**
 * StateCovenant — A stateful UTXO chain covenant that guards a state root.
 *
 * Demonstrates the core pattern for a validity-proof-based state covenant:
 * each spend advances the state by providing a new state root, a block number,
 * and proof data. The covenant verifies the proof and enforces monotonic
 * block number progression.
 *
 * This contract exercises the key primitives needed for STARK/FRI verification
 * on BSV: Baby Bear field arithmetic, SHA-256 Merkle proof verification, and
 * hash256 batch data binding — without implementing the full FRI verifier.
 *
 * State fields (persisted across UTXO spends via OP_PUSH_TX):
 * - stateRoot: 32-byte hash representing the current state
 * - blockNumber: monotonically increasing block counter
 *
 * Readonly property (baked into locking script at compile time):
 * - verifyingKeyHash: commitment to the proof system's verifying key;
 *   also used as the expected Merkle root for commitment verification
 */
class StateCovenant extends StatefulSmartContract {
  stateRoot: ByteString;
  blockNumber: bigint;
  readonly verifyingKeyHash: ByteString;

  constructor(stateRoot: ByteString, blockNumber: bigint, verifyingKeyHash: ByteString) {
    super(stateRoot, blockNumber, verifyingKeyHash);
    this.stateRoot = stateRoot;
    this.blockNumber = blockNumber;
    this.verifyingKeyHash = verifyingKeyHash;
  }

  /**
   * Advance the covenant state. Verifies proof data and updates state root
   * and block number.
   *
   * @param newStateRoot - The new 32-byte state root after execution
   * @param newBlockNumber - The new block number (must be > current)
   * @param batchDataHash - hash256 of the batch data (binding check)
   * @param preStateRoot - Claimed pre-state root (must match current state)
   * @param proofFieldA - Baby Bear field element (simplified proof element)
   * @param proofFieldB - Baby Bear field element (simplified proof element)
   * @param proofFieldC - Expected bbFieldMul(A, B) result
   * @param merkleLeaf - Leaf hash for commitment tree verification
   * @param merkleProof - Concatenated 32-byte sibling hashes (depth 4 = 128 bytes)
   * @param merkleIndex - Leaf position in the commitment tree
   */
  public advanceState(
    newStateRoot: ByteString,
    newBlockNumber: bigint,
    batchDataHash: ByteString,
    preStateRoot: ByteString,
    proofFieldA: bigint,
    proofFieldB: bigint,
    proofFieldC: bigint,
    merkleLeaf: ByteString,
    merkleProof: ByteString,
    merkleIndex: bigint,
  ) {
    // 1. Block number must strictly increase
    assert(newBlockNumber > this.blockNumber);

    // 2. Pre-state root must match current covenant state
    assert(preStateRoot === this.stateRoot);

    // 3. Verify Baby Bear field multiplication (simplified proof check).
    //    In the full FRI verifier this would be hundreds of field operations;
    //    here we verify a single multiplication to prove OP_MUL handles
    //    31-bit operands correctly on BSV.
    assert(bbFieldMul(proofFieldA, proofFieldB) === proofFieldC);

    // 4. Verify Merkle commitment: the leaf must be in a SHA-256 tree
    //    whose root matches the verifying key hash (a compile-time commitment).
    //    In the full FRI verifier, this verifies polynomial commitments against
    //    the committed Merkle roots from the proof.
    const computedRoot = merkleRootSha256(merkleLeaf, merkleProof, merkleIndex, 4n);
    assert(computedRoot === this.verifyingKeyHash);

    // 5. Batch data hash binding: verify the caller provided the correct
    //    hash256 of the state transition. In the full covenant this binds
    //    the STARK proof to the OP_RETURN data via native OP_HASH256.
    const expectedBatchHash = hash256(cat(preStateRoot, newStateRoot));
    assert(batchDataHash === expectedBatchHash);

    // 6. Update state — compiler auto-enforces output carries new state
    this.stateRoot = newStateRoot;
    this.blockNumber = newBlockNumber;
  }
}
