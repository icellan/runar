import {
  SmartContract, assert,
  merkleRootSha256, merkleRootHash256,
} from 'runar-lang';
import type { ByteString } from 'runar-lang';

/**
 * MerkleProofDemo — Demonstrates Merkle proof verification in Bitcoin Script.
 *
 * Two built-in functions:
 * - merkleRootSha256(leaf, proof, index, depth) — SHA-256 Merkle root (STARK/FRI)
 * - merkleRootHash256(leaf, proof, index, depth) — Hash256 Merkle root (Bitcoin)
 *
 * Parameters:
 * - leaf: 32-byte leaf hash
 * - proof: concatenated 32-byte sibling hashes (depth * 32 bytes)
 * - index: leaf position (determines left/right at each level)
 * - depth: number of tree levels (MUST be a compile-time constant)
 *
 * The depth parameter is consumed at compile time — the loop is unrolled,
 * producing ~15 opcodes per level. No runtime iteration.
 */
class MerkleProofDemo extends SmartContract {
  readonly expectedRoot: ByteString;

  constructor(expectedRoot: ByteString) {
    super(expectedRoot);
    this.expectedRoot = expectedRoot;
  }

  /** Verify a SHA-256 Merkle proof at depth 4. */
  public verifySha256(leaf: ByteString, proof: ByteString, index: bigint) {
    const root = merkleRootSha256(leaf, proof, index, 4n);
    assert(root === this.expectedRoot);
  }

  /** Verify a Hash256 Merkle proof at depth 4. */
  public verifyHash256(leaf: ByteString, proof: ByteString, index: bigint) {
    const root = merkleRootHash256(leaf, proof, index, 4n);
    assert(root === this.expectedRoot);
  }
}
