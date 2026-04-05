import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { TestContract } from 'runar-testing';
import { createHash } from 'node:crypto';

const __dirname = dirname(fileURLToPath(import.meta.url));
const source = readFileSync(join(__dirname, 'MerkleProofDemo.runar.sol'), 'utf8');
const FILE_NAME = 'MerkleProofDemo.runar.sol';

// ---------------------------------------------------------------------------
// Merkle tree helpers (for building test fixtures)
// ---------------------------------------------------------------------------

function sha256(hex: string): string {
  return createHash('sha256').update(Buffer.from(hex, 'hex')).digest('hex');
}

function hash256(hex: string): string {
  return sha256(sha256(hex));
}

/**
 * Build a depth-4 Merkle tree (16 leaves) and return the root + proof for a given leaf index.
 */
function buildMerkleTree(leaves: string[], hashFn: (h: string) => string): {
  root: string;
  getProof: (index: number) => { proof: string; leaf: string };
} {
  let level = [...leaves];
  const layers: string[][] = [level];

  while (level.length > 1) {
    const next: string[] = [];
    for (let i = 0; i < level.length; i += 2) {
      next.push(hashFn(level[i]! + level[i + 1]!));
    }
    level = next;
    layers.push(level);
  }

  const root = level[0]!;

  return {
    root,
    getProof(index: number) {
      const siblings: string[] = [];
      let idx = index;
      for (let d = 0; d < layers.length - 1; d++) {
        const siblingIdx = idx ^ 1;
        siblings.push(layers[d]![siblingIdx]!);
        idx = idx >> 1;
      }
      return {
        proof: siblings.join(''),
        leaf: leaves[index]!,
      };
    },
  };
}

describe('MerkleProofDemo (Solidity)', () => {
  // Create 16 leaves (32-byte hashes)
  const leaves: string[] = [];
  for (let i = 0; i < 16; i++) {
    leaves.push(sha256(Buffer.from([i]).toString('hex')));
  }

  describe('verifySha256 (merkleRootSha256, depth=4)', () => {
    const tree = buildMerkleTree(leaves, sha256);

    it('verifies leaf at index 0', () => {
      const { proof, leaf } = tree.getProof(0);
      const c = TestContract.fromSource(source, { expectedRoot: tree.root }, FILE_NAME);
      const r = c.call('verifySha256', { leaf, proof, index: 0n });
      expect(r.success).toBe(true);
    });

    it('verifies leaf at index 7', () => {
      const { proof, leaf } = tree.getProof(7);
      const c = TestContract.fromSource(source, { expectedRoot: tree.root }, FILE_NAME);
      const r = c.call('verifySha256', { leaf, proof, index: 7n });
      expect(r.success).toBe(true);
    });

    it('verifies leaf at index 15', () => {
      const { proof, leaf } = tree.getProof(15);
      const c = TestContract.fromSource(source, { expectedRoot: tree.root }, FILE_NAME);
      const r = c.call('verifySha256', { leaf, proof, index: 15n });
      expect(r.success).toBe(true);
    });

    it('rejects wrong leaf', () => {
      const { proof } = tree.getProof(0);
      const wrongLeaf = sha256('ff');
      const c = TestContract.fromSource(source, { expectedRoot: tree.root }, FILE_NAME);
      const r = c.call('verifySha256', { leaf: wrongLeaf, proof, index: 0n });
      expect(r.success).toBe(false);
    });

    it('rejects wrong index', () => {
      const { proof, leaf } = tree.getProof(0);
      const c = TestContract.fromSource(source, { expectedRoot: tree.root }, FILE_NAME);
      const r = c.call('verifySha256', { leaf, proof, index: 1n });
      expect(r.success).toBe(false);
    });
  });

  describe('verifyHash256 (merkleRootHash256, depth=4)', () => {
    const tree = buildMerkleTree(leaves, hash256);

    it('verifies leaf at index 0', () => {
      const { proof, leaf } = tree.getProof(0);
      const c = TestContract.fromSource(source, { expectedRoot: tree.root }, FILE_NAME);
      const r = c.call('verifyHash256', { leaf, proof, index: 0n });
      expect(r.success).toBe(true);
    });

    it('verifies leaf at index 10', () => {
      const { proof, leaf } = tree.getProof(10);
      const c = TestContract.fromSource(source, { expectedRoot: tree.root }, FILE_NAME);
      const r = c.call('verifyHash256', { leaf, proof, index: 10n });
      expect(r.success).toBe(true);
    });
  });
});
