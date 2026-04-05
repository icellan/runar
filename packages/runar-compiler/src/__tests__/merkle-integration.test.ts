/**
 * Integration tests for Merkle proof verification.
 *
 * These tests verify the full pipeline: parse → validate → typecheck → ANF →
 * stack-lower → emit → interpret. Both happy and unhappy paths are tested.
 *
 * Uses real SHA-256/Hash256 Merkle trees built in the test to verify the
 * interpreter produces correct roots.
 */
import { describe, it, expect } from 'vitest';
import { compile } from '../index.js';
// @ts-expect-error vitest resolves this via alias
import { TestContract } from 'runar-testing';
import { createHash } from 'node:crypto';

// ---------------------------------------------------------------------------
// Merkle tree helpers
// ---------------------------------------------------------------------------

function sha256(hex: string): string {
  return createHash('sha256').update(Buffer.from(hex, 'hex')).digest('hex');
}

function hash256(hex: string): string {
  return sha256(sha256(hex));
}

function buildTree(leaves: string[], hashFn: (h: string) => string) {
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
  return {
    root: level[0]!,
    getProof(index: number) {
      const siblings: string[] = [];
      let idx = index;
      for (let d = 0; d < layers.length - 1; d++) {
        siblings.push(layers[d]![idx ^ 1]!);
        idx >>= 1;
      }
      return { proof: siblings.join(''), leaf: leaves[index]! };
    },
  };
}

// ---------------------------------------------------------------------------
// Test contract sources
// ---------------------------------------------------------------------------

const SHA256_SOURCE = `
class MerkleSha256Test extends SmartContract {
  readonly expectedRoot: ByteString;
  constructor(expectedRoot: ByteString) {
    super(expectedRoot);
    this.expectedRoot = expectedRoot;
  }
  public verify(leaf: ByteString, proof: ByteString, index: bigint) {
    const root = merkleRootSha256(leaf, proof, index, 4n);
    assert(root === this.expectedRoot);
  }
}
`;

const HASH256_SOURCE = `
class MerkleHash256Test extends SmartContract {
  readonly expectedRoot: ByteString;
  constructor(expectedRoot: ByteString) {
    super(expectedRoot);
    this.expectedRoot = expectedRoot;
  }
  public verify(leaf: ByteString, proof: ByteString, index: bigint) {
    const root = merkleRootHash256(leaf, proof, index, 4n);
    assert(root === this.expectedRoot);
  }
}
`;

const DEEP_SOURCE = `
class MerkleDeepTest extends SmartContract {
  readonly expectedRoot: ByteString;
  constructor(expectedRoot: ByteString) {
    super(expectedRoot);
    this.expectedRoot = expectedRoot;
  }
  public verify(leaf: ByteString, proof: ByteString, index: bigint) {
    const root = merkleRootSha256(leaf, proof, index, 8n);
    assert(root === this.expectedRoot);
  }
}
`;

// ---------------------------------------------------------------------------
// Compilation tests
// ---------------------------------------------------------------------------

describe('Merkle integration — compilation', () => {
  it('compiles merkleRootSha256 contract', () => {
    const result = compile(SHA256_SOURCE);
    expect(result.success).toBe(true);
    expect(result.artifact?.script.length).toBeGreaterThan(0);
  });

  it('compiles merkleRootHash256 contract', () => {
    expect(compile(HASH256_SOURCE).success).toBe(true);
  });

  it('compiles deep tree (depth 8)', () => {
    expect(compile(DEEP_SOURCE).success).toBe(true);
  });

  it('rejects wrong argument types (leaf as bigint)', () => {
    const src = `
class Bad extends SmartContract {
  constructor() { super(); }
  public test(leaf: bigint, proof: ByteString, index: bigint) {
    const r = merkleRootSha256(leaf, proof, index, 4n);
    assert(r === proof);
  }
}`;
    expect(compile(src).success).toBe(false);
  });

  it('rejects wrong argument count', () => {
    const src = `
class Bad extends SmartContract {
  constructor() { super(); }
  public test(leaf: ByteString, proof: ByteString) {
    const r = merkleRootSha256(leaf, proof);
    assert(r === proof);
  }
}`;
    expect(compile(src).success).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// Happy path — SHA-256 Merkle tree (depth 4 = 16 leaves)
// ---------------------------------------------------------------------------

describe('Merkle integration — SHA-256 happy path', () => {
  const leaves: string[] = [];
  for (let i = 0; i < 16; i++) {
    leaves.push(sha256(Buffer.from([i]).toString('hex')));
  }
  const tree = buildTree(leaves, sha256);

  it('verifies leaf at index 0 (leftmost)', () => {
    const { proof, leaf } = tree.getProof(0);
    const c = TestContract.fromSource(SHA256_SOURCE, { expectedRoot: tree.root });
    expect(c.call('verify', { leaf, proof, index: 0n }).success).toBe(true);
  });

  it('verifies leaf at index 7 (middle)', () => {
    const { proof, leaf } = tree.getProof(7);
    const c = TestContract.fromSource(SHA256_SOURCE, { expectedRoot: tree.root });
    expect(c.call('verify', { leaf, proof, index: 7n }).success).toBe(true);
  });

  it('verifies leaf at index 15 (rightmost)', () => {
    const { proof, leaf } = tree.getProof(15);
    const c = TestContract.fromSource(SHA256_SOURCE, { expectedRoot: tree.root });
    expect(c.call('verify', { leaf, proof, index: 15n }).success).toBe(true);
  });

  it('verifies all 16 leaves', () => {
    for (let i = 0; i < 16; i++) {
      const { proof, leaf } = tree.getProof(i);
      const c = TestContract.fromSource(SHA256_SOURCE, { expectedRoot: tree.root });
      expect(c.call('verify', { leaf, proof, index: BigInt(i) }).success).toBe(true);
    }
  });
});

// ---------------------------------------------------------------------------
// Happy path — Hash256 Merkle tree
// ---------------------------------------------------------------------------

describe('Merkle integration — Hash256 happy path', () => {
  const leaves: string[] = [];
  for (let i = 0; i < 16; i++) {
    leaves.push(hash256(Buffer.from([i]).toString('hex')));
  }
  const tree = buildTree(leaves, hash256);

  it('verifies leaf at index 0', () => {
    const { proof, leaf } = tree.getProof(0);
    const c = TestContract.fromSource(HASH256_SOURCE, { expectedRoot: tree.root });
    expect(c.call('verify', { leaf, proof, index: 0n }).success).toBe(true);
  });

  it('verifies leaf at index 10', () => {
    const { proof, leaf } = tree.getProof(10);
    const c = TestContract.fromSource(HASH256_SOURCE, { expectedRoot: tree.root });
    expect(c.call('verify', { leaf, proof, index: 10n }).success).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// Happy path — deeper tree (depth 8 = 256 leaves)
// ---------------------------------------------------------------------------

describe('Merkle integration — deep tree (depth 8)', () => {
  const leaves: string[] = [];
  for (let i = 0; i < 256; i++) {
    leaves.push(sha256(Buffer.from([i]).toString('hex')));
  }
  const tree = buildTree(leaves, sha256);

  it('verifies leaf at index 0', () => {
    const { proof, leaf } = tree.getProof(0);
    const c = TestContract.fromSource(DEEP_SOURCE, { expectedRoot: tree.root });
    expect(c.call('verify', { leaf, proof, index: 0n }).success).toBe(true);
  });

  it('verifies leaf at index 128 (middle)', () => {
    const { proof, leaf } = tree.getProof(128);
    const c = TestContract.fromSource(DEEP_SOURCE, { expectedRoot: tree.root });
    expect(c.call('verify', { leaf, proof, index: 128n }).success).toBe(true);
  });

  it('verifies leaf at index 255 (last)', () => {
    const { proof, leaf } = tree.getProof(255);
    const c = TestContract.fromSource(DEEP_SOURCE, { expectedRoot: tree.root });
    expect(c.call('verify', { leaf, proof, index: 255n }).success).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// Unhappy path — should fail verification
// ---------------------------------------------------------------------------

describe('Merkle integration — unhappy path', () => {
  const leaves: string[] = [];
  for (let i = 0; i < 16; i++) {
    leaves.push(sha256(Buffer.from([i]).toString('hex')));
  }
  const tree = buildTree(leaves, sha256);

  it('rejects wrong leaf', () => {
    const { proof } = tree.getProof(0);
    const wrongLeaf = sha256('ff');
    const c = TestContract.fromSource(SHA256_SOURCE, { expectedRoot: tree.root });
    expect(c.call('verify', { leaf: wrongLeaf, proof, index: 0n }).success).toBe(false);
  });

  it('rejects wrong index', () => {
    const { proof, leaf } = tree.getProof(0);
    const c = TestContract.fromSource(SHA256_SOURCE, { expectedRoot: tree.root });
    // Proof is for index 0, using it at index 1 should fail
    expect(c.call('verify', { leaf, proof, index: 1n }).success).toBe(false);
  });

  it('rejects wrong root', () => {
    const { proof, leaf } = tree.getProof(0);
    const wrongRoot = sha256('00');
    const c = TestContract.fromSource(SHA256_SOURCE, { expectedRoot: wrongRoot });
    expect(c.call('verify', { leaf, proof, index: 0n }).success).toBe(false);
  });

  it('rejects tampered proof (modified sibling)', () => {
    const { proof, leaf } = tree.getProof(5);
    // Corrupt the first byte of the proof
    const tampered = 'ff' + proof.slice(2);
    const c = TestContract.fromSource(SHA256_SOURCE, { expectedRoot: tree.root });
    expect(c.call('verify', { leaf, proof: tampered, index: 5n }).success).toBe(false);
  });

  it('rejects proof for different hash function', () => {
    // Build a Hash256 tree proof but try to verify with SHA-256 contract
    const h256leaves: string[] = [];
    for (let i = 0; i < 16; i++) {
      h256leaves.push(hash256(Buffer.from([i]).toString('hex')));
    }
    const h256tree = buildTree(h256leaves, hash256);
    const { proof, leaf } = h256tree.getProof(3);
    // Use SHA-256 contract with Hash256 proof — should fail
    const c = TestContract.fromSource(SHA256_SOURCE, { expectedRoot: h256tree.root });
    expect(c.call('verify', { leaf, proof, index: 3n }).success).toBe(false);
  });
});
