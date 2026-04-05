import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { TestContract } from 'runar-testing';
import { createHash } from 'node:crypto';

const __dirname = dirname(fileURLToPath(import.meta.url));
const source = readFileSync(join(__dirname, 'StateCovenant.runar.sol'), 'utf8');
const FILE_NAME = 'StateCovenant.runar.sol';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

const BB_P = 2013265921n;

function bbFieldMul(a: bigint, b: bigint): bigint {
  return (a * b) % BB_P;
}

function sha256(hex: string): string {
  return createHash('sha256').update(Buffer.from(hex, 'hex')).digest('hex');
}

function hash256(hex: string): string {
  return sha256(sha256(hex));
}

function buildMerkleTree(leaves: string[]): {
  root: string;
  getProof: (index: number) => { proof: string; leaf: string };
} {
  let level = [...leaves];
  const layers: string[][] = [level];

  while (level.length > 1) {
    const next: string[] = [];
    for (let i = 0; i < level.length; i += 2) {
      next.push(sha256(level[i]! + level[i + 1]!));
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
        idx = idx >> 1;
      }
      return { proof: siblings.join(''), leaf: leaves[index]! };
    },
  };
}

function stateRootForBlock(n: number): string {
  return sha256(Buffer.from([n]).toString('hex'));
}

const MERKLE_LEAVES: string[] = [];
for (let i = 0; i < 16; i++) {
  MERKLE_LEAVES.push(sha256(Buffer.from([i]).toString('hex')));
}
const MERKLE_TREE = buildMerkleTree(MERKLE_LEAVES);
const VERIFYING_KEY_HASH = MERKLE_TREE.root;
const LEAF_INDEX = 3;

const GENESIS_STATE_ROOT = '00'.repeat(32);

function buildAdvanceArgs(preStateRoot: string, newBlockNumber: bigint) {
  const newStateRoot = stateRootForBlock(Number(newBlockNumber));
  const batchDataHash = hash256(preStateRoot + newStateRoot);
  const proofFieldA = 1000000n;
  const proofFieldB = 2000000n;
  const proofFieldC = bbFieldMul(proofFieldA, proofFieldB);
  const { proof, leaf } = MERKLE_TREE.getProof(LEAF_INDEX);

  return {
    newStateRoot,
    newBlockNumber,
    batchDataHash,
    preStateRoot,
    proofFieldA,
    proofFieldB,
    proofFieldC,
    merkleLeaf: leaf,
    merkleProof: proof,
    merkleIndex: BigInt(LEAF_INDEX),
  };
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe('StateCovenant (Solidity)', () => {
  it('starts with initial state', () => {
    const c = TestContract.fromSource(source, {
      stateRoot: GENESIS_STATE_ROOT,
      blockNumber: 0n,
      verifyingKeyHash: VERIFYING_KEY_HASH,
    }, FILE_NAME);
    expect(c.state.stateRoot).toBe(GENESIS_STATE_ROOT);
    expect(c.state.blockNumber).toBe(0n);
  });

  it('advances state with valid proof', () => {
    const args = buildAdvanceArgs(GENESIS_STATE_ROOT, 1n);
    const c = TestContract.fromSource(source, {
      stateRoot: GENESIS_STATE_ROOT,
      blockNumber: 0n,
      verifyingKeyHash: VERIFYING_KEY_HASH,
    }, FILE_NAME);
    const r = c.call('advanceState', args);
    expect(r.success).toBe(true);
    expect(c.state.stateRoot).toBe(args.newStateRoot);
    expect(c.state.blockNumber).toBe(1n);
  });

  it('chains multiple advances (0 -> 1 -> 2 -> 3)', () => {
    const c = TestContract.fromSource(source, {
      stateRoot: GENESIS_STATE_ROOT,
      blockNumber: 0n,
      verifyingKeyHash: VERIFYING_KEY_HASH,
    }, FILE_NAME);

    let pre = GENESIS_STATE_ROOT;
    for (let block = 1; block <= 3; block++) {
      const args = buildAdvanceArgs(pre, BigInt(block));
      const r = c.call('advanceState', args);
      expect(r.success).toBe(true);
      expect(c.state.blockNumber).toBe(BigInt(block));
      pre = args.newStateRoot;
    }
  });

  it('rejects wrong pre-state root', () => {
    const args = buildAdvanceArgs(GENESIS_STATE_ROOT, 1n);
    const c = TestContract.fromSource(source, {
      stateRoot: GENESIS_STATE_ROOT,
      blockNumber: 0n,
      verifyingKeyHash: VERIFYING_KEY_HASH,
    }, FILE_NAME);
    const r = c.call('advanceState', { ...args, preStateRoot: 'ff'.repeat(32) });
    expect(r.success).toBe(false);
  });

  it('rejects non-increasing block number', () => {
    const args = buildAdvanceArgs(GENESIS_STATE_ROOT, 3n);
    const c = TestContract.fromSource(source, {
      stateRoot: GENESIS_STATE_ROOT,
      blockNumber: 5n,
      verifyingKeyHash: VERIFYING_KEY_HASH,
    }, FILE_NAME);
    const r = c.call('advanceState', { ...args, newBlockNumber: 3n });
    expect(r.success).toBe(false);
  });

  it('rejects invalid Baby Bear proof', () => {
    const args = buildAdvanceArgs(GENESIS_STATE_ROOT, 1n);
    const c = TestContract.fromSource(source, {
      stateRoot: GENESIS_STATE_ROOT,
      blockNumber: 0n,
      verifyingKeyHash: VERIFYING_KEY_HASH,
    }, FILE_NAME);
    const r = c.call('advanceState', { ...args, proofFieldC: 99999n });
    expect(r.success).toBe(false);
  });

  it('rejects invalid Merkle proof (wrong leaf)', () => {
    const args = buildAdvanceArgs(GENESIS_STATE_ROOT, 1n);
    const c = TestContract.fromSource(source, {
      stateRoot: GENESIS_STATE_ROOT,
      blockNumber: 0n,
      verifyingKeyHash: VERIFYING_KEY_HASH,
    }, FILE_NAME);
    const r = c.call('advanceState', { ...args, merkleLeaf: 'aa'.repeat(32) });
    expect(r.success).toBe(false);
  });

  it('rejects wrong batch data hash', () => {
    const args = buildAdvanceArgs(GENESIS_STATE_ROOT, 1n);
    const c = TestContract.fromSource(source, {
      stateRoot: GENESIS_STATE_ROOT,
      blockNumber: 0n,
      verifyingKeyHash: VERIFYING_KEY_HASH,
    }, FILE_NAME);
    const r = c.call('advanceState', { ...args, batchDataHash: 'bb'.repeat(32) });
    expect(r.success).toBe(false);
  });
});
