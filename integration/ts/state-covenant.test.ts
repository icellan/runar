/**
 * StateCovenant integration test — stateful covenant combining Baby Bear field
 * arithmetic, Merkle proof verification, and hash256 batch data binding.
 *
 * Deploys and advances the covenant on a real regtest node. Tests both valid
 * state transitions and on-chain rejection of invalid inputs.
 */

import { describe, it, expect } from 'vitest';
import { compileContract } from './helpers/compile.js';
import { RunarContract } from 'runar-sdk';
import { createFundedWallet } from './helpers/wallet.js';
import { createProvider } from './helpers/node.js';
import { createHash } from 'crypto';

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

// Baby Bear field prime
const BB_P = 2013265921n;

describe('StateCovenant', () => {
  it('should compile the StateCovenant contract', () => {
    const artifact = compileContract('examples/ts/state-covenant/StateCovenant.runar.ts');
    expect(artifact).toBeTruthy();
    expect(artifact.contractName).toBe('StateCovenant');
  });

  it('should deploy with initial state', async () => {
    const artifact = compileContract('examples/ts/state-covenant/StateCovenant.runar.ts');

    // Build a Merkle tree for verification key
    const leaves: string[] = [];
    for (let i = 0; i < 16; i++) leaves.push(sha256(Buffer.from([i]).toString('hex')));
    const tree = buildTree(leaves, sha256);

    const initialRoot = 'aa'.repeat(32);
    const contract = new RunarContract(artifact, [initialRoot, 0n, tree.root]);

    const provider = createProvider();
    const { signer } = await createFundedWallet(provider);

    const { txid } = await contract.deploy(provider, signer, { satoshis: 100000 });
    expect(txid).toBeTruthy();
    expect(txid.length).toBe(64);
  });

  it('should advance state with valid inputs (auto-computed state)', async () => {
    const artifact = compileContract('examples/ts/state-covenant/StateCovenant.runar.ts');

    // Merkle tree setup
    const leaves: string[] = [];
    for (let i = 0; i < 16; i++) leaves.push(sha256(Buffer.from([i]).toString('hex')));
    const tree = buildTree(leaves, sha256);
    const { proof, leaf } = tree.getProof(3);

    const preStateRoot = 'aa'.repeat(32);
    const newStateRoot = 'bb'.repeat(32);

    // Baby Bear field multiplication: a * b mod p
    const proofFieldA = 6n;
    const proofFieldB = 7n;
    const proofFieldC = (proofFieldA * proofFieldB) % BB_P; // 42

    // Batch data hash = hash256(preStateRoot || newStateRoot)
    const batchDataHash = hash256(preStateRoot + newStateRoot);

    const contract = new RunarContract(artifact, [preStateRoot, 0n, tree.root]);

    const provider = createProvider();
    const { signer } = await createFundedWallet(provider);

    await contract.deploy(provider, signer, { satoshis: 100000 });

    const { txid } = await contract.call(
      'advanceState',
      [newStateRoot, 1n, batchDataHash, preStateRoot, proofFieldA, proofFieldB, proofFieldC, leaf, proof, 3n],
      provider,
      signer,
    );
    expect(txid).toBeTruthy();
    expect(contract.state.stateRoot).toBe(newStateRoot);
    expect(contract.state.blockNumber).toBe(1n);
  });

  it('should reject non-increasing block number', async () => {
    const artifact = compileContract('examples/ts/state-covenant/StateCovenant.runar.ts');

    const leaves: string[] = [];
    for (let i = 0; i < 16; i++) leaves.push(sha256(Buffer.from([i]).toString('hex')));
    const tree = buildTree(leaves, sha256);
    const { proof, leaf } = tree.getProof(3);

    const preStateRoot = 'aa'.repeat(32);
    const newStateRoot = 'bb'.repeat(32);
    const batchDataHash = hash256(preStateRoot + newStateRoot);

    const contract = new RunarContract(artifact, [preStateRoot, 5n, tree.root]);

    const provider = createProvider();
    const { signer } = await createFundedWallet(provider);

    await contract.deploy(provider, signer, { satoshis: 100000 });

    // Block number 3 is NOT greater than 5 — should fail
    await expect(
      contract.call(
        'advanceState',
        [newStateRoot, 3n, batchDataHash, preStateRoot, 6n, 7n, 42n, leaf, proof, 3n],
        provider,
        signer,
      ),
    ).rejects.toThrow();
  });
});
