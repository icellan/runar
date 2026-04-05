/**
 * Merkle proof verification integration tests — inline contracts testing
 * merkleRootSha256/merkleRootHash256 on a real regtest node.
 *
 * Each test compiles a minimal stateless contract, deploys on regtest, and
 * spends via contract.call(). The compiled script contains unrolled Merkle
 * path verification validated by a real BSV node.
 *
 * Tests include:
 *   - Happy path: SHA-256 proof at various leaf positions (depth 4)
 *   - Happy path: Hash256 proof (double SHA-256)
 *   - Unhappy path: wrong leaf, wrong index, tampered proof — all rejected on-chain
 */

import { describe, it, expect } from 'vitest';
import { compileSource } from './helpers/compile.js';
import { RunarContract } from 'runar-sdk';
import { createFundedWallet } from './helpers/wallet.js';
import { createProvider } from './helpers/node.js';
import { createHash } from 'crypto';

// ---- Merkle tree helpers ----

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

// Build a depth-4 SHA-256 tree (16 leaves)
const sha256Leaves: string[] = [];
for (let i = 0; i < 16; i++) {
  sha256Leaves.push(sha256(Buffer.from([i]).toString('hex')));
}
const sha256Tree = buildTree(sha256Leaves, sha256);

// Build a depth-4 Hash256 tree (16 leaves)
const hash256Leaves: string[] = [];
for (let i = 0; i < 16; i++) {
  hash256Leaves.push(hash256(Buffer.from([i]).toString('hex')));
}
const hash256Tree = buildTree(hash256Leaves, hash256);

// ---- Contract sources ----

const MERKLE_SHA256_SOURCE = `
import { SmartContract, assert, merkleRootSha256 } from 'runar-lang';
import type { ByteString } from 'runar-lang';

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

const MERKLE_HASH256_SOURCE = `
import { SmartContract, assert, merkleRootHash256 } from 'runar-lang';
import type { ByteString } from 'runar-lang';

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

// ---- Tests ----

describe('Merkle Proof Verification', () => {
  // ---- merkleRootSha256 happy path ----

  it('merkleRootSha256: verifies leaf at index 0 (leftmost)', async () => {
    const { proof, leaf } = sha256Tree.getProof(0);
    const artifact = compileSource(MERKLE_SHA256_SOURCE, 'MerkleSha256Test.runar.ts');
    const contract = new RunarContract(artifact, [sha256Tree.root]);

    const provider = createProvider();
    const { signer } = await createFundedWallet(provider);

    await contract.deploy(provider, signer, {});
    const { txid } = await contract.call('verify', [leaf, proof, 0n], provider, signer);
    expect(txid).toBeTruthy();
    expect(txid.length).toBe(64);
  });

  it('merkleRootSha256: verifies leaf at index 7 (middle)', async () => {
    const { proof, leaf } = sha256Tree.getProof(7);
    const artifact = compileSource(MERKLE_SHA256_SOURCE, 'MerkleSha256Test.runar.ts');
    const contract = new RunarContract(artifact, [sha256Tree.root]);

    const provider = createProvider();
    const { signer } = await createFundedWallet(provider);

    await contract.deploy(provider, signer, {});
    const { txid } = await contract.call('verify', [leaf, proof, 7n], provider, signer);
    expect(txid).toBeTruthy();
  });

  it('merkleRootSha256: verifies leaf at index 15 (rightmost)', async () => {
    const { proof, leaf } = sha256Tree.getProof(15);
    const artifact = compileSource(MERKLE_SHA256_SOURCE, 'MerkleSha256Test.runar.ts');
    const contract = new RunarContract(artifact, [sha256Tree.root]);

    const provider = createProvider();
    const { signer } = await createFundedWallet(provider);

    await contract.deploy(provider, signer, {});
    const { txid } = await contract.call('verify', [leaf, proof, 15n], provider, signer);
    expect(txid).toBeTruthy();
  });

  // ---- merkleRootHash256 happy path ----

  it('merkleRootHash256: verifies leaf at index 0', async () => {
    const { proof, leaf } = hash256Tree.getProof(0);
    const artifact = compileSource(MERKLE_HASH256_SOURCE, 'MerkleHash256Test.runar.ts');
    const contract = new RunarContract(artifact, [hash256Tree.root]);

    const provider = createProvider();
    const { signer } = await createFundedWallet(provider);

    await contract.deploy(provider, signer, {});
    const { txid } = await contract.call('verify', [leaf, proof, 0n], provider, signer);
    expect(txid).toBeTruthy();
  });

  it('merkleRootHash256: verifies leaf at index 10', async () => {
    const { proof, leaf } = hash256Tree.getProof(10);
    const artifact = compileSource(MERKLE_HASH256_SOURCE, 'MerkleHash256Test.runar.ts');
    const contract = new RunarContract(artifact, [hash256Tree.root]);

    const provider = createProvider();
    const { signer } = await createFundedWallet(provider);

    await contract.deploy(provider, signer, {});
    const { txid } = await contract.call('verify', [leaf, proof, 10n], provider, signer);
    expect(txid).toBeTruthy();
  });

  // ---- Unhappy path: on-chain rejection ----

  it('rejects wrong leaf on-chain', async () => {
    const { proof } = sha256Tree.getProof(0);
    const wrongLeaf = sha256('ff');
    const artifact = compileSource(MERKLE_SHA256_SOURCE, 'MerkleSha256Test.runar.ts');
    const contract = new RunarContract(artifact, [sha256Tree.root]);

    const provider = createProvider();
    const { signer } = await createFundedWallet(provider);

    await contract.deploy(provider, signer, {});
    await expect(
      contract.call('verify', [wrongLeaf, proof, 0n], provider, signer),
    ).rejects.toThrow();
  });

  it('rejects wrong index on-chain', async () => {
    const { proof, leaf } = sha256Tree.getProof(0);
    const artifact = compileSource(MERKLE_SHA256_SOURCE, 'MerkleSha256Test.runar.ts');
    const contract = new RunarContract(artifact, [sha256Tree.root]);

    const provider = createProvider();
    const { signer } = await createFundedWallet(provider);

    await contract.deploy(provider, signer, {});
    // Proof is for index 0, using it at index 1 should fail
    await expect(
      contract.call('verify', [leaf, proof, 1n], provider, signer),
    ).rejects.toThrow();
  });

  it('rejects tampered proof on-chain', async () => {
    const { proof, leaf } = sha256Tree.getProof(5);
    // Corrupt the first byte
    const tampered = 'ff' + proof.slice(2);
    const artifact = compileSource(MERKLE_SHA256_SOURCE, 'MerkleSha256Test.runar.ts');
    const contract = new RunarContract(artifact, [sha256Tree.root]);

    const provider = createProvider();
    const { signer } = await createFundedWallet(provider);

    await contract.deploy(provider, signer, {});
    await expect(
      contract.call('verify', [leaf, tampered, 5n], provider, signer),
    ).rejects.toThrow();
  });
});
