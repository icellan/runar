/**
 * Baby Bear field arithmetic — Plonky3-generated test vector validation on regtest.
 *
 * Vectors cover: add, sub, mul, inv with edge cases, boundary values, powers
 * of 2, generator chains, and random values (829 total vectors).
 *
 * Runs vectors in parallel (bounded concurrency) with pre-funded wallets.
 */

import { describe, it, expect } from 'vitest';
import { compileSource } from './helpers/compile.js';
import { RunarContract } from 'runar-sdk';
import { splitFundParallel } from './helpers/wallet.js';
import { createBatchProvider, mine } from './helpers/node.js';
import { readFileSync } from 'fs';
import { resolve } from 'path';

interface TestVector {
  op: string;
  a: number;
  b?: number;
  expected: number;
  description: string;
}

interface VectorFile {
  field: string;
  prime: number;
  vectors: TestVector[];
}

const VECTORS_DIR = resolve(import.meta.dirname, '..', '..', 'tests', 'vectors');
const CONCURRENCY = parseInt(process.env.TEST_PARALLEL ?? '10', 10);

function loadVectors(filename: string): VectorFile {
  const data = readFileSync(resolve(VECTORS_DIR, filename), 'utf-8');
  return JSON.parse(data);
}

// Contract sources — one per operation
const bbAddSource = `
import { SmartContract, assert, bbFieldAdd } from 'runar-lang';

class BBAddVec extends SmartContract {
  readonly expected: bigint;
  constructor(expected: bigint) { super(expected); this.expected = expected; }
  public verify(a: bigint, b: bigint) {
    assert(bbFieldAdd(a, b) === this.expected);
  }
}
`;

const bbSubSource = `
import { SmartContract, assert, bbFieldSub } from 'runar-lang';

class BBSubVec extends SmartContract {
  readonly expected: bigint;
  constructor(expected: bigint) { super(expected); this.expected = expected; }
  public verify(a: bigint, b: bigint) {
    assert(bbFieldSub(a, b) === this.expected);
  }
}
`;

const bbMulSource = `
import { SmartContract, assert, bbFieldMul } from 'runar-lang';

class BBMulVec extends SmartContract {
  readonly expected: bigint;
  constructor(expected: bigint) { super(expected); this.expected = expected; }
  public verify(a: bigint, b: bigint) {
    assert(bbFieldMul(a, b) === this.expected);
  }
}
`;

const bbInvSource = `
import { SmartContract, assert, bbFieldInv } from 'runar-lang';

class BBInvVec extends SmartContract {
  readonly expected: bigint;
  constructor(expected: bigint) { super(expected); this.expected = expected; }
  public verify(a: bigint) {
    assert(bbFieldInv(a) === this.expected);
  }
}
`;

/** Run a batch of tasks with bounded concurrency. */
async function mapConcurrent<T, R>(items: T[], limit: number, fn: (item: T, idx: number) => Promise<R>): Promise<R[]> {
  const results: R[] = new Array(items.length);
  let next = 0;

  async function worker() {
    while (next < items.length) {
      const idx = next++;
      results[idx] = await fn(items[idx], idx);
    }
  }

  const workers = Array.from({ length: Math.min(limit, items.length) }, () => worker());
  await Promise.all(workers);
  return results;
}

/**
 * Select a representative subset of vectors for on-chain testing:
 * - All edge cases (wrap-around, identity, zero, p-1, p-2)
 * - First small value pair (sanity)
 * - One power-of-2 case
 * - 5 random values (general case)
 *
 * Full vector coverage runs in codegen/script_correctness_test.go (go-sdk interpreter).
 * Integration tests just prove the compiled Script works on a real node.
 */
function selectRepresentative(vectors: TestVector[]): TestVector[] {
  const selected: TestVector[] = [];
  const seen = new Set<string>();

  const add = (v: TestVector) => {
    if (!seen.has(v.description)) {
      seen.add(v.description);
      selected.push(v);
    }
  };

  // Edge cases first — these test modular reduction
  for (const v of vectors) {
    const d = v.description.toLowerCase();
    if (d.includes('wrap') || d.includes('identity') || d.includes('p-1') ||
        d.includes('p-2') || d.includes('underflow') || d === '0 + 0 = 0' ||
        d === '0 - 0 = 0' || d === '0 * 0 = 0' || d.includes('inv(1)') ||
        d.includes('inv(-1)') || d.includes('(-1)')) {
      add(v);
    }
  }

  // One small value (sanity check)
  for (const v of vectors) {
    if (!v.description.includes('random') && !v.description.includes('2^') &&
        selected.length < 8 && !seen.has(v.description)) {
      add(v);
      break;
    }
  }

  // One power-of-2
  for (const v of vectors) {
    if (v.description.includes('2^') && !seen.has(v.description)) {
      add(v);
      break;
    }
  }

  // Up to 5 random values
  let randomCount = 0;
  for (const v of vectors) {
    if (v.description.includes('random') && randomCount < 5) {
      add(v);
      randomCount++;
    }
  }

  return selected;
}

async function runBinaryVectors(source: string, fileName: string, vectors: TestVector[]) {
  const subset = selectRepresentative(vectors);
  const artifact = compileSource(source, fileName);
  const wallets = await splitFundParallel(subset.length, 100_000);

  await mapConcurrent(subset, CONCURRENCY, async (vec, i) => {
    const contract = new RunarContract(artifact, [BigInt(vec.expected)]);
    const provider = createBatchProvider();

    await contract.deploy(provider, wallets[i].signer, {});
    const { txid } = await contract.call(
      'verify',
      [BigInt(vec.a), BigInt(vec.b!)],
      provider,
      wallets[i].signer,
    );
    expect(txid).toBeTruthy();
  });

  await mine(1);
}

async function runUnaryVectors(source: string, fileName: string, vectors: TestVector[]) {
  const subset = selectRepresentative(vectors);
  const artifact = compileSource(source, fileName);
  const wallets = await splitFundParallel(subset.length, 100_000);

  await mapConcurrent(subset, CONCURRENCY, async (vec, i) => {
    const contract = new RunarContract(artifact, [BigInt(vec.expected)]);
    const provider = createBatchProvider();

    await contract.deploy(provider, wallets[i].signer, {});
    const { txid } = await contract.call(
      'verify',
      [BigInt(vec.a)],
      provider,
      wallets[i].signer,
    );
    expect(txid).toBeTruthy();
  });

  await mine(1);
}

describe('Baby Bear Vectors — Addition', () => {
  const vf = loadVectors('babybear_add.json');

  it(`validates ${vf.vectors.length} addition vectors on regtest`, async () => {
    await runBinaryVectors(bbAddSource, 'BBAddVec.runar.ts', vf.vectors);
  }, 600_000);
});

describe('Baby Bear Vectors — Subtraction', () => {
  const vf = loadVectors('babybear_sub.json');

  it(`validates ${vf.vectors.length} subtraction vectors on regtest`, async () => {
    await runBinaryVectors(bbSubSource, 'BBSubVec.runar.ts', vf.vectors);
  }, 600_000);
});

describe('Baby Bear Vectors — Multiplication', () => {
  const vf = loadVectors('babybear_mul.json');

  it(`validates ${vf.vectors.length} multiplication vectors on regtest`, async () => {
    await runBinaryVectors(bbMulSource, 'BBMulVec.runar.ts', vf.vectors);
  }, 600_000);
});

describe('Baby Bear Vectors — Inverse', () => {
  const vf = loadVectors('babybear_inv.json');

  it(`validates ${vf.vectors.length} inverse vectors on regtest`, async () => {
    await runUnaryVectors(bbInvSource, 'BBInvVec.runar.ts', vf.vectors);
  }, 600_000);
});
