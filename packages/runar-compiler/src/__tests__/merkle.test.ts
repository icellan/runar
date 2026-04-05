import { describe, it, expect } from 'vitest';
import { compile } from '../index.js';

// ---------------------------------------------------------------------------
// Test sources
// ---------------------------------------------------------------------------

const MERKLE_SHA256_SOURCE = `
class MerkleTestSha256 extends SmartContract {
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
class MerkleTestHash256 extends SmartContract {
  readonly expectedRoot: ByteString;

  constructor(expectedRoot: ByteString) {
    super(expectedRoot);
    this.expectedRoot = expectedRoot;
  }

  public verify(leaf: ByteString, proof: ByteString, index: bigint) {
    const root = merkleRootHash256(leaf, proof, index, 8n);
    assert(root === this.expectedRoot);
  }
}
`;

const MERKLE_DEEP_SOURCE = `
class MerkleDeepTest extends SmartContract {
  readonly expectedRoot: ByteString;

  constructor(expectedRoot: ByteString) {
    super(expectedRoot);
    this.expectedRoot = expectedRoot;
  }

  public verify(leaf: ByteString, proof: ByteString, index: bigint) {
    const root = merkleRootSha256(leaf, proof, index, 20n);
    assert(root === this.expectedRoot);
  }
}
`;

// ---------------------------------------------------------------------------
// Compilation tests
// ---------------------------------------------------------------------------

function expectNoErrors(result: ReturnType<typeof compile>): void {
  const errors = result.diagnostics.filter(d => d.severity === 'error');
  expect(errors).toEqual([]);
  expect(result.success).toBe(true);
}

describe('Merkle proof verification — compilation', () => {
  it('compiles merkleRootSha256 usage with depth 4', () => {
    expectNoErrors(compile(MERKLE_SHA256_SOURCE));
  });

  it('compiles merkleRootHash256 usage with depth 8', () => {
    expectNoErrors(compile(MERKLE_HASH256_SOURCE));
  });

  it('compiles merkleRootSha256 with depth 20', () => {
    expectNoErrors(compile(MERKLE_DEEP_SOURCE));
  });

  it('produces non-empty script', () => {
    const result = compile(MERKLE_SHA256_SOURCE);
    expectNoErrors(result);
    expect(result.artifact?.script.length).toBeGreaterThan(0);
  });
});

describe('Merkle proof verification — type checking', () => {
  it('rejects merkleRootSha256 with wrong argument types', () => {
    const src = `
class Bad extends SmartContract {
  constructor() { super(); }
  public test(leaf: bigint, proof: ByteString, index: bigint) {
    const r = merkleRootSha256(leaf, proof, index, 4n);
    assert(r === proof);
  }
}
`;
    const result = compile(src);
    expect(result.success).toBe(false);
  });
});
