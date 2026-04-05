/**
 * Integration tests for Baby Bear field arithmetic.
 *
 * These tests verify the full pipeline: parse → validate → typecheck → ANF →
 * stack-lower → emit → interpret. Both happy and unhappy paths are tested.
 *
 * The TestContract interpreter runs real Baby Bear arithmetic, so these tests
 * verify mathematical correctness — not just that compilation succeeds.
 */
import { describe, it, expect } from 'vitest';
import { compile } from '../index.js';
import { TestContract } from 'runar-testing';

const BB_P = 2013265921n;

// ---------------------------------------------------------------------------
// Test contract source
// ---------------------------------------------------------------------------

const SOURCE = `
class BabyBearIntegration extends SmartContract {
  constructor() { super(); }

  public checkAdd(a: bigint, b: bigint, expected: bigint) {
    assert(bbFieldAdd(a, b) === expected);
  }

  public checkSub(a: bigint, b: bigint, expected: bigint) {
    assert(bbFieldSub(a, b) === expected);
  }

  public checkMul(a: bigint, b: bigint, expected: bigint) {
    assert(bbFieldMul(a, b) === expected);
  }

  public checkInv(a: bigint, expected: bigint) {
    assert(bbFieldInv(a) === expected);
  }

  public checkInvIdentity(a: bigint) {
    const inv = bbFieldInv(a);
    assert(bbFieldMul(a, inv) === 1n);
  }

  public checkAddSubRoundtrip(a: bigint, b: bigint) {
    const sum = bbFieldAdd(a, b);
    assert(bbFieldSub(sum, b) === a);
  }

  public checkMulDistributive(a: bigint, b: bigint, c: bigint) {
    const lhs = bbFieldMul(a, bbFieldAdd(b, c));
    const rhs = bbFieldAdd(bbFieldMul(a, b), bbFieldMul(a, c));
    assert(lhs === rhs);
  }

  public checkChainedOps(a: bigint, b: bigint) {
    const sum = bbFieldAdd(a, b);
    const prod = bbFieldMul(sum, a);
    const diff = bbFieldSub(prod, b);
    const inv = bbFieldInv(diff);
    assert(bbFieldMul(diff, inv) === 1n);
  }
}
`;

// ---------------------------------------------------------------------------
// Compilation tests
// ---------------------------------------------------------------------------

describe('Baby Bear integration — compilation', () => {
  it('compiles successfully', () => {
    const result = compile(SOURCE);
    expect(result.success).toBe(true);
    expect(result.artifact?.script.length).toBeGreaterThan(0);
  });

  it('produces valid artifact with methods', () => {
    const result = compile(SOURCE);
    expect(result.success).toBe(true);
    expect(result.artifact).toBeTruthy();
    expect(result.artifact!.script.length).toBeGreaterThan(100);
  });

  it('rejects wrong argument types', () => {
    const src = `
class BadTypes extends SmartContract {
  constructor() { super(); }
  public test(x: ByteString) {
    assert(bbFieldAdd(x, 1n) === 0n);
  }
}`;
    expect(compile(src).success).toBe(false);
  });

  it('rejects too few arguments', () => {
    const src = `
class BadArgs extends SmartContract {
  constructor() { super(); }
  public test(x: bigint) {
    assert(bbFieldAdd(x) === 0n);
  }
}`;
    expect(compile(src).success).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// Happy path — mathematical correctness via interpreter
// ---------------------------------------------------------------------------

describe('Baby Bear integration — happy path', () => {
  const c = () => TestContract.fromSource(SOURCE, {});

  describe('bbFieldAdd', () => {
    it('adds small values', () => {
      expect(c().call('checkAdd', { a: 3n, b: 7n, expected: 10n }).success).toBe(true);
    });

    it('wraps at field prime boundary', () => {
      expect(c().call('checkAdd', { a: BB_P - 1n, b: 1n, expected: 0n }).success).toBe(true);
    });

    it('wraps at 2x field prime', () => {
      expect(c().call('checkAdd', { a: BB_P - 1n, b: BB_P - 1n, expected: BB_P - 2n }).success).toBe(true);
    });

    it('adds zero (identity)', () => {
      expect(c().call('checkAdd', { a: 42n, b: 0n, expected: 42n }).success).toBe(true);
    });

    it('is commutative', () => {
      expect(c().call('checkAdd', { a: 100n, b: 200n, expected: 300n }).success).toBe(true);
      expect(c().call('checkAdd', { a: 200n, b: 100n, expected: 300n }).success).toBe(true);
    });
  });

  describe('bbFieldSub', () => {
    it('subtracts small values', () => {
      expect(c().call('checkSub', { a: 10n, b: 3n, expected: 7n }).success).toBe(true);
    });

    it('wraps negative to field prime', () => {
      expect(c().call('checkSub', { a: 0n, b: 1n, expected: BB_P - 1n }).success).toBe(true);
    });

    it('subtracts equal values (zero)', () => {
      expect(c().call('checkSub', { a: 42n, b: 42n, expected: 0n }).success).toBe(true);
    });

    it('subtracts zero (identity)', () => {
      expect(c().call('checkSub', { a: 99n, b: 0n, expected: 99n }).success).toBe(true);
    });
  });

  describe('bbFieldMul', () => {
    it('multiplies small values', () => {
      expect(c().call('checkMul', { a: 6n, b: 7n, expected: 42n }).success).toBe(true);
    });

    it('multiplies by zero', () => {
      expect(c().call('checkMul', { a: 12345n, b: 0n, expected: 0n }).success).toBe(true);
    });

    it('multiplies by one (identity)', () => {
      expect(c().call('checkMul', { a: 999n, b: 1n, expected: 999n }).success).toBe(true);
    });

    it('wraps large products', () => {
      // (p-1) * 2 = 2p - 2 ≡ p - 2 (mod p)
      expect(c().call('checkMul', { a: BB_P - 1n, b: 2n, expected: BB_P - 2n }).success).toBe(true);
    });

    it('(p-1) * (p-1) = 1', () => {
      // (-1) * (-1) = 1
      expect(c().call('checkMul', { a: BB_P - 1n, b: BB_P - 1n, expected: 1n }).success).toBe(true);
    });
  });

  describe('bbFieldInv', () => {
    it('inv(1) = 1', () => {
      expect(c().call('checkInv', { a: 1n, expected: 1n }).success).toBe(true);
    });

    it('inv(2) is correct', () => {
      // 2 * inv(2) = 1 mod p → inv(2) = (p+1)/2
      const inv2 = (BB_P + 1n) / 2n;
      expect(c().call('checkInv', { a: 2n, expected: inv2 }).success).toBe(true);
    });

    it('a * inv(a) = 1 for various values', () => {
      for (const a of [3n, 7n, 42n, 1000000n, BB_P - 1n]) {
        expect(c().call('checkInvIdentity', { a }).success).toBe(true);
      }
    });
  });

  describe('algebraic properties', () => {
    it('add-sub roundtrip', () => {
      expect(c().call('checkAddSubRoundtrip', { a: 42n, b: 99n }).success).toBe(true);
      expect(c().call('checkAddSubRoundtrip', { a: 0n, b: BB_P - 1n }).success).toBe(true);
    });

    it('distributive law', () => {
      expect(c().call('checkMulDistributive', { a: 5n, b: 7n, c: 11n }).success).toBe(true);
      expect(c().call('checkMulDistributive', { a: BB_P - 1n, b: 100n, c: 200n }).success).toBe(true);
    });

    it('chained operations with inverse', () => {
      expect(c().call('checkChainedOps', { a: 5n, b: 3n }).success).toBe(true);
    });
  });
});

// ---------------------------------------------------------------------------
// Unhappy path — assert failures when results don't match
// ---------------------------------------------------------------------------

describe('Baby Bear integration — unhappy path', () => {
  const c = () => TestContract.fromSource(SOURCE, {});

  it('rejects wrong addition result', () => {
    expect(c().call('checkAdd', { a: 3n, b: 7n, expected: 11n }).success).toBe(false);
  });

  it('rejects wrong subtraction result', () => {
    expect(c().call('checkSub', { a: 10n, b: 3n, expected: 8n }).success).toBe(false);
  });

  it('rejects wrong multiplication result', () => {
    expect(c().call('checkMul', { a: 6n, b: 7n, expected: 43n }).success).toBe(false);
  });

  it('rejects wrong inverse', () => {
    expect(c().call('checkInv', { a: 2n, expected: 2n }).success).toBe(false);
  });

  it('rejects non-wrapping addition (forgetting mod)', () => {
    // If someone forgets modular reduction: p-1 + 1 = p, not 0
    expect(c().call('checkAdd', { a: BB_P - 1n, b: 1n, expected: BB_P }).success).toBe(false);
  });
});
