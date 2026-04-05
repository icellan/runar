import { describe, it, expect } from 'vitest';
import { compile } from '../index.js';

// ---------------------------------------------------------------------------
// Test sources
// ---------------------------------------------------------------------------

const BB_FIELD_ADD_SOURCE = `
class BBAddTest extends SmartContract {
  constructor() { super(); }

  public verifyAdd(a: bigint, b: bigint, expected: bigint) {
    const result = bbFieldAdd(a, b);
    assert(result === expected);
  }
}
`;

const BB_FIELD_SUB_SOURCE = `
class BBSubTest extends SmartContract {
  constructor() { super(); }

  public verifySub(a: bigint, b: bigint, expected: bigint) {
    const result = bbFieldSub(a, b);
    assert(result === expected);
  }
}
`;

const BB_FIELD_MUL_SOURCE = `
class BBMulTest extends SmartContract {
  constructor() { super(); }

  public verifyMul(a: bigint, b: bigint, expected: bigint) {
    const result = bbFieldMul(a, b);
    assert(result === expected);
  }
}
`;

const BB_FIELD_INV_SOURCE = `
class BBInvTest extends SmartContract {
  constructor() { super(); }

  public verifyInv(a: bigint, expected: bigint) {
    const result = bbFieldInv(a);
    assert(result === expected);
  }
}
`;

const BB_COMBINED_SOURCE = `
class BBCombinedTest extends SmartContract {
  constructor() { super(); }

  public verifyIdentity(a: bigint) {
    const inv = bbFieldInv(a);
    const product = bbFieldMul(a, inv);
    assert(product === 1n);
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

describe('Baby Bear field arithmetic — compilation', () => {
  it('compiles bbFieldAdd usage', () => {
    expectNoErrors(compile(BB_FIELD_ADD_SOURCE));
  });

  it('compiles bbFieldSub usage', () => {
    expectNoErrors(compile(BB_FIELD_SUB_SOURCE));
  });

  it('compiles bbFieldMul usage', () => {
    expectNoErrors(compile(BB_FIELD_MUL_SOURCE));
  });

  it('compiles bbFieldInv usage', () => {
    expectNoErrors(compile(BB_FIELD_INV_SOURCE));
  });

  it('compiles combined Baby Bear operations', () => {
    expectNoErrors(compile(BB_COMBINED_SOURCE));
  });

  it('produces non-empty script', () => {
    const result = compile(BB_FIELD_ADD_SOURCE);
    expectNoErrors(result);
    expect(result.artifact?.script.length).toBeGreaterThan(0);
  });
});

describe('Baby Bear field arithmetic — type checking', () => {
  it('rejects bbFieldAdd with wrong argument type', () => {
    const src = `
class Bad extends SmartContract {
  constructor() { super(); }
  public test(x: ByteString) {
    const r = bbFieldAdd(x, 1n);
    assert(r === 0n);
  }
}
`;
    const result = compile(src);
    expect(result.success).toBe(false);
  });

  it('rejects bbFieldInv with wrong argument type', () => {
    const src = `
class Bad extends SmartContract {
  constructor() { super(); }
  public test(x: ByteString) {
    const r = bbFieldInv(x);
    assert(r === 0n);
  }
}
`;
    const result = compile(src);
    expect(result.success).toBe(false);
  });
});
