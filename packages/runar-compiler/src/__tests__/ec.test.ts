import { describe, it, expect } from 'vitest';
import { compile } from '../index.js';

// ---------------------------------------------------------------------------
// Test sources
// ---------------------------------------------------------------------------

const EC_POINT_OPS_SOURCE = `
class EcPointOps extends SmartContract {
  readonly storedPoint: Point;

  constructor(storedPoint: Point) {
    super(storedPoint);
    this.storedPoint = storedPoint;
  }

  public verifyX(expectedX: bigint) {
    const x = ecPointX(this.storedPoint);
    assert(x === expectedX);
  }

  public verifyY(expectedY: bigint) {
    const y = ecPointY(this.storedPoint);
    assert(y === expectedY);
  }

  public verifyOnCurve() {
    assert(ecOnCurve(this.storedPoint));
  }
}
`;

const EC_MOD_REDUCE_SOURCE = `
class EcModReduceTest extends SmartContract {
  readonly modulus: bigint;

  constructor(modulus: bigint) {
    super(modulus);
    this.modulus = modulus;
  }

  public verifyReduce(value: bigint, expected: bigint) {
    const result = ecModReduce(value, this.modulus);
    assert(result === expected);
  }
}
`;

const EC_MAKE_POINT_SOURCE = `
class EcMakePointTest extends SmartContract {
  readonly expected: Point;

  constructor(expected: Point) {
    super(expected);
    this.expected = expected;
  }

  public verifyMakePoint(x: bigint, y: bigint) {
    const pt = ecMakePoint(x, y);
    assert(pt === this.expected);
  }
}
`;

const EC_NEGATE_SOURCE = `
class EcNegateTest extends SmartContract {
  readonly pt: Point;

  constructor(pt: Point) {
    super(pt);
    this.pt = pt;
  }

  public verifyNegate(expectedY: bigint) {
    const neg = ecNegate(this.pt);
    const y = ecPointY(neg);
    assert(y === expectedY);
  }
}
`;

const EC_ADD_SOURCE = `
class EcAddTest extends SmartContract {
  readonly a: Point;
  readonly b: Point;

  constructor(a: Point, b: Point) {
    super(a, b);
    this.a = a;
    this.b = b;
  }

  public verifyAddX(expectedX: bigint) {
    const result = ecAdd(this.a, this.b);
    const rx = ecPointX(result);
    assert(rx === expectedX);
  }
}
`;

const EC_ENCODE_COMPRESSED_SOURCE = `
class EcEncodeTest extends SmartContract {
  readonly pt: Point;

  constructor(pt: Point) {
    super(pt);
    this.pt = pt;
  }

  public verifyCompressed(expected: ByteString) {
    const compressed = ecEncodeCompressed(this.pt);
    assert(compressed === expected);
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

describe('EC builtins — compilation', () => {
  it('compiles ecPointX / ecPointY usage', () => {
    expectNoErrors(compile(EC_POINT_OPS_SOURCE));
  });

  it('compiles ecModReduce usage', () => {
    expectNoErrors(compile(EC_MOD_REDUCE_SOURCE));
  });

  it('compiles ecMakePoint usage', () => {
    expectNoErrors(compile(EC_MAKE_POINT_SOURCE));
  });

  it('compiles ecNegate usage', () => {
    expectNoErrors(compile(EC_NEGATE_SOURCE));
  });

  it('compiles ecAdd usage', () => {
    expectNoErrors(compile(EC_ADD_SOURCE));
  });

  it('compiles ecEncodeCompressed usage', () => {
    expectNoErrors(compile(EC_ENCODE_COMPRESSED_SOURCE));
  });
});

describe('EC builtins — type checking', () => {
  it('rejects ecPointX with wrong argument type', () => {
    const src = `
class Bad extends SmartContract {
  constructor() { super(); }
  public test(x: bigint) {
    const r = ecPointX(x);
    assert(r === 0n);
  }
}`;
    const result = compile(src);
    const errors = result.diagnostics.filter(d => d.severity === 'error');
    expect(errors.length).toBeGreaterThan(0);
  });

  it('rejects ecModReduce with wrong number of args', () => {
    const src = `
class Bad extends SmartContract {
  constructor() { super(); }
  public test(x: bigint) {
    const r = ecModReduce(x);
    assert(r === 0n);
  }
}`;
    const result = compile(src);
    const errors = result.diagnostics.filter(d => d.severity === 'error');
    expect(errors.length).toBeGreaterThan(0);
  });
});
