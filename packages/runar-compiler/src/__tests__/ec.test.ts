import { describe, it, expect } from 'vitest';
import { compile } from '../index.js';
import {
  emitEcAdd,
  emitEcMul,
  emitEcMulGen,
  emitEcNegate,
  emitEcOnCurve,
  emitEcModReduce,
  emitEcEncodeCompressed,
  emitEcMakePoint,
  emitEcPointX,
  emitEcPointY,
} from '../passes/ec-codegen.js';
import type { StackOp } from '../ir/index.js';

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

// ---------------------------------------------------------------------------
// T-11: Op-count goldens for every EC emitter.
//
// The "compilation" tests above only check that EC builtins compile without
// errors; they don't pin codegen output. These goldens — copied from the
// Python peer (compilers/python/tests/codegen/test_ec.py) which in turn
// matches the Java reference EcTest — lock the exact op count for each
// emitter so codegen drift surfaces here as a localized regression rather
// than only as a cross-tier hex mismatch in the conformance harness.
//
// To update goldens after an intentional codegen change, run the Java peer
// EcTest, copy the new numbers, and update Python + this file together.
// ---------------------------------------------------------------------------

describe('EC builtins — op-count goldens (T-11)', () => {
  const goldens: Array<[name: string, fn: (emit: (op: StackOp) => void) => void, expected: number]> = [
    ['ecAdd',              emitEcAdd,                8078],
    ['ecMul',              emitEcMul,               63828],
    ['ecMulGen',           emitEcMulGen,            63830],
    ['ecNegate',           emitEcNegate,              945],
    ['ecOnCurve',          emitEcOnCurve,             520],
    ['ecModReduce',        emitEcModReduce,             8],
    ['ecEncodeCompressed', emitEcEncodeCompressed,     14],
    ['ecMakePoint',        emitEcMakePoint,           467],
    ['ecPointX',           emitEcPointX,              233],
    ['ecPointY',           emitEcPointY,              234],
  ];

  for (const [name, fn, expected] of goldens) {
    it(`${name} op count is ${expected}`, () => {
      const ops: StackOp[] = [];
      fn((op: StackOp) => ops.push(op));
      expect(ops.length).toBe(expected);
    });
  }

  it('ecModReduce emits the exact 8-op shape (OP_2DUP, OP_MOD, rot, drop, over, OP_ADD, swap, OP_MOD)', () => {
    const ops: StackOp[] = [];
    emitEcModReduce((op: StackOp) => ops.push(op));
    expect(ops).toHaveLength(8);
    // Representative byte assertion: the first emitted op must be OP_2DUP.
    // Loose-typed because StackOp variants differ across opcode/stack ops.
    const first: any = ops[0];
    expect(first.op === 'opcode' && first.code === 'OP_2DUP').toBe(true);
    const last: any = ops[7];
    expect(last.op === 'opcode' && last.code === 'OP_MOD').toBe(true);
  });
});
