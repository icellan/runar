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
// matches the Java reference EcTest — lock the exact size of each emitter's
// op TREE (`if` bodies included, see countOpTree) so codegen drift surfaces
// here as a localized regression rather than only as a cross-tier hex
// mismatch in the conformance harness.
//
// To update goldens after an intentional codegen change, run the Java peer
// EcTest, copy the new numbers, and update Python + this file together.
//
// WHY THE ZIG GOLDENS DIFFER (~8%) AND THAT IS NOT A BUG.
// These are OP counts, not bytes. For the ladder's `k' = k + 3n` step this file
// (and the Go / Rust / Python / Ruby / Java peers) emit `push n; OP_ADD` three
// times and let the peephole optimizer fold them — see the 4-op chain rule
// `PUSH(a), ADD, PUSH(b), ADD -> PUSH(a+b), ADD` in
// packages/runar-compiler/src/optimizer/peephole.ts. Zig pre-computes the sum
// and emits `push 3n; OP_ADD` directly — see the `p256_3n_be` / `p384_3n_be`
// constants and the "matches Go peephole output" comments in
// compilers/zig/src/passes/helpers/nist_ec_emitters.zig. Both reach the SAME
// post-peephole hex, which is what conformance compares; only the pre-peephole
// op count differs. Do not "reconcile" the two sets of goldens — they are
// measuring different points in the pipeline.
// ---------------------------------------------------------------------------

/**
 * Total number of StackOps in `ops`, INCLUDING the bodies of `if` ops.
 *
 * A flat `ops.length` cannot see inside a branch, so any emitter whose work
 * sits in an `if` body — the scalar ladders emit 257 / 385 conditional
 * additions, WOTS+ and SLH-DSA are almost entirely conditional — reports a
 * count that barely moves no matter what the branch contains. Adding +1.3 KB
 * of script inside the ladder's last step left the `p256Mul` / `p384Mul`
 * goldens byte-identical. Recursing is what makes the golden a gate.
 */
function countOpTree(ops: StackOp[]): number {
  let total = 0;
  for (const op of ops) {
    total++;
    if (op.op === 'if') {
      total += countOpTree(op.then);
      total += countOpTree(op.else ?? []);
    }
  }
  return total;
}

describe('EC builtins — op-count goldens (T-11)', () => {
  const goldens: Array<[name: string, fn: (emit: (op: StackOp) => void) => void, expected: number]> = [
    // 8078 -> 8202 (+124): affineAdd now selects the tangent numerator and
    // denominator so ecAdd can DOUBLE a point. One fieldInv still, so the cost
    // is +1.5%, not +100%.
    // 8202 -> 8223 (+21): and it now detects P == -Q (px == qx but py != qy)
    // and forces the all-zero point, instead of taking the tangent and
    // returning an on-curve, plausible, WRONG 2P. +21 bytes of script.
    //
    // R-052 / CL-BUG-095, the Point WIDTH gate. A `Point` is 64 bytes by
    // definition and nothing checked it, so a surplus byte was split off and
    // silently dropped: `ecOnCurve(G || 0xff)` returned TRUE and
    // `ecEncodeCompressed` took its parity bit from the caller's extra byte.
    // The deltas below are all structural, which is what makes them portable
    // to the six other tiers byte-for-byte:
    //
    //   +3  per decomposePoint call site — OP_SIZE, push 64, OP_NUMEQUALVERIFY.
    //       ecAdd decomposes TWICE, hence +6; ecMul / ecMulGen / ecNegate once.
    //   +15 ecOnCurve — 9 for the clamp-and-flag gate (it must stay a PREDICATE
    //       and answer `false`, not abort, or `if (ecOnCurve(p))` stops being
    //       writable), +3 for the decomposePoint gate, +1 for the extra
    //       OP_BOOLAND folding `_len_ok` in, +2 for rolling the two flags up.
    //   +3  ecPointX / ecPointY.
    //
    // ecEncodeCompressed stays at 16 and that is NOT an oversight: the gate
    // adds 3 ops while the fixed-offset parity read (push 31, OP_SPLIT, OP_NIP)
    // replaces a 6-op OP_SIZE/OP_SUB/OP_SPLIT/OP_SWAP/OP_DROP sequence with 3.
    // Net zero ops, different bytes.
    //
    // 8229 -> 8279 (+50): R-053 / CL-BUG-096, the infinity-operand case. The
    // adder had no case for the point at infinity even though this codegen
    // MANUFACTURES that value (ecMul(P, k) for k = 0 mod n, affineAdd's own
    // P + (-P) masking, and the ec-mul-zero / ec-add-negate-cancel rewrites),
    // so ecAdd(G, O) returned an off-curve blob from a SUCCEEDING script while
    // the always-on optimizer rewrote the same expression to the identity.
    // The +50 is the branch-free three-way select (pinf / qinf / usep / useq /
    // user plus the two three-term coordinate selects); it SUBSUMES the two
    // standalone `notinf` OP_MULs it replaces, which is why it is +50 and not
    // +52. ONLY the adders move: ecMul / ecMulGen / ecNegate / ecOnCurve /
    // ecPointX / ecPointY / ecEncodeCompressed are all +0, because the select
    // lives entirely inside affineAdd.
    ['ecAdd',              emitEcAdd,                8279],
    ['ecMul',              emitEcMul,              130518],
    ['ecMulGen',           emitEcMulGen,           130520],
    ['ecNegate',           emitEcNegate,              948],
    ['ecOnCurve',          emitEcOnCurve,             548],
    ['ecModReduce',        emitEcModReduce,             8],
    ['ecEncodeCompressed', emitEcEncodeCompressed,     16],
    ['ecMakePoint',        emitEcMakePoint,           467],
    ['ecPointX',           emitEcPointX,              236],
    ['ecPointY',           emitEcPointY,              237],
  ];

  for (const [name, fn, expected] of goldens) {
    it(`${name} op count is ${expected}`, () => {
      const ops: StackOp[] = [];
      fn((op: StackOp) => ops.push(op));
      expect(countOpTree(ops)).toBe(expected);
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
