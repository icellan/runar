import { describe, it, expect } from 'vitest';
import {
  emitMethod, emitBn254G1OnCurve, emitBn254G1Negate, emitBn254G1Add,
} from 'runar-compiler';
import type { StackOp } from 'runar-ir-schema';
import { ScriptVM } from '../index.js';

/**
 * R-141 — `bn254G1OnCurve` had no coordinate-canonicity guard, and
 * `bn254DecomposePoint` had no OP_SIZE-64 gate.
 *
 * Every other curve family in the repo carries both: `emitEcOnCurve` (GAP-301
 * for the coordinates, CL-BUG-095 for the width), its a = -3 P-256/P-384 twin,
 * and — since R-117 — an aborting coordinate gate on the EC value builtins. The
 * BN254 body was decompose → y² → x³+3 → OP_EQUAL, with nothing in front of it.
 * Measured on @bsv/sdk's `Spend` before this commit, with the EIP-197 generator
 * G = (1, 2):
 *
 *     bn254G1OnCurve(G)              -> 1
 *     bn254G1OnCurve((1+p) ‖ 2)      -> 1     ← a non-canonical x certified
 *     bn254G1OnCurve(1 ‖ (2+p))      -> 1     ← and a non-canonical y
 *     bn254G1OnCurve(G ‖ 0xff)       -> 1     ← 65 bytes, surplus discarded
 *     bn254G1OnCurve(1 ‖ 3)          -> 0     (correctly off-curve)
 *
 * BN254's field prime is ~2^253.6, so `x + p < 2^256` for EVERY x < p. On
 * secp256k1 the alias only fits for x < 2^32 + 977; here it exists for every
 * point on the curve, so the predicate said "yes" to an unbounded family of
 * encodings of each point.
 *
 * WHAT IS **NOT** BROKEN, measured rather than assumed: BN254's adder is not
 * fooled into a wrong answer the way secp256k1's was under R-117.
 * `bn254G1Add(G, (1+p)‖2)` returned the correct 2G, because
 * `bn254G1InfinityFlag` reduces before it compares where `affineAdd`'s two
 * selectors did not. The value builtins are therefore gated for a different
 * reason: `bn254ComposePoint`'s own contract says callers must supply [0, p-1]
 * and that it does not check, and `bn254G1Negate` handed it the RAW decomposed
 * x — a value builtin PRODUCING a blob that is not a point.
 *
 * THE SPLIT follows R-117 exactly: the predicate CLAMPS and FLAGS so it stays
 * total and answers false; the value builtins OP_VERIFY; and the WIDTH check
 * goes inside the shared decompose helper, where every consumer inherits it —
 * the placement CL-BUG-095 already chose for `ecDecomposePoint`.
 *
 * Everything below is EXECUTED on @bsv/sdk's `Spend`.
 */

const BN254_P =
  0x30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd47n;
const GX = 1n;
const GY = 2n;

const be32 = (v: bigint) => {
  const h = v.toString(16).padStart(64, '0');
  return Uint8Array.from(Buffer.from(h, 'hex'));
};
const blob = (x: bigint, y: bigint) => {
  const out = new Uint8Array(64);
  out.set(be32(x), 0);
  out.set(be32(y), 32);
  return out;
};
const push = (b: Uint8Array) => ({ op: 'push', value: b }) as StackOp;

function runOps(ops: StackOp[]) {
  const { scriptHex } = emitMethod({ name: 't', ops } as never) as { scriptHex: string };
  return new ScriptVM().executeHex(scriptHex);
}

/** onCurve must be TOTAL: it answers true or false, and never aborts. */
function onCurve(b: Uint8Array): { value: boolean; aborted: boolean } {
  const ops: StackOp[] = [push(b)];
  emitBn254G1OnCurve((op) => ops.push(op));
  const r = runOps(ops);
  if (r.error !== undefined) return { value: false, aborted: true };
  return { value: r.success, aborted: false };
}

/** A value builtin: true if the script ran to completion. */
function valueRuns(emitFn: (e: (op: StackOp) => void) => void, ...bs: Uint8Array[]) {
  const ops: StackOp[] = bs.map(push);
  emitFn((op) => ops.push(op));
  ops.push({ op: 'drop' } as StackOp, { op: 'opcode', code: 'OP_1' } as StackOp);
  return runOps(ops).error === undefined;
}

const G = blob(GX, GY);

describe('R-141 bn254G1OnCurve coordinate canonicity', () => {
  it('the alias really fits 32 bytes — otherwise this file proves nothing', () => {
    expect(GX + BN254_P < 1n << 256n).toBe(true);
    expect(GY + BN254_P < 1n << 256n).toBe(true);
    // And it holds for the whole field, not just the generator.
    expect((BN254_P - 1n) + BN254_P < 1n << 256n).toBe(true);
  });

  it('CONTROL — the real generator still certifies', () => {
    const r = onCurve(G);
    expect(r.aborted).toBe(false);
    expect(r.value).toBe(true);
  });

  it('ASSERTION — a non-canonical coordinate returns FALSE (and does not abort)', () => {
    for (const [name, b] of [
      ['(x+p, y)', blob(GX + BN254_P, GY)],
      ['(x, y+p)', blob(GX, GY + BN254_P)],
      ['(x+p, y+p)', blob(GX + BN254_P, GY + BN254_P)],
      ['(p, y)', blob(BN254_P, GY)],
      ['(x, p)', blob(GX, BN254_P)],
    ] as const) {
      const r = onCurve(b);
      expect(r.value, `onCurve${name}`).toBe(false);
      expect(r.aborted, `onCurve${name} must answer, not abort`).toBe(false);
    }
  });

  it('ASSERTION — a wrong-width blob returns FALSE (and does not abort)', () => {
    const cases: Array<[string, Uint8Array]> = [
      ['65 bytes', Uint8Array.from([...G, 0xff])],
      ['66 bytes', Uint8Array.from([...G, 0, 0])],
      ['63 bytes', G.subarray(0, 63)],
      ['32 bytes', G.subarray(0, 32)],
      ['empty', new Uint8Array(0)],
    ];
    for (const [name, b] of cases) {
      const r = onCurve(b);
      expect(r.value, `onCurve(${name})`).toBe(false);
      expect(r.aborted, `onCurve(${name}) must answer, not abort`).toBe(false);
    }
  });

  it('BOUNDARY — p-1 is a legal coordinate (the curve equation decides)', () => {
    expect(onCurve(blob(BN254_P - 1n, 0n)).aborted).toBe(false);
    expect(onCurve(blob(0n, BN254_P - 1n)).aborted).toBe(false);
    // The all-zero blob — the value builtins' encoding of infinity — stays a
    // legal input and answers false: 0 != 0^3 + 3.
    const O = new Uint8Array(64);
    expect(onCurve(O).aborted).toBe(false);
    expect(onCurve(O).value).toBe(false);
  });

  it('a genuinely off-curve point is still false, not aborted', () => {
    const r = onCurve(blob(1n, 3n));
    expect(r.aborted).toBe(false);
    expect(r.value).toBe(false);
  });
});

describe('R-141 the BN254 value builtins abort on a non-canonical point', () => {
  const alias = blob(GX + BN254_P, GY);
  const g65 = Uint8Array.from([...G, 0xff]);

  it('CONTROL — negate(G) and add(G, G) still run', () => {
    expect(valueRuns(emitBn254G1Negate, G)).toBe(true);
    expect(valueRuns(emitBn254G1Add, G, G)).toBe(true);
  });

  it('CONTROL — add(G, G) still produces the RIGHT 2G, computed off-chain', () => {
    // 2P on y^2 = x^3 + 3 over F_p, with bigint arithmetic in this file.
    const inv = (a: bigint) => {
      let [old_r, r] = [((a % BN254_P) + BN254_P) % BN254_P, BN254_P];
      let [old_s, s] = [1n, 0n];
      while (r !== 0n) { const q = old_r / r; [old_r, r] = [r, old_r - q * r]; [old_s, s] = [s, old_s - q * s]; }
      return ((old_s % BN254_P) + BN254_P) % BN254_P;
    };
    const lam = (3n * GX * GX % BN254_P) * inv(2n * GY) % BN254_P;
    const rx = ((lam * lam - 2n * GX) % BN254_P + BN254_P) % BN254_P;
    const ry = ((lam * (GX - rx) - GY) % BN254_P + BN254_P) % BN254_P;

    const ops: StackOp[] = [push(G), push(G)];
    emitBn254G1Add((op) => ops.push(op));
    ops.push(push(blob(rx, ry)), { op: 'opcode', code: 'OP_EQUAL' } as StackOp);
    const r = runOps(ops);
    expect(r.error).toBeUndefined();
    expect(r.success).toBe(true);
  });

  it('ASSERTION — negate REJECTS a non-canonical x (it used to re-emit it)', () => {
    expect(valueRuns(emitBn254G1Negate, alias)).toBe(false);
    expect(valueRuns(emitBn254G1Negate, g65)).toBe(false);
  });

  it('ASSERTION — add REJECTS a non-canonical operand on either side', () => {
    expect(valueRuns(emitBn254G1Add, G, alias)).toBe(false);
    expect(valueRuns(emitBn254G1Add, alias, G)).toBe(false);
    expect(valueRuns(emitBn254G1Add, G, g65)).toBe(false);
    expect(valueRuns(emitBn254G1Add, g65, G)).toBe(false);
  });

  it('BOUNDARY — a coordinate of p-1 is accepted by the value builtins, p is not', () => {
    expect(valueRuns(emitBn254G1Negate, blob(BN254_P - 1n, 1n))).toBe(true);
    expect(valueRuns(emitBn254G1Negate, blob(BN254_P, 1n))).toBe(false);
    expect(valueRuns(emitBn254G1Negate, blob(1n, BN254_P - 1n))).toBe(true);
    expect(valueRuns(emitBn254G1Negate, blob(1n, BN254_P))).toBe(false);
  });
});
