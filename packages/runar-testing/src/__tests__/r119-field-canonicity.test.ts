import { describe, it, expect } from 'vitest';
import {
  emitMethod,
  emitBBFieldAdd, emitBBFieldSub, emitBBFieldMul, emitBBFieldInv,
  emitBBExt4Mul0, emitBBExt4Inv0,
  emitKBFieldAdd, emitKBFieldSub, emitKBFieldMul, emitKBFieldInv,
  emitKBExt4Mul0, emitKBExt4Inv0,
} from 'runar-compiler';
import type { StackOp } from 'runar-ir-schema';
import { ScriptVM, TestContract } from '../index.js';

/**
 * R-119 — no canonicity or range check on ANY witness-supplied field element.
 *
 * `babybear-codegen.ts` and `koalabear-codegen.ts` (and their four ports)
 * emitted only OP_ADD / OP_SUB / OP_MUL / OP_MOD plus shifts and alt-stack
 * traffic. The OP_LESSTHAN / OP_WITHIN / OP_GREATERTHANOREQUAL count in both
 * files was ZERO. Every operand of the four scalar builtins and the eight ext4
 * entry points is an unlock argument, so a witness element >= p, or negative,
 * flowed into the arithmetic unchallenged.
 *
 * WHAT REPRODUCED, AND WHAT DID NOT — the finding names two shapes, and they
 * are not equally broken.
 *
 *   `v + p`: NOT broken. Every emitter reduces its result mod p, so measured on
 *   @bsv/sdk's Spend before this gate, `bbFieldAdd(5+p, 0)` and
 *   `bbFieldAdd(5, 0)` both returned 5, and `bbFieldInv(3+p)` equalled
 *   `bbFieldInv(3)`. On the finding's own disjunction ("rejected, or the same
 *   verdict as v at every equality site") the second disjunct already held.
 *
 *   NEGATIVE: broken. `fieldAdd` and `fieldMul` reduce with a BARE OP_MOD, on
 *   the documented assumption that both operands are already in [0, p-1]
 *   ("Sum of two values in [0, p-1] is always non-negative, so simple OP_MOD
 *   suffices"). OP_MOD takes the sign of the DIVIDEND. Measured:
 *
 *       bbFieldAdd(-1, 0) -> -1          bbFieldAdd(p-1, 0) -> 2013265920
 *       bbFieldMul(-1, 1) -> -1          bbFieldInv(-1)     -> -1
 *       kbExt4Mul0((0,-1,0,0),(0,0,0,1)) -> -3   canonical -> 2130706430
 *
 *   The builtin returned a number congruent to the right answer that is NOT the
 *   right answer's script encoding. Script equality is numeric, so the escaped
 *   spelling breaks every downstream `===`, every OP_NUM2BIN of the element,
 *   and the closure property the ext4 / Poseidon2 code relies on when it feeds
 *   one field builtin into the next.
 *
 * THE GATE REJECTS rather than reduces, and sits on the INPUT: a reduce would
 * leave `v` and `v + p` as two accepted spellings of one element, which is the
 * aliasing this finding is about. Gating the input makes the builtins
 * canonical-in / canonical-out, so the gate is idempotent under composition.
 * Aborting form, because these are VALUE builtins — the split R-117 drew for
 * the EC value builtins and CL-BUG-095 set for the Point width.
 *
 * Everything below is EXECUTED on @bsv/sdk's `Spend`.
 */

const BB_P = 2013265921n;
const KB_P = 2130706433n;

function run(pushes: StackOp[], emitFn: (e: (op: StackOp) => void) => void) {
  const ops: StackOp[] = [...pushes];
  emitFn((op) => ops.push(op));
  // Leave a truthy top so `success` means "ran to completion", and read the
  // value through an explicit comparison in the callers that need one.
  const { scriptHex } = emitMethod({ name: 't', ops } as never) as { scriptHex: string };
  const r = new ScriptVM().executeHex(scriptHex);
  return { rejected: r.error !== undefined, stack: r.stack };
}

const num = (n: bigint) => ({ op: 'push', value: n }) as StackOp;

/** Decode a script number (little-endian, sign-magnitude) back to a bigint. */
function fromScriptNum(b: Uint8Array): bigint {
  if (b.length === 0) return 0n;
  const rev = Array.from(b).reverse();
  const neg = (rev[0]! & 0x80) !== 0;
  rev[0] = rev[0]! & 0x7f;
  let v = 0n;
  for (const byte of rev) v = (v << 8n) | BigInt(byte);
  return neg ? -v : v;
}

function result(pushes: StackOp[], emitFn: (e: (op: StackOp) => void) => void): bigint | null {
  const r = run(pushes, emitFn);
  if (r.rejected) return null;
  return fromScriptNum(r.stack[r.stack.length - 1]!);
}

const FIELDS = [
  {
    name: 'babybear', p: BB_P,
    add: emitBBFieldAdd, sub: emitBBFieldSub, mul: emitBBFieldMul, inv: emitBBFieldInv,
    ext4Mul: emitBBExt4Mul0, ext4Inv: emitBBExt4Inv0,
  },
  {
    name: 'koalabear', p: KB_P,
    add: emitKBFieldAdd, sub: emitKBFieldSub, mul: emitKBFieldMul, inv: emitKBFieldInv,
    ext4Mul: emitKBExt4Mul0, ext4Inv: emitKBExt4Inv0,
  },
] as const;

describe.each(FIELDS)('R-119 witness field elements are gated — $name', (F) => {
  const p = F.p;
  const pm1 = p - 1n;

  it('ASSERTION — an operand >= p is REJECTED on every scalar builtin', () => {
    for (const bad of [p, p + 5n, 2n * p]) {
      expect(run([num(bad), num(1n)], F.add).rejected, `add(${bad}, 1)`).toBe(true);
      expect(run([num(1n), num(bad)], F.add).rejected, `add(1, ${bad})`).toBe(true);
      expect(run([num(bad), num(1n)], F.sub).rejected).toBe(true);
      expect(run([num(1n), num(bad)], F.sub).rejected).toBe(true);
      expect(run([num(bad), num(1n)], F.mul).rejected).toBe(true);
      expect(run([num(1n), num(bad)], F.mul).rejected).toBe(true);
      expect(run([num(bad)], F.inv).rejected).toBe(true);
    }
  });

  it('ASSERTION — a NEGATIVE operand is REJECTED on every scalar builtin', () => {
    for (const bad of [-1n, -p, -(p + 1n)]) {
      expect(run([num(bad), num(0n)], F.add).rejected, `add(${bad}, 0)`).toBe(true);
      expect(run([num(0n), num(bad)], F.add).rejected).toBe(true);
      expect(run([num(bad), num(0n)], F.sub).rejected).toBe(true);
      expect(run([num(0n), num(bad)], F.sub).rejected).toBe(true);
      expect(run([num(bad), num(1n)], F.mul).rejected).toBe(true);
      expect(run([num(1n), num(bad)], F.mul).rejected).toBe(true);
      expect(run([num(bad)], F.inv).rejected).toBe(true);
    }
  });

  it('ASSERTION — each of the eight ext4Mul operands is gated independently', () => {
    const ok8 = [1n, 2n, 3n, 4n, 5n, 6n, 7n, pm1];
    expect(run(ok8.map(num), F.ext4Mul).rejected, 'canonical control').toBe(false);
    for (let i = 0; i < 8; i++) {
      for (const bad of [ok8[i]! + p, -1n, p]) {
        const v = [...ok8]; v[i] = bad;
        expect(run(v.map(num), F.ext4Mul).rejected, `operand ${i} = ${bad}`).toBe(true);
      }
    }
  });

  it('ASSERTION — each of the four ext4Inv operands is gated independently', () => {
    const ok4 = [1n, 2n, 3n, pm1];
    expect(run(ok4.map(num), F.ext4Inv).rejected, 'canonical control').toBe(false);
    for (let i = 0; i < 4; i++) {
      for (const bad of [ok4[i]! + p, -1n, p]) {
        const v = [...ok4]; v[i] = bad;
        expect(run(v.map(num), F.ext4Inv).rejected, `operand ${i} = ${bad}`).toBe(true);
      }
    }
  });

  // -------------------------------------------------------------------------
  // Controls. Each must STAY green; an over-strict gate reddens them, and each
  // accept is graded against a value computed here rather than by the compiler.
  // -------------------------------------------------------------------------

  it('CONTROL — every legal pair still computes the RIGHT value', () => {
    const mod = (x: bigint) => ((x % p) + p) % p;
    for (const [a, b] of [[0n, 0n], [0n, pm1], [pm1, 0n], [pm1, pm1], [5n, 7n], [1n, pm1]] as const) {
      expect(result([num(a), num(b)], F.add), `add(${a},${b})`).toBe(mod(a + b));
      expect(result([num(a), num(b)], F.sub), `sub(${a},${b})`).toBe(mod(a - b));
      expect(result([num(a), num(b)], F.mul), `mul(${a},${b})`).toBe(mod(a * b));
    }
  });

  it('CONTROL — inv still inverts, and inv(0) stays 0', () => {
    const powMod = (b: bigint, e: bigint) => {
      let r = 1n, base = b % p, exp = e;
      while (exp > 0n) { if (exp & 1n) r = (r * base) % p; base = (base * base) % p; exp >>= 1n; }
      return r;
    };
    for (const a of [1n, 3n, 12345n, pm1]) {
      expect(result([num(a)], F.inv), `inv(${a})`).toBe(powMod(a, p - 2n));
    }
    expect(result([num(0n)], F.inv)).toBe(0n);
  });

  it('BOUNDARY — p-1 is accepted and p is not, on both operands', () => {
    expect(run([num(pm1), num(pm1)], F.add).rejected).toBe(false);
    expect(run([num(p), num(0n)], F.add).rejected).toBe(true);
    expect(run([num(0n), num(p)], F.add).rejected).toBe(true);
    expect(run([num(pm1)], F.inv).rejected).toBe(false);
    expect(run([num(p)], F.inv).rejected).toBe(true);
  });

  it('CLOSURE — a gated builtin returns a value the next gate accepts', () => {
    // sub(add(a, b), b) === a in ONE script: the inner result is fed straight
    // into the outer builtin's gate. If the output ever escaped the field this
    // aborts, which is the property that makes gating the INPUT sufficient.
    for (const [a, b] of [[pm1, pm1], [0n, pm1], [5n, 7n]] as const) {
      const ops: StackOp[] = [num(a), num(b)];
      F.add((op) => ops.push(op));
      ops.push(num(b));
      F.sub((op) => ops.push(op));
      ops.push(num(a), { op: 'opcode', code: 'OP_NUMEQUAL' } as StackOp);
      const { scriptHex } = emitMethod({ name: 't', ops } as never) as { scriptHex: string };
      const r = new ScriptVM().executeHex(scriptHex);
      expect(r.error, `sub(add(${a},${b}),${b})`).toBeUndefined();
      expect(r.success).toBe(true);
    }
  });
});

/**
 * The reference interpreter must refuse on the SAME bound as the script — the
 * three-places rule `pow` (R-169) established, minus the folder (which does not
 * fold these builtins). Without it, the source-vs-script differential oracle
 * disagrees on every non-canonical witness and `TestContract` keeps telling an
 * author a spend works that the chain rejects.
 *
 * KoalaBear has no interpreter case at all — `kbFieldMul` falls through to
 * "Unknown function" — so only BabyBear is checked here.
 */
describe('R-119 the interpreter refuses what the script refuses', () => {
  const SRC = `
class BBDomain extends SmartContract {
  readonly expected: bigint;
  constructor(expected: bigint) { super(expected); this.expected = expected; }
  public verify(a: bigint, b: bigint) {
    assert(bbFieldMul(a, b) === this.expected);
  }
}
`;
  const c = () => TestContract.fromSource(SRC, { expected: 35n }, 'BBDomain.runar.ts');

  it('accepts a canonical pair and refuses >= p and negative', () => {
    const k = c();
    expect(k.call('verify', { a: 5n, b: 7n }).success).toBe(true);
    for (const bad of [BB_P, BB_P + 5n, -1n]) {
      const r = k.call('verify', { a: bad, b: 7n });
      expect(r.success, `a = ${bad}`).toBe(false);
      expect(r.error).toMatch(/not a BabyBear field element/);
    }
  });

  it('gates the second operand too', () => {
    const r = c().call('verify', { a: 5n, b: -1n });
    expect(r.success).toBe(false);
    expect(r.error).toMatch(/argument 1/);
  });
});
