import { describe, it, expect } from 'vitest';
import {
  emitMethod, emitEcAdd, emitEcNegate, emitEcOnCurve,
  emitP256Add, emitP256Negate, emitP256OnCurve,
  emitP384Add, emitP384Negate, emitP384OnCurve,
} from 'runar-compiler';
import type { StackOp } from 'runar-ir-schema';
import { ScriptVM, ScriptExecutionContract } from '../index.js';

/**
 * CL-BUG-096 / R-053 — `ecAdd(P, O)` returned an off-curve blob while the
 * always-on EC optimizer rewrote the same expression as the identity.
 *
 * The group law has an identity element. This codegen has a REPRESENTATION for
 * it — the all-zero blob — and manufactures that value itself, from three
 * different places:
 *
 *   - `ecMul(P, k)` for any k ≡ 0 (mod n) (the ladder's Z3 is 0 and the Fermat
 *     inverse in jacobianToAffine turns the whole point to zeros);
 *   - `affineAdd` itself, which returns the all-zero blob for P + (−P);
 *   - the `ec-mul-zero` / `ec-add-negate-cancel` rewrites in
 *     optimizer/ec-rules.json, which fold to the INFINITY constant.
 *
 * So O is a REACHABLE RUNTIME VALUE, and `affineAdd` had no case for it. Fed
 * (G, O) it took the chord path with s = Gy/Gx and returned
 * cf88213f…169139c6 — not G, not on the curve, from a script that SUCCEEDED.
 *
 * What made it a v1 blocker rather than a curiosity is the second half. The
 * optimizer's `ec-add-identity-right` / `-left` rules already believe
 * `P + O = P`, and they are ON BY DEFAULT. So `ecAdd(p, ecMul(q, 0n))` compiles
 * to "just p" with the EC optimizer enabled and to the off-curve blob with it
 * disabled: THE TWO MODES DISAGREE ABOUT WHAT THE SAME SOURCE MEANS. Testing
 * either mode alone would have passed.
 *
 * Of the two filed remediations — teach `affineAdd` the infinity case, or drop
 * the two identity rules — only the first can work. Dropping the rules leaves
 * the runtime paths above (a zero scalar the optimizer cannot see, a P + (−P)
 * feeding a later add) producing garbage with nothing rewritten at all. The
 * rules are right; the adder was wrong.
 *
 * Semantics pinned here, for all three curves:
 *   P + O = P,  O + P = P,  O + O = O,  P + (−P) = O
 * i.e. the all-zero blob really is the identity, and `ecOnCurve` still rejects
 * it (0² ≠ 0³ + b), so the `assert(ecOnCurve(ecAdd(a, b)))` idiom keeps working.
 *
 * Everything is EXECUTED on @bsv/sdk's `Spend`.
 */

const bytes = (h: string) => Uint8Array.from(Buffer.from(h, 'hex'));
const hex = (b: Uint8Array) => Buffer.from(b).toString('hex');

function exec(args: string[], emitFn: (e: (op: StackOp) => void) => void) {
  const ops: StackOp[] = args.map(h => ({ op: 'push', value: bytes(h) }) as StackOp);
  emitFn((op) => ops.push(op));
  const { scriptHex } = emitMethod({ name: 't', ops } as never) as { scriptHex: string };
  const r = new ScriptVM().executeHex(scriptHex);
  return { aborted: r.error !== undefined, top: r.stack.length ? hex(r.stack[r.stack.length - 1]!) : '' };
}

function onCurve(point: string, emitFn: (e: (op: StackOp) => void) => void): boolean {
  const ops: StackOp[] = [{ op: 'push', value: bytes(point) } as StackOp];
  emitFn((op) => ops.push(op));
  const { scriptHex } = emitMethod({ name: 't', ops } as never) as { scriptHex: string };
  return new ScriptVM().executeHex(scriptHex).success;
}

const CURVES = {
  secp256k1: {
    w: 32,
    g: '79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798'
     + '483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8',
    emitAdd: emitEcAdd, emitNegate: emitEcNegate, emitOnCurve: emitEcOnCurve,
  },
  p256: {
    w: 32,
    g: '6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296'
     + '4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5',
    emitAdd: emitP256Add, emitNegate: emitP256Negate, emitOnCurve: emitP256OnCurve,
  },
  p384: {
    w: 48,
    g: 'aa87ca22be8b05378eb1c71ef320ad746e1d3b628ba79b9859f741e082542a385502f25dbf55296c3a545e3872760ab7'
     + '3617de4a96262c6f5d9e98bf9292dc29f8f41dbd289a147ce9da3113b5f0b8c00a60b1ce1d7e819d7a431d7c90ea0e5f',
    emitAdd: emitP384Add, emitNegate: emitP384Negate, emitOnCurve: emitP384OnCurve,
  },
} as const;

describe.each(Object.entries(CURVES))('R-053 the all-zero blob is the additive identity — %s', (_n, C) => {
  const G = C.g;
  const O = '00'.repeat(2 * C.w);

  it('ASSERTION 1 — add(G, O) returns G, and it is on the curve', () => {
    const r = exec([G, O], C.emitAdd);
    expect(r.aborted).toBe(false);
    expect(r.top).toBe(G);
    expect(onCurve(r.top, C.emitOnCurve)).toBe(true);
  });

  it('ASSERTION 1 — add(O, G) returns G, and it is on the curve', () => {
    const r = exec([O, G], C.emitAdd);
    expect(r.aborted).toBe(false);
    expect(r.top).toBe(G);
    expect(onCurve(r.top, C.emitOnCurve)).toBe(true);
  });

  it('O is absorbing for itself: add(O, O) = O', () => {
    const r = exec([O, O], C.emitAdd);
    expect(r.aborted).toBe(false);
    expect(r.top).toBe(O);
  });

  it('add(2G, O) = 2G — not only the generator', () => {
    const twoG = exec([G, G], C.emitAdd);
    expect(twoG.aborted).toBe(false);
    const r = exec([twoG.top, O], C.emitAdd);
    expect(r.top).toBe(twoG.top);
  });

  it('CONTROL — add(G, G) is still the correct double and is on the curve', () => {
    const r = exec([G, G], C.emitAdd);
    expect(r.aborted).toBe(false);
    expect(r.top).not.toBe(G);
    expect(r.top).toHaveLength(4 * C.w);
    expect(onCurve(r.top, C.emitOnCurve)).toBe(true);
  });

  it('CONTROL — add(G, -G) is still O, and O is still off-curve', () => {
    const neg = exec([G], C.emitNegate);
    const r = exec([G, neg.top], C.emitAdd);
    expect(r.top).toBe(O);
    expect(onCurve(O, C.emitOnCurve)).toBe(false);
  });

  it('CONTROL — add(G, 2G) is unchanged by the infinity case', () => {
    const twoG = exec([G, G], C.emitAdd);
    const threeG = exec([G, twoG.top], C.emitAdd);
    expect(threeG.aborted).toBe(false);
    expect(onCurve(threeG.top, C.emitOnCurve)).toBe(true);
    // 3G = G + 2G = 2G + G: the adder must be commutative here too.
    const threeGSwapped = exec([twoG.top, G], C.emitAdd);
    expect(threeGSwapped.top).toBe(threeG.top);
  });

  it('CONTROL — associativity across the identity: (G + O) + G = G + G', () => {
    const gPlusO = exec([G, O], C.emitAdd);
    const lhs = exec([gPlusO.top, G], C.emitAdd);
    const rhs = exec([G, G], C.emitAdd);
    expect(lhs.top).toBe(rhs.top);
  });
});

// ---------------------------------------------------------------------------
// ASSERTION 2 — the two optimizer modes must agree about the same source.
// ---------------------------------------------------------------------------

const SOURCE = `
import { SmartContract, assert, ecAdd, ecMul, ecOnCurve } from 'runar-lang';
import type { Point } from 'runar-lang';

class AddIdentity extends SmartContract {
    readonly tag: bigint;
    constructor(tag: bigint) {
        super(tag);
        this.tag = tag;
    }

    public right(p: Point, q: Point) {
        const r = ecAdd(p, ecMul(q, 0n));
        assert(ecOnCurve(r));
    }

    public left(p: Point, q: Point) {
        const r = ecAdd(ecMul(q, 0n), p);
        assert(ecOnCurve(r));
    }
}
`;

describe('R-053 ASSERTION 2 — ecAdd(P, ecMul(Q, 0n)) means the same thing with and without the EC optimizer', () => {
  const G = CURVES.secp256k1.g;

  // Both fold modes, because the goldens are stamped fold-OFF and CI runs
  // fold-ON as a separate lane; a disagreement in either lane is a divergence.
  for (const disableConstantFolding of [true, false]) {
    const foldLabel = disableConstantFolding ? 'fold-OFF' : 'fold-ON';

    for (const method of ['right', 'left']) {
      it(`${foldLabel}: \`${method}\` reaches the same verdict with the EC optimizer on and off`, () => {
        const on = ScriptExecutionContract.fromSource(
          SOURCE, { tag: 1n }, 'AddIdentity.runar.ts',
          { disableConstantFolding, disableEcOptimizer: false } as never,
        );
        const off = ScriptExecutionContract.fromSource(
          SOURCE, { tag: 1n }, 'AddIdentity.runar.ts',
          { disableConstantFolding, disableEcOptimizer: true } as never,
        );
        const onResult = on.execute(method, [G, G]);
        const offResult = off.execute(method, [G, G]);
        expect(offResult.success).toBe(onResult.success);
        // ...and the shared verdict must be ACCEPT: P + O = P is on the curve.
        expect(onResult.success).toBe(true);
      }, 120_000);
    }
  }
});
