import { describe, it, expect } from 'vitest';
import { ScriptExecutionContract } from '../index.js';

/**
 * N-104 — the EC optimizer's identity rewrites must not drop the operand
 * validation the builtin they replace performs.
 *
 * optimizer/ec-rules.json rewrites
 *
 *     R1 ecAdd(q, O) -> q        R3 ecMul(q, 1) -> q
 *     R2 ecAdd(O, q) -> q        R4 ecMul(q, 0) -> O
 *
 * and is on by default. The builtins themselves validate `q` before computing
 * anything: `ecAdd` aborts unless q is exactly 64 bytes with both coordinates
 * below p (CL-BUG-095 / R-117); `ecMul` aborts unless q is on the curve or is
 * the all-zero O (R-157). The rewrites used to replace the whole call with an
 * alias, gate included, so a malformed or off-curve q was ACCEPTED by the
 * default compile and REJECTED by `disableEcOptimizer` — the same source with
 * two meanings. Measured before the fix on @bsv/sdk's Spend:
 *
 *     ecAdd(q, O), q = (1+p) || 2     opt: returns q     noopt: aborts
 *     ecAdd(q, O), q = 63 bytes       opt: returns q     noopt: aborts
 *     ecMul(q, 1), q = (5, 7)         opt: returns q     noopt: aborts
 *     ecMul(q, 0), q = (5, 7)         opt: returns O     noopt: aborts
 *
 * User decision R45: keep the rewrites (they elide ~425-450 KB of add/mul) but
 * leave the operand's validation in place of the call. This table is the
 * contract, pinned against BOTH compiles, executed on the real Spend engine.
 *
 * WHAT IT PROVES: for every input class below (a valid point, O, an off-curve
 * canonical point, a 2-torsion off-curve point, a non-canonical x >= p, and a
 * 63-byte blob) the optimized and unoptimized scripts return the same value or
 * both abort, and that answer is the one written in the table — so agreement
 * cannot be reached by both modes regressing together.
 *
 * WHAT IT DOES NOT PROVE: that the other tiers emit the same gate (the
 * conformance suite's cross-tier hex parity covers that), or anything about
 * rules R5-R12. Those were audited separately: R7 and R8/R8r keep their gate
 * because the inner `ecNegate` call is never dead-code-eliminated; R8's
 * disagreement with the unoptimized adder on an off-curve (x, 0) point (which
 * N-110 made abort) is closed by N-251's y = 0 gate and pinned by
 * n251-ec-negate-cancel-y0.test.ts.
 */

const P = 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2fn;
const h32 = (n: bigint) => n.toString(16).padStart(64, '0');

const G = '79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798'
        + '483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8';
const O = '00'.repeat(64);

const INPUTS: Record<string, string> = {
  G,
  O,
  offCurve: h32(5n) + h32(7n),       // canonical, off the curve
  twoTorsion: h32(5n) + h32(0n),     // canonical, off the curve, y = 0
  xGeP: h32(1n + P) + h32(2n),       // non-canonical x
  short63: G.slice(0, 126),          // 63 bytes
};

type Outcome = 'q' | 'O' | 'abort';

const RULES: Record<string, { expr: string; expect: Record<string, Outcome> }> = {
  'R1 ecAdd(q, O)': {
    expr: 'ecAdd(q, ecMulGen(0n))',
    expect: { G: 'q', O: 'O', offCurve: 'q', twoTorsion: 'q', xGeP: 'abort', short63: 'abort' },
  },
  'R2 ecAdd(O, q)': {
    expr: 'ecAdd(ecMulGen(0n), q)',
    expect: { G: 'q', O: 'O', offCurve: 'q', twoTorsion: 'q', xGeP: 'abort', short63: 'abort' },
  },
  'R3 ecMul(q, 1)': {
    expr: 'ecMul(q, 1n)',
    expect: { G: 'q', O: 'O', offCurve: 'abort', twoTorsion: 'abort', xGeP: 'abort', short63: 'abort' },
  },
  'R4 ecMul(q, 0)': {
    expr: 'ecMul(q, 0n)',
    expect: { G: 'O', O: 'O', offCurve: 'abort', twoTorsion: 'abort', xGeP: 'abort', short63: 'abort' },
  },
};

function source(expr: string): string {
  return `import { SmartContract, assert, ecAdd, ecMul, ecMulGen } from 'runar-lang';
import type { Point } from 'runar-lang';
class Probe extends SmartContract {
  constructor() { super(); }
  public check(q: Point, e: Point) {
    const r = ${expr};
    assert(r === e);
  }
}`;
}

/** What the script returns for q: 'q' (q itself, q != O), 'O', or 'abort'. */
function outcome(c: ScriptExecutionContract, q: string): Outcome {
  const accepts = (e: string) => c.execute('check', [q, e]).success;
  // A real `assert(r === e)` must also REJECT a wrong `e`, or "accepted" means
  // nothing; G vs O are always distinct, and one of them is never the answer.
  if (accepts(q) && q !== O) { expect(accepts(q === G ? O : G)).toBe(false); return 'q'; }
  if (accepts(O)) { expect(accepts(G)).toBe(false); return 'O'; }
  return 'abort';
}

describe('N-104 EC optimizer identity rewrites keep the replaced builtin\'s operand gate', () => {
  for (const [rule, { expr, expect: table }] of Object.entries(RULES)) {
    describe(rule, () => {
      const modes = {
        optimized: ScriptExecutionContract.fromSource(source(expr), {}, 'Probe.runar.ts'),
        unoptimized: ScriptExecutionContract.fromSource(source(expr), {}, 'Probe.runar.ts', { disableEcOptimizer: true }),
      };
      for (const [mode, c] of Object.entries(modes)) {
        it(`${mode}: every input class gets the pinned answer`, () => {
          const got: Record<string, Outcome> = {};
          for (const [name, q] of Object.entries(INPUTS)) got[name] = outcome(c, q);
          expect(got).toEqual(table);
        });
      }
      it('the rewrite still fires: the optimized script is a small fraction of the builtin', () => {
        expect(modes.optimized.scriptHex.length * 20).toBeLessThan(modes.unoptimized.scriptHex.length);
      });
    });
  }
}, 600_000);
