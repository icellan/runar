/**
 * R-169 — the emitted `sqrt` disagreed with the constant folder and with the
 * reference interpreter, and was simply wrong.
 *
 * WHAT WAS EMITTED (`passes/05-stack-lower.ts#lowerSqrt`, plus its six peers):
 *
 *     OP_DUP OP_IF
 *       OP_DUP                                     ; guess = n
 *       [ OP_OVER OP_OVER OP_DIV OP_ADD <2> OP_DIV ] x 16
 *       OP_NIP
 *     OP_ENDIF
 *
 * i.e. SIXTEEN UNCONDITIONAL Newton rounds seeded at `guess = n`, with no
 * convergence test. Two independent defects:
 *
 *  1. NO CONVERGENCE BREAK. Integer Newton reaches `floor(sqrt(n))` and then
 *     OSCILLATES between it and `floor(sqrt(n))+1` forever. With a fixed round
 *     count the answer is whichever value the parity of the round count lands
 *     on. `sqrt(8)` -> 3, `sqrt(15)` -> 4, `sqrt(48)` -> 7, `sqrt(63)` -> 8:
 *     wrong for 19 of the first 1000 non-negative integers.
 *
 *  2. SIXTEEN ROUNDS IS NOT ENOUGH, break or no break. Seeded at `guess = n`
 *     the iterate only HALVES per round until it nears sqrt(n), so a correct
 *     run needs ~log2(n)/2 rounds before quadratic convergence begins:
 *     20 rounds for a 32-bit n, 37 for 64-bit, 135 for 256-bit. Sixteen rounds
 *     leaves `sqrt(2^32)` at 86050 (true 65536) and `sqrt(10^12)` at 15280627
 *     (true 1000000) — off by three orders of magnitude, with the shortfall
 *     growing without bound.
 *
 * WHY IT SURVIVED. `optimizer/constant-fold.ts` and `interpreter.ts` both do it
 * CORRECTLY — 256 rounds WITH `if (next >= guess) break`. Every `sqrt` test in
 * the repo (`examples/ts/math-demo/MathDemo.test.ts`) drives `TestContract`,
 * which is the interpreter; none ever executed the emitted script. Its four
 * values (100, 0, 10, 1000000) are all inputs where the buggy script happens to
 * agree, as are the perfect squares 4/9/16/25 — kept below as controls, because
 * a test suite made only of those reproduces nothing.
 *
 * THE CONSEQUENCE THAT MATTERS. `sqrt(8n)` FOLDED to 2 and RAN as 3: the same
 * expression meant two different things depending on whether the constant
 * folder had run. That breaks the fold-ON/fold-OFF invariant CI enforces in
 * both directions, so it gets its own permanent guard below via
 * `runFoldEquivalence`.
 *
 * THE FIX. Each round becomes
 *
 *     OP_OVER OP_OVER OP_DIV OP_OVER OP_ADD <2> OP_DIV OP_MIN
 *
 * — `OP_MIN` against the previous iterate IS the convergence break. The Newton
 * sequence from `guess = n` is strictly decreasing while `guess > isqrt(n)` and
 * non-decreasing once `guess == isqrt(n)`, so `guess := min(guess, next)` is a
 * fixed point at exactly `isqrt(n)` and every post-convergence round is a
 * no-op. Round count goes 16 -> 256, matching the folder's bound, which makes
 * the emitted script the SAME FUNCTION as the folder and the interpreter at
 * every input rather than merely at the inputs someone remembered to test.
 * A negative `n` is now REFUSED (`OP_DUP <0> OP_GREATERTHANOREQUAL OP_VERIFY`)
 * instead of returning `n` itself: the interpreter throws on it and the folder
 * declines to fold it, so a silently wrong number was the only one of the three
 * behaviours that was not a refusal.
 *
 * DOMAIN. 256 rounds are exact for every 0 <= n < 2^497 (measured against the
 * algebraic oracle below, not against the folder). Both ends are ENFORCED, not
 * merely documented, because outside them the iteration returns a wrong number
 * rather than failing and a silently wrong number is the whole defect:
 *
 *     OP_DUP <0> OP_GREATERTHANOREQUAL OP_VERIFY    ; n >= 0
 *     OP_SIZE <63> OP_LESSTHAN OP_VERIFY            ; n encodes in <= 62 bytes
 *
 * A minimally-encoded script number of at most 62 bytes is at most 2^495 - 1,
 * so the ENFORCED domain is 0 <= n < 2^495 — inside the proven-exact 2^497.
 * The upper guard is not theoretical: before it, a 500-byte n ran to completion
 * on the real ScriptVM and returned a wrong root with no error. The folder and
 * the reference interpreter carry the same bound, so all three refuse together.
 */

import { describe, it, expect } from 'vitest';
// @ts-expect-error vitest resolves these via the root alias
import { ScriptExecutionContract, runFoldEquivalence } from 'runar-testing';

// ---------------------------------------------------------------------------
// GROUND TRUTH. Deliberately NOT a second square-root implementation.
//
// Agreement with `optimizer/constant-fold.ts` would prove only that the script
// matches a PEER implementation — the exact circularity that let this defect
// live (seven tiers agreeing, a whole test suite driving the interpreter). So
// the oracle here is algebra with no sqrt in it at all: `s` is floor(sqrt(n))
// if and only if `s >= 0 && s*s <= n && n < (s+1)*(s+1)`. Every correctness
// assertion below goes through `isFloorSqrt`.
//
// `isqrt` exists only to NAME the tests and to pick probe arguments; it is
// itself checked against `isFloorSqrt` wherever it is used, so a bug in it
// cannot make a wrong script look right.
// ---------------------------------------------------------------------------
function isFloorSqrt(n: bigint, s: bigint): boolean {
  return s >= 0n && s * s <= n && n < (s + 1n) * (s + 1n);
}

function isqrt(n: bigint): bigint {
  if (n < 0n) throw new Error('isqrt: negative');
  if (n < 2n) return n;
  let x = n;
  let y = (x + 1n) / 2n;
  while (y < x) {
    x = y;
    y = (x + n / x) / 2n;
  }
  return x;
}

// ---------------------------------------------------------------------------
// Probes. Two single-method contracts so no method selector / branch lowering
// sits between the witness and the sqrt fragment.
//
// `eq` is the assertion under test. `ge` exists only to RECOVER the value the
// compiled script actually computes: `scriptSqrt(n) >= k` is monotone in k
// whatever scriptSqrt computes, so a binary search over it reports the script's
// answer exactly — which is how the RED numbers in the header were measured,
// rather than inferred from a failing equality.
// ---------------------------------------------------------------------------
const EQ_SRC = `
import { SmartContract, assert, sqrt } from 'runar-lang';

export class SqrtProbeEq extends SmartContract {
  readonly tag: bigint;
  constructor(tag: bigint) { super(tag); this.tag = tag; }
  public probe(n: bigint, expected: bigint): void {
    assert(sqrt(n) === expected);
  }
}
`;

const GE_SRC = `
import { SmartContract, assert, sqrt } from 'runar-lang';

export class SqrtProbeGe extends SmartContract {
  readonly tag: bigint;
  constructor(tag: bigint) { super(tag); this.tag = tag; }
  public probe(n: bigint, k: bigint): void {
    assert(sqrt(n) >= k);
  }
}
`;

const eqProbe = ScriptExecutionContract.fromSource(EQ_SRC, { tag: 1n }, 'SqrtProbeEq.runar.ts');
const geProbe = ScriptExecutionContract.fromSource(GE_SRC, { tag: 1n }, 'SqrtProbeGe.runar.ts');

/** Does the COMPILED SCRIPT accept `sqrt(n) === expected`? */
function scriptAcceptsEq(n: bigint, expected: bigint): boolean {
  return eqProbe.execute('probe', [n, expected]).success;
}

/** The value the COMPILED SCRIPT computes for sqrt(n), recovered by bisection. */
function scriptSqrt(n: bigint): bigint {
  // scriptSqrt(n) is in [0, n] for every construction this test has ever seen;
  // widen defensively so a regression reports a number instead of hanging.
  let lo = 0n;
  let hi = n > 0n ? n * 2n + 2n : 2n;
  if (!geProbe.execute('probe', [n, lo]).success) {
    throw new Error(`sqrt(${n}) >= 0 was rejected by the script`);
  }
  while (lo < hi) {
    const mid = (lo + hi + 1n) / 2n;
    if (geProbe.execute('probe', [n, mid]).success) lo = mid;
    else hi = mid - 1n;
  }
  return lo;
}

// ---------------------------------------------------------------------------
// 1. The executed script must compute floor(sqrt(n)).
// ---------------------------------------------------------------------------
describe('R-169 sqrt — the EMITTED SCRIPT, executed on ScriptVM', () => {
  // The oscillation rows: Newton reaches isqrt(n) and bounces, and 16 rounds
  // lands on the wrong side of the bounce.
  const OSCILLATION = [8n, 15n, 24n, 35n, 48n, 63n, 80n, 99n];
  // The insufficient-rounds rows: 16 halvings do not get near sqrt(n).
  const TOO_FEW_ROUNDS = [2n ** 32n, 10n ** 12n, 2n ** 40n, 123456789012345n];
  // Controls: inputs the BUGGY script already agreed on. These must stay green
  // through the fix — a fix that reddens them broke something else.
  const CONTROLS = [0n, 1n, 4n, 9n, 16n, 25n, 100n, 10n, 1000000n];

  for (const n of [...CONTROLS, ...OSCILLATION, ...TOO_FEW_ROUNDS]) {
    it(`sqrt(${n}) === ${isqrt(n)}`, () => {
      const actual = scriptSqrt(n);
      // The oracle: pure algebra, no reference sqrt.
      expect(
        isFloorSqrt(n, actual),
        `compiled script computed sqrt(${n}) = ${actual}; ` +
          `floor(sqrt) requires s*s <= ${n} < (s+1)^2`,
      ).toBe(true);
      // ...and the equality path agrees with the bisected value.
      expect(scriptAcceptsEq(n, actual)).toBe(true);
      expect(scriptAcceptsEq(n, actual + 1n)).toBe(false);
      if (actual > 0n) expect(scriptAcceptsEq(n, actual - 1n)).toBe(false);
    });
  }

  it('is exact for every n in [0, 1024) — 20 of them were wrong', () => {
    const wrong: string[] = [];
    for (let n = 0n; n < 1024n; n++) {
      const got = scriptSqrt(n);
      if (!isFloorSqrt(n, got)) wrong.push(`sqrt(${n})=${got}`);
    }
    expect(wrong, `${wrong.length} wrong: ${wrong.slice(0, 8).join(', ')}`).toEqual([]);
  });

  it('the adversarial Newton shapes: s^2, s^2-1, s^2+1, s^2+s, 2^k-1, 2^k, 2^k+1', () => {
    // The OP_MIN fixed-point argument rests on "Newton from at-or-above
    // isqrt(n) never undershoots it". These are the shapes where an
    // off-by-one in that bound would show: exactly on a square, one either
    // side of it, the midpoint s^2+s where (s+1)^2 is still one away, and
    // both sides of every power of two the halving phase passes through.
    const probes: bigint[] = [];
    for (let s = 1n; s <= 40n; s++) probes.push(s * s, s * s - 1n, s * s + 1n, s * s + s);
    for (let k = 1n; k <= 34n; k++) {
      const p = 2n ** k;
      probes.push(p - 1n, p, p + 1n);
    }
    for (const s of [65536n, 1000000n, 4294967296n]) {
      probes.push(s * s, s * s - 1n, s * s + 1n, s * s + s);
    }
    const wrong: string[] = [];
    for (const n of probes) {
      if (n < 0n) continue;
      if (!scriptAcceptsEq(n, isqrt(n)) || !isFloorSqrt(n, isqrt(n))) wrong.push(`sqrt(${n})`);
    }
    expect(wrong, `${wrong.length} wrong: ${wrong.slice(0, 8).join(', ')}`).toEqual([]);
  });
});

// ---------------------------------------------------------------------------
// 2. Fold agreement — the invariant the defect actually broke.
// ---------------------------------------------------------------------------
describe('R-169 sqrt — fold-OFF script ≡ fold-ON constant ≡ interpreter', () => {
  // `sqrt(<literal>)` is an all-constant subexpression, so fold-ON collapses it
  // to a literal push and fold-OFF emits the Newton fragment. Those are the two
  // implementations that disagreed.
  function foldSrc(literal: bigint): string {
    return `
import { SmartContract, assert, sqrt } from 'runar-lang';

export class SqrtFold extends SmartContract {
  readonly tag: bigint;
  constructor(tag: bigint) { super(tag); this.tag = tag; }
  public probe(expected: bigint): void {
    assert(sqrt(${literal}n) === expected);
  }
}
`;
  }

  const FOLD_INPUTS = [0n, 1n, 4n, 8n, 9n, 15n, 25n, 48n, 63n, 99n, 100n, 1000000n, 2n ** 32n];

  for (const n of FOLD_INPUTS) {
    it(`sqrt(${n}n) folds and runs to the same value`, () => {
      const want = isqrt(n);
      const r = runFoldEquivalence({
        source: foldSrc(n),
        fileName: 'SqrtFold.runar.ts',
        method: 'probe',
        constructorArgs: { tag: 1n },
        // One accepting and one rejecting witness: agreement on "both reject"
        // is vacuous, so the accepting row is what pins the VALUE.
        witnesses: [[want], [want + 1n]],
      });
      expect(r.equivalent, JSON.stringify(r.divergences)).toBe(true);
      expect(r.bytesDiffer, 'folding must actually have collapsed the sqrt').toBe(true);
    });
  }
});

// ---------------------------------------------------------------------------
// 3. The documented limits.
// ---------------------------------------------------------------------------
describe('R-169 sqrt — guaranteed domain and its edges', () => {
  it('is exact across the whole 64-bit range and beyond', () => {
    const wide = [
      2n ** 16n - 1n,
      2n ** 31n - 1n,
      2n ** 32n - 1n,
      2n ** 63n - 1n,
      2n ** 64n - 1n,
      2n ** 64n,
      2n ** 96n - 1n,
      2n ** 128n - 1n,
      2n ** 160n - 1n,
      2n ** 200n - 1n,
      2n ** 255n - 1n,
      2n ** 256n - 1n,
    ];
    for (const n of wide) {
      const s = isqrt(n);
      expect(isFloorSqrt(n, s), `${n.toString(2).length}-bit probe value`).toBe(true);
      expect(scriptAcceptsEq(n, s), `sqrt of a ${n.toString(2).length}-bit n`).toBe(true);
      expect(scriptAcceptsEq(n, s + 1n)).toBe(false);
      expect(scriptAcceptsEq(n, s - 1n)).toBe(false);
    }
  });

  it('is exact at the top of the enforced domain, 2^495 - 1', () => {
    // 2^495 - 1 is the largest value that encodes in 62 script bytes, so it is
    // the largest the OP_SIZE guard admits. Pinning the edge stops a later
    // "optimisation" from quietly shrinking the round count: drop to 128 and
    // this reddens.
    const n = 2n ** 495n - 1n;
    const s = isqrt(n);
    expect(isFloorSqrt(n, s)).toBe(true);
    expect(scriptAcceptsEq(n, s)).toBe(true);
    expect(scriptAcceptsEq(n, s + 1n)).toBe(false);
  });

  it('REFUSES n at or above 2^495 instead of returning a wrong root', () => {
    // Every one of these ran to completion before the guard and returned a
    // wrong root with no error — measured on ScriptVM, at 63, 64, 75, 125, 256
    // and 500 bytes. Reachability was confirmed by execution, not assumed.
    const OVER = [
      2n ** 495n,
      2n ** 496n,
      2n ** 497n - 1n,
      2n ** 498n - 1n,
      2n ** 512n - 1n,
      2n ** 600n - 1n,
      2n ** 1000n - 1n,
      2n ** 2048n - 1n,
      2n ** 4000n - 1n,
    ];
    for (const n of OVER) {
      // No candidate root is accepted: not the true one, not the one the
      // unguarded script used to return, not zero.
      expect(geProbe.execute('probe', [n, 0n]).success, `sqrt(2^${n.toString(2).length}) must abort`).toBe(false);
      expect(scriptAcceptsEq(n, isqrt(n))).toBe(false);
    }
  });

  it('the folder and the interpreter refuse on the same bound as the script', () => {
    // A fold that produced a value where the script aborts would re-open
    // R-169 at the other end of the domain, so the folder must DECLINE. Both
    // fold modes must therefore compile to a script that rejects.
    const n = 2n ** 500n;
    const src = `
import { SmartContract, assert, sqrt } from 'runar-lang';

export class SqrtOver extends SmartContract {
  readonly tag: bigint;
  constructor(tag: bigint) { super(tag); this.tag = tag; }
  public probe(expected: bigint): void {
    assert(sqrt(${n}n) === expected);
  }
}
`;
    const r = runFoldEquivalence({
      source: src,
      fileName: 'SqrtOver.runar.ts',
      method: 'probe',
      constructorArgs: { tag: 1n },
      witnesses: [[isqrt(n)], [0n]],
    });
    expect(r.equivalent, JSON.stringify(r.divergences)).toBe(true);
    // Declining to fold means the bytes are identical in both modes.
    expect(r.bytesDiffer, 'an out-of-domain sqrt must not fold').toBe(false);
  });

  it('REFUSES a negative n instead of returning a wrong number', () => {
    // A negative n is a FIXED POINT of the min-clamped recurrence, so without
    // the OP_GREATERTHANOREQUAL guard the fix itself would have introduced a
    // new wrong answer: sqrt(-8) = -8, truthy and accepted. Three
    // implementations of one builtin used to disagree three ways here — script
    // returned n, interpreter threw, folder declined. Now all three refuse.
    for (const n of [-1n, -8n, -100n, -(2n ** 40n)]) {
      expect(scriptAcceptsEq(n, n), `sqrt(${n}) must not accept ${n}`).toBe(false);
      expect(scriptAcceptsEq(n, 0n)).toBe(false);
      expect(scriptAcceptsEq(n, isqrt(-n))).toBe(false);
      expect(geProbe.execute('probe', [n, 0n]).success, `sqrt(${n}) must abort`).toBe(false);
    }
  });
});
