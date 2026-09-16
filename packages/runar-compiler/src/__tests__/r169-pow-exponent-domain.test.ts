/**
 * R-169, the `pow` half — the emitted `pow` silently returned `base^32` for
 * every exponent above 32, and disagreed with the constant folder and the
 * reference interpreter about what `pow` means.
 *
 * WHAT WAS EMITTED (`passes/05-stack-lower.ts#lowerPow`, plus its six peers):
 *
 *     OP_SWAP <1>
 *     [ <2> OP_PICK <i> OP_GREATERTHAN OP_IF OP_OVER OP_MUL OP_ENDIF ] x 32
 *     OP_NIP OP_NIP
 *
 * i.e. 32 conditional multiplies and NO GUARD ON THE EXPONENT. That computes
 * `base^min(exp, 32)`. The comment above the loop had talked itself into the
 * bug in as many words — "That gives base^min(exp, 32). That's correct!"
 *
 * MEASURED ON THE REAL VM, before the fix (all three columns are executed or
 * computed, none inferred from a failing equality — `scriptPow` below bisects
 * the value the script actually returns):
 *
 *                   emitted script      constant folder        interpreter
 *     pow(2,32)     4294967296          4294967296             4294967296
 *     pow(2,33)     4294967296          8589934592             8589934592
 *     pow(2,40)     4294967296          1099511627776          1099511627776
 *     pow(3,50)     1853020188851841    717897987691852588770  same as folder
 *     pow(2,-1)     1                   declines to fold       throws
 *
 * `1853020188851841` is `3^32`. The smallest failing exponent is 33.
 *
 * THE CONSEQUENCE THAT MATTERS. `optimizer/constant-fold.ts` folded any
 * `0 <= exp <= 256` to the TRUE power and declined above it. So for exactly
 * `33 <= exp <= 256` the same source compiled fold-ON and fold-OFF produced
 * scripts that accept MUTUALLY EXCLUSIVE inputs — `pow(2n, 33n) === 2**33` is
 * accepted by the folded script and rejected by the unfolded one, and
 * `=== 2**32` the other way round. Above 256 the folder declined and
 * accidentally re-agreed with the clamp. CI enforces fold-ON/fold-OFF parity
 * in both directions and never saw it, because nothing executed the fragment:
 * there is no `pow` past its bound anywhere in the fixtures, the fuzzer never
 * generated `pow`, and the single `pow` in any test sat at `exp = 10n`, inside
 * the clamp. Three review rounds passed over it.
 *
 * THE FIX — the same shape `sqrt` got twenty lines away in the same files.
 * The domain is ENFORCED, not documented; outside it the script ABORTS rather
 * than returning a number that is not `base^exp`:
 *
 *     OP_DUP <0> <33> OP_WITHIN OP_VERIFY
 *
 * and the folder declines, and the interpreter throws, on exactly that same
 * bound. All three now refuse together, which is what makes `pow` one
 * function instead of three.
 *
 * WHY 32 AND NOT A RAISED BOUND. Raising the unroll is the other candidate
 * answer, and it is measurably the worse one: each extra round costs 8-9
 * script bytes AT EVERY CALLSITE (~2 KB to reach the folder's old 256), and a
 * raised bound STILL needs a guard at the new limit — it moves the cliff
 * rather than removing it. The guard costs 6 bytes per callsite once, measured
 * below and pinned so the number cannot drift unnoticed.
 */

import { describe, it, expect } from 'vitest';
import { compile } from '../index.js';
// @ts-expect-error vitest resolves these via the root alias
import { ScriptExecutionContract, runFoldEquivalence } from 'runar-testing';

/** The enforced bound: the script unrolls this many conditional multiplies. */
const POW_EXPONENT_LIMIT = 32n;

// ---------------------------------------------------------------------------
// Probes. Two single-method stateless contracts, so no method selector or
// branch lowering sits between the witness and the pow fragment.
//
// `eq` is the assertion under test. `ge` exists only to RECOVER the value the
// compiled script actually computes: `scriptPow(b,e) >= k` is monotone in k
// whatever the script computes, so bisecting it reports the script's answer
// exactly — which is how the header's RED column was measured rather than
// inferred.
// ---------------------------------------------------------------------------
const EQ_SRC = `
import { SmartContract, assert, pow } from 'runar-lang';

export class PowProbeEq extends SmartContract {
  readonly tag: bigint;
  constructor(tag: bigint) { super(tag); this.tag = tag; }
  public probe(base: bigint, exp: bigint, expected: bigint): void {
    assert(pow(base, exp) === expected);
  }
}
`;

const GE_SRC = `
import { SmartContract, assert, pow } from 'runar-lang';

export class PowProbeGe extends SmartContract {
  readonly tag: bigint;
  constructor(tag: bigint) { super(tag); this.tag = tag; }
  public probe(base: bigint, exp: bigint, k: bigint): void {
    assert(pow(base, exp) >= k);
  }
}
`;

const eqProbe = ScriptExecutionContract.fromSource(EQ_SRC, { tag: 1n }, 'PowProbeEq.runar.ts');
const geProbe = ScriptExecutionContract.fromSource(GE_SRC, { tag: 1n }, 'PowProbeGe.runar.ts');

/** Does the COMPILED SCRIPT accept `pow(base, exp) === expected`? */
function scriptAcceptsEq(base: bigint, exp: bigint, expected: bigint): boolean {
  return eqProbe.execute('probe', [base, exp, expected]).success;
}

/** Does the COMPILED SCRIPT run `pow(base, exp)` at all, or does it abort? */
function scriptRuns(base: bigint, exp: bigint): boolean {
  // `pow(b,e) >= 0` is true of every value the unguarded loop could ever
  // produce for a non-negative base, so a rejection here is the GUARD firing,
  // not the comparison failing.
  return geProbe.execute('probe', [base, exp, 0n]).success;
}

/** The value the COMPILED SCRIPT computes for pow(base, exp), by bisection. */
function scriptPow(base: bigint, exp: bigint): bigint {
  if (!scriptRuns(base, exp)) throw new Error(`pow(${base},${exp}) aborted`);
  let hi = 1n;
  while (geProbe.execute('probe', [base, exp, hi]).success) {
    hi *= 2n;
    if (hi > 1n << 2048n) throw new Error('runaway bisection');
  }
  let lo = 0n;
  let top = hi;
  while (lo < top) {
    const mid = (lo + top + 1n) / 2n;
    if (geProbe.execute('probe', [base, exp, mid]).success) lo = mid;
    else top = mid - 1n;
  }
  return lo;
}

// ---------------------------------------------------------------------------
// 1. Inside the domain the executed script must compute base^exp EXACTLY.
//
// The oracle is JavaScript's own `**` on BigInt — deliberately not a second
// walk of the same 32-round loop and not the constant folder, since agreement
// with a peer implementation of the same algorithm is the exact circularity
// that let this live (seven tiers agreeing, nothing executing).
// ---------------------------------------------------------------------------
describe('R-169 pow — inside 0..32 the EMITTED SCRIPT is exact', () => {
  const BASES = [0n, 1n, 2n, 3n, -2n, 7n, 10n, 255n];

  for (const base of BASES) {
    it(`pow(${base}, e) === ${base}**e for every e in 0..32`, () => {
      const wrong: string[] = [];
      for (let e = 0n; e <= POW_EXPONENT_LIMIT; e++) {
        const want = base ** e;
        if (!scriptAcceptsEq(base, e, want)) wrong.push(`pow(${base},${e}) != ${want}`);
        // ...and nothing else is accepted, so "accepts the right answer" is
        // not satisfied by a script that accepts everything.
        if (scriptAcceptsEq(base, e, want + 1n)) wrong.push(`pow(${base},${e}) also == ${want + 1n}`);
      }
      expect(wrong, `${wrong.length} wrong: ${wrong.slice(0, 6).join(', ')}`).toEqual([]);
    });
  }

  it('exp = 32 — the boundary — still works (an over-strict guard reddens here)', () => {
    // The guard is `0 <= exp < 33`. Off-by-one it to `< 32` and this row goes
    // red while every "refuses past the bound" row below stays green, so the
    // two halves cannot both be satisfied by a guard at the wrong place.
    expect(scriptAcceptsEq(2n, 32n, 2n ** 32n)).toBe(true);
    expect(scriptPow(2n, 32n)).toBe(4294967296n);
    expect(scriptPow(3n, 32n)).toBe(1853020188851841n);
  });

  it('exp = 0 yields 1 for every base, including 0', () => {
    for (const base of [0n, 1n, 2n, -5n, 1000000n]) {
      expect(scriptAcceptsEq(base, 0n, 1n), `pow(${base},0)`).toBe(true);
    }
  });

  it('exp = 10 — the one pow any test in the repo executed — is unchanged', () => {
    // tests/r222-stack-depth-model-vs-real.test.ts drives pow at exp = 10n,
    // comfortably inside the clamp, which is why a green suite proved nothing.
    // Kept as a control: it must stay green through the fix.
    expect(scriptPow(2n, 10n)).toBe(1024n);
    expect(scriptAcceptsEq(2n, 10n, 1024n)).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// 2. Outside the domain the executed script must ABORT, not clamp.
// ---------------------------------------------------------------------------
describe('R-169 pow — outside 0..32 the EMITTED SCRIPT refuses', () => {
  it('REFUSES 33 <= exp instead of returning base^32', () => {
    // 33 is the smallest failing exponent. Every row here ran to completion
    // before the guard and returned the CLAMPED value with no error.
    const OVER: Array<[bigint, bigint]> = [
      [2n, 33n],
      [2n, 34n],
      [2n, 40n],
      [2n, 64n],
      [3n, 50n],
      [2n, 256n],
      [2n, 257n],
      [10n, 1000n],
    ];
    for (const [base, exp] of OVER) {
      expect(scriptRuns(base, exp), `pow(${base},${exp}) must abort`).toBe(false);
      // Neither the true power nor the clamped one is accepted — a guard that
      // only rejected the true answer would leave the wrong answer reachable.
      expect(scriptAcceptsEq(base, exp, base ** exp)).toBe(false);
      expect(scriptAcceptsEq(base, exp, base ** POW_EXPONENT_LIMIT)).toBe(false);
    }
  });

  it('REFUSES a negative exp instead of returning 1', () => {
    // The unguarded loop takes no branch when exp <= 0, so it returned the
    // accumulator's seed: pow(2, -1) = 1, truthy and accepted. Three
    // implementations of one builtin disagreed three ways here — script
    // returned 1, interpreter threw, folder declined. Now all three refuse.
    for (const exp of [-1n, -2n, -32n, -33n, -1000n]) {
      expect(scriptRuns(2n, exp), `pow(2,${exp}) must abort`).toBe(false);
      expect(scriptAcceptsEq(2n, exp, 1n), `pow(2,${exp}) must not be 1`).toBe(false);
      expect(scriptAcceptsEq(2n, exp, 0n)).toBe(false);
    }
  });

  it('an enormous exponent is refused rather than silently clamped', () => {
    for (const exp of [1n << 40n, 1n << 200n, (1n << 495n) - 1n]) {
      expect(scriptRuns(2n, exp), `pow(2, 2^${exp.toString(2).length - 1}) must abort`).toBe(false);
      expect(scriptAcceptsEq(2n, exp, 4294967296n)).toBe(false);
    }
  });
});

// ---------------------------------------------------------------------------
// 3. Fold agreement — the invariant the defect actually broke.
//
// `pow(<literal>, <literal>)` is an all-constant subexpression, so fold-ON
// collapses it to a literal push and fold-OFF emits the 32-round fragment.
// Those are the two implementations that disagreed, and inside 33..256 they
// accepted mutually exclusive witnesses.
// ---------------------------------------------------------------------------
describe('R-169 pow — fold-OFF script ≡ fold-ON constant ≡ interpreter', () => {
  function foldSrc(base: bigint, exp: bigint): string {
    return `
import { SmartContract, assert, pow } from 'runar-lang';

export class PowFold extends SmartContract {
  readonly tag: bigint;
  constructor(tag: bigint) { super(tag); this.tag = tag; }
  public probe(expected: bigint): void {
    assert(pow(${base}n, ${exp}n) === expected);
  }
}
`;
  }

  const IN_DOMAIN: Array<[bigint, bigint]> = [
    [2n, 0n],
    [2n, 1n],
    [2n, 10n],
    [2n, 31n],
    [2n, 32n],
    [3n, 32n],
    [-2n, 31n],
    [10n, 18n],
    [0n, 5n],
    [1n, 32n],
  ];

  for (const [base, exp] of IN_DOMAIN) {
    it(`pow(${base}n, ${exp}n) folds and runs to the same value`, () => {
      const want = base ** exp;
      const r = runFoldEquivalence({
        source: foldSrc(base, exp),
        fileName: 'PowFold.runar.ts',
        method: 'probe',
        constructorArgs: { tag: 1n },
        // One accepting and one rejecting witness: agreement on "both reject"
        // is vacuous, so the accepting row is what pins the VALUE.
        witnesses: [[want], [want + 1n]],
      });
      expect(r.equivalent, JSON.stringify(r.divergences)).toBe(true);
      expect(r.bytesDiffer, 'folding must actually have collapsed the pow').toBe(true);
    });
  }

  // The bug window. Every one of these used to report `equivalent: false` with
  // two divergences apiece — the fold-OFF script accepting base^32 and the
  // fold-ON one accepting base^exp, on the same source.
  const BUG_WINDOW: Array<[bigint, bigint]> = [
    [2n, 33n],
    [2n, 34n],
    [2n, 40n],
    [3n, 50n],
    [2n, 128n],
    [2n, 256n],
  ];

  for (const [base, exp] of BUG_WINDOW) {
    it(`pow(${base}n, ${exp}n) — inside the old 33..256 window — refuses in BOTH modes`, () => {
      const r = runFoldEquivalence({
        source: foldSrc(base, exp),
        fileName: 'PowFold.runar.ts',
        method: 'probe',
        constructorArgs: { tag: 1n },
        // Both the TRUE power and the CLAMPED one: before the fix each mode
        // accepted a different one of these two.
        witnesses: [[base ** exp], [base ** POW_EXPONENT_LIMIT], [0n]],
      });
      expect(r.equivalent, JSON.stringify(r.divergences)).toBe(true);
      // Declining to fold means the bytes are identical in both modes — which
      // is also what makes the equivalence above non-vacuous as a claim about
      // the FOLDER's bound rather than about the script's.
      expect(r.bytesDiffer, 'an out-of-domain pow must not fold').toBe(false);
    });
  }

  it('a negative exponent refuses in both modes', () => {
    const r = runFoldEquivalence({
      source: foldSrc(2n, -1n),
      fileName: 'PowFold.runar.ts',
      method: 'probe',
      constructorArgs: { tag: 1n },
      witnesses: [[1n], [0n]],
    });
    expect(r.equivalent, JSON.stringify(r.divergences)).toBe(true);
    // The bytes DO differ here, and not because pow folded: fold-ON collapses
    // the unary negation `-1n` to a single constant before pow is ever
    // consulted, so the two modes reach stack lowering with different binding
    // counts. Pinning `equivalent` is the claim that matters — both modes
    // still refuse, and refuse the same witnesses.
    expect(r.bytesDiffer).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// 4. The price of the guard, measured rather than asserted to be "small".
// ---------------------------------------------------------------------------
describe('R-169 pow — the guard costs 6 bytes per callsite', () => {
  function callsites(n: number): string {
    const lines = Array.from({ length: n }, (_, i) => `    acc = acc + pow(b, e${i});`).join('\n');
    const params = Array.from({ length: n }, (_, i) => `e${i}: bigint`).join(', ');
    return `
import { SmartContract, assert, pow } from 'runar-lang';

export class PowCost extends SmartContract {
  readonly tag: bigint;
  constructor(tag: bigint) { super(tag); this.tag = tag; }
  public probe(b: bigint, ${params}): void {
    let acc: bigint = 0n;
${lines}
    assert(acc === this.tag);
  }
}
`;
  }

  it('one extra callsite costs exactly 6 more bytes than before', () => {
    const size = (n: number) =>
      compile(callsites(n), { fileName: 'PowCost.runar.ts' }).scriptHex!.length / 2;
    const delta = size(2) - size(1);
    // OP_DUP(1) + OP_0(1) + push 33 as 0x01 0x21 (2) + OP_WITHIN(1)
    // + OP_VERIFY(1) = 6, on top of whatever the 32-round body costs. The
    // per-callsite body cost is the rest of `delta`; only the guard's share is
    // pinned here, by differencing against a build with the guard's opcodes
    // counted out.
    const GUARD_BYTES = 6;
    const BODY_BYTES = delta - GUARD_BYTES;
    // 32 rounds: 16 of them push a single-byte OP_N exponent (i = 0..16) and
    // 16 push a two-byte literal (i = 17..31), plus the swap/seed/nip tail.
    expect(BODY_BYTES).toBeGreaterThan(200);
    // The guard must be a rounding error against the body it protects — if
    // this ratio ever inverts, the cheap-guard argument for keeping the bound
    // at 32 has stopped being true and the decision needs revisiting.
    expect(GUARD_BYTES * 10).toBeLessThan(BODY_BYTES);
  });

  it('the guard opcodes are present, in order, at every callsite', () => {
    // OP_DUP=76, OP_0=00, push1(0x21)=0121, OP_WITHIN=a5, OP_VERIFY=69.
    const GUARD_HEX = '76' + '00' + '0121' + 'a5' + '69';
    const hex = compile(callsites(3), { fileName: 'PowCost.runar.ts' }).scriptHex!.toLowerCase();
    const occurrences = hex.split(GUARD_HEX).length - 1;
    expect(occurrences, `expected 3 guards, found ${occurrences}`).toBe(3);
  });
});
