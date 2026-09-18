import { describe, it, expect } from 'vitest';
import { join } from 'node:path';
import { ScriptVM } from 'runar-testing';
import {
  ALL_TIER_IDS,
  REPO,
  Tier,
  buildSourceTiers,
  compileHex,
  missingTierIds,
} from '../negatives/tier-harness.js';

/**
 * N-140 — dead-code elimination deleted a LIVE `if`, on all seven tiers.
 *
 * `optimizer/dce.ts` (and its six ports) kept a binding iff
 * `refs.has(binding.name) || hasSideEffect(binding.value)`. An `if` that merges
 * branch locals is a binding named `t<n>` carrying `results: ['a','b']`, with
 * the arms binding `a` and `b`. NOTHING references `t<n>`; later code
 * references `a` and `b`. Both arms are pure `load_const`, so `hasSideEffect`
 * is false. Liveness never considered the names a binding DEFINES, so the whole
 * `OP_IF … OP_ELSE … OP_ENDIF` was deleted and the merged locals kept their
 * initial values.
 *
 * Why this needs its own gate rather than the conformance corpus:
 *
 *   - the defect is IDENTICAL in all seven tiers, so the byte-identity
 *     invariant holds while every tier emits the same unspendable script.
 *     Cross-tier parity cannot see it, by construction.
 *   - it only fires when DCE actually runs, and DCE runs only after an EC
 *     rewrite fires (`optimizeEC`'s `if (!anyChanged) return program`). The
 *     fixture's `ecMulGen(0n)` is what arms it.
 *
 * So the assertion here is SEMANTIC, not comparative: each tier's locking
 * script is EXECUTED. `DceLiveIf.go` leaves `a + b` at 3 or 7 depending on `k`,
 * both strictly positive, so a correct compile succeeds for every `k`. The
 * broken compile evaluates `0 + 0 > 0` and fails for every `k` — 154 hex chars,
 * byte-identical on all seven tiers, no signal anywhere else in the suite.
 */

const SOURCE = join(__dirname, 'DceLiveIf.runar.ts');

const TIERS: Tier[] = buildSourceTiers();
const available = TIERS.filter((t) => t.cmd !== null);

/**
 * Unlocking script: a single minimally-encoded push of `k`.
 *
 * `go` is the only public method, so there is no method selector — the
 * compiled script consumes exactly one stack item. Verified against the
 * pre-fix script, which ends `… OP_ADD OP_0 OP_GREATERTHAN OP_NIP OP_NIP`:
 * two NIPs, one for the point and one for `k`.
 */
function pushSmallInt(n: number): Uint8Array {
  if (n === 0) return new Uint8Array([0x00]); // OP_0
  if (n >= 1 && n <= 16) return new Uint8Array([0x50 + n]); // OP_1..OP_16
  throw new Error(`pushSmallInt: ${n} is outside OP_0..OP_16`);
}

function hexToBytes(hex: string): Uint8Array {
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  return out;
}

/** `k` values that take the then-arm (a+b = 3) and the else-arm (a+b = 7). */
const K_VALUES = [
  { k: 5, arm: 'then (k > 1): a=1, b=2, a+b=3' },
  { k: 0, arm: 'else (k <= 1): a=3, b=4, a+b=7' },
];

describe('N-140 DCE must not delete a live branch', () => {
  // -- vacuity guards -------------------------------------------------------

  it('the matrix names all seven tiers (a silently dropped tier fails here)', () => {
    expect([...TIERS.map((t) => t.id)].sort()).toEqual([...ALL_TIER_IDS]);
  });

  it('every tier is built (strict in CI, ">=2" locally)', () => {
    const missing = missingTierIds(TIERS);
    if (process.env.CI === 'true' || process.env.RUNAR_CONFORMANCE_STRICT) {
      expect(
        missing,
        `these tiers have no toolchain: ${missing.join(', ')}. The matrix ` +
          `would silently shrink and still report PASS.`,
      ).toEqual([]);
    }
    expect(available.length).toBeGreaterThanOrEqual(2);
  });

  it('the fixture compiles at all on the reference tier', () => {
    const ts = TIERS.find((t) => t.id === 'ts');
    expect(ts, 'the TS reference tier is not runnable').toBeDefined();
    expect(ts!.cmd, `TS tier unavailable; REPO=${REPO}`).not.toBeNull();
    expect(compileHex(ts!, SOURCE).length).toBeGreaterThan(0);
  });

  // -- the gate itself ------------------------------------------------------

  for (const tier of available) {
    for (const { k, arm } of K_VALUES) {
      it(`${tier.id}: script is spendable with k=${k} — ${arm}`, () => {
        const hex = compileHex(tier, SOURCE);
        const vm = new ScriptVM();
        const res = vm.execute(pushSmallInt(k), hexToBytes(hex));
        expect(
          res.success,
          `${tier.id} produced a locking script that CANNOT be satisfied with ` +
            `k=${k}. Both arms leave a+b > 0, so the only way this fails is ` +
            `that DCE deleted the live \`if\` and a+b stayed 0. ` +
            `error=${res.error ?? '(none)'} script=${hex.length} hex chars.`,
        ).toBe(true);
      });
    }
  }

  // -- parity, kept as a secondary check ------------------------------------
  //
  // Deliberately NOT the primary assertion: the pre-fix bytes were identical
  // on all seven tiers. Parity proves the tiers agree; only execution proves
  // they agree on something spendable.

  it('all available tiers emit the same locking script', () => {
    const byTier = available.map((t) => [t.id, compileHex(t, SOURCE)] as const);
    const [, first] = byTier[0]!;
    for (const [id, hex] of byTier) {
      expect(hex, `${id} diverges from ${byTier[0]![0]}`).toBe(first);
    }
  });
});
