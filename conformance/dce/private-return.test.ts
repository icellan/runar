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
import { isCiEnv } from '../anf-interpreter/driver-gate.js';

/**
 * F-108 — dead-code elimination deleted a private helper's RETURN VALUE.
 *
 * A private helper with no output side effect (`add1(n) { return n + 1n; }`)
 * is not inlined at ANF level: it stays its own ANF method, the call site stays
 * a `method_call`, and stack lowering inlines it later, taking the helper's LAST
 * binding as the call's result. Nothing inside the helper references that
 * binding and a `bin_op` is pure, so DCE — which had no "a private method's
 * last binding is live" root — deleted it. The helper was emptied and the
 * contract failed to compile ("value 't2' not found on stack").
 *
 * DCE only runs after an EC rewrite fires (`optimizeEC`'s anyChanged gate), so
 * each fixture carries `ecMulGen(0n)` (EC rule 5) to arm it:
 *
 *   - DcePrivateReturnCaller: the rewrite fires in the CALLER. TS, Rust, Python,
 *     Zig, Ruby and Java DCE every method once anything changed, so they lost
 *     `add1`; Go DCEs only the rewritten method and compiled it.
 *   - DcePrivateReturnHelper: the rewrite fires INSIDE `add1`, which reaches all
 *     seven tiers including Go.
 *
 * The assertion is SEMANTIC: each tier's locking script is EXECUTED. `target`
 * is 6, so the script must accept n=5 and REJECT n=4. The reject case is the
 * negative control: it proves the helper really computes n+1 rather than the
 * script passing vacuously.
 *
 * What this does NOT prove: anything about private helpers whose last binding
 * is something other than the returned value (ANF always puts the returned
 * expression last), or about public methods (whose last binding is never a
 * return value and stays freely eliminable when pure).
 */

const FIXTURES = [
  { file: 'DcePrivateReturnCaller.runar.ts', where: 'EC rewrite in the caller' },
  { file: 'DcePrivateReturnHelper.runar.ts', where: 'EC rewrite inside the helper' },
];

const TIERS: Tier[] = buildSourceTiers();
const available = TIERS.filter((t) => t.cmd !== null);

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

describe('F-108 DCE must not delete a private helper\'s return value', () => {
  // -- vacuity guards -------------------------------------------------------

  it('the matrix names all seven tiers (a silently dropped tier fails here)', () => {
    expect([...TIERS.map((t) => t.id)].sort()).toEqual([...ALL_TIER_IDS]);
  });

  it('every tier is built (strict in CI, ">=2" locally)', () => {
    const missing = missingTierIds(TIERS);
    if (isCiEnv(process.env) || process.env.RUNAR_CONFORMANCE_STRICT) {
      expect(missing, `these tiers have no toolchain: ${missing.join(', ')}`).toEqual([]);
    }
    expect(available.length).toBeGreaterThanOrEqual(2);
  });

  it('the TS reference tier is runnable', () => {
    const ts = TIERS.find((t) => t.id === 'ts');
    expect(ts!.cmd, `TS tier unavailable; REPO=${REPO}`).not.toBeNull();
  });

  // -- the gate itself ------------------------------------------------------

  for (const { file, where } of FIXTURES) {
    const source = join(__dirname, file);
    for (const tier of available) {
      it(`${tier.id}: ${file} (${where}) accepts n=5 and rejects n=4`, () => {
        const hex = compileHex(tier, source);
        const script = hexToBytes(hex);
        const ok = new ScriptVM().execute(pushSmallInt(5), script);
        expect(
          ok.success,
          `${tier.id}: add1(5) === 6 must hold. error=${ok.error ?? '(none)'} ` +
            `script=${hex.length} hex chars.`,
        ).toBe(true);
        const bad = new ScriptVM().execute(pushSmallInt(4), script);
        expect(
          bad.success,
          `${tier.id}: add1(4) === 6 must FAIL — the script accepts a wrong ` +
            `input, so the helper is not computing n + 1.`,
        ).toBe(false);
      });
    }

    it(`${file}: all available tiers emit the same locking script`, () => {
      const byTier = available.map((t) => [t.id, compileHex(t, source)] as const);
      const [firstId, first] = byTier[0]!;
      for (const [id, hex] of byTier) {
        expect(hex, `${id} diverges from ${firstId}`).toBe(first);
      }
    });
  }
});
