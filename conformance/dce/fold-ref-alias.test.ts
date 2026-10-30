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
import { isCiEnv } from '../env.js';

/**
 * N-397 — the constant folder did not see through `@ref:` alias bindings, so a
 * named `const` local defeated folding.
 *
 * `const seven = 7n` lowers to `t0 = 7; seven = @ref:t0`. Every tier's folder
 * skipped `@ref:` values outright, so `seven` was never known to be 7 and
 * `seven / 2n` stayed a runtime OP_DIV: fold-ON emitted exactly the fold-OFF
 * bytes (`57 52 96 9c` and `57 78 52 52 79 7c 96 a2 69 9f` below), while the
 * literal `7n / 2n` folds to `53 9c`. The other half of the finding — fold-ON
 * longer than fold-OFF for `7n / 2n` because the orphaned operands survived —
 * was already closed by the N-138 prune; the first fixture pins it.
 *
 * What this proves: under the default fold-ON compile every tier folds through
 * the alias, the bytes are identical across all seven tiers and are the pinned
 * short form (never longer than fold-OFF), an alias that stays LIVE after the
 * fold still pushes its value, an alias folded inside an `if` arm still
 * reaches the arm's merge block, fold-OFF bytes are unchanged, and each script
 * executes with the source's semantics for accepting and rejecting `p`.
 *
 * What it does not prove: that every aliasing shape folds (aliases inside
 * loop bodies, aliases of byte strings), nor that no other fold
 * leaves fold-ON longer than fold-OFF — the fold-ON fuzz campaign
 * (`conformance/fuzzer --ir --hex --fold-on`) is the broad check.
 */

const FIXTURES = [
  {
    file: 'FoldDivLiteral.runar.ts',
    foldOff: '5752969c',
    // Already short before N-397 (the N-138 prune); pinned so it stays so.
    foldOn: '539c',
    spends: [
      { p: 3, ok: true },
      { p: 2, ok: false },
      { p: 4, ok: false },
      { p: -3, ok: false },
    ],
  },
  {
    file: 'FoldRefAlias.runar.ts',
    foldOff: '5752969c',
    // Pre-fix fold-ON: 5752969c (identical to fold-OFF — nothing folded).
    foldOn: '539c',
    spends: [
      { p: 3, ok: true },
      { p: 2, ok: false },
      { p: 4, ok: false },
      { p: 7, ok: false },
    ],
  },
  {
    file: 'FoldRefAliasLive.runar.ts',
    foldOff: '57785252797c96a2699f',
    // Pre-fix fold-ON: 57785252797c96a2699f. `seven` stays live (`p < seven`)
    // and still pushes 7; only `seven / 2n` folds to 3.
    foldOn: '577853a2699f',
    spends: [
      { p: 3, ok: true },
      { p: 4, ok: true },
      { p: 6, ok: true },
      { p: 2, ok: false },
      { p: 7, ok: false },
      { p: 0, ok: false },
    ],
  },
  {
    file: 'FoldRefAliasInArm.runar.ts',
    foldOff: '517800a0635552795152797c939f696776687793528fa0',
    // Pre-fix fold-ON: 517800a0635552795152797c939f6967766877930182a0. In the
    // then arm `x + 1n` now folds to 6 (`56 9f`); `x` still reaches the merge.
    foldOn: '517800a063555279569f6967766877930182a0',
    spends: [
      { p: 1, ok: true },
      { p: 5, ok: true },
      { p: 0, ok: true },
      { p: -2, ok: true },
      { p: 6, ok: false },
      { p: -3, ok: false },
    ],
  },
];

const TIERS: Tier[] = buildSourceTiers();
const available = TIERS.filter((t) => t.cmd !== null);

function foldOff(tier: Tier): Tier {
  return { ...tier, argsFor: (s) => [...tier.argsFor(s), '--disable-constant-folding'] };
}

/** Minimal script-number push of `n`, as an unlocking script. */
function pushInt(n: number): Uint8Array {
  if (n === 0) return new Uint8Array([0x00]);
  if (n === -1) return new Uint8Array([0x4f]);
  if (n >= 1 && n <= 16) return new Uint8Array([0x50 + n]);
  const neg = n < 0;
  let a = Math.abs(n);
  const bytes: number[] = [];
  while (a > 0) {
    bytes.push(a & 0xff);
    a >>= 8;
  }
  if (bytes[bytes.length - 1]! & 0x80) bytes.push(neg ? 0x80 : 0x00);
  else if (neg) bytes[bytes.length - 1]! |= 0x80;
  return new Uint8Array([bytes.length, ...bytes]);
}

function hexToBytes(hex: string): Uint8Array {
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  return out;
}

describe('N-397 fold-ON: the folder sees through @ref: aliases', () => {
  it('the matrix names all seven tiers (a silently dropped tier fails here)', () => {
    expect([...TIERS.map((t) => t.id)].sort()).toEqual([...ALL_TIER_IDS]);
  });

  it('every tier is built (strict in CI, ">=2" locally)', () => {
    const missing = missingTierIds(TIERS);
    if (isCiEnv(process.env) || process.env.RUNAR_CONFORMANCE_STRICT) {
      expect(missing, `these tiers have no toolchain: ${missing.join(', ')}`).toEqual([]);
    }
    expect(available.length, `REPO=${REPO}`).toBeGreaterThanOrEqual(2);
  });

  for (const { file, foldOff: offHex, foldOn: onHex, spends } of FIXTURES) {
    const source = join(__dirname, file);
    for (const tier of available) {
      it(`${tier.id}: ${file} fold-ON is not longer than fold-OFF`, () => {
        expect(compileHex(tier, source).length).toBeLessThanOrEqual(
          compileHex(foldOff(tier), source).length,
        );
      });

      it(`${tier.id}: ${file} compiles fold-ON to the folded script`, () => {
        expect(compileHex(tier, source)).toBe(onHex);
      });

      it(`${tier.id}: ${file} fold-OFF bytes are unchanged`, () => {
        expect(compileHex(foldOff(tier), source)).toBe(offHex);
      });

      it(`${tier.id}: ${file} executes with the source's semantics`, () => {
        const lock = hexToBytes(compileHex(tier, source));
        for (const { p, ok } of spends) {
          const res = new ScriptVM().execute(pushInt(p), lock);
          expect(res.success, `${tier.id} ${file} p=${p} error=${res.error ?? '(none)'}`).toBe(ok);
        }
      });
    }
  }
});
