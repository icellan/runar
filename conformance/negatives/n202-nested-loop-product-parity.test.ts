import { describe, it, expect, beforeAll } from 'vitest';
import { mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { Tier, buildSourceTiers, compileHex, judge } from './tier-harness.js';
import { isCiEnv } from '../env.js';

/**
 * N-202 — seven-tier gate for the nested-loop PRODUCT bound on the source path.
 *
 * Every tier's ANF lowering capped each `for` at MAX_LOOP_COUNT (10,000) on its
 * own, so two nested loops of 9,000 (81,000,000 unrolled iterations) passed the
 * check and the compiler ran until killed — Python with no diagnostic at all.
 * F-283 refuses the same nest on the `--ir` path ("... nested inside an
 * enclosing loop of total count E, producing T total iterations ..."), so a
 * source contract compiled while its own emitted IR was refused on replay.
 *
 * Proves, for every available tier: N214 (101 x 100) is refused with the ONE
 * shared diagnostic below; a 9000 x 9000 nest is refused the same way inside
 * the per-tier spawn timeout (a hang is a `BrokenTier` failure, never a stuck
 * run); a nest of exactly 10,000 (100 x 100) still compiles, to the TS
 * reference's bytes.
 * Does not prove: loops reached through a private method call that stack
 * lowering inlines later (the bound is per-method nesting in ANF, the same rule
 * as the `--ir` loaders), or surfaces other than `.runar.ts` (every surface
 * lowers to the same AST `for` node; rejection-parity.test.ts runs N214).
 */

const CASE_TIMEOUT_MS = 600_000;
const N214 = join(__dirname, 'N214-ts-nested-loop-product-over-max.runar.ts');

/** The 9000 x 9000 case gets a tighter per-spawn budget: refusing it is a
 *  front-end decision, so anything near this is already a regression. */
const HANG_BUDGET_MS = 60_000;

const TIERS = buildSourceTiers().filter((t) => t.cmd !== null);
const HANG_TIERS: Tier[] = TIERS.map((t) => ({ ...t, timeoutMs: Math.min(t.timeoutMs, HANG_BUDGET_MS) }));

function productDiag(count: number, enclosing: number): string {
  return (
    `For loop unrolls to ${count} iterations nested inside an enclosing loop of total count ` +
    `${enclosing}, producing ${count * enclosing} total iterations, exceeding the maximum loop ` +
    `count of 10000.`
  );
}

function nestedSource(outer: number, inner: number): string {
  return `import { SmartContract, assert } from 'runar-lang';

class NestedLoops extends SmartContract {
  readonly a: bigint;

  constructor(a: bigint) {
    super(a);
    this.a = a;
  }

  public go(x: bigint) {
    let s: bigint = 0n;
    for (let i = 0n; i < ${outer}n; i++) {
      for (let j = 0n; j < ${inner}n; j++) {
        s = s + x;
      }
    }
    assert(s > this.a);
  }
}
`;
}

let dir = '';
beforeAll(() => {
  dir = mkdtempSync(join(tmpdir(), 'n202-nested-loop-'));
});

function write(name: string, text: string): string {
  const p = join(dir, `${name}.runar.ts`);
  writeFileSync(p, text);
  return p;
}

describe('N-202 seven-tier nested-loop product bound (source path)', () => {
  it('at least two tiers are available (all seven in CI)', () => {
    expect(TIERS.length).toBeGreaterThanOrEqual(2);
    if (isCiEnv(process.env)) expect(TIERS.length).toBe(7);
  });

  it('N214 (101 x 100): every tier refuses with the shared product diagnostic', () => {
    for (const tier of TIERS) {
      const { verdict, diag } = judge(tier, N214);
      expect(verdict, `${tier.id} accepted N214`).toBe('rejected');
      expect(diag, `${tier.id} refused N214 for another reason`).toContain(productDiag(100, 101));
    }
  }, CASE_TIMEOUT_MS);

  it('9000 x 9000: every tier refuses promptly instead of unrolling 81,000,000 iterations', () => {
    const file = write('Nested9000', nestedSource(9000, 9000));
    for (const tier of HANG_TIERS) {
      const { verdict, diag } = judge(tier, file);
      expect(verdict, `${tier.id} accepted 9000 x 9000`).toBe('rejected');
      expect(diag, `${tier.id} refused 9000 x 9000 for another reason`).toContain(productDiag(9000, 9000));
    }
  }, CASE_TIMEOUT_MS);

  it('100 x 100 (exactly MAX_LOOP_COUNT): every tier compiles it to the TS bytes', () => {
    const file = write('Nested100', nestedSource(100, 100));
    const ts = TIERS.find((t) => t.id === 'ts');
    expect(ts, 'the TS reference tier is required').toBeDefined();
    const want = compileHex(ts!, file);
    for (const tier of TIERS) {
      expect(compileHex(tier, file), `${tier.id} on 100 x 100`).toBe(want);
    }
  }, CASE_TIMEOUT_MS);
});
