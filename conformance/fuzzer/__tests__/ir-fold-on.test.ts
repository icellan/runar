/**
 * N-399 — `--ir` (contract-level) fuzzing had no fold-ON mode.
 *
 * Every tier was invoked with `--disable-constant-folding` (and the TS tier
 * with `disableConstantFolding: true`), so cross-tier fold-ON parity was only
 * fuzzed by `--anf --fold-on`, on straight-line programs. A contract with an
 * `if` or a loop was never compared fold-ON across tiers by any fuzz mode.
 * `--ir --hex --fold-on` now omits the flag in every tier.
 *
 * PROVES:
 *   - `sourceArgs` (the argv tail all six native tiers receive) carries
 *     `--disable-constant-folding` when folding is off and omits it when on;
 *   - the real harness (real generator with branches/loops, real in-process TS
 *     tier) run fold-ON at a fixed seed reports a non-zero count of programs
 *     whose bytes folding changed, and 0 when run fold-OFF, so the counter is
 *     not a constant;
 *   - fold-ON with the ANF-depth compare is refused.
 * DOES NOT PROVE: anything about the six native binaries (none runs here; the
 * campaign and CI gates run them), that the folded bytes are correct, or that
 * the generated corpus reaches every fold rule.
 */
import { describe, it, expect } from 'vitest';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { runIRDifferentialFuzzing, sourceArgs } from '../ir-differential.js';

describe('ir-differential: fold-ON mode (N-399)', () => {
  it('fold-OFF argv keeps --disable-constant-folding', () => {
    expect(sourceArgs('f.runar.ts', true, true)).toEqual([
      '--source', 'f.runar.ts', '--hex', '--disable-constant-folding',
    ]);
    expect(sourceArgs('f.runar.ts', false, true)).toEqual([
      '--source', 'f.runar.ts', '--emit-ir', '--disable-constant-folding',
    ]);
  });

  it('fold-ON argv omits --disable-constant-folding', () => {
    expect(sourceArgs('f.runar.ts', true, false)).toEqual(['--source', 'f.runar.ts', '--hex']);
  });

  it('the harness folds in fold-ON mode and not in fold-OFF mode (TS tier, real generator)', async () => {
    const dir = mkdtempSync(join(tmpdir(), 'n399-'));
    try {
      const base = {
        seed: 42,
        compilers: ['ts' as const],
        compareHex: true,
        includeStateful: true,
        findingsDir: dir,
        requireTiers: [] as const,
      };
      const off = await runIRDifferentialFuzzing(60, { ...base, disableConstantFolding: true });
      const on = await runIRDifferentialFuzzing(60, { ...base, disableConstantFolding: false });
      expect(off.foldedPrograms).toBe(0);
      expect(on.foldedPrograms).toBeGreaterThan(0);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  }, 120_000);

  it('refuses fold-ON with the ANF-depth compare', async () => {
    await expect(
      runIRDifferentialFuzzing(1, { compilers: ['ts'], compareHex: false, disableConstantFolding: false, requireTiers: [] }),
    ).rejects.toThrow(/fold-ON requires compareHex/);
  });
});
