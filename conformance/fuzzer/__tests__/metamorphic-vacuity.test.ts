/**
 * A metamorphic run that compared NOTHING must not print PASS.
 *
 * `metamorphic-fuzz.ts` ended with an unconditional
 * `console.log('OK: no metamorphic divergences.'); return 0` — no guard on
 * `pairsTested` or `witnessChecks`. Every contract is filtered by
 * `extractMeta`, which needs a public method whose params are all bigint and
 * properties that are all bigint; a generator that drifts away from that shape
 * sends every contract to `skippedNoMeta`, and the nightly job
 * (`fuzzer-nightly.yml`, "Metamorphic fuzz (fixed seed, hard-fail on
 * divergence)") reports OK having executed no pair at all.
 *
 * The sibling `--spend-oracle` lane already refuses that: `vacuousRun` in
 * `index.ts` fails a run in which nothing reached the real engine. This pins
 * the same rule here.
 *
 * It also pins the executor-error counters. The file header promises that a
 * pair which "produces code the compiler rejects" is "skipped and counted";
 * a transformed program that COMPILES and then cannot be executed hit a bare
 * `continue` with no counter at all — and "the transformed program produces a
 * script the engine cannot run" is precisely the regression this fuzzer
 * exists to find.
 */
import { describe, it, expect } from 'vitest';
import { spawnSync } from 'node:child_process';
import { resolve } from 'node:path';

const CONFORMANCE = resolve(__dirname, '../..');
const TSX = resolve(CONFORMANCE, 'node_modules/.bin/tsx');
const DRIVER = resolve(CONFORMANCE, 'fuzzer/metamorphic-fuzz.ts');

function runDriver(args: string[]): { status: number | null; out: string } {
  const r = spawnSync(TSX, [DRIVER, ...args], {
    cwd: CONFORMANCE,
    encoding: 'utf-8',
    timeout: 300_000,
  });
  return { status: r.status, out: `${r.stdout ?? ''}${r.stderr ?? ''}` };
}

describe('metamorphic-fuzz: a run that compared nothing is not a pass', () => {
  it('fails a run in which no transform pair was ever executed', () => {
    // `--num 0` samples no contracts, so nothing is transformed and nothing is
    // executed. Before the guard this printed "OK: no metamorphic divergences."
    // and exited 0.
    const { status, out } = runDriver(['--num', '0', '--seed', '424242']);

    expect(out).toContain('VACUOUS RUN');
    expect(out).not.toContain('OK: no metamorphic divergences.');
    expect(status, out).not.toBe(0);
  }, 300_000);

  it('CONTROL: a real run that did compare things still passes', () => {
    // The guard must not redden a healthy corpus. Six contracts on the fixed
    // seed yield 10 transform pairs and 20 witness comparisons.
    const { status, out } = runDriver([
      '--num', '6',
      '--seed', '424242',
      '--witnesses', '2',
    ]);

    expect(out).toContain('OK: no metamorphic divergences.');
    expect(out).not.toContain('VACUOUS RUN');
    expect(status, out).toBe(0);

    const pairs = /transform pairs tested:\s+(\d+)/.exec(out)?.[1];
    const witnesses = /witness comparisons:\s+(\d+)/.exec(out)?.[1];
    expect(Number(pairs)).toBeGreaterThan(0);
    expect(Number(witnesses)).toBeGreaterThan(0);
  }, 300_000);

  it('reports the executor errors it skips instead of dropping them silently', () => {
    const { out } = runDriver(['--num', '6', '--seed', '424242', '--witnesses', '2']);

    // Both sides of the pair. A transformed program that compiles and then
    // cannot be run is the regression this fuzzer exists to find; a witness the
    // ORIGINAL could not run is equally invisible without a counter.
    expect(out).toMatch(/executor errors \(transformed\):\s+\d+/);
    expect(out).toMatch(/executor errors \(original\):\s+\d+/);
  }, 300_000);
});
