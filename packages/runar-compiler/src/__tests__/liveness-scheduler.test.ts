/**
 * Liveness-aware stack scheduling — size and default-invariance.
 *
 * ANF names every intermediate, and the current lowering pushes each result on
 * top of the operands that produced it. In an arithmetic chain that reads the
 * same two values repeatedly, every result buries them one slot deeper, so the
 * next access costs a `push d; OP_PICK` pair instead of a 1-byte `OP_2DUP`.
 * `conformance/tests/arithmetic` spends 16 of its 28 bytes exactly that way.
 *
 * The `liveness` scheduler parks a result on the alt stack when the next
 * binding does not want it, keeping the hot operands at depth 0/1, and
 * restores the whole spill group in one go before the first binding that
 * needs any of it. Restoring en masse puts the values back in production
 * order (first-spilled on top), which is the order an ANF accumulation chain
 * consumes them in.
 *
 * Pinned here: (1) `current` mode is byte-identical to what ships, and
 * (2) `liveness` mode actually shrinks the arithmetic-heavy fixtures.
 * Semantic equivalence is proved on the real interpreter in
 * `packages/runar-testing/src/__tests__/liveness-scheduler-equivalence.test.ts`.
 */

import { describe, it, expect } from 'vitest';
import { readFileSync, existsSync, readdirSync } from 'fs';
import { join, resolve } from 'path';
import { compile } from '../index.js';
import { analyzeScriptHex } from '../metrics/script-metrics.js';

const CONFORMANCE_DIR = join(__dirname, '..', '..', '..', '..', 'conformance', 'tests');

function tsSourceFor(fixture: string): string | null {
  const configFile = join(CONFORMANCE_DIR, fixture, 'source.json');
  if (!existsSync(configFile)) return null;
  const config = JSON.parse(readFileSync(configFile, 'utf-8')) as { sources?: Record<string, string> };
  const rel = config.sources?.['.runar.ts'];
  if (rel === undefined) return null;
  const abs = resolve(CONFORMANCE_DIR, fixture, rel);
  return existsSync(abs) ? abs : null;
}

function hexFor(fixture: string, liveness: boolean): string {
  const path = tsSourceFor(fixture)!;
  const result = compile(readFileSync(path, 'utf-8'), {
    fileName: path,
    disableConstantFolding: true,
    ...(liveness ? { schedulerMode: 'liveness' as const } : {}),
  });
  expect(result.success, result.diagnostics.map(d => d.message).join('; ')).toBe(true);
  return result.scriptHex!;
}

const ALL_FIXTURES = readdirSync(CONFORMANCE_DIR, { withFileTypes: true })
  .filter(e => e.isDirectory())
  .map(e => e.name)
  .filter(name => tsSourceFor(name) !== null
    && existsSync(join(CONFORMANCE_DIR, name, 'expected-script.hex')))
  .sort();

describe('scheduler mode "current" is the shipping default', () => {
  it.each(ALL_FIXTURES)('%s matches its golden', (fixture) => {
    const golden = readFileSync(join(CONFORMANCE_DIR, fixture, 'expected-script.hex'), 'utf-8')
      .replace(/\s+/g, '');
    expect(hexFor(fixture, false)).toBe(golden);
  });
});

describe('scheduler mode "liveness"', () => {
  it('never grows a fixture', () => {
    // A scheduler that trades bytes for bytes is not an optimization. Every
    // spill decision goes through the cost model, so growth is a bug.
    const grew: string[] = [];
    for (const fixture of ALL_FIXTURES) {
      const before = hexFor(fixture, false).length / 2;
      const after = hexFor(fixture, true).length / 2;
      if (after > before) grew.push(`${fixture}: ${before} -> ${after}`);
    }
    expect(grew).toEqual([]);
  });

  it('shrinks the arithmetic fixture by more than 10 %', () => {
    const before = hexFor('arithmetic', false).length / 2;
    const after = hexFor('arithmetic', true).length / 2;
    expect(before).toBe(28);
    expect(1 - after / before).toBeGreaterThan(0.1);
  });

  it('replaces PICK/ROLL traffic with alt-stack round trips on arithmetic', () => {
    const before = analyzeScriptHex(hexFor('arithmetic', false));
    const after = analyzeScriptHex(hexFor('arithmetic', true));
    const shuffle = (m: typeof before) => m.categories['stack-shuffle'];
    expect(shuffle(after)).toBeLessThan(shuffle(before));
    expect(after.opcodes['OP_PICK'] ?? 0).toBeLessThan(before.opcodes['OP_PICK'] ?? 0);
    expect(after.opcodes['OP_TOALTSTACK'] ?? 0).toBeGreaterThan(0);
  });

  it('balances every spill it introduces', () => {
    // A static count is NOT a balance proof on its own: `sha256-finalize`
    // already emits 896 OP_TOALTSTACK against 897 OP_FROMALTSTACK, because
    // one arm of an `if` pushes to the alt stack and the other does not, and
    // both arms are counted. So the invariant is a DELTA one: whatever the
    // scheduler adds must be added in pairs.
    for (const fixture of ALL_FIXTURES) {
      const before = analyzeScriptHex(hexFor(fixture, false));
      const after = analyzeScriptHex(hexFor(fixture, true));
      const to = (after.opcodes['OP_TOALTSTACK'] ?? 0) - (before.opcodes['OP_TOALTSTACK'] ?? 0);
      const from = (after.opcodes['OP_FROMALTSTACK'] ?? 0) - (before.opcodes['OP_FROMALTSTACK'] ?? 0);
      expect(to, `${fixture}: unbalanced spill traffic`).toBe(from);
      expect(to, `${fixture}: negative spill count`).toBeGreaterThanOrEqual(0);
    }
  });
});
