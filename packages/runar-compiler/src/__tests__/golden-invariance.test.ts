/**
 * Default output is byte-identical to the checked-in goldens.
 *
 * The size experiments in `docs/experiments/` add opt-in flags that change
 * emitted bytes. This is the guard that says the DEFAULT path did not move:
 * every fixture that ships a `.runar.ts`, compiled with the same options the
 * goldens were stamped under (fold-OFF), must reproduce
 * `conformance/tests/<fixture>/expected-script.hex` exactly.
 *
 * `conformance/runner/runner.ts` checks this across all seven tiers in CI, but
 * that needs six native toolchains built. This is the TS-tier-only version that
 * runs anywhere in seconds-to-minutes, so an experiment can be shown to be
 * byte-neutral without a full conformance run.
 */

import { describe, it, expect } from 'vitest';
import { readFileSync, existsSync, readdirSync } from 'fs';
import { join, resolve } from 'path';
import { compile } from '../index.js';

const CONFORMANCE_DIR = join(__dirname, '..', '..', '..', '..', 'conformance', 'tests');

function tsSourceFor(fixture: string): string | null {
  const configFile = join(CONFORMANCE_DIR, fixture, 'source.json');
  if (!existsSync(configFile)) return null;
  const config = JSON.parse(readFileSync(configFile, 'utf-8')) as { sources?: Record<string, string> };
  const rel = config.sources?.['.runar.ts'];
  if (rel === undefined) return null;
  const abs = resolve(CONFORMANCE_DIR, fixture, rel);
  if (!existsSync(abs)) throw new Error(`source.json points at a missing file: ${abs}`);
  return abs;
}

const FIXTURES = readdirSync(CONFORMANCE_DIR, { withFileTypes: true })
  .filter(e => e.isDirectory())
  .map(e => e.name)
  .filter(name => tsSourceFor(name) !== null
    && existsSync(join(CONFORMANCE_DIR, name, 'expected-script.hex')))
  .sort();

describe('default compilation reproduces the goldens', () => {
  it('found the corpus', () => {
    expect(FIXTURES.length).toBeGreaterThan(50);
  });

  it.each(FIXTURES)('%s', (fixture) => {
    const path = tsSourceFor(fixture)!;
    const golden = readFileSync(join(CONFORMANCE_DIR, fixture, 'expected-script.hex'), 'utf-8')
      .replace(/\s+/g, '');
    // Goldens are stamped fold-OFF (CLAUDE.md, CONTRIBUTING.md).
    const result = compile(readFileSync(path, 'utf-8'), {
      fileName: path,
      disableConstantFolding: true,
    });
    expect(result.success, result.diagnostics.map(d => d.message).join('; ')).toBe(true);
    expect(result.scriptHex).toBe(golden);
  });
});
