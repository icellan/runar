/**
 * R-209 (CL-GAP-046): `@embedAlways` and the `@sighash` directive — both real
 * compiler features, one of them broken in four tiers (CL-BUG-021) — have ZERO
 * example usage anywhere.
 *
 * Confirmed before the fix. Neither directive appeared in `examples/`, in
 * `docs/`, in `spec/`, or in any conformance fixture. Every occurrence in the
 * repo was inside the compilers themselves or their own unit tests, so the only
 * way to discover either feature was to read the implementation.
 *
 * This test is the guard, not the example. It requires that both directives
 * stay reachable from the two places a user actually looks — a worked example
 * and the language reference — so they cannot drift back into being
 * implementation-only.
 */

import { describe, it, expect } from 'vitest';
import { execSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { join, dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const DIRECTIVES = ['@embedAlways', '@sighash'] as const;

/**
 * Contract files under `dir` that mention `needle`.
 *
 * Scoped to `*.runar.*` via `find` rather than grepping the whole tree: a bare
 * `grep -rl examples/` walks node_modules and Gradle build output and took ~28
 * seconds per call.
 */
function mentions(dir: string, needle: string): string[] {
  const out = execSync(
    `find ${dir} -name '*.runar.*' -not -path '*/node_modules/*' -not -path '*/build/*' ` +
      `-exec grep -l -- ${JSON.stringify(needle)} {} + 2>/dev/null || true`,
    { cwd: ROOT, encoding: 'utf-8' },
  );
  return out.trim().split('\n').filter(Boolean);
}

describe('R-209: both compiler directives have a worked example and are documented', () => {
  for (const directive of DIRECTIVES) {
    it(`${directive} appears in a contract under examples/`, () => {
      const hits = mentions('examples', directive);
      expect(
        hits,
        `${directive} is a shipped compiler feature with no example contract using it`,
      ).not.toEqual([]);
    });

    it(`${directive} is described in the language reference`, () => {
      const ref = readFileSync(join(ROOT, 'docs/language-reference.md'), 'utf-8');
      expect(
        ref.includes(directive),
        `${directive} is absent from docs/language-reference.md`,
      ).toBe(true);
    });
  }

  it('the example is exercised by a test, not just parked in the tree', () => {
    // An example nobody runs rots. The directives example carries its own
    // falsifications; this only checks the test file exists and names both.
    const test = readFileSync(
      join(ROOT, 'examples/ts/compiler-directives/Directives.test.ts'),
      'utf-8',
    );
    for (const directive of DIRECTIVES) {
      expect(test, `the example's test never mentions ${directive}`).toContain(directive);
    }
  });

  it('the directives section names the surface restriction', () => {
    // Both are `.runar.ts`-only and the other eight parsers REJECT them. A user
    // who copies the directive into a .runar.py file gets a parse error, so the
    // reference has to say so.
    const ref = readFileSync(join(ROOT, 'docs/language-reference.md'), 'utf-8');
    const section = ref.slice(ref.indexOf('## Compiler Directives'));
    expect(section, 'the reference does not say the directives are TS-surface only').toMatch(
      /\.runar\.ts/,
    );
  });
});
