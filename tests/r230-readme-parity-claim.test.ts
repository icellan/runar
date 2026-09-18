/**
 * R-230 (GK-DOC-006): the README claimed every format "produce[s] identical
 * Bitcoin Script", and that all seven compilers "produce byte-identical
 * output", both unqualified.
 *
 * CLAUDE.md states the truth as two SEPARATE invariants, and only the first is
 * unconditional: all seven tiers parse all nine surfaces for every fixture (no
 * exceptions), while Stack-IR/hex parity is SCOPED — a fixture may carry a
 * `"compilers"` allowlist and opt out of tiers. Measured: 4 of the 78 fixtures
 * carry one, all of them `["go"]`, for the Go-only proof-system families.
 *
 * An unqualified claim in the README is the one a reader meets first, and it
 * contradicts the project's own statement of what it guarantees.
 *
 * This test ties the README to the corpus: if a fixture is allowlisted, the
 * README must acknowledge the exception; if the allowlists ever disappear, the
 * qualifier should be revisited rather than left in place.
 */

import { describe, it, expect } from 'vitest';
import { readFileSync, readdirSync, existsSync } from 'node:fs';
import { join, dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..');

function allowlistedFixtures(): string[] {
  const testsDir = join(ROOT, 'conformance', 'tests');
  return readdirSync(testsDir).filter((d) => {
    const src = join(testsDir, d, 'source.json');
    if (!existsSync(src)) return false;
    const json = JSON.parse(readFileSync(src, 'utf8')) as { compilers?: string[] };
    return Array.isArray(json.compilers);
  });
}

describe('R-230: the README parity claim matches the corpus', () => {
  it('acknowledges the tier-scoped exception while allowlisted fixtures exist', () => {
    const allowlisted = allowlistedFixtures();
    const readme = readFileSync(join(ROOT, 'README.md'), 'utf8');

    expect(allowlisted.length, 'no allowlisted fixtures — revisit the README qualifier')
      .toBeGreaterThan(0);

    expect(
      /Go-only by project policy|"compilers": \["go"\]|compilers.*allowlist/i.test(readme),
      'the README claims byte-identical output across all seven compilers without ' +
        `mentioning the ${allowlisted.length} fixtures scoped to one tier: ` +
        allowlisted.join(', '),
    ).toBe(true);
  });

  it('does not restate the unqualified claim', () => {
    const readme = readFileSync(join(ROOT, 'README.md'), 'utf8');
    const offenders = readme
      .split('\n')
      .map((line, i) => ({ line: line.trim(), n: i + 1 }))
      .filter(
        ({ line }) =>
          /produce identical Bitcoin Script/.test(line) ||
          /all produce byte-identical output/.test(line),
      );

    expect(
      offenders.map((o) => `README.md:${o.n}: ${o.line}`),
      'this sentence claims unconditional byte-identity; parity is scoped',
    ).toEqual([]);
  });
});
