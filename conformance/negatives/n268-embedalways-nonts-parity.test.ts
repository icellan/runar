import { describe, it, expect } from 'vitest';
import { mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { basename, join } from 'node:path';
import { REPO, buildSourceTiers, judge } from './tier-harness.js';

/**
 * N-268 — the same shape N-244 fixed for `@sighash`, applied to
 * `@embedAlways`. `@embedAlways` is honoured only on the `.runar.ts` surface;
 * the eight other surfaces refuse it because their parsers drop comments.
 * Unlike `@sighash` (N-244), `@embedAlways` was already correctly
 * word-boundary matched (`\b`) in every tier — the defect here is narrower:
 * the REFUSAL TEXT itself differed per tier. TypeScript, Go, Rust and Python
 * already shared one message (`@embedAlways directive (issue #109) is not
 * supported by the <Surface> surface parser; write the contract in
 * TypeScript (.runar.ts) where @embedAlways is honoured`), but Zig, Ruby and
 * Java each spoke their own: Zig said "is only honoured on the TypeScript
 * (.runar.ts) surface", Ruby said "is not supported by the Ruby compiler for
 * this format" (hardcoding "Ruby" regardless of which non-TS surface actually
 * triggered it), and Java said "is only supported on the .runar.ts surface".
 *
 * What this proves:
 *   - for each of the eight non-TS surfaces, every tier refuses a readonly
 *     field carrying an `@embedAlways` comment, and the diagnostic carries
 *     the ONE shared message `@embedAlways directive (issue #109) is not
 *     supported by the <Surface> surface parser; ...` with the same surface
 *     name in all seven tiers;
 *   - every fixture is otherwise valid: with the marker replaced by plain
 *     prose, the annotated field becomes an ordinary unreferenced readonly
 *     field that every tier eliminates by DCE, and all seven tiers emit the
 *     same hex, so the refusal is the guard's and nothing else's;
 *   - every tier is present (a missing toolchain fails, it is not skipped).
 * What it does NOT prove:
 *   - anything about `.runar.ts`, which honours the directive;
 *   - anything about `@sighash`, whose guard N-244 already fixed;
 *   - where the guard sits in each tier's pipeline beyond "before a script is
 *     emitted": the CLIs expose only the final verdict and diagnostic.
 */

const TIERS = buildSourceTiers();
const DIR = join(REPO, 'conformance/negatives');

const MARKER = '@embedAlways';

const FIXTURES: ReadonlyArray<readonly [string, string]> = [
  ['N254-sol-embedalways.runar.sol', 'Solidity'],
  ['N255-move-embedalways.runar.move', 'Move'],
  ['N256-py-embedalways.runar.py', 'Python'],
  ['N257-go-embedalways.runar.go', 'Go DSL'],
  ['N258-rs-embedalways.runar.rs', 'Rust'],
  ['N259-zig-embedalways.runar.zig', 'Zig'],
  ['N260-rb-embedalways.runar.rb', 'Ruby'],
  ['N261-java-embedalways.runar.java', 'Java'],
];

const message = (surface: string): string =>
  `@embedAlways directive (issue #109) is not supported by the ${surface} surface parser; write the contract in TypeScript (.runar.ts) where @embedAlways is honoured`;

/** The fixture with its marker comment replaced by prose, written under its
 *  own file name (the extension selects the surface) in a fresh temp
 *  directory. */
function variant(fixture: string, replacement: string): string {
  const text = readFileSync(join(DIR, fixture), 'utf8');
  if (text.split(MARKER).length !== 2) throw new Error(`${fixture}: expected exactly one '${MARKER}'`);
  const dir = mkdtempSync(join(tmpdir(), 'n268-'));
  const out = join(dir, basename(fixture));
  writeFileSync(out, text.replace(MARKER, replacement));
  return out;
}

/** The hex a tier printed: the last stdout/stderr line that is pure hex. */
function hexOf(diag: string): string {
  const lines = diag.split('\n').map((l) => l.trim()).filter((l) => /^[0-9a-f]+$/.test(l));
  return lines[lines.length - 1] ?? `<no hex in: ${diag.slice(0, 200)}>`;
}

describe('N-268: every tier refuses an @embedAlways marker on every non-TS surface, with one message', () => {
  it('has all seven tiers', () => {
    expect(TIERS.filter((t) => t.cmd === null).map((t) => t.id)).toEqual([]);
  });

  for (const [fixture, surface] of FIXTURES) {
    it(`${fixture} -> ${message(surface).slice(0, 80)}...`, () => {
      const src = join(DIR, fixture);
      const got: Record<string, string> = {};
      for (const tier of TIERS) {
        const r = judge(tier, src);
        got[tier.id] =
          r.verdict === 'rejected' && r.diag.includes(message(surface))
            ? 'shared diagnostic'
            : `${r.verdict}: ${r.diag.trim().slice(0, 300)}`;
      }
      expect(got).toEqual(Object.fromEntries(TIERS.map((t) => [t.id, 'shared diagnostic'])));
    }, 900_000);

    it(`${fixture} with the marker replaced by prose compiles to the same hex in every tier`, () => {
      const src = variant(fixture, 'Deploy-time metadata.');
      const got: Record<string, string> = {};
      for (const tier of TIERS) {
        const r = judge(tier, src);
        got[tier.id] = r.verdict === 'accepted' ? hexOf(r.diag) : `rejected: ${r.diag.trim().slice(0, 300)}`;
      }
      const reference = got.ts!;
      expect(reference).toMatch(/^[0-9a-f]+$/);
      expect(got).toEqual(Object.fromEntries(TIERS.map((t) => [t.id, reference])));
    }, 900_000);
  }
});
