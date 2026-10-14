import { describe, it, expect } from 'vitest';
import { mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { REPO, buildSourceTiers, judge } from './tier-harness.js';

/**
 * N-199 (user decision R75, "Refuse, all 7 tiers") — a `@sighash` /
 * `@embedAlways` directive inside the contract class body that attaches to no
 * member is a compile error in every tier, with ONE diagnostic, located at the
 * marker's `@`.
 *
 * ts-morph never attaches a comment that shares a line with the preceding
 * token (it is that token's trailing trivia), and F-282 made every tier follow
 * that rule — so `bump() {...} // @sighash SINGLE|FORKID` above a public method
 * compiled in all seven tiers under the default ALL|FORKID, with no
 * diagnostic. "Attached" means: in the leading comments of a method (for
 * `@sighash`) or of a property (for `@embedAlways`), the member kind that
 * reads the directive.
 *
 * What this proves:
 *   - every tier refuses a lost directive in four class-body positions
 *     (N262 same-line after a method, N263 above the constructor, N264
 *     `@embedAlways` same-line after a property, N265 inside a method body)
 *     with `<file>:<line>:<col>: <shared message>`, where line is 1-based and
 *     col 0-based, both computed here from the fixture text, never copied
 *     from a compiler;
 *   - every tier still compiles a contract whose header and class doc
 *     comments mention both markers as prose (outside the class braces) and
 *     whose directives are attached, and all seven emit the same hex for it;
 *   - every tier is present (a missing toolchain fails, it is not skipped).
 * What it does NOT prove:
 *   - anything about a marker OUTSIDE the class body: that is prose by design
 *     (shipped fixtures and examples document the directives in their header
 *     comments) and is not scanned;
 *   - an attached directive the member ignores (e.g. `@embedAlways` on a
 *     mutable property) — the directive is attached, so R75 does not apply;
 *   - the non-TS surfaces, which refuse any marker (N-244 / N-268 gates);
 *   - column units for non-ASCII text before the marker on its line (byte vs
 *     UTF-16 columns differ by tier); every fixture here is ASCII.
 */

const TIERS = buildSourceTiers();
const DIR = join(REPO, 'conformance/negatives');

const lost = (directive: '@sighash' | '@embedAlways'): string => {
  const target = directive === '@sighash' ? 'method' : 'property';
  return `${directive} directive is not attached to any ${target} and would be silently ignored; put the comment on its own line directly above the ${target} it annotates (a comment that shares a line with the preceding code belongs to that code)`;
};

const REFUSED: Array<[string, '@sighash' | '@embedAlways']> = [
  ['N262-ts-sighash-lost-same-line.runar.ts', '@sighash'],
  ['N263-ts-sighash-lost-before-constructor.runar.ts', '@sighash'],
  ['N264-ts-embedalways-lost-same-line.runar.ts', '@embedAlways'],
  ['N265-ts-sighash-lost-in-method-body.runar.ts', '@sighash'],
];

/** 1-based line and 0-based column of the (only) marker in the fixture. */
function markerAt(fixture: string, marker: string): { line: number; col: number } {
  const text = readFileSync(join(DIR, fixture), 'utf8');
  const idx = text.indexOf(marker);
  if (idx < 0 || text.indexOf(marker, idx + 1) >= 0) throw new Error(`${fixture}: want exactly one ${marker}`);
  const before = text.slice(0, idx);
  return { line: before.split('\n').length, col: idx - (before.lastIndexOf('\n') + 1) };
}

const escape = (s: string): string => s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');

const CONTROL = `import { StatefulSmartContract } from 'runar-lang';
// Header prose: this contract uses @sighash SINGLE|FORKID and @embedAlways.
/** Class doc: \`@sighash\` sits on bump, \`@embedAlways\` on tag. */
export class Probe extends StatefulSmartContract {
  count: bigint;
  /** @embedAlways */
  readonly tag: bigint;
  constructor(count: bigint, tag: bigint) { super(count, tag); this.count = count; this.tag = tag; }
  public grow(): void { this.addOutput(1000n, this.count + 1n); }
  // @sighash SINGLE|FORKID
  public bump(): void {
    this.addOutput(1000n, this.count);
  }
}
`;

/** The hex a tier printed: the last stdout/stderr line that is pure hex. */
function hexOf(diag: string): string {
  const lines = diag.split('\n').map((l) => l.trim()).filter((l) => /^[0-9a-f]+$/.test(l));
  return lines[lines.length - 1] ?? `<no hex in: ${diag.slice(0, 200)}>`;
}

describe('N-199: every tier refuses a directive that attaches to no member', () => {
  it('has all seven tiers', () => {
    expect(TIERS.filter((t) => t.cmd === null).map((t) => t.id)).toEqual([]);
  });

  for (const [fixture, directive] of REFUSED) {
    it(`${fixture} -> ${fixture}:<line>:<col of ${directive}>: lost-directive diagnostic`, () => {
      const { line, col } = markerAt(fixture, directive);
      const re = new RegExp(escape(`${fixture}:${line}:${col}: ${lost(directive)}`));
      const got: Record<string, string> = {};
      for (const tier of TIERS) {
        const r = judge(tier, join(DIR, fixture));
        got[tier.id] = r.verdict === 'rejected' && re.test(r.diag) ? 'shared diagnostic' : `${r.verdict}: ${r.diag.trim().slice(0, 300)}`;
      }
      expect(got).toEqual(Object.fromEntries(TIERS.map((t) => [t.id, 'shared diagnostic'])));
    }, 900_000);
  }

  it('prose outside the class body plus attached directives compiles to the same hex in every tier', () => {
    const dir = mkdtempSync(join(tmpdir(), 'n199-'));
    const src = join(dir, 'Probe.runar.ts');
    writeFileSync(src, CONTROL);
    const got: Record<string, string> = {};
    for (const tier of TIERS) {
      const r = judge(tier, src);
      got[tier.id] = r.verdict === 'accepted' ? hexOf(r.diag) : `rejected: ${r.diag.trim().slice(0, 300)}`;
    }
    const reference = got.ts!;
    expect(reference).toMatch(/^[0-9a-f]+$/);
    expect(got).toEqual(Object.fromEntries(TIERS.map((t) => [t.id, reference])));
  }, 900_000);
});
