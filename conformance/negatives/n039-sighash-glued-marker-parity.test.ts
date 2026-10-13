import { describe, it, expect } from 'vitest';
import { mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { REPO, buildSourceTiers, judge } from './tier-harness.js';

/**
 * N-039 (user decision R85, "Refuse, all 7 tiers") — a comment token that
 * starts with `@sighash` but is not exactly `@sighash <FLAGS>` is a compile
 * error in every tier, with ONE diagnostic.
 *
 * Before this item every tier read `@sighashSINGLE|FORKID` (no space) as prose
 * and silently compiled the method under the default ALL|FORKID: the author
 * asked for SINGLE and got a covenant that commits to every output. F-039 had
 * already made a malformed list after a space-delimited marker an error; the
 * word-boundary rule it kept (`@sighash` + letter/digit/_ is prose) was the
 * remaining hole.
 *
 * What this proves:
 *   - every tier refuses `@sighash` glued to a flag list (block and line
 *     comment), to a word (`@sighashType`) and to `_`, with
 *     `<file>:<line>:<col>: Method 'bump': <F-039 malformed diagnostic>`,
 *     where line/col are the method declaration's start (its `public`), the
 *     column 0-based (N-078, R88a) and computed from the fixture text, never
 *     copied from a compiler;
 *   - every tier still compiles a well-formed `@sighash SINGLE|FORKID` and a
 *     method with no directive, and all seven emit the same hex for it;
 *   - every tier is present (a missing toolchain fails, it is not skipped).
 * What it does NOT prove:
 *   - anything about a `@sighash` outside a method's leading comments (a class,
 *     property or file comment): that is N-199's "lost directive" rule;
 *   - the non-TS surfaces, which refuse a word-bounded `@sighash` with their
 *     own per-tier message and are not touched here;
 *   - the signing mode on-chain: the well-formed control is compared across
 *     tiers, not executed (the sdk-call vector does that under Spend.validate).
 */

const TIERS = buildSourceTiers();
const DIR = join(REPO, 'conformance/negatives');

const MALFORMED =
  "Method 'bump': @sighash: malformed directive; expected `@sighash <FLAGS>` where FLAGS is a |-separated list of ALL, NONE, SINGLE, FORKID, ANYONECANPAY (e.g. `@sighash SINGLE|FORKID`)";

const REFUSED = [
  'N235-ts-sighash-no-space.runar.ts',
  'N236-ts-sighash-no-space-line-comment.runar.ts',
  'N237-ts-sighash-prose-suffix.runar.ts',
  'N238-ts-sighash-underscore-suffix.runar.ts',
];

/** 1-based line and 0-based column of the method declaration (`public bump`). */
function methodStart(fixture: string): { line: number; col: number } {
  const lines = readFileSync(join(DIR, fixture), 'utf8').split('\n');
  const idx = lines.findIndex((l) => /^\s*public bump\(/.test(l));
  if (idx < 0) throw new Error(`${fixture}: no 'public bump(' line`);
  return { line: idx + 1, col: lines[idx]!.indexOf('public') };
}

const escape = (s: string): string => s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');

const accepted = (directive: string): string => `import { StatefulSmartContract } from 'runar-lang';

export class Probe extends StatefulSmartContract {
  count: bigint;
  constructor(count: bigint) { super(count); this.count = count; }
  ${directive}
  public bump() {
    this.addOutput(1000n, this.count);
  }
}
`;

/** The hex a tier printed: the last stdout/stderr line that is pure hex. */
function hexOf(diag: string): string {
  const lines = diag.split('\n').map((l) => l.trim()).filter((l) => /^[0-9a-f]+$/.test(l));
  return lines[lines.length - 1] ?? `<no hex in: ${diag.slice(0, 200)}>`;
}

describe('N-039: every tier refuses a @sighash marker glued to the next token', () => {
  it('has all seven tiers', () => {
    expect(TIERS.filter((t) => t.cmd === null).map((t) => t.id)).toEqual([]);
  });

  for (const fixture of REFUSED) {
    it(`${fixture} -> ${fixture}:<line>:<0-based col of 'public'>: ${MALFORMED.slice(0, 60)}...`, () => {
      const { line, col } = methodStart(fixture);
      const re = new RegExp(escape(`${fixture}:${line}:${col}: ${MALFORMED}`));
      const got: Record<string, string> = {};
      for (const tier of TIERS) {
        const r = judge(tier, join(DIR, fixture));
        got[tier.id] = r.verdict === 'rejected' && re.test(r.diag) ? 'shared diagnostic' : `${r.verdict}: ${r.diag.trim().slice(0, 300)}`;
      }
      expect(got).toEqual(Object.fromEntries(TIERS.map((t) => [t.id, 'shared diagnostic'])));
    }, 900_000);
  }

  for (const [label, directive] of [
    ['a well-formed `@sighash SINGLE|FORKID`', '/** @sighash SINGLE|FORKID */'],
    ['no directive', '/** Bump the counter. */'],
  ] as const) {
    it(`${label} still compiles to the same hex in every tier`, () => {
      const dir = mkdtempSync(join(tmpdir(), 'n039-'));
      const src = join(dir, 'Probe.runar.ts');
      writeFileSync(src, accepted(directive));
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
