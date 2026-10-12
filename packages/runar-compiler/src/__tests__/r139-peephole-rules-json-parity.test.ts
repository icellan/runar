import { describe, it, expect } from 'vitest';
import { readFileSync, readdirSync } from 'node:fs';
import { resolve, extname, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { loadPeepholeRules, ruleNames } from '../optimizer/rule-loader.js';
import { PEEPHOLE_RULES } from '../optimizer/peephole-rules.js';

/**
 * R-139 / CL-BUG-018 — `optimizer/peephole-rules.json` shipped the naive 2-op
 * `OP_NOT OP_NOT → []` elimination that the C17 fix replaced.
 *
 * `OP_NOT OP_NOT` is boolean NORMALISATION, not numeric identity: on a
 * non-canonical operand (5, say) the pair yields 1 while deleting it leaves 5.
 * Both implementations know this — the TS table matches the 3-op
 * `OP_NUMEQUAL OP_NOT OP_NOT` window and `compilers/go/codegen/optimizer.go`
 * carries the same guard with `producesCanonicalBool` — and the JSON, which
 * presents itself as "the canonical rule definition shared across all four
 * compilers", still declared the unguarded pair.
 *
 * Nothing read the file: `grep -rn peephole-rules.json` outside the audit
 * artefacts matches only `rule-loader.ts`, whose three exports had no callers
 * anywhere in the repo (CL-GAP-005 / R-235). A rule table that claims to be the
 * porting source of truth and is validated by nothing is how the stale rule
 * survived the C17 fix — and the next tier ported from it would have
 * reintroduced an unsound elimination.
 *
 * This test is that validation, and it is also what makes the loader live.
 * It compares OP SHAPE rather than literals: the JSON const-fold family uses
 * symbolic `$a`/`$b` where the TS table carries representative constants for
 * its sweep harness, so literal equality would be noise. Op count and opcode
 * codes are what the not-not drift actually changed — 2 ops to 3.
 */

/** Op kinds and opcode codes only; literals and depths are deliberately out. */
type Op = { op: string; code?: string };
const shape = (ops: readonly Op[]): string =>
  ops.map((o) => (o.code ? `${o.op}:${o.code}` : o.op)).join(' ');

const jsonRules = loadPeepholeRules();
const tsRules = PEEPHOLE_RULES as unknown as Array<{
  name: string;
  pattern: Op[];
  replacement: Op[];
}>;

describe('R-139 optimizer/peephole-rules.json matches the implemented table', () => {
  it('the loader returns a non-empty rule set (a silently empty file proves nothing)', () => {
    expect(jsonRules.length).toBeGreaterThanOrEqual(20);
    expect(ruleNames().length).toBe(jsonRules.length);
  });

  it('declares the same number of rules as the TS implementation', () => {
    expect(jsonRules.length).toBe(tsRules.length);
  });

  it('every JSON rule has a TS rule with the same pattern AND replacement shape', () => {
    const tsByShape = new Map<string, string>();
    for (const r of tsRules) {
      tsByShape.set(`${shape(r.pattern)} => ${shape(r.replacement)}`, r.name);
    }
    const orphans = jsonRules
      .map((r) => ({
        name: r.name,
        key: `${shape(r.match as Op[])} => ${shape(r.replace as Op[])}`,
      }))
      .filter((r) => !tsByShape.has(r.key));
    expect(
      orphans,
      `these JSON rules match no implemented rule:\n` +
        orphans.map((o) => `  ${o.name}: ${o.key}`).join('\n') +
        `\nThe JSON is the porting source of truth; a rule here that no tier ` +
        `implements is a rule the next tier will implement wrongly.`,
    ).toEqual([]);
  });

  it('every implemented rule is declared in the JSON — no silent extras either', () => {
    const jsonShapes = new Set(
      jsonRules.map((r) => `${shape(r.match as Op[])} => ${shape(r.replace as Op[])}`),
    );
    const undeclared = tsRules
      .map((r) => ({ name: r.name, key: `${shape(r.pattern)} => ${shape(r.replacement)}` }))
      .filter((r) => !jsonShapes.has(r.key));
    expect(
      undeclared,
      `these implemented rules are absent from the JSON:\n` +
        undeclared.map((o) => `  ${o.name}: ${o.key}`).join('\n'),
    ).toEqual([]);
  });

  it('the not-not rule is the GUARDED 3-op form, in both places', () => {
    const json = jsonRules.find((r) => /not-not/.test(r.name));
    expect(json, 'the not-not rule vanished from the JSON').toBeDefined();
    expect(
      shape(json!.match as Op[]),
      'the JSON is back to the unguarded 2-op OP_NOT OP_NOT elimination, which ' +
        'deletes the pair on a non-canonical operand and changes the value',
    ).toBe('opcode:OP_NUMEQUAL opcode:OP_NOT opcode:OP_NOT');
    expect(shape(json!.replace as Op[])).toBe('opcode:OP_NUMEQUAL');

    const ts = tsRules.find((r) => r.name === 'not-not-elim');
    expect(shape(ts!.pattern)).toBe('opcode:OP_NUMEQUAL opcode:OP_NOT opcode:OP_NOT');
  });

  it('no rule deletes a bare OP_NOT OP_NOT pair', () => {
    const unguarded = jsonRules.filter(
      (r) => shape(r.match as Op[]) === 'opcode:OP_NOT opcode:OP_NOT',
    );
    expect(unguarded.map((r) => r.name)).toEqual([]);
  });
});

/**
 * F-364 / CX-DOC-002 — rule-loader.ts's header said the JSON is "the canonical
 * rule definition shared across all four compilers." The repo now has seven
 * compiler tiers.
 *
 * "Loads the rules file" is itself misleading: only this TS loader reads
 * peephole-rules.json (see the describe block above — it has no other
 * caller). What the header actually means, and what the recommended
 * remediation asks for, is "tiers that procedurally MIRROR the table" — each
 * native tier reimplements the same rules in its own optimizer rather than
 * reading this JSON at runtime. This test counts mirrors, not readers: it
 * walks each compilers/<tier> directory for a non-test source file named
 * "optimizer" or "peephole" (the procedural implementation), does the same
 * for this TS tier's own optimizer directory, and checks the header's
 * claimed count against that discovered total instead of a hardcoded
 * number.
 *
 * It does NOT prove every discovered tier's rules actually match the JSON
 * byte-for-byte — only the TS table is held to that by the describe block
 * above (R-139). A tier could carry an optimizer file whose rules have
 * drifted from the JSON; that is a separate, undetected gap this test does
 * not close.
 */
describe('F-364 rule-loader.ts header names the actual mirrored-tier count', () => {
  const __dirname = dirname(fileURLToPath(import.meta.url));
  const REPO_ROOT = resolve(__dirname, '..', '..', '..', '..');
  const RULE_LOADER_SRC = resolve(REPO_ROOT, 'packages/runar-compiler/src/optimizer/rule-loader.ts');
  const COMPILERS_DIR = resolve(REPO_ROOT, 'compilers');
  const TS_OPTIMIZER_DIR = resolve(REPO_ROOT, 'packages/runar-compiler/src/optimizer');

  const SKIP_DIRS = new Set([
    'node_modules', '.git', 'build', '.gradle', 'target', '__pycache__',
    '.zig-cache', 'zig-cache', 'zig-out', 'dist', 'test', 'tests',
    '__tests__', 'spec', '.venv', 'venv', 'vendor',
  ]);
  const SOURCE_EXT = new Set(['.go', '.rs', '.py', '.zig', '.rb', '.java', '.ts']);

  /** True if `dir` (recursively, excluding build/vendor/test dirs) contains a
   *  non-test source file whose name matches /optimizer|peephole/i — i.e. a
   *  procedural mirror of the peephole rule table, not a reader of the JSON. */
  function hasOptimizerModule(dir: string): boolean {
    for (const entry of readdirSync(dir, { withFileTypes: true })) {
      if (SKIP_DIRS.has(entry.name)) continue;
      const full = resolve(dir, entry.name);
      if (entry.isDirectory()) {
        if (hasOptimizerModule(full)) return true;
        continue;
      }
      if (!entry.isFile()) continue; // skip dangling symlinks etc.
      if (!SOURCE_EXT.has(extname(entry.name))) continue;
      if (/test/i.test(entry.name)) continue;
      if (/optimizer|peephole/i.test(entry.name)) return true;
    }
    return false;
  }

  /** Native (non-TS) compiler tier directory names under compilers/* that
   *  ship their own procedural peephole/optimizer implementation. */
  function nativeTiersWithOptimizer(): string[] {
    return readdirSync(COMPILERS_DIR, { withFileTypes: true })
      .filter((e) => e.isDirectory())
      .map((e) => e.name)
      .filter((tier) => hasOptimizerModule(resolve(COMPILERS_DIR, tier)));
  }

  const WORD_TO_NUMBER: Record<string, number> = {
    one: 1, two: 2, three: 3, four: 4, five: 5, six: 6, seven: 7, eight: 8, nine: 9, ten: 10,
  };

  it('discovers both the TS mirror and at least one native-tier mirror (a vacuous sweep proves nothing)', () => {
    expect(hasOptimizerModule(TS_OPTIMIZER_DIR)).toBe(true);
    expect(nativeTiersWithOptimizer().length).toBeGreaterThan(0);
  });

  it("the header's compiler-tier count equals the discovered mirrored-tier count, not a hardcoded figure", () => {
    const tsHasOptimizer = hasOptimizerModule(TS_OPTIMIZER_DIR);
    const nativeTiers = nativeTiersWithOptimizer();
    const discoveredCount = nativeTiers.length + (tsHasOptimizer ? 1 : 0);

    const rawHeader = readFileSync(RULE_LOADER_SRC, 'utf-8');
    // Strip comment-line prefixes and collapse whitespace so a future
    // line-wrap of "all seven compiler tiers" can't dodge the regex.
    const header = rawHeader.replace(/^\s*\*\s?/gm, '').replace(/\s+/g, ' ');
    const match = header.match(/shared across all (\w+) compiler/i);
    expect(
      match?.[1],
      "rule-loader.ts header no longer says 'shared across all <N> compiler(s)' — update this test too",
    ).toBeDefined();

    const word = (match![1] as string).toLowerCase();
    const claimed = WORD_TO_NUMBER[word] ?? Number(word);
    expect(
      claimed,
      `rule-loader.ts claims ${word} compilers, but ${discoveredCount} tiers actually ship a ` +
        `procedural optimizer/peephole module (TypeScript${tsHasOptimizer ? '' : ' excluded'} + ` +
        `native tiers: ${nativeTiers.join(', ')})`,
    ).toBe(discoveredCount);
  });

  it('the header names every discovered native tier', () => {
    const header = readFileSync(RULE_LOADER_SRC, 'utf-8');
    const missing = nativeTiersWithOptimizer().filter(
      (tier) => !new RegExp(tier, 'i').test(header),
    );
    expect(
      missing,
      `rule-loader.ts header omits these discovered compiler tiers: ${missing.join(', ')}`,
    ).toEqual([]);
  });
});
