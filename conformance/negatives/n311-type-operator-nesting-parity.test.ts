import { describe, it, expect, beforeAll } from 'vitest';
import { mkdirSync, mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { buildSourceTiers, judge } from './tier-harness.js';
import { isCiEnv } from '../env.js';

/**
 * N-311 — seven-tier gate: measure (A) of MAX_SOURCE_NESTING counts
 * intersection / union type nesting (user decision R117).
 *
 * Measure (A) counted nested type ARGUMENTS but no type OPERATOR, so a
 * `.runar.ts` annotation could nest `&` / `|` without bound. The Go tier's
 * tree-sitter grammar builds even `&&&…&Int` as a valid right-nested
 * intersection_type chain, and its measure-(A) walk followed every level (about
 * 208 MB of Go heap at 256k levels) before any diagnostic. The rule is now +1 per
 * operand of an intersection or union type.
 *
 * Which tiers name the shared diagnostic: only the three whose `.runar.ts`
 * grammar HAS these operators — ts (TypeScript's parser), go (tree-sitter),
 * rust (swc). The python, zig, ruby and java `.runar.ts` parsers are
 * hand-written and have no `&`, `|` or `(` in type position: they refuse at the
 * first such token, with no recursion to bound. On the parenthesised shape they
 * then re-read the rest of the line as an expression, where each `(` is a
 * counted group, so they too name the shared diagnostic past the limit — one
 * level earlier (at n = 127) than the three type-grammar tiers. That is error
 * recovery, not the type-operator measure, so at n = 127 it is permitted, not
 * required. Nothing here compiles: no Rúnar type is an intersection or union,
 * so "within (A)" means "refused for the type", never "accepted".
 *
 * Proves, for every available tier: the parenthesised shape (`&`, `|`, and an
 * alternation) one past the limit (n = 128) and deep (n = 2000) is refused with
 * the shared diagnostic; at n = 127 it is refused, and ts / go / rust refuse it
 * for another reason (the measure-(A) boundary); a flat 500-operand
 * intersection is refused but not for nesting by ts / go / rust; and the
 * tree-sitter-only `&&&…Int` shape is refused by every tier, by Go with the
 * shared diagnostic (the others see a syntax error: `&&` is one token to them).
 * Does not prove: Go's memory bound (compilers/go/frontend/
 * n311_type_operator_nesting_test.go measures it), or other type positions.
 */

const L = 128;
const CASE_TIMEOUT_MS = 600_000;
const DIAG = `source nesting depth exceeds MAX_SOURCE_NESTING (limit=${L})`;
const TYPE_GRAMMAR_TIERS = new Set(['ts', 'go', 'rust']);

const HEAD = "import { SmartContract, assert } from 'runar-lang';\nclass P extends SmartContract {\n readonly t: bigint;\n constructor(t: bigint) { super(t); this.t = t; }\n public verify(a: bigint, b: bigint) {\n let q: {T} = a;\n assert(q == this.t);\n }\n}\n";

/** n parenthesised levels; `ops` cycles per level. */
function nested(n: number, ops: string[]): string {
  let open = '';
  for (let i = 0; i < n; i++) open += `(bigint ${ops[i % ops.length]} `;
  return HEAD.replace('{T}', open + 'bigint' + ')'.repeat(n));
}

const TIERS = buildSourceTiers().filter((t) => t.cmd !== null);

let dir = '';
beforeAll(() => {
  dir = mkdtempSync(join(tmpdir(), 'n311-type-ops-'));
});

let seq = 0;
function write(text: string): string {
  const sub = join(dir, String(seq++));
  mkdirSync(sub, { recursive: true });
  const p = join(sub, 'P.runar.ts');
  writeFileSync(p, text);
  return p;
}

describe('N-311 seven-tier type-operator nesting', () => {
  it('at least two tiers are available (all seven in CI)', () => {
    expect(TIERS.length).toBeGreaterThanOrEqual(2);
    if (isCiEnv(process.env)) expect(TIERS.length).toBe(7);
  });

  for (const ops of [['&'], ['|'], ['&', '|']]) {
    const name = ops.join(' ');

    it(`${name} n=${L - 1} (at the limit): refused, and not for nesting by ts / go / rust`, () => {
      const file = write(nested(L - 1, ops));
      for (const tier of TIERS) {
        const { verdict, diag } = judge(tier, file);
        expect(verdict, `${tier.id} accepted ${name} n=${L - 1}`).toBe('rejected');
        if (TYPE_GRAMMAR_TIERS.has(tier.id)) {
          expect(diag, `${tier.id} refused ${name} n=${L - 1} for nesting`).not.toContain(DIAG);
        }
      }
    }, CASE_TIMEOUT_MS);

    for (const n of [L, 2000]) {
      it(`${name} n=${n}: every tier refuses with the shared diagnostic`, () => {
        const file = write(nested(n, ops));
        for (const tier of TIERS) {
          const { verdict, diag } = judge(tier, file);
          expect(verdict, `${tier.id} accepted ${name} n=${n}`).toBe('rejected');
          expect(diag, `${tier.id} refused ${name} n=${n} for another reason`).toContain(DIAG);
        }
      }, CASE_TIMEOUT_MS);
    }
  }

  it('a flat 500-operand intersection: refused, and not for nesting by ts / go / rust', () => {
    const file = write(HEAD.replace('{T}', Array(500).fill('bigint').join(' & ')));
    for (const tier of TIERS) {
      const { verdict, diag } = judge(tier, file);
      expect(verdict, `${tier.id} accepted a flat intersection`).toBe('rejected');
      if (TYPE_GRAMMAR_TIERS.has(tier.id)) {
        expect(diag, `${tier.id} refused a flat intersection for nesting`).not.toContain(DIAG);
      }
    }
  }, CASE_TIMEOUT_MS);

  it('`&&&…Int` (300 levels): every tier refuses, Go with the shared diagnostic', () => {
    const file = write(HEAD.replace('{T}', '&'.repeat(300) + 'Int'));
    for (const tier of TIERS) {
      const { verdict, diag } = judge(tier, file);
      expect(verdict, `${tier.id} accepted the & chain`).toBe('rejected');
      if (tier.id === 'go') {
        expect(diag, 'go refused the & chain for another reason').toContain(DIAG);
      }
    }
  }, CASE_TIMEOUT_MS);
});
