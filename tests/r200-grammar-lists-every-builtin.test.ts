/**
 * R-200 (CL-DOC-025): three real cross-tier intent intrinsics —
 * `requireOutputP2PKH`, `extractPrevOutputScript`, `currentBlockHeight` — are
 * documented only in a niche pattern doc, while `spec/grammar.md` explicitly
 * claims to list "the complete set of built-in functions".
 *
 * Confirmed: all three appeared zero times in `spec/grammar.md` and zero times
 * in `docs/language-reference.md`, under a heading that says the list is
 * complete.
 *
 * The fix is not "add three lines" but "make the claim checkable". This test
 * derives the built-in set from the TYPE CHECKER — the thing that decides what
 * a contract may call — and requires every name in it to appear in the grammar.
 * A builtin added tomorrow fails here until the spec that claims completeness
 * actually has it.
 */

import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { join, dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..');

/**
 * Every builtin name the TS type checker knows, read out of its own tables.
 *
 * Parsed from source rather than imported: the tables are module-private, and
 * exporting them only for a test would widen the compiler's public surface.
 */
function builtinNames(): string[] {
  const src = readFileSync(
    join(ROOT, 'packages/runar-compiler/src/passes/03-typecheck.ts'),
    'utf-8',
  );
  const names = new Set<string>();
  // Entries look like:  ['requireOutputP2PKH', { params: [...], returnType: ... }],
  const entry = /\[\s*'([A-Za-z_][A-Za-z0-9_]*)',\s*\{\s*params:/g;
  let m: RegExpExecArray | null;
  while ((m = entry.exec(src)) !== null) names.add(m[1]!);
  return [...names].sort();
}

/**
 * The EVM/STARK proof-system families, which CLAUDE.md scopes to the Go
 * reference compiler alone. Their fixtures carry a `"compilers": ["go"]`
 * allowlist and they are not a conformance target for the other six tiers, so a
 * contract calling one is not portable Rúnar and the language grammar does not
 * define it. Excluded by PREFIX, so a new BabyBear primitive is excluded for the
 * documented reason rather than by being added to a hand-kept list.
 */
const GO_ONLY_PREFIXES = ['bb', 'kb', 'bn254', 'merkleRoot'] as const;

function isGoOnly(name: string): boolean {
  return GO_ONLY_PREFIXES.some((p) => name.startsWith(p));
}

const grammar = readFileSync(join(ROOT, 'spec/grammar.md'), 'utf-8');

/**
 * Terminals actually DEFINED by a production, i.e. `'name'` on the left of an
 * EBNF alternative — not every mention of the word in the file.
 *
 * The first version of this test asked `grammar.includes(name)`, and removing
 * two builtins from their production left it GREEN: the prose paragraph I had
 * written underneath still mentioned them by name. A guard satisfied by its own
 * explanatory text is the same trap as R-228 and R-210 in this pass.
 */
const definedTerminals = new Set(
  [...grammar.matchAll(/^\s*[=|]\s*'([A-Za-z_][A-Za-z0-9_]*)'/gm)].map((m) => m[1]!),
);

describe('R-200: the grammar lists every builtin it claims to', () => {
  it('the extraction found a plausible builtin set', () => {
    // Anti-vacuity: a broken regex would make the assertion below pass while
    // checking nothing.
    const names = builtinNames();
    expect(names.length).toBeGreaterThan(40);
    for (const anchor of ['checkSig', 'hash160', 'assert']) {
      expect(names, `the extraction missed the well-known builtin ${anchor}`).toContain(anchor);
    }
  });

  it('claims completeness', () => {
    // If this sentence goes away the test's premise does too, so pin it.
    expect(grammar).toMatch(/complete set of built-in functions/);
  });

  it('and every all-tier builtin appears in it', () => {
    const missing = builtinNames()
      .filter((n) => !isGoOnly(n))
      .filter((n) => !definedTerminals.has(n));
    expect(
      missing,
      'these are callable in a portable contract but absent from the spec that claims to list them all',
    ).toEqual([]);
  });

  it('and the Go-only exclusion is stated, not silent', () => {
    // Excluding 35 names from a list that calls itself complete is only honest
    // if the document says so and says why.
    expect(grammar).toMatch(/Go-only by\s+project policy/);
    const goOnly = builtinNames().filter(isGoOnly);
    expect(goOnly.length, 'the Go-only prefixes matched nothing; the split is stale').toBeGreaterThan(
      30,
    );
  });

  it('the three intent intrinsics carry their literal-index constraint', () => {
    // Listing the name is not enough for these two: the first argument must be
    // an integer literal, enforced as a special case in checkCallArgs, and a
    // reader who misses that writes a contract that fails to compile for a
    // reason the grammar did not mention.
    const section = grammar.slice(grammar.indexOf('BuiltinFunction_Intent'));
    expect(section).toMatch(/must be an integer literal/);
  });
});
