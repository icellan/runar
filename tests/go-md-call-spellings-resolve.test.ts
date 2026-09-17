// ---------------------------------------------------------------------------
// `docs/formats/go.md` is the only place a contract author learns which
// `runar.X(...)` spellings a `.runar.go` file may use. Every row of its call
// tables asserts a checkable fact about another file — the Go builtin table
// the seven parsers share — and nothing checked it.
//
// The defect that motivated this gate: the digest section listed
//
//     | the RIPEMD-160 **hash** | `runar.Ripemd160(data)` (alias `runar.Ripemd160Func`) |
//
// presented identically to the `runar.Sha256(data)` (alias `runar.Sha256Hash`)
// row above it. `Sha256Hash` IS in all seven builtin tables; `Ripemd160Func`
// was in none — it exists only in `packages/runar-go`, its tests and docs. So
// the symmetric SHA spelling compiled and this one was refused by all seven
// tiers with `unknown function 'ripemd160Func'`. Measured, not inferred.
//
// The Go surface resolves a builtin in two steps: consult `GO_BUILTIN_MAP`,
// else lower-case the leading character. This gate applies that same rule to
// every spelling the document PRESENTS as contract-callable and requires it to
// land where the document says it lands. A Go-only helper can still be
// mentioned in prose — it just cannot be dressed as a contract spelling in a
// call table or as an `(alias ...)` of one.
//
// Scope note: this checks the Go NAME resolution only. That the resolved name
// is a real builtin, and that all seven tiers agree on the mapping, is held by
// `packages/runar-compiler/src/__tests__/01-parse-go.test.ts` (the at-risk
// alias class) and by `conformance/subtype-parity/` (cross-tier acceptance
// plus byte equality against the reference spelling).
// ---------------------------------------------------------------------------

import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { GO_BUILTIN_MAP } from '../packages/runar-compiler/src/passes/01-parse-go.js';

const REPO_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const GO_MD = resolve(REPO_ROOT, 'docs/formats/go.md');

/** The Go surface's two-step builtin resolution, verbatim. */
function resolveGoSpelling(name: string): string {
  return GO_BUILTIN_MAP[name] ?? name.charAt(0).toLowerCase() + name.slice(1);
}

const doc = readFileSync(GO_MD, 'utf-8');
const lines = doc.split('\n');

describe('docs/formats/go.md: every call spelling it presents resolves where it says', () => {
  // -------------------------------------------------------------------------
  // Two-column rows: | `runar.Abs(n)` | `abs(n)` |
  //
  // The right cell names the Rúnar node. Resolving the left spelling through
  // the parser's own rule must produce exactly that name.
  // -------------------------------------------------------------------------
  it('two-column table rows land on the Rúnar name the row claims', () => {
    const ROW = /^\|\s*`runar\.([A-Za-z0-9_]+)\([^`]*\)`\s*\|\s*`([A-Za-z0-9_]+)\(/;

    const mismatches: string[] = [];
    let rows = 0;

    for (const line of lines) {
      const m = ROW.exec(line);
      if (!m) continue;
      const [, goName, claimedRunarName] = m;
      rows++;
      const actual = resolveGoSpelling(goName!);
      if (actual !== claimedRunarName) {
        mismatches.push(
          `runar.${goName} resolves to '${actual}', but the table claims '${claimedRunarName}'`,
        );
      }
    }

    // A regex that silently matches nothing is the failure mode this whole
    // repo keeps tripping over, so require the row count to be substantial.
    expect(rows, 'the two-column row regex matched nothing — the table shape changed').toBeGreaterThan(40);

    expect(
      mismatches,
      `docs/formats/go.md presents a call spelling that does not resolve where ` +
        `it claims. Either add the name to GO_BUILTIN_MAP in ALL SEVEN tiers, ` +
        `or correct the document — a spelling in this table is one a contract ` +
        `author will write.`,
    ).toEqual([]);
  });

  // -------------------------------------------------------------------------
  // `(alias `runar.X`)` — the shape that carried the defect. An alias must
  // resolve to the SAME Rúnar builtin as the primary spelling in its cell, or
  // it is not an alias, it is a name the compiler rejects.
  // -------------------------------------------------------------------------
  it('every documented (alias ...) resolves to the same builtin as its primary', () => {
    const ALIAS_ROW = /`runar\.([A-Za-z0-9_]+)\([^`]*\)`\s*\(alias\s*`runar\.([A-Za-z0-9_]+)`\)/g;

    const mismatches: string[] = [];
    let aliases = 0;

    for (const m of doc.matchAll(ALIAS_ROW)) {
      const [, primary, alias] = m;
      aliases++;
      const primaryTarget = resolveGoSpelling(primary!);
      const aliasTarget = resolveGoSpelling(alias!);
      if (primaryTarget !== aliasTarget) {
        mismatches.push(
          `runar.${alias} is documented as an alias of runar.${primary}, but ` +
            `resolves to '${aliasTarget}' while runar.${primary} resolves to ` +
            `'${primaryTarget}'`,
        );
      }
    }

    expect(aliases, 'the (alias ...) regex matched nothing — the doc shape changed').toBeGreaterThan(0);

    expect(
      mismatches,
      `docs/formats/go.md documents a contract-callable alias that no tier maps. ` +
        `An "(alias X)" in a call table is a promise that a contract may write X; ` +
        `if X is a Go-side helper only, say so in prose instead.`,
    ).toEqual([]);
  });
});
