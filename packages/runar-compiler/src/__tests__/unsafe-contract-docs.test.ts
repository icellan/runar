/**
 * R-099 — `UnsafeSmartContract` and its raw `asm()` escape hatch were
 * implemented in all seven tiers, exercised by a dedicated nine-format example
 * (the `asm-raw-script` example, `Anyone`, in every surface directory), and documented NOWHERE: not in
 * `docs/`, not in `CLAUDE.md`, and `SECURITY.md` did not mention that a
 * contract can opt out of every static guarantee the project makes.
 *
 * It is the one construct in the language where the compiler's safety argument
 * stops applying: `asm({ body, in_arity, out_arity })` lowers to a `raw_script`
 * ANF node the compiler does not interpret. Dead-code elimination must not
 * remove it, the stack model cannot verify the declared arity, and no type
 * information crosses it. A reader who never learns it exists cannot review a
 * contract that uses it, and a reporter reading SECURITY.md could not tell
 * whether a stack bug behind `asm()` is a compiler defect or the author's.
 *
 * `spec/grammar.md` and `spec/ir-format.md` gained their half under R-098. This
 * file covers the user-facing half and pins it so the feature cannot go
 * undocumented again.
 */
import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { join, resolve } from 'node:path';

const REPO = resolve(__dirname, '../../../..');
const read = (rel: string) => readFileSync(join(REPO, rel), 'utf-8');

/**
 * The base classes the AST admits. Derived, not hand-copied: the point of the
 * test is that documentation tracks the implementation.
 */
function parentClasses(): string[] {
  const src = read('packages/runar-compiler/src/ir/runar-ast.ts');
  const m = src.match(/parentClass:\s*([^;]+);/);
  if (!m) throw new Error('parentClass union not found in runar-ast.ts');
  const names = [...m[1]!.matchAll(/'([A-Za-z0-9_]+)'/g)].map((x) => x[1]!);
  if (names.length === 0) throw new Error('parentClass union parsed to an empty list');
  return names;
}

/** Documents that must describe every base class a contract can extend. */
const CONTRACT_MODEL_DOCS = ['CLAUDE.md', 'docs/language-reference.md'];

describe('R-099: the asm() escape hatch is documented where readers look', () => {
  it('the derivation is non-empty (a silent parse failure would pass vacuously)', () => {
    expect(parentClasses()).toContain('UnsafeSmartContract');
  });

  for (const doc of CONTRACT_MODEL_DOCS) {
    it(`${doc} describes every base class the compiler admits`, () => {
      const text = read(doc);
      const missing = parentClasses().filter((c) => !new RegExp(`\\b${c}\\b`).test(text));
      expect(
        missing,
        `${doc} does not mention: ${missing.join(', ')} — a contract can extend it, ` +
          `so a reader of the contract model needs to know it exists.`,
      ).toEqual([]);
    });
  }

  it('docs/language-reference.md documents the asm() intrinsic itself', () => {
    const text = read('docs/language-reference.md');
    expect(/\basm\s*\(/.test(text), 'no asm( call form shown').toBe(true);
    expect(/in_arity/.test(text), 'the declared stack effect is not described').toBe(true);
  });

  it('SECURITY.md says where the compiler stops guaranteeing anything', () => {
    const text = read('SECURITY.md');
    expect(
      /UnsafeSmartContract/.test(text),
      `SECURITY.md's scope section does not mention the one construct that opts a ` +
        `contract out of the compiler's static guarantees — a reporter cannot tell ` +
        `whether a stack bug behind asm() is a compiler defect or the author's.`,
    ).toBe(true);
  });
});
