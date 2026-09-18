/**
 * R-098 — `spec/` is the self-declared authoritative specification, and it was
 * stale in four specific ways. Each one is a thing a porting author would look
 * up and not find:
 *
 *   1. `spec/ir-format.md` documented 15 of the 19 ANF node kinds. The four
 *      missing ones were `add_raw_output`, `add_data_output`, `array_literal`
 *      and `raw_script` — and this audit found real cross-tier divergences in
 *      exactly two of them (the add_raw_output / add_data_output defects).
 *   2. `spec/type-system.md`, `spec/grammar.md` and `spec/abi.md` omitted
 *      `P256Point` and `P384Point` — a whole NIST-curve builtin family that
 *      ships in all seven tiers.
 *   3. `spec/grammar.md`'s BaseClass production admitted only `SmartContract`
 *      and `StatefulSmartContract`; `UnsafeSmartContract` is a third parent
 *      class every tier accepts. (The wider "the escape hatch is documented
 *      nowhere" problem is R-099; this file only requires the grammar to admit
 *      what the parsers admit.)
 *
 * A specification that omits four IR node kinds and a builtin family cannot be
 * the porting reference it claims to be, and the omissions are not random —
 * they cluster exactly where the defects were.
 *
 * The durable half is this test, not the edit. It derives the required
 * vocabulary from the COMPILER — the typed `ALL_ANF_KINDS` list, the parser's
 * own `PRIMITIVE_TYPES` set, the `parentClass` union — so the spec cannot drift
 * again without a red test. A kind or type added later fails here until the
 * spec learns about it.
 */
import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { ALL_ANF_KINDS } from './anf-kind-list.js';

const REPO = resolve(__dirname, '../../../..');
const read = (rel: string) => readFileSync(join(REPO, rel), 'utf-8');

/**
 * The parser's primitive type vocabulary, read out of its source.
 *
 * Deliberately not a hand-copied list: a second copy is a second thing to
 * drift, which is the failure this whole file is about. The regex is anchored
 * on the declaration so a shape change fails loudly rather than silently
 * matching nothing.
 */
function parserPrimitiveTypes(): string[] {
  const src = read('packages/runar-compiler/src/passes/01-parse.ts');
  const m = src.match(/const PRIMITIVE_TYPES = new Set<string>\(\[([\s\S]*?)\]\)/);
  if (!m) throw new Error('PRIMITIVE_TYPES declaration not found in 01-parse.ts');
  const names = [...m[1]!.matchAll(/'([A-Za-z0-9_]+)'/g)].map((x) => x[1]!);
  if (names.length === 0) throw new Error('PRIMITIVE_TYPES parsed to an empty list');
  return names;
}

/** The base classes the AST admits, read out of the `parentClass` union. */
function parentClasses(): string[] {
  const src = read('packages/runar-compiler/src/ir/runar-ast.ts');
  const m = src.match(/parentClass:\s*([^;]+);/);
  if (!m) throw new Error('parentClass union not found in runar-ast.ts');
  const names = [...m[1]!.matchAll(/'([A-Za-z0-9_]+)'/g)].map((x) => x[1]!);
  if (names.length === 0) throw new Error('parentClass union parsed to an empty list');
  return names;
}

describe('R-098: spec/ documents what the compiler implements', () => {
  it('the vocabularies are non-empty (a silent parse failure would pass vacuously)', () => {
    expect(ALL_ANF_KINDS.length).toBeGreaterThanOrEqual(19);
    expect(parserPrimitiveTypes().length).toBeGreaterThanOrEqual(10);
    expect(parentClasses().length).toBeGreaterThanOrEqual(3);
  });

  it('spec/ir-format.md documents every ANF node kind', () => {
    const doc = read('spec/ir-format.md');
    const missing = ALL_ANF_KINDS.filter((k) => !new RegExp(`\\b${k}\\b`).test(doc));
    expect(
      missing,
      `spec/ir-format.md omits these ANF kinds: ${missing.join(', ')}. ` +
        `A porting author reading the IR format spec would not know they exist.`,
    ).toEqual([]);
  });

  it('spec/type-system.md names every primitive type the parser accepts', () => {
    const doc = read('spec/type-system.md');
    // `void` is a return-position-only marker, not a value type; the type
    // system document covers it under method signatures rather than the
    // domain-type tables, and it is spelled in lowercase prose.
    const missing = parserPrimitiveTypes()
      .filter((t) => !new RegExp(`\\b${t}\\b`).test(doc));
    expect(
      missing,
      `spec/type-system.md omits these primitive types: ${missing.join(', ')}`,
    ).toEqual([]);
  });

  it('spec/grammar.md admits every base class the AST admits', () => {
    const doc = read('spec/grammar.md');
    const missing = parentClasses().filter((c) => !new RegExp(`\\b${c}\\b`).test(doc));
    expect(
      missing,
      `spec/grammar.md's BaseClass production omits: ${missing.join(', ')}`,
    ).toEqual([]);
  });

  it('spec/abi.md names the NIST curve point types', () => {
    const doc = read('spec/abi.md');
    const missing = ['P256Point', 'P384Point'].filter((t) => !new RegExp(`\\b${t}\\b`).test(doc));
    expect(missing, `spec/abi.md omits: ${missing.join(', ')}`).toEqual([]);
  });
});
