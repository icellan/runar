/**
 * R-251 (CL-DOC-008): the newer ANF and Stack IR node types are not re-exported
 * from either package's `ir/index.ts` barrel, and the ir-schema README's tables
 * do not list them. `UnsafeSmartContract` is likewise missing from the README's
 * documented `parentClass` values.
 *
 * Missing from the barrels at the time of writing:
 *
 *   ANF    DeserializeState, AddDataOutput, ArrayLiteral, RawScript
 *   Stack  PushCodeSepIndexOp, VerifyCodePartLenOp, RawBytesOp
 *
 * The union types themselves are complete — `ANFValue` and `StackOp` list every
 * member — so nothing is broken. What breaks is the consumer: a downstream
 * package imports from `runar-compiler/ir` (the barrel), gets `ANFValue`, and
 * cannot name the member it needs to narrow to. It either reaches into the
 * deep path `ir/anf-ir.js`, which is not the supported entry point, or hand-
 * copies the interface, which is how two definitions of one wire type start.
 *
 * The list is derived from the union declarations, so the next node kind added
 * to `ANFValue` or `StackOp` has to reach the barrel — the same rule
 * `anf-kind-enumeration.test.ts` applies to the LOWERINGS, applied to the
 * exports.
 */

import { describe, it, expect } from 'vitest';
import { readFileSync, existsSync } from 'node:fs';
import { join, dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..');

/**
 * The two packages that define the IR types, with where each keeps its sources
 * and its barrel. They are laid out differently: runar-compiler nests them under
 * `src/ir/`, runar-ir-schema keeps them flat under `src/`.
 */
const PACKAGES = [
  { pkg: 'packages/runar-compiler', src: 'src/ir', barrel: 'src/ir/index.ts' },
  { pkg: 'packages/runar-ir-schema', src: 'src', barrel: 'src/index.ts' },
];

/** Members of `export type <Union> = | A | B | …`. */
function unionMembers(src: string, union: string): string[] {
  const m = src.match(new RegExp(`export type ${union} =([\\s\\S]*?);`));
  if (!m) return [];
  return [...m[1]!.matchAll(/\|\s*([A-Z][A-Za-z0-9]*)/g)].map((x) => x[1]!);
}

function read(rel: string): string {
  const p = join(ROOT, rel);
  return existsSync(p) ? readFileSync(p, 'utf8') : '';
}

describe('R-251: the IR barrels export every node kind the unions declare', () => {
  for (const { pkg, src, barrel: barrelPath } of PACKAGES) {
    const anfSrc = read(`${pkg}/${src}/anf-ir.ts`);
    const stackSrc = read(`${pkg}/${src}/stack-ir.ts`);
    const barrel = read(`${pkg}/${barrelPath}`);

    it(`${pkg}: the union scan is not vacuous`, () => {
      expect(barrel, `${pkg} has no ${barrelPath}`).not.toBe('');
      const anf = unionMembers(anfSrc, 'ANFValue');
      const stack = unionMembers(stackSrc, 'StackOp');
      expect(anf.length + stack.length, `${pkg}: found no union members`).toBeGreaterThan(10);
    });

    it(`${pkg}: every ANFValue member is re-exported`, () => {
      const members = unionMembers(anfSrc, 'ANFValue');
      if (members.length === 0) return;
      // `UnaryOp` is re-exported under an alias because the AST exports the same
      // name; the barrel spells it `UnaryOp as ANFUnaryOp`.
      const missing = members.filter(
        (m) => !new RegExp(`\\b${m}\\b`).test(barrel),
      );
      expect(missing, `${pkg}/${barrelPath} does not re-export these ANF node types`).toEqual([]);
    });

    it(`${pkg}: every StackOp member is re-exported`, () => {
      const members = unionMembers(stackSrc, 'StackOp');
      if (members.length === 0) return;
      const missing = members.filter((m) => !new RegExp(`\\b${m}\\b`).test(barrel));
      expect(missing, `${pkg}/${barrelPath} does not re-export these Stack IR op types`).toEqual([]);
    });
  }

  it('the ir-schema README documents every parentClass the AST allows', () => {
    const ast = read('packages/runar-ir-schema/src/runar-ast.ts');
    const declared = [...ast.matchAll(/parentClass\??:\s*([^;]+);/g)]
      .flatMap((m) => [...m[1]!.matchAll(/'([A-Za-z]+)'/g)].map((x) => x[1]!));
    expect(declared.length, 'no parentClass values found — the scan broke').toBeGreaterThan(1);

    const readme = read('packages/runar-ir-schema/README.md');
    const missing = [...new Set(declared)].filter((v) => !readme.includes(v));
    expect(missing, "parentClass values the README does not document").toEqual([]);
  });
});
