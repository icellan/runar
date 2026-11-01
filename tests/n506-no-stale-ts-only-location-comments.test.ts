/**
 * N-506: since N-491..N-497 every surface parser in every tier locates the
 * operands of binary and unary expressions and identifiers, as the TS
 * reference does. The doc comments written for N-463/N-472 still said only the
 * `.runar.ts` parser sets those locations. This test reads the comments of the
 * declaring AST types and the type-checker anchoring code in all seven tiers
 * and fails while any of the stale phrasings remain.
 *
 * Proves: none of the listed stale sentences is present in the listed files.
 * Does not prove: that the replacement wording is accurate, or that no other
 * stale phrasing exists elsewhere (ByteStringLiteral N-432, PropertyAccess,
 * ternary and call-argument locations are deliberately not claimed here;
 * they are still `.runar.ts`-only). The phrases are exact, so a reworded
 * regression would not be caught.
 */
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { describe, expect, it } from 'vitest';

const ROOT = resolve(__dirname, '..');

/** Strip comment leaders, backticks and Javadoc {@code} wrappers; collapse whitespace. */
function normalize(text: string): string {
  return text
    .replace(/\{@code ([^}]*)\}/g, '$1')
    .replace(/`/g, '')
    .replace(/^\s*(\/\/\/?|\/\*\*|\*\/|\*|#)/gm, '')
    .replace(/\s+/g, ' ')
    .toLowerCase();
}

const J = 'compilers/java/src/main/java/runar/compiler';
const STALE: Array<[string, string]> = [
  [`${J}/ir/ast/BinaryExpr.java`, 'leading ( (n-472). only the .runar.ts parser sets it'],
  [`${J}/ir/ast/UnaryExpr.java`, 'operator token (n-472); only the .runar.ts parser sets it'],
  [`${J}/ir/ast/Identifier.java`, "identifier's token (n-463). only the .runar.ts parser sets it"],
  [`${J}/passes/Typecheck.java`, 'the .runar.ts parser records where the whole expression'],
  ['compilers/rust/src/frontend/ast.rs', 'leading ( (n-472). only the .runar.ts parser sets it'],
  ['compilers/rust/src/frontend/ast.rs', 'operator token (n-472); .runar.ts parser only'],
  ['compilers/rust/src/frontend/ast.rs', "identifier's token (n-463). only the .runar.ts parser sets it"],
  ['compilers/rust/src/frontend/typecheck.rs', 'the .runar.ts parser records where the whole expression'],
  ['compilers/rust/src/frontend/typecheck.rs', 'the operator token; the other surfaces record none'],
  ['compilers/python/runar_compiler/frontend/ast_nodes.py', 'leading ( (n-472). only the .runar.ts parser sets it'],
  ['compilers/python/runar_compiler/frontend/ast_nodes.py', 'operator token (n-472); .runar.ts parser only'],
  ['compilers/python/runar_compiler/frontend/ast_nodes.py', "identifier's token (n-463). only the .runar.ts parser sets it"],
  ['compilers/python/runar_compiler/frontend/typecheck.py', 'when its position is known (the .runar.ts parser records it)'],
  ['compilers/python/runar_compiler/frontend/typecheck.py', 'the .runar.ts parser records where the whole expression'],
  ['compilers/go/frontend/ast.go', 'leading ( (n-472). only the .runar.ts parser sets it'],
  ['compilers/go/frontend/ast.go', 'operator token (n-472); .runar.ts parser only'],
  ['compilers/go/frontend/ast.go', "identifier's token (n-463). only the .runar.ts parser sets it"],
  ['compilers/go/frontend/typecheck.go', 'when its position is known (the .runar.ts parser records it'],
  ['compilers/go/frontend/typecheck.go', 'the .runar.ts parser records where the whole expression'],
  ['compilers/ruby/lib/runar_compiler/frontend/ast_nodes.rb', "identifier's token (n-463). only the .runar.ts parser sets it"],
  ['compilers/ruby/lib/runar_compiler/frontend/ast_nodes.rb', '(n-472); .runar.ts parser only, nil elsewhere'],
  ['compilers/ruby/lib/runar_compiler/frontend/ast_nodes.rb', 'operator token (n-472); .runar.ts parser only'],
  ['compilers/ruby/lib/runar_compiler/frontend/typecheck.rb', 'when its position is known (the .runar.ts parser records it)'],
  ['compilers/ruby/lib/runar_compiler/frontend/typecheck.rb', 'the .runar.ts parser records where the whole expression'],
  ['compilers/zig/src/passes/typecheck.zig', 'only the .runar.ts parser records expression positions'],
];

describe('N-506: no comment claims operand locations are .runar.ts-only', () => {
  for (const [file, phrase] of STALE) {
    it(`${file}: "${phrase}"`, () => {
      const text = normalize(readFileSync(resolve(ROOT, file), 'utf8'));
      expect(text.includes(phrase)).toBe(false);
    });
  }
});
