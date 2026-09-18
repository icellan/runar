/**
 * snake_case → camelCase, the way the other six tiers do it (R-113).
 *
 * The TypeScript parsers used to convert with `replace(/_([a-z0-9])/g, …)`,
 * which only uppercases when the character after the underscore is lower-case
 * or a digit, and consumes one underscore at a time. The other six tiers split
 * on `_` and capitalise each following part. Measured on a `.runar.py` contract
 * through every shipping compiler:
 *
 *     foo__bar     TS foo_Bar     go/rust/python/zig/ruby/java  fooBar
 *     baz_Qux      TS baz_Qux     go/rust/python/zig/ruby/java  bazQux
 *
 * So an identifier with adjacent underscores, or an underscore before an
 * upper-case letter, produced a different AST name — and therefore a different
 * canonical ANF — in the reference tier than in the other six. Invariant 2
 * failing on a name.
 *
 * This is the six-tier algorithm, in one place, for the four TypeScript
 * surface parsers that need it (python, ruby, rust, move). The per-surface
 * conventions that sit AROUND it — Python's dunder and trailing-underscore
 * handling, Ruby's leading-underscore strip — stay with their parsers, because
 * they are surface conventions rather than the shared normalisation.
 *
 * Mirrors `compilers/go/frontend/parser_move.go::snakeToCamel`.
 */
export function snakeToCamelCore(name: string): string {
  const parts = name.split('_');
  if (parts.length <= 1) return name;
  let out = parts[0]!;
  for (const part of parts.slice(1)) {
    if (part.length > 0) {
      out += part[0]!.toUpperCase() + part.slice(1);
    }
  }
  return out;
}
