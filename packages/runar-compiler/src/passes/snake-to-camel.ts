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

/**
 * F-017 — the identifier-collision rule.
 *
 * Five surfaces rename identifiers on the way into the AST: `.runar.py`,
 * `.runar.rb`, `.runar.rs`, `.runar.move` (snake_case -> camelCase via
 * `snakeToCamelCore`, plus Python's trailing/leading-underscore strip and
 * Ruby's leading-underscore strip) and `.runar.go` (PascalCase -> camelCase,
 * first letter lowered). None of those mappings is injective: `tmp` and
 * `tmp_`, `a_b` and `aB`, `a__b` and `a_b`, `_tmp` and `tmp` (.py/.rb),
 * `Tmp` and `tmp` (.go) each land on one Rúnar name. Before this rule the
 * compiler silently bound both spellings to one variable, so
 * `tmp = n + 1; tmp_ = n + 2; assert_(tmp == tmp_)` — always false in the
 * source language — compiled to a self-comparison that always passes.
 *
 * THE RULE. While parsing one contract, the surface parser records a pair
 * (source spelling, Rúnar name) for every identifier it DECLARES:
 *
 *   - property / struct-field names,
 *   - method / function names (not the constructor),
 *   - parameter names (receivers such as `self` / `contract` are not
 *     parameters and are not recorded),
 *   - local-variable names at every declaration or bare-name assignment
 *     target (`x = …`, `let x`, `x :=`, `var x`),
 *   - loop variables.
 *
 * If two recorded pairs share a Rúnar name but differ in source spelling,
 * the contract is refused with exactly ONE error, whose text is identical in
 * all seven tiers:
 *
 *   identifier collision: '<a>' and '<b>' both convert to '<name>'; rename one of them
 *
 * where `<name>` is the smallest colliding Rúnar name and `<a>` < `<b>` are
 * the two smallest source spellings that map to it. "Smallest" is ordinal
 * string order (code-unit / byte order; identifiers on these surfaces are
 * ASCII), so the report does not depend on the order in which a tier's
 * parser happens to visit declarations.
 *
 * Scope is the whole contract, not one method: a spelling in one method
 * collides with a different spelling of the same name in another. Using ONE
 * spelling many times (a property and the constructor parameter that sets
 * it, Rust `let x` shadowing -- which N-509 refuses separately when both
 * are in one scope -- the same local in two methods) is not a collision,
 * and a single identifier that maps to a different name (`sum_` -> `sum`)
 * is still accepted. References are not recorded: an undeclared
 * spelling is already an error in the source language itself.
 */
export function identifierCollisionMessage(
  decls: ReadonlyArray<readonly [raw: string, name: string]>,
): string | null {
  const spellings = new Map<string, Set<string>>();
  for (const [raw, name] of decls) {
    let set = spellings.get(name);
    if (set === undefined) {
      set = new Set();
      spellings.set(name, set);
    }
    set.add(raw);
  }
  let best: [string, string, string] | null = null;
  for (const [name, set] of spellings) {
    if (set.size < 2) continue;
    if (best !== null && !(name < best[0])) continue;
    const sorted = [...set].sort((x, y) => (x < y ? -1 : x > y ? 1 : 0));
    best = [name, sorted[0]!, sorted[1]!];
  }
  if (best === null) return null;
  return `identifier collision: '${best[1]}' and '${best[2]}' both convert to '${best[0]}'; rename one of them`;
}
