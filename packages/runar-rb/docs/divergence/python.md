# Python Format — Divergence from Specification

**Date:** 2026-03-20
**Perspective:** Observed from Ruby format parity analysis

---

## Summary

The Python format has several divergences, primarily in the TS compiler's Python
parser which is missing builtin name mappings that the Python compiler's own parser
handles correctly. One type mapping bug affects conformance tests.

---

## Divergences

### P1 — `Bool` type not mapped in Python TS parser [BUG]

**Where:** `packages/runar-compiler/src/passes/01-parse-python.ts` — `mapPyType`

**Status:** The `property-initializers.runar.py` conformance test uses `Bool` as a
type annotation. The Python TS parser's `mapPyType` only maps `bool` (lowercase) to
`boolean` — it does not map `Bool` (capitalised). This means `Bool` falls through to
`makePrimitiveOrCustom('Bool')`, creating a `custom_type` named `Bool` instead of
`primitive_type` `boolean`.

The Python compiler's own parser similarly only handles `bool`. The Go and Rust
compilers' Python parsers should also be checked.

**Fix required:** Add `'Bool'` to `mapPyType` alongside `'bool'` in all four
compilers' Python parsers, or correct the conformance test to use `bool`.

### P2 — Missing builtins in Python TS parser [BUG]

**Where:** `packages/runar-compiler/src/passes/01-parse-python.ts` — `mapBuiltinName`

**Status:** The TS Ruby parser has the following mappings that the TS Python parser
lacks:

| Name | Ruby maps to | Python maps to | Impact |
|------|-------------|----------------|--------|
| `add_raw_output` | `addRawOutput` | Missing | Python contracts cannot use `add_raw_output` |
| `safe_div` | `safediv` | Missing | Would produce `safeDiv` via generic camelCase |
| `safe_mod` | `safemod` | Missing | Would produce `safeMod` via generic camelCase |
| `div_mod` | `divmod` | Missing | Would produce `divMod` instead of `divmod` |
| `extract_nsequence` | `extractNSequence` | Missing | Would produce `extractNsequence` (wrong case) |

The Python compiler's own parser (`parser_python.py`) includes these mappings. The
asymmetry is only in the TS compiler's Python parser.

### P3 — Python TS parser accepts `/` as integer division [PERMISSIVE]

**Where:** `packages/runar-compiler/src/passes/01-parse-python.ts`

**Status:** The documented spec says Python contracts should use `//` for integer
division. The parser silently accepts `/` as well, producing the same `OP_DIV`
output. This is overly permissive — it means a Python contract could use `/` (which
in real Python would be float division) and produce correct Runar output, masking a
potential developer error.

Ruby's `/` is correctly integer division by language design, so this asymmetry does
not affect Ruby.

### P4 — Postfix method calls use `snakeToCamel` instead of `mapBuiltinName` [MINOR]

**Where:** `packages/runar-compiler/src/passes/01-parse-python.ts`

**Status:** The TS Python parser uses `snakeToCamel` for method calls in postfix
position (e.g., `obj.method()`), while the TS Ruby parser uses the full
`mapBuiltinName` table. This means special-case names like `extract_nsequence` would
be incorrectly converted when called as methods in Python.

Low practical impact — most builtins are called as free functions, not method chains.

---

## Conformance Coverage Gap

| Tests with Python variant | 16 of 27 |
| Tests with Ruby variant | 21 of 27 |

Python-format tests that Ruby has but Python lacks: `convergence-proof`, `ec-demo`,
`function-patterns`, `math-demo`, `oracle-price`, `post-quantum-wallet`,
`sphincs-wallet`, `stateful-counter`.

---

## Notes

- The Python compiler's Ruby parser is the **most complete** Ruby parser of all four
  compilers — it includes the trailing-underscore mappings that the TS, Go, and Rust
  compilers lack. The Python team's attention to Ruby-specific naming conventions is
  commendable.

- Python uses `__init__` for constructor (vs Ruby's `initialize`) and
  `super().__init__()` for super calls (vs Ruby's `super()`). Both produce identical
  AST output. Not a divergence.

- Python uses `Readonly[T]` for readonly properties (vs Ruby's `readonly: true`
  keyword). Both produce identical AST. Not a divergence.
