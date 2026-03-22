# Rust Format — Divergence from Specification

**Date:** 2026-03-20
**Perspective:** Observed from Ruby format parity analysis

---

## Summary

The Rust format has two minor divergences related to TS compiler support for
Rust-specific syntax. These do not affect production use because `.runar.rs` files
are routed through the Go/Rust/Python compilers in the conformance runner, not the
TS compiler.

---

## Divergences

### R1 — `#[runar::stateful_contract]` not supported by TS Rust parser [MINOR]

**Where:** `packages/runar-compiler/src/passes/01-parse-rust.ts`

**Status:** The `#[runar::stateful_contract]` attribute is supported by the Go and
Rust compilers' Rust parsers, but the TS compiler's Rust parser does not recognise
it. Since `.runar.rs` files are not routed through the TS compiler in the conformance
runner, this has no operational impact.

### R2 — `assert_eq!` macro not supported by TS Rust parser [MINOR]

**Where:** `packages/runar-compiler/src/passes/01-parse-rust.ts`

**Status:** The `assert_eq!(a, b)` macro (which maps to `assert(a === b)`) is
supported by the Go and Python compilers' Rust parsers, but not by the TS compiler's
Rust parser. Same routing caveat as R1 applies.

---

## Conformance Coverage Gap

The Rust format has the fewest conformance test variants of any inline format:

| Tests with Rust variant | 9 of 27 |
| Tests with Ruby variant | 21 of 27 |

Rust-format conformance tests exist for: `arithmetic`, `basic-p2pkh`, `boolean-logic`,
`bounded-loop`, `if-else`, `if-without-else`, `multi-method`, `property-initializers`,
`stateful`.

---

## Notes

- `bool_cast` is a Rust-specific naming convention that maps to `bool()`. Ruby
  contracts should use `bool()` directly. This is by design, not a divergence.

- `Int` is used extensively in Rust conformance tests (e.g., `expected_sum: Int`).
  The Ruby format docs reference `Int` but no Ruby parser maps it — see `ruby.md` D4.
  This is a shared gap, not a Rust-specific divergence.

- For the 9 tests where both Rust and Ruby format variants exist, both produce
  identical Bitcoin Script output.
