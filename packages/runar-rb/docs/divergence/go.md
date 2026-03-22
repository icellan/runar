# Go Format — Divergence from Specification

**Date:** 2026-03-20
**Perspective:** Observed from Ruby format parity analysis

---

## Summary

The Go format is well-aligned with the specification. One minor documentation gap
was found. No output divergences exist for any construct that both Ruby and Go
formats implement.

---

## Divergences

### G1 — Go format guide does not mention Python compiler support [DOCUMENTATION]

**Where:** `docs/formats/go.md`

**Status:** The Go format (`.runar.go`) is supported by all four compilers, but
the Go format documentation does not mention the Python compiler as a supported
compiler. This is a documentation omission — the Python compiler's Go parser
(`parser_go.py`) exists and functions correctly.

---

## Conformance Coverage Gap

The Go format has fewer conformance test variants than Ruby:

| Tests with Go variant | 9 of 27 |
| Tests with Ruby variant | 21 of 27 |

Go-format conformance tests exist for: `arithmetic`, `basic-p2pkh`, `boolean-logic`,
`bounded-loop`, `if-else`, `if-without-else`, `multi-method`, `property-initializers`,
`stateful`.

Missing Go variants that Ruby has: `convergence-proof`, `ec-demo`, `ec-primitives`,
`function-patterns`, `math-demo`, `oracle-price`, `post-quantum-slhdsa`,
`post-quantum-wallet`, `post-quantum-wots`, `sphincs-wallet`, `stateful-counter`.

This is not a divergence — the Go parser correctly handles all these constructs.
The gap is in test coverage, not in implementation.

---

## Verified Parity

For the 9 tests where both Go and Ruby format variants exist, both produce identical
Bitcoin Script output across all four compilers.
