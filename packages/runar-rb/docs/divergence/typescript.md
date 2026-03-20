# TypeScript Format — Divergence from Specification

**Date:** 2026-03-20
**Perspective:** Observed from Ruby format parity analysis

---

## Summary

TypeScript is the reference format. No divergences from specification were found.
The TS format defines the canonical AST shape that all other formats target.

---

## Notes

- The TS compiler's Ruby parser (`01-parse-ruby.ts`) is missing trailing-underscore
  builtin mappings (`sign_`, `pow_`, `sqrt_`, `gcd_`, `log2_`) — this is a Ruby
  parser bug within the TS compiler, not a TS format divergence. See
  `ruby.md` D1 for details.

- The TS format uses `this.count++` / `this.count--` (post-increment), while Ruby
  uses `@count += 1` / `@count -= 1`. Both produce identical ANF IR after lowering.
  This is expected surface-level syntax difference, not a divergence.

- The TS parser (ts-morph) warns on `==` usage, while the Ruby parser silently maps
  `==` to `===`. Both produce the same AST. Not a divergence.
