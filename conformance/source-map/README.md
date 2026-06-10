# GAP-002 — Source map conformance suite

Validates the `--emit-source-map=<path>` flag that all 7 compiler tiers ship
under GAP-002. Each (fixture, tier) pair has a per-tier `expected-source-map.json`
golden; the runner re-invokes the tier's CLI and asserts byte identity
plus a small set of structural invariants.

## Layout

```
conformance/source-map/
├── run.ts                       # runner (entry point)
├── <fixture>/
│   ├── <tier>/
│   │   └── expected-source-map.json
│   └── ...
└── .gitignore                   # ignores .tmp/ scratch dirs
```

## Fixtures (5)

- `basic-p2pkh`
- `stateful-counter`
- `escrow`
- `arithmetic` — substituted for `ec-demo` (GAP-002 brief), because
  `ec-demo`'s compiled output explodes EC primitives to ~750 KB of hex
  and ~45 MB of source-map JSON per tier; committing 7 × 45 MB into the
  repo is not OK. `arithmetic` is structurally similar (computation-dense,
  multi-method) and stays sub-kilobyte per tier. See
  `_review/GAP-002-audit.md`.
- `if-else`

## Tiers (7)

`ts`, `go`, `rs`, `py`, `zig`, `rb`, `java`. Each tier compiles its
own surface syntax (`.runar.ts`, `.runar.go`, …), so line / column
numbers in the goldens are tier-specific by design.

## Running

```bash
# All tiers, all fixtures. Exits non-zero on any byte-identity or
# structural failure.
node --import <tsx-loader> conformance/source-map/run.ts

# Regenerate every golden (use after a compiler change that legitimately
# moves source positions).
node --import <tsx-loader> conformance/source-map/run.ts --update

# Restrict to one tier or one fixture.
node --import <tsx-loader> conformance/source-map/run.ts --tier=go
node --import <tsx-loader> conformance/source-map/run.ts --fixture=arithmetic
```

## Structural invariants

Applied to every emitted source map, in addition to byte identity vs the
committed golden:

1. Top-level shape is `{ "mappings": SourceMapping[] }`.
2. `mappings.length <= opcodeCount` (the compiled hex's opcode count is
   approximated by walking the bytes). Tiers may omit a mapping for ops
   the lowering pass had no `sourceLoc` for; `length == opcodeCount` is
   too strict.
3. `mappings` is sorted ascending by `opcodeIndex`.
4. No duplicate `opcodeIndex` values.
5. Each entry has `opcodeIndex >= 0`, `line >= 0`, `column >= 0`, and
   a non-empty `sourceFile`. (The JSON schema demands `line >= 1` and
   `column >= 0`; the Java tier's parser still defaults to `line=0`
   on the surface forms it doesn't track, so the structural check
   relaxes to `>= 0`. A future Java parser improvement should bump this
   back to `>= 1` here and across the schema.)
6. `opcodeIndex` values lie in `[0, opcodeCount)`.

## Notes per tier

- **Rust** — peephole pass previously wiped `source_locs` to all-`None`.
  Fixed by `optimize_stack_ops_with_locs` (preserves the head input's
  loc on every collapsed window).
- **Zig** — peephole pass previously dropped `instruction_source_locs`.
  Same head-input-preserves fix as Rust. Also fixes the artifact JSON's
  `"sourceMap"` field (previously a bare array; now the canonical
  `{"mappings":[…]}` object).
- **Java** — had no source-map plumbing at all. Now threads
  `runar.compiler.ir.ast.SourceLocation` from AST statements through
  `AnfLower` → `StackLower` (re-stamps stack ops) → `Peephole`
  (preserves through window-collapse) → `Emit` (accumulates the
  source-map table). `--emit-source-map=<path>` is wired in `Cli.java`.

## Generated artefacts (gitignored)

- `conformance/source-map/.tmp/` — scratch dir for per-tier intermediates
  (Go binary, per-run artifact outputs).
