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
  multi-method) and stays sub-kilobyte per tier.
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
   `column >= 0`. The check stays relaxed to `line >= 0` because a tier
   may legitimately emit `line=0, column=0` for a *synthesized* node that
   has no position in any source file; every tier now tracks real
   positions for nodes that do come from source.)

**Column convention: 1-based line, 0-based column.** The TypeScript tier is
the reference (e.g. `P2PKH.runar.ts` line 43 column 4 = the `a` of `assert`,
where `'    assert(...)'[4] === 'a'`), and `independent-oracle.ts` indexes
`lineText[column]` directly. Tiers whose parsers/tokenizers carry 1-based
columns for diagnostics (`file:line:column`) convert at the source-map
emission point only, so diagnostics keep their conventional 1-based columns.
6. `opcodeIndex` values lie in `[0, opcodeCount)`.

## Independent source-anchor oracle (audit finding #22)

The byte-identity check and the structural invariants above are both graded
against the source-map *generator's own output*: the golden was produced by
the same generator (`--update`), and the structural check only inspects the
mapping table's shape (sorted, in-range, non-empty `sourceFile`, …) — it
never opens the file a mapping claims to point at. A generator that
consistently emits a WRONG `(line, column)` for a given opcode passes both
checks forever, because there is no independent witness in the loop.

`independent-oracle.ts#checkSourceAnchors` is that witness. For every
mapping with a tracked position (`line > 0`) it re-reads the REAL
`.runar.*` source file from disk — never the golden, never any Rúnar
compiler pass — and verifies the claimed position:

- is in-bounds (the file has that many lines; the line has that many
  columns),
- does not land on whitespace,
- does not land inside a same-line comment, and
- does not split an identifier/keyword token in half (the character
  immediately before the mapped column must not be a word character when
  the mapped character is).

It also tracks, per source map, how many mappings are `line === 0`
("untracked" — the documented carve-out for surface forms a tier's parser
doesn't yet stamp a location on; see invariant 5 above) versus genuinely
position-checked. A source map where every mapping is untracked is flagged
even though every per-mapping check trivially "passes" (there's nothing to
check) — `ok` additionally requires `trackedCount > 0`.

This is deliberately a *necessary*, not sufficient, correctness condition:
it does not re-derive "the true statement boundary for opcode N" (that
would recouple the check to a specific parser's node-boundary semantics).
It checks the weaker property that must hold for ANY correct mapping
regardless of a tier's chosen granularity (statement-level for TS/Python,
method-signature-level for some of Zig's mappings, etc.) — but that
weaker property still has real teeth: run against the current committed
goldens, it independently found genuine, pre-existing bugs across four of
the seven tiers (details in `conformance/source-map/anchor-known-issues.json`):

- **Go, Rust, Ruby, Zig** — the tracked column was consistently one
  character past the true token start (e.g. `assert(` mapped at the `s`,
  not the `a`), because these tiers emitted their parsers' 1-based
  diagnostic columns into a 0-based source-map field. **FIXED** — each now
  converts at its source-map emission point only.
- **Java** — every mapping carried `line=0, column=0`: `JavaParser`'s
  `locationOf()` was a stub returning zeros because `parseToTree` discarded
  the `JavacTask` before `Trees.getSourcePositions()` could be taken. The
  rest of the pipeline (AST → ANF → StackLower → Emit) already threaded
  positions correctly. **FIXED** — positions are now resolved, with the
  column taken as a raw character offset (`start - lineMap.getStartPosition`)
  rather than `LineMap.getColumnNumber`, which expands tabs to 8-column
  stops and would mis-anchor every tab-indented contract.

All of the above are fixed: `anchor-known-issues.json` is now empty, so
every (fixture, tier) pair is unconditionally enforced.

None of this is visible from byte-identity or `checkStructural` alone —
both were green before this oracle existed. Fixing those generators is out
of scope for the change that added this file (see `anchor-known-issues.json`
for the per-(fixture, tier) pinned violation signatures and reasons); this
oracle exists so future changes can't silently regenerate a golden to match
a *new* wrong mapping, or make an already-broken tier worse, without the
gate noticing.

### `anchor-known-issues.json`

Mirrors `conformance/fold-on-allowlist.json`'s contract: every entry pins
the exact `{violationCount, trackedCount, totalCount}` signature observed
for a `(fixture, tier)` pair, plus a required `reason`. `run.ts` and
`independent-oracle.test.ts` both evaluate every source map (live-compiled
output in `run.ts`; the committed goldens in the test file) against this
file via `evaluateAgainstKnownIssues`:

- A pair with **no entry** must be fully clean (zero violations, every
  mapping tracked) — any violation here is a hard failure.
- A pair **with an entry** must match its signature exactly — any drift
  (more violations, fewer, or a `trackedCount` regression even at constant
  `violationCount`, as would happen if a partially-tracked tier collapsed
  to fully-untracked) is also a hard failure, forcing a deliberate,
  reviewed allowlist update rather than a silent pass-through.

### Residual limitations (things this oracle cannot independently validate)

- It confirms a mapped position is a *plausible* token anchor, not that
  it's the *correct* one — e.g. it cannot detect a mapping swapped between
  two adjacent, otherwise-valid statement positions (both would pass the
  per-mapping checks). Catching that would require an independent
  statement-boundary derivation (re-parsing each of the 7 surface syntaxes
  outside the Rúnar frontend), which is out of scope here.
- It does not check that mapped positions are monotonically non-decreasing
  in `opcodeIndex` order — true of every current fixture (none use `for`
  loops, whose unrolled bodies would legitimately revisit earlier lines),
  but not asserted as a general invariant to avoid a false positive once a
  looping fixture is added.
- Comment detection is a simple same-line scanner (tracks quote state, not
  a full lexer) — sufficient for the small hand-written contract fixtures
  here, not general-purpose.
- `stateful-counter`'s goldens are stale across all 7 tiers (opcode indices
  — and for Rust/Zig, mapping *counts* — have drifted from current compiler
  output; confirmed while wiring this oracle). That produces a pre-existing
  `byte-id: DIFF` (and, for tiers whose live mapping count no longer matches
  the pinned `anchor-known-issues.json` signature, an additional anchor
  mismatch) unrelated to source-map correctness. Out of scope for this
  change; needs a `--update` pass once someone re-verifies the fixture
  against current compiler output.

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
