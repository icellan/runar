# Contributing to Rúnar

Thanks for your interest in contributing. Rúnar compiles a strict subset of
several languages into Bitcoin SV Script, and its correctness guarantees come
from a few hard invariants. Please read this before opening a PR — changes that
break these invariants cannot be merged.

By participating in this project you agree to abide by our
[Code of Conduct](CODE_OF_CONDUCT.md).

## The Central Invariant: Seven Tiers Must Stay in Sync

Rúnar ships **seven independent compiler implementations** (TypeScript, Go,
Rust, Python, Zig, Ruby, Java) and **seven deployment SDKs**. Two rules are
non-negotiable:

1. **Every language-feature or codegen change must land in all seven compiler
   tiers.** Adding an AST node, an ANF value kind, a built-in, or a new surface
   format means touching TS, Go, Rust, Python, Zig, Ruby, *and* Java in the same
   change. The exact file checklists live in
   [`CLAUDE.md`](CLAUDE.md) under **"Adding a New ANF Value Kind"** and
   **"Adding a New Input Format Parser"**; the rationale is in **"Seven
   Compilers Must Stay in Sync."** A partial port is a conformance gap, not a
   contribution. (The narrow, documented exception is the Go-only EVM/STARK
   proof-system family — see CLAUDE.md.)

2. **Wire-protocol primitives must stay byte-identical across all seven SDKs.**
   Anything whose bytes cross a tier boundary — `canonicalJson` (RFC 8785 / JCS),
   and the `SignedEnvelope` / `signEnvelope` / `verifyEnvelope` protocol — must
   produce identical bytes and identical rejection reasons in every SDK. See
   CLAUDE.md **"Seven SDKs Must Stay in Sync (wire-protocol primitives)."** Any
   envelope-related change must round-trip through `conformance/sdk-envelope/`.
   Per-tier ergonomic wrappers (provider classes, `LocalSigner`, etc.) do *not*
   need API parity — sync the wire bytes, not the API shape.

## Build & Test

Set up the repo (Node >= 20, pnpm 9.15+; plus Go 1.26+, Rust 1.75+, Python
3.10+, and the Zig/Ruby/Java toolchains for those tiers):

```bash
pnpm install && pnpm build
```

Layered test entry points (see the table in [`README.md`](README.md)):

| Command | Scope |
|---|---|
| `pnpm test` | TS unit suites only (fast inner loop). |
| `pnpm test:all` | `test` + conformance + examples + e2e + wallet-client. Excludes the live regtest node. |
| `pnpm test:ci` | `test:all` + integration suite (requires `pnpm integration:svnode:start` first). Mirrors CI. |

**`pnpm test:all` must be green before you open a PR.** If your change touches a
specific tier, also run that tier's native suite:

```bash
npx vitest run                                  # TypeScript (packages + examples)
cd compilers/go && go test ./...                # Go compiler
cd compilers/rust && cargo test                 # Rust compiler
cd packages/runar-py && python3 -m pytest        # Python
cd compilers/zig && zig build test              # Zig compiler
cd compilers/ruby && rake test                  # Ruby compiler
cd compilers/java && gradle test                # Java compiler (gradle 8.5+)
```

(The full per-tier matrix is in `CLAUDE.md` → **Build & Test**.)

## Conformance Discipline

The [`conformance/`](conformance/) suite is the enforcement mechanism for the
seven-tier invariant. A new language feature needs a fixture under
`conformance/tests/<name>/`:

- **Author the contract in all nine surface formats** —
  `.runar.{ts,sol,move,go,rs,py,zig,rb,java}`. The runner asserts every fixture
  ships all nine source files; the per-fixture `compilers` allowlist scopes
  Stack-IR/hex parity *only* — the parser layer is universal (all 7 tiers parse
  all 9 formats). A single-format parser carve-out requires a `parserSkip` +
  `parserSkipReason` in `source.json`, and is reserved for genuinely blocked
  ports.
- **Stamp goldens from the TypeScript reference compiler.** `expected-ir.json`
  is canonical JSON (RFC 8785); `expected-script.hex` is the compiled script.
  Use `runar compile … --ir` / `runar compile …`, or
  `cd conformance && pnpm run update-golden`.
- **Goldens are stamped fold-OFF.** CI runs the suite **twice**: once with
  `--disable-constant-folding` (matches the checked-in goldens *and* enforces
  cross-tier parity) and once with `RUNAR_DISABLE_CONSTANT_FOLDING=0` (folding
  ON), which enforces cross-tier hex + ANF parity across all 7 tiers but skips
  the golden comparison. A fold-ON-only divergence must be fixed, or
  allowlisted with a `reason` in `conformance/fold-on-allowlist.json` (currently
  empty — no exemptions).
- **New `compilers` allowlists are gated.** Opting a fixture out of a tier
  requires adding it to `APPROVED_ALLOWLISTS` in
  `runner/__tests__/allowlist-audit.test.ts` *and* a non-empty
  `compilersJustification` in `source.json`. See
  [`conformance/README.md`](conformance/README.md).

SDK changes additionally need coverage in `conformance/sdk-output/` (byte-
identical locking script across all seven SDKs) — run `pnpm run conformance:sdk`.

## Pull Request Expectations

- **Surgical changes.** Touch only what the task needs. Don't refactor,
  reformat, or "improve" adjacent code that isn't part of your change.
- **Match existing style.** Follow the conventions already present in the file
  and the tier you're editing.
- **Reproduce bugs with a failing test first**, then fix.
- **No AI attribution** in commit messages or PR descriptions — no
  `Co-Authored-By`, no "Generated with" lines.
- Keep the description focused on *what* changed and *why*, and confirm which
  test suites you ran.
