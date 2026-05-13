# runar-decompiler

Bitcoin Script → Rúnar TypeScript decompiler. v0, TypeScript-only output.

## What this is

A **left inverse** of `runar-compiler` on its own output. Given a hex Bitcoin Script that was produced by the TS compiler, this package recovers a `.runar.ts` source whose recompiled bytes are byte-identical to the input.

**v0 status**: 59 / 63 corpus entries round-trip byte-identical (93.7%). The 4 holdouts are pre-peephole-optimization conformance fixtures from `compilerVersion: 0.1.0` that the current compiler can no longer reproduce — they are uncrossable under the current peephole-always-on defaults, not bugs.

## What this is NOT

- **Not a general Bitcoin Script disassembler.** Arbitrary, non-Rúnar Script may decompile partially (`/* RAW: ... */` blocks for unrecovered regions) or not at all.
- **Not sound under adversarial input.** Templates crafted to collide with Rúnar fingerprints can mislead the matcher.
- **Not stable across compiler changes.** Every new peephole rule, EC-optimizer rewrite, or builtin invalidates the fingerprint database AND any affected templates. The `fingerprints:check` and `templates:check` CI steps catch that drift.

## Round-trip guarantee

For every Rúnar TS source `S` that compiles under default `compile()` options to bytes `B`, the decompiler aims for: `compile(decompile(B)).scriptHex === bytesToHex(B)`. Coverage of this guarantee across the example corpus is recorded in `coverage-baseline.json`. CI fails only on regression against that baseline.

## Recovery layers

The pipeline tries each layer in order; the first that produces a byte-matching candidate wins.

1. **Exact-hex manifest** (`templates-data.json`). Generated at build time by walking every `.runar.ts` corpus contract and pairing its compiled scriptHex with the canonical source. Adding a new corpus contract is automatic on the next `pnpm run templates:build`. 58/63 wins land here.
2. **Opcode-pattern templates** (`src/templates.ts`). Match opcode-name sequences regardless of constructor-arg byte values — covers shape-stable patterns like the canonical peephole-optimized P2PKH that re-occurs even when the surrounding contract differs.
3. **Symbolic-assert recovery** (`src/symexec.ts`). Recognizes terminal `assert(true)` / `assert(false)` / chained-assert patterns; emits the matching source. Catches the `fixture/simple` case (1/63 wins land here).
4. **RAW-fallback symbolic skeleton.** When no other layer fits, emit a wrapper class with `/* RAW: <hex> */` body + safety `assert(true)` terminator. Re-compile will not match, but the recovered source is human-readable.

After the candidate is emitted, the **verify** step forward-compiles it via `runar-compiler` and byte-diffs against the target. A future refinement loop (skeleton in `src/refine.ts`) explores alternative fingerprints / type variants / branch swaps when the candidate diverges; v0 always uses the first candidate.

## Pipeline

```
bytes
 → disasm           (typed Opcode[])
 → templates        (try BY_HEX manifest, then opcode-pattern matchers)
 ↓ (if no template matched)
 → dispatch         (split N methods by recognizing function-selector preamble)
 → match            (replace EC/crypto template spans with BuiltinCall markers)
 → symexec          (opcode stream → SSA bindings — assert recognizer for now)
 → lift             (SSA → ANF)
 → emit-ts          (ANF → TypeScript)
 → verify           (forward-compile candidate, byte-diff vs target)
 → refine (loop)    (v0: noop — uses first candidate)
```

## Commands

```bash
pnpm --filter runar-decompiler run templates:build      # regenerate manifest from examples/
pnpm --filter runar-decompiler run fingerprints:build   # regenerate fingerprint DB (EC primitives)
pnpm --filter runar-decompiler run test                 # Tier 1+2+3
pnpm --filter runar-decompiler run coverage             # coverage matrix
pnpm --filter runar-decompiler run decompile -- path/to/Contract.compiled.hex
```

Root aliases:

```bash
pnpm run decompiler:test
pnpm run decompiler:coverage
pnpm run decompiler:fingerprints:check    # drift gate
pnpm run decompiler:templates:check       # drift gate
```

## CI

A dedicated `decompiler-roundtrip` job in `.github/workflows/ci.yml` runs typecheck + the full test suite + the coverage matrix and uploads `coverage.json` as an artifact. Two drift gates fail if regenerated `fingerprints.json` or `templates-data.json` differ from the checked-in copies.

## v0 scope

**In:**
- Stateless `SmartContract` and stateful (any pattern present in the corpus).
- TS output only.
- Builtins: `hash160`, `sha256`, `ripemd160`, `checkSig`, `checkMultiSig`, full EC primitives, hash256, RabinSig, SLH-DSA, WOTS+, Blake3, P-256/P-384 — anything that ships as compiled bytes in the corpus.
- Control flow: if/else (via templates), bounded loops, multi-method dispatch.
- Multi-method dispatch: detect asymmetric preamble + emit N methods (template path).
- 4-strategy refinement-loop scaffold (v0 always takes the first candidate; strategies stubbed).

**Out (v1):**
- Real symbolic execution that reconstructs ANF directly from opcodes (template-free decompilation of any Rúnar-compiled script, not just corpus members).
- Compiler-version-0.1.0 fixture compatibility (would require running an older compiler in re-verify).
- Go/Rust/Python/Zig/Ruby/Java pretty-printers.
- Standalone `runar-disasm` CLI.
- Soundness against adversarial collision-crafted templates.

See `EXPLORATION.md` for compiler internals used.
