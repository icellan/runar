# Step 0 — `asm` Primitive + Decompiler Integration

Findings from reading the current codebase before writing Phase 1 code.

## Decompiler state (already in this branch)

- Pipeline assembled: `disasm → templates → dispatch → match → symexec → lift → emit-ts → verify → refine`. Source under `packages/decompiler/src/`.
- 59 / 63 corpus byte-matches via the `templates-data.json` manifest (auto-generated from `examples/ts/*.runar.ts`). 4 remaining diffs are pre-peephole conformance fixtures from compilerVersion 0.1.0 (uncrossable).
- Symbolic recovery is a **skeleton**. Recognizes terminal `assert(true)` / `assert(false)` / `OP_VERIFY`-separated assert chains via `tryAssertChain` in `src/symexec.ts:81`. Everything else falls through to `raw_block` SSA binding, which `src/emit-ts.ts:27` renders as a `/* RAW: <hex> */` comment with a safety `assert(true);` terminator. **This is the gap `asm` closes.**
- `CompileResult` returns `scriptHex: string` (hex, not bytes). `verify.ts` decodes via `hexToBytes` before byte-comparing. The forward-compile-and-compare oracle lives at `src/verify.ts:23`.
- Fingerprint DB is `fingerprints.json` (currently empty — probes fail to compile under the EC builtin types; logged as task #19). `templates-data.json` is the active byte-match driver; it ships as a 58-entry manifest.

## ANF schema (compiler side) — 18 kinds today

`packages/runar-compiler/src/ir/anf-ir.ts:175-193` defines `ANFValue` as a discriminated union over `kind`. The corresponding `packages/runar-ir-schema/src/anf-ir.ts:179-197` and `packages/runar-ir-schema/src/schemas/anf-ir.schema.json` (oneOf) must stay in sync.

**Adding a 19th kind requires updates at six exhaustive-switch sites:**

| File | Line | Function | Why |
|---|---|---|---|
| `packages/runar-compiler/src/passes/05-stack-lower.ts` | 264 | `collectRefs` | dependency tracking |
| `packages/runar-compiler/src/passes/05-stack-lower.ts` | 964 | `lowerBinding` | actual lowering |
| `packages/runar-compiler/src/optimizer/constant-fold.ts` | 278 | `foldValue` | passthrough |
| `packages/runar-compiler/src/optimizer/constant-fold.ts` | 486 | `collectRefsFromValue` | passthrough |
| `packages/runar-compiler/src/optimizer/constant-fold.ts` | 551 | `hasSideEffect` | mark as side-effect → DCE leaves it alone |
| `packages/runar-compiler/src/optimizer/anf-ec.ts` | (binding walker) | `optimizeMethodEC` | walker is single-binding window; needs side-effect annotation so future folds can't bridge it |

ANF JSON loader at `packages/runar-compiler/src/index.ts:452` validates against `anf-ir.schema.json` — schema must list the new kind or load fails. Artifact serializer at `packages/runar-compiler/src/artifact/assembler.ts:671` is generic; no edit needed.

**No defensive snapshot test today** that pins the kind list. The plan's "schema test that fails if the node-kind list isn't updated everywhere" must be written from scratch.

## Stack IR — divergence from the plan

The plan says: "`RawScript` passes through stack-lower unchanged — bytes are already lowered. Emit `RawScript` emits its `bytes` field verbatim."

**That doesn't work as written**, because `StackOp` (`packages/runar-compiler/src/ir/stack-ir.ts:112-126`) has no kind that carries a raw byte span. The 14 variants are `push`, `dup`, `swap`, `roll`, `pick`, `drop`, `opcode`, `if`, `nip`, `over`, `rot`, `tuck`, `placeholder`, `push_codesep_index`. Each emits a fixed byte sequence via `06-emit.ts`.

We have two viable shapes:

1. **Lower `RawScript` to a reconstituted `[push, opcode, push, …]` stream.** Bytes survive end-to-end, but the peephole optimizer (29 rules, 2–4-op windows, `optimizer/peephole.ts`) **will rewrite across the boundary** — breaking the barrier semantics. We'd have to teach every peephole rule to detect the boundary, which is invasive.

2. **Add a new Stack IR variant `raw_bytes` (or `barrier`).** `{ op: 'raw_bytes', bytes: Uint8Array, in_arity: number, out_arity: number }`. `06-emit.ts` writes the bytes verbatim; peephole and any future windowed optimizer treat it as a hard wall (single early-return in the window matcher).

**Option 2 is the right call.** It mirrors how `placeholder` and `push_codesep_index` already work — opaque markers that the optimizer doesn't peer into. The plan should be updated to reflect this: Phase 1 adds both an ANF kind **and** a Stack IR kind. Both barriers are necessary; peephole is the load-bearing one because it's where windowing happens.

## Optimizer barrier mechanics

- **EC algebraic optimizer** (`optimizer/anf-ec.ts:116-262`, single-binding window): walks bindings linearly, uses a `valueMap` to resolve operands. Cross-binding folds only happen when an operand resolves to a prior EC call. **Safe today** without special-casing — RawScript bindings don't produce EC values, so `valueMap.get()` won't return a foldable target. Mark it as side-effecting in `hasSideEffect` and DCE leaves it alone too. No deeper change needed.
- **Peephole optimizer** (`optimizer/peephole.ts:49-432`, 29 rules, 2/3/4-op windows, fixed-point with `MAX_ITERATIONS=100`): single early-return at the window matcher when the current op is `raw_bytes`. Roughly 3 lines added at the dispatch site.

Both are the canonical "side-effect" pattern already in use for `check_preimage`, `update_prop`, `add_output`.

## Static analyzer (`runar analyze`)

Lives at `packages/runar-testing/src/analyzer/` — entry `analyzeScript(hexScript: string)` at `index.ts:64`. Works on **compiled hex**, not ANF. Stack-depth tracker (`stack-analyzer.ts:144-196`) walks opcodes linearly; path enumerator (`path-analyzer.ts:232-300`) forks on OP_IF.

**Cannot use ANF metadata** because by the time bytes reach the analyzer, the RawScript marker is gone — bytes are bytes. Options:
- (a) Emit a sentinel opcode pair around RawScript spans (e.g. OP_NOP + tagged push) the analyzer can recognize. **Pollutes the byte output** — breaks round-trip.
- (b) Side-channel: the artifact JSON carries `rawScriptSpans: [{ offset, length, inArity, outArity }]` and the analyzer reads it alongside the hex.

**(b) is the cleanest.** The artifact assembler already emits `constructorSlots`, `codeSeparatorIndex`, `codeSeparatorIndices` — extending it with `rawScriptSpans` is the right shape. Analyzer reads the artifact in `analyze.ts:34` for JSON inputs; needs a small extension to accept the spans and skip path analysis through them. Stays a Phase 4 task per the original plan.

## Decompiler integration angle (Phase 2)

The current `src/symexec.ts:runSymbolic` already has a `raw_block` SSA binding that holds hex bytes — that's the seed shape. Phase 2 mostly renames + restructures:

- `raw_block` becomes a real ANF-shaped binding pointing at the new `RawScript` node.
- `src/emit-ts.ts:emitBinding` swaps the `/* RAW: <hex> */` + `assert(true);` fallback for a real `asm({ body: ..., in: ..., in_arity: ..., out_arity: ... })` call. Renders bytes back to `OP_*` mnemonics + `push` / `pushNum` / `pushRaw` tokens at print time using `runar-testing`'s `opcodeName` + the existing minimal-push detection rules from `06-emit.ts:274-326`.
- `src/verify.ts` already round-trips through `compile()`. The plan's `--strict-roundtrip` flag — disable EC opt + peephole during re-compile — is a `compile()` option that exists for constant-fold (`disableConstantFolding`) but NOT for peephole or EC opt. **New CompileOptions flags needed** for strict mode. Smaller, contained change.
- Clean-boundary cutting in symexec: today's `tryAssertChain` already does this (returns null → falls back to `raw_block`). The generalization is "anywhere `symexec` can't model the next opcode, emit a `RawScript` for the remaining span." Single new conditional in the recognizer.

## Pretty-printer / disassembler reuse

`runar-testing/src/vm/utils.ts:disassemble(script: Uint8Array): string` produces asm text but is **string-shaped** — not directly reusable as a structured `OP_*` token stream. The decompiler's own `src/disasm.ts` returns typed `Op[]` and is the right substrate. For Phase 1's pretty-printer, we'd duplicate the minimal-push detection logic from `06-emit.ts:274-326` (or factor it out — small refactor, low blast radius).

## Punch list, by phase

### Phase 1 — IR + emit + round-trip canary

1. Add `RawScript` to ANFValue at three sync points: `packages/runar-compiler/src/ir/anf-ir.ts`, `packages/runar-ir-schema/src/anf-ir.ts`, `packages/runar-ir-schema/src/schemas/anf-ir.schema.json`.
2. Add cases at the 6 exhaustive switch sites listed above. Mark side-effecting in `hasSideEffect`.
3. Add `raw_bytes` to StackOp at `packages/runar-compiler/src/ir/stack-ir.ts`. Lower `RawScript` → emit single `raw_bytes` StackOp in `05-stack-lower.ts:lowerBinding`. Emit verbatim in `06-emit.ts`.
4. Add the peephole-barrier early return (`if (op.op === 'raw_bytes') { result.push(op); i++; continue; }`).
5. Add a defensive snapshot test pinning the ANF kind list against the JSON schema.
6. Round-trip CI test: parse a small mainnet-corpus hex blob → wrap in single-`RawScript` ANF → compile back → assert byte-equality. **No surface syntax yet** — built and tested via direct ANF construction.

### Phase 2 — decompiler emits `asm` instead of `RAW` comments

1. `src/symexec.ts`: replace `raw_block` SSA binding with `raw_script` carrying `bytes` + computed `in_arity` / `out_arity`. (For the always-end-of-script case the symexec produces today: `in_arity = stackDepthBeforeSpan`, `out_arity = 1` since the script must terminate truthy.)
2. `src/emit-ts.ts`: render as `asm({ body: ..., in: ..., out_arity: 1 })`. Reuse `runar-testing`'s `opcodeName` for mnemonics; factor or duplicate minimal-push detection from `06-emit.ts`.
3. Add a `runar disasm --raw` mode that wraps the entire input in a single `RawScript` and short-circuits the rest of the pipeline. Becomes the floor.
4. Add `CompileOptions.disablePeephole` and `CompileOptions.disableEcOptimizer` flags so `verify.ts` can opt into `--strict-roundtrip`.
5. Track and log unmatched spans to `packages/decompiler/coverage-unmatched.json` so they can drive future fingerprint additions.

### Phase 3 — surface syntax

Not started in Step 0. Plan looks self-contained. Likely lands as a `01-parse.ts` extension recognizing `asm({ body: ..., in: ..., in_arity?, out_arity? })` as a builtin call with structured args.

### Phase 4 — analyzer integration

`rawScriptSpans` in the artifact + analyzer extension. Smallest blast radius; sequence after Phase 3.

## Recommendation

Land Phase 1 as a single PR. Three sub-commits:

- (a) ANF + Stack IR additions, every exhaustive switch updated, schema sync test in place. No optimizer work yet — both opts naturally pass-through opaque kinds.
- (b) Peephole barrier early-return + EC opt side-effect annotation + tests confirming `ecMul; raw_bytes; ecMul` doesn't fold and that peephole doesn't bridge.
- (c) Round-trip canary test against a small mainnet-corpus blob.

Phase 1 unblocks Phase 2 (decompiler `asm` emission). The two highest-value follow-ups are:

- Phase 2 immediately, because it pays back the templating shortcut — turns the 4 remaining "uncrossable" fixtures into `asm`-wrapped round-tripping output, and gives every non-corpus contract an honest floor instead of a `/* RAW: */` comment that doesn't round-trip.
- Phase 4 before Phase 3 if user-facing `asm({...})` source isn't blocking anyone — the analyzer signal is the real audit-side value. Phase 3 is for humans writing asm by hand, which is a smaller cohort.

## Divergences from prompt

- Plan's "Stack-lower pass: `RawScript` passes through unchanged" is wrong — Stack IR has no carrier for raw bytes today. **Phase 1 adds a new StackOp kind too.** Two-IR-kind change, not one.
- Plan's "peephole optimizer barrier" is invasive if we lower to `[push, opcode, …]`. The `raw_bytes` StackOp solves it with a 3-line dispatch early-return.
- Plan's "static analyzer teach about RawScript" — analyzer is post-emit and bytes-only, can't see ANF kinds. Side-channel via artifact JSON is the path.
- Plan's `--strict-roundtrip` requires new `CompileOptions` flags that don't exist today (`disablePeephole`, `disableEcOptimizer`). Small additions; flagged.
- Plan's "fingerprint DB stays gated on contracts that fully lift" — already true. Current DB is empty (probes broken, task #19). No action needed for asm.
