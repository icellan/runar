# Combined findings — Rúnar v1 tri-review (round 2)

Generated 2026-09-22 · base `d207ee8e` (origin/main) · branch `fix/v1-tri-review-r2` · machine-readable twin: `COMBINED-findings.json`

## Inputs and comparability

| Reviewer | Prefix | Review commit | Findings ingested | Files inspected |
|---|---|---|---:|---:|
| Claude Code | CL | `8937c1ad` | 428 | 4641 / 4641 |
| Grok | GK | `2b3af765` | 55 | 4590 / 4591 (1 by proxy) |
| Codex | CX | `2b3af765` | 165 (reconstructed) | 349 / 4601 |

- **Codex did not finish.** It left 11 breadth worker reports and no `findings.json`. Per the user's instruction ("take whatever results are there") its 165 findings were reconstructed mechanically from those reports and given `CX-<CAT>-NNN` IDs; each record carries `cx_source` pointing at the report and finding number. Codex inspected only the compiler pipeline/optimizer partitions, so its silence elsewhere is uninformative.
- **The reviewers used two commits.** CL reviewed `8937c1ad`, 16 commits ahead of the CX/GK pin `2b3af765`. Recorded as a known limitation, not resolved.
- **Drift to HEAD is large:** 617 commits after `8937c1ad`, including the previous remediation run of the OLD review (PRs #168/#169). That is why 185 items verified STALE.
- **Excluded:** `runar-audit/claude/` (the old Claude review, already remediated). `runar-verification/` was excluded by all three reviewers and is off-limits.

## Method

1. **Mechanical merge** (`remediation-logs/combine/ingest.py`): 648 findings concatenated and normalized. 568 bare-filename citations resolved against the reviewed trees; 150 CL table-row and range-heading descriptions corrected to their own row/bullet.
2. **Candidate groups** (`group2.py`): over-inclusive, bucketed by fix location, 141 groups + singletons. Recall was checked against known duplicate pairs before dispatch.
3. **Semantic dedup**: 19 read-only `sonnet` subagents, one per batch of groups.
4. **Tier assignment**: 470 findings mechanically, 51 untiered, and 127 ambiguous ones classified by 2 `sonnet` subagents. The brief requires every compiler/SDK item to be single-tier, so assembly (`assemble3.py`) unions per *(finding, tier, facet)* node.
5. **Dispatcher review (§2.3)**: all 96 multi-source items read (not a 1-in-5 sample). 1 merge split, 1 dedup cluster overridden, 11 redundant copies dropped, 4 collective bundles decomposed into 32 bullet items.
6. **Pre-dispatch verification (§3)**: all 676 items checked against HEAD by 48 read-only `sonnet` verifiers. Verdicts: 472 confirmed, 192 stale, 8 rejected, 4 unclear. Five cross-verifier conflicts were re-derived by the dispatcher (below).

## Dispatcher conflict resolutions


## R1 — Chronicle `OP_2MUL` "every stateful contract unspendable on mainnet" (V253 vs V257; CL-BUG-112 family)
Verifier batch 9 REJECTED (V253); verifier batch 16 CONFIRMED CRITICAL (V257). **Batch 9 is correct.**
- `docs/chronicle-opcode-policy.md:10` and `spec/opcodes.md:500` at HEAD: Chronicle activated on BSV mainnet at
  block 943,816 on 7 April 2026. HEAD is dated September 2026, so the emitted opcodes are valid on mainnet.
- The Chronicle dependence is the project's declared target profile; the only real gap (undisclosed dependence)
  was closed by `6321feb4` R-014.
- Evidence error in the CL review: `go-chaincfg/params.go:277` is not a dependency of this repository
  (`git grep go-chaincfg -- '*.mod' '*.sum'` → nothing). The height was right; the citation was not.
Outcome: REJECTED (by design; disclosure already fixed). False-positive attributed to CL.

## R2 — phantom CL IDs (bookkeeping defect in the CL review's findings.json extraction)
CL-GAP-146 and CL-GAP-153 occur only as the END of a level-1 section range heading
(`# PASS C BATCH 3 — … (CL-BUG-251 … CL-GAP-146)`, `… (CL-BUG-257 … CL-GAP-153)`) — they were allocated by the range
and never given a finding body. Outcome: REJECTED (phantom ID, not a finding). Attributed to CL (review tooling).
CL-BUG-186 / CL-BUG-098 / CL-BUG-099 are REAL findings whose title the extractor failed to capture ("(see ledger)");
the verifiers read the ledger text. Not phantoms.

## R1 addendum
V259 (batch 19) is a third item carrying the same Chronicle `OP_2MUL` claim; resolved by R1 → REJECTED (by design).

## R3 — STALE verdicts that admit a residual (10 reviewed by the dispatcher)
Upheld STALE (headline defect fixed; residual cosmetic, unreachable, or defence-in-depth behind an enforced upstream
guard): V095, V515, V548, V169, V045, V299, V218; V253 via R1.
Re-scoped to CONFIRMED (narrowed):
- **V279** — negatives corpus now spans 5 of 9 surfaces (ts/sol/move/go/zig); **rust/python/ruby/java have zero
  negative fixtures**. Narrowed item: add rejection fixtures for those four surfaces.
- **V543** — see R4.

## R4 — sdk-bip143 locktime: V242 (batch 1, "non-zero locktime now covered") vs V543 (batch 5, "residual locktime hardcoding")
Checked at HEAD: `conformance/sdk-bip143/generate-fixtures.ts:143,261` default `lockTime = 0`; the self-check recompute
at `:504` hardcodes `lockTime: 0`; `fixtures.json` carries no locktime field. **V543 is correct; V242's locktime claim is
wrong.** The sighash-mode half is fixed (R-206, 2676af7d). Outcome: V242 STALE (modes), V543 CONFIRMED narrowed to
"every sdk-bip143 scenario pins nLockTime = 0".

## R5 — Rust-tier source maps on non-native surfaces: V058 (batch 27, STALE) vs V634 (batch 30, CONFIRMED)
Measured by the dispatcher with the built binary at HEAD (output to scratchpad only; worktree unchanged):
  compilers/rust/target/release/runar-compiler-rust --source examples/<surface>/arithmetic/Arithmetic.runar.<ext> --emit-source-map
  .runar.ts  → 28 mappings, 1 distinct (line,col)      .runar.sol → 28 mappings, 1 distinct
  .runar.rs  → 28 mappings, 6 distinct
**V634 is correct.** V058's STALE verdict checked `conformance/source-map/*/rs/expected-source-map.json`, which grades each
tier only on its OWN surface — the exact blind spot the original CL-GAP-156 described. Outcome: V058 re-scoped to CONFIRMED
(non-native surfaces of the Rust tier still emit degenerate maps, and the harness does not grade cross-surface maps).


## Outcomes

| Status | Items |
|---|---:|
| QUEUED | 421 |
| STALE | 185 |
| SKIPPED | 33 |
| REJECTED | 18 |
| DECISION-D2 | 10 |
| DECISION-D1 | 5 |

Every one of the 648 source IDs traces to at least one outcome (checked by script).

### Needs a user decision — D1: FixedArray out-of-range reads (5)

| ID | Reviewer | Tier | Title | Reason |
|---|---|---|---|---|
| F-422 | CX (CX-BUG-076) | compiler:ruby | Ruby: FixedArray runtime reads have no bounds check; out-of-range/negative index | FixedArray runtime reads alias out-of-range indices to the last slot in all 7 tiers — documented intentional v1 semantics (spec/grammar.md:3 |
| F-423 | CX (CX-BUG-101) | compiler:ts | Runtime FixedArray element reads silently alias any out-of-range index to the fi | FixedArray runtime reads alias out-of-range indices to the last slot in all 7 tiers — documented intentional v1 semantics (spec/grammar.md:3 |
| F-424 | CX (CX-BUG-066) | compiler:python | Runtime FixedArray reads alias every invalid index to the final element | FixedArray runtime reads alias out-of-range indices to the last slot in all 7 tiers — documented intentional v1 semantics (spec/grammar.md:3 |
| F-425 | CX (CX-BUG-085) | compiler:rust | Runtime FixedArray reads alias every invalid index to the final element | FixedArray runtime reads alias out-of-range indices to the last slot in all 7 tiers — documented intentional v1 semantics (spec/grammar.md:3 |
| F-426 | CX (CX-BUG-124) | compiler:zig | Runtime fixed-array reads alias every invalid index to the final element | FixedArray runtime reads alias out-of-range indices to the last slot in all 7 tiers — documented intentional v1 semantics (spec/grammar.md:3 |

### Needs a user decision — D2: RabinSig/RabinPubKey state width (10)

| ID | Reviewer | Tier | Title | Reason |
|---|---|---|---|---|
| F-427 | CL (CL-BUG-038, CL-BUG-070) | * | Go: mutable RabinSig/RabinPubKey/Sig/SigHashPreimage state fields are written in | RabinSig/RabinPubKey state width: compiler emits fixed 8-byte slots, the shared schema + 7 SDK codecs push-data-frame them. N-066 deliberate |
| F-428 | CL (CL-BUG-070, CL-BUG-133) | sdk:java | Java SDK: RabinSig/RabinPubKey/P256Point/P384Point missing from StateSerializer' | RabinSig/RabinPubKey state width: compiler emits fixed 8-byte slots, the shared schema + 7 SDK codecs push-data-frame them. N-066 deliberate |
| F-429 | CL (CL-BUG-070, CL-BUG-124, CL-BUG-133) | sdk:python | Python SDK: RabinSig/RabinPubKey/P256Point/P384Point absent from _TYPE_WIDTHS (s | RabinSig/RabinPubKey state width: compiler emits fixed 8-byte slots, the shared schema + 7 SDK codecs push-data-frame them. N-066 deliberate |
| F-430 | CL (CL-BUG-070, CL-BUG-133) | sdk:rust | Rust SDK: RabinSig/RabinPubKey/P256Point/P384Point missing from state.rs's width | RabinSig/RabinPubKey state width: compiler emits fixed 8-byte slots, the shared schema + 7 SDK codecs push-data-frame them. N-066 deliberate |
| F-431 | CL (CL-BUG-070, CL-BUG-133) | sdk:ts | TS SDK: RabinSig/RabinPubKey/P256Point/P384Point missing from state.ts's width t | RabinSig/RabinPubKey state width: compiler emits fixed 8-byte slots, the shared schema + 7 SDK codecs push-data-frame them. N-066 deliberate |
| F-432 | CL (CL-BUG-070, CL-BUG-133) | sdk:ruby | Ruby SDK: RabinSig/RabinPubKey/P256Point/P384Point missing from state.rb's width | RabinSig/RabinPubKey state width: compiler emits fixed 8-byte slots, the shared schema + 7 SDK codecs push-data-frame them. N-066 deliberate |
| F-433 | CL (CL-BUG-070) | * | Zig SDK: sdk_state.zig's width table omits RabinSig/RabinPubKey/P256Point/P384Po | RabinSig/RabinPubKey state width: compiler emits fixed 8-byte slots, the shared schema + 7 SDK codecs push-data-frame them. N-066 deliberate |
| F-434 | CL+GK (CL-BUG-070, GK-GAP-001) | compiler:ts | Shared state-field width table (runar-ir-schema/state-layout.ts) omits RabinSig, | RabinSig/RabinPubKey state width: compiler emits fixed 8-byte slots, the shared schema + 7 SDK codecs push-data-frame them. N-066 deliberate |
| F-435 | CL (CL-BUG-070, CL-BUG-133) | * | Shared state-layout width table omits RabinSig/RabinPubKey/P256Point/P384Point,  | RabinSig/RabinPubKey state width: compiler emits fixed 8-byte slots, the shared schema + 7 SDK codecs push-data-frame them. N-066 deliberate |
| F-436 | CL (CL-BUG-070, CL-BUG-133) | sdk:go | Shared state-layout width table omits RabinSig/RabinPubKey/P256Point/P384Point,  | RabinSig/RabinPubKey state width: compiler emits fixed 8-byte slots, the shared schema + 7 SDK codecs push-data-frame them. N-066 deliberate |

### Rejected (18)

| ID | Reviewer | Tier | Title | Reason |
|---|---|---|---|---|
| F-655 | CX (CX-GAP-013) | compiler:java | Java compiler CLI exposes no annotated-script/debug output mode of its own (may  | Cli.java's flag dispatch (~936-960) confirms the factual claim — there is no --debug/--annotated flag, only --hex/--emit-ir/--emit-ir-to/--e |
| F-656 | CL (CL-GAP-098) | compiler:zig | Conformance gate builds the Zig compiler `-Doptimize=ReleaseFast`; CI builds `Re | conformance/runner/index.ts:466 `zig build -Doptimize=ReleaseFast` does exist inside `prebuildAllCompilers()`, but that function only runs ` |
| F-657 | CX+GK (CX-BUG-103, GK-GAP-002) | compiler:ts | TS: isSubtype's 'both in the ByteString family -> compatible' rule makes every n | Prior user decision (previous remediation run, "USER DECISIONS #2 — Length discipline → KEEP PERMISSIVE"): ByteString-family mutual assignab |
| F-658 | CL (CL-GAP-136) | * | sdk-envelope CI gate only greps for the literal string 'sdk-envelope' in six fil | At BOTH the reviewed commit (2b3af765) and HEAD, all six non-TS SDK envelope interop tests already consume the SAME shared conformance/sdk-e |
| F-659 | CL (CL-BUG-112) | compiler:go | Every stateful contract's auto-injected checkPreimage binding emits OP_2MUL, a p | R1: Chronicle activated on BSV mainnet at 943,816 on 2026-04-07 (docs/chronicle-opcode-policy.md:10, spec/opcodes.md:500); the dependency is |
| F-660 | CL (CL-BUG-112) | compiler:ruby | Every stateful contract's auto-injected checkPreimage binding emits OP_2MUL, a p | R1: Chronicle activated on BSV mainnet at 943,816 on 2026-04-07 (docs/chronicle-opcode-policy.md:10, spec/opcodes.md:500); the dependency is |
| F-661 | CL (CL-BUG-112) | compiler:ts | Every stateful contract's auto-injected checkPreimage binding emits OP_2MUL, a p | R1: Chronicle activated on BSV mainnet at 943,816 on 2026-04-07 (docs/chronicle-opcode-policy.md:10, spec/opcodes.md:500); the dependency is |
| F-662 | CL (CL-BUG-112) | compiler:zig | Every stateful contract's auto-injected checkPreimage binding emits OP_2MUL, a p | R1: Chronicle activated on BSV mainnet at 943,816 on 2026-04-07 (docs/chronicle-opcode-policy.md:10, spec/opcodes.md:500); the dependency is |
| F-663 | CL (CL-BUG-112) | compiler:java | Every stateful contract's auto-injected checkPreimage binding emits OP_2MUL, a p | R1: Chronicle activated on BSV mainnet at 943,816 on 2026-04-07 (docs/chronicle-opcode-policy.md:10, spec/opcodes.md:500); the dependency is |
| F-664 | CL (CL-BUG-112) | compiler:rust | Every stateful contract's auto-injected checkPreimage binding emits OP_2MUL, a p | R1: Chronicle activated on BSV mainnet at 943,816 on 2026-04-07 (docs/chronicle-opcode-policy.md:10, spec/opcodes.md:500); the dependency is |
| F-665 | CL (CL-BUG-112) | compiler:python | Every stateful contract's auto-injected checkPreimage binding emits OP_2MUL, a p | R1: Chronicle activated on BSV mainnet at 943,816 on 2026-04-07 (docs/chronicle-opcode-policy.md:10, spec/opcodes.md:500); the dependency is |
| F-666 | GK (GK-BUG-016) | sdk:go | SHA2-256f tree-index mask computed as 1<<(h-hp) with h-hp=64: Java's `1L << 64`  | Tier wrong and Go is correct: Go shift wraparound yields the right all-ones mask; the Java and Rust instances have their own items (V264/V26 |
| F-667 | CL (CL-BUG-250) | compiler:rust | Java: `final Bigint limit` in a stateful contract parses to `readonly: False`, j | docs/formats/java.md:80 (present since commit c3b18294, an ancestor of the CL review commit 8937c1ad): 'Fields use plain Java declarations - |
| F-668 | CL (CL-GAP-121) | * | No conformance mode compiles through a non-TS tier with the ANF constant folder  | The item's narrow, literal claim (conformance/fuzzer/ir-differential.ts hard-codes '--disable-constant-folding' for every native tier, and ` |
| F-669 | GK (GK-GAP-009) | * | SHA-1 is listed as a spec opcode but intentionally has no Rúnar language builtin | spec/opcodes.md documents OP_SHA1 (0xa7) explicitly as 'Not used by Rúnar (weak hash)' in its own opcode-usage table (line ~405); no sha1()  |
| F-670 | CL (CL-GAP-060) | compiler:go | Go: Merkle and EC codegen emit Chronicle-only opcodes (OP_2DIV/OP_RSHIFTNUM/OP_2 | R1: Chronicle activated on BSV mainnet at 943,816 on 2026-04-07 (docs/chronicle-opcode-policy.md:10, spec/opcodes.md:500); the dependency is |
| F-671 | CL (CL-GAP-146) | * | (see ledger) | R2: phantom CL ID — only a range-heading endpoint in the CL ledger, never a finding. |
| F-672 | CL (CL-GAP-153) | compiler:ruby | (see ledger) | R2: phantom CL ID — only a range-heading endpoint in the CL ledger, never a finding. |

### Skipped — too large for one failing test (§4) (33)

| ID | Reviewer | Tier | Title | Reason |
|---|---|---|---|---|
| F-437 | CL (CL-GAP-165, CL-GAP-166) | compiler:ruby | Ruby: systemic <unknown>-type inference gaps make 8 subtype? call sites (includi | too large for one failing test (§4): Core mechanism verified at HEAD: `subtype?` (typecheck.rb:224-229) returns `true` whenever either side  |
| F-438 | CL (CL-GAP-108) | compiler:ts | Seven of the ten compiler-supported state-field types (boolean, Addr, Ripemd160, | too large for one failing test (§4): Repo-wide census (parsed all 625 git-tracked, parseable *.json files outside node_modules/runar-verific |
| F-439 | CL (CL-GAP-105, CL-GAP-127) | sdk:java | Java example test suite: 70 of 151 tests (46.4%) never falsify contract logic | too large for one failing test (§4): Spot-checked both cited files at HEAD. examples/java/src/test/java/runar/examples/escrow/EscrowTest.jav |
| F-440 | CL (CL-GAP-106, CL-GAP-127) | * | Zig example test suite: 92 of 204 tests (45.1%) never falsify contract logic | too large for one failing test (§4): examples/zig still has 55 *_test.zig files (54 imported by examples_test.zig's test{} block at line 76, |
| F-441 | CL+GK (CL-BUG-051, CL-BUG-077, GK-BUG-013) | compiler:ts | SLH-DSA-SHA2-256f ships FORS tree height a=8 in every tier's parameter table; FI | too large for one failing test (§4): For every tier's SLH-DSA parameter table, `SLH_PARAMS['SHA2_256f'].a` (the slhMk 4th arg) must equal 9, |
| F-442 | CL (CL-BUG-051, CL-BUG-077) | compiler:java | SLH-DSA SHA2-256f codegen uses a=8 where FIPS 205 requires a=9, identically acro | too large for one failing test (§4): A unit test asserting `SLH_PARAMS.get("SHA2_256f").a == 9` (mirroring the equivalent per-tier parameter |
| F-443 | CL (CL-GAP-134) | compiler:ts | sdk-output conformance suite exercises only 3 of 12 compiler-supported state fie | too large for one failing test (§4): Parsed every `conformance/sdk-output/tests/*/input.json` (70 fixture directories at HEAD, not 98 — the  |
| F-444 | CL (CL-GAP-138) | * | sdk-codegen's one mandatory requirement is met by only 1 of 3 runners, 4 of 7 ti | too large for one failing test (§4): conformance/sdk-codegen/ contains only a fixtures/ subdirectory -- no runners/ directory exists -- whil |
| F-445 | CL (CL-GAP-097) | compiler:python | 100% of Bitcoin Script bytes ever executed by any conformance engine are TypeScr | too large for one failing test (§4): conformance/script_execution_test.go's compileRúnar (lines 76-98) and compileRúnarInline (lines 2873-28 |
| F-446 | CL (CL-BUG-074) | * | The flagship end2end PriceBet webapp's settle path is provably unspendable and n | too large for one failing test (§4): Build the deployed PriceBet unlock path with a valid Rabin signature over the actual (signed) oracle pr |
| F-447 | CL (CL-GAP-020) | compiler:ts | Eleven enumerated TS test sites assert strictly less than the test name or comme | too large for one failing test (§4): Exemplar (site 2): in 05-stack-lower.test.ts's 'contains OP_VERIFY for assert calls' test, assert `opco |
| F-448 | CL (CL-GAP-101) | compiler:ts | `placeholder` and `push_codesep_index` peephole ops are safe only by accident —  | too large for one failing test (§4): No live bug exists today to reproduce as a failing test — every current peephole rule matches fixed, fu |
| F-449 | CX (CX-TODO-001) | compiler:ts | Altstack round-trip peephole optimization is deliberately disabled pending full  | too large for one failing test (§4): N/A as a failing test today (the optimization is correctly disabled, so there is nothing incorrect to r |
| F-450 | CL (CL-GAP-093) | * | The large majority of integration negative tests pass on any error (including th | too large for one failing test (§4): Add AssertTxRejectedWithReason(t, txHex, wantSubstring) to integration/go/helpers/assert.go and require |
| F-451 | CL (CL-BUG-105) | sdk:zig | Zig ANF interpreter: 81 of 129 builtins unimplemented, evalCall falls through to | too large for one failing test (§4): packages/runar-zig/src/sdk_anf_interpreter.zig: `evalCall` (starts line 1424) is a long linear `if (std |
| F-452 | CL (CL-GAP-091) | * | CRITICAL (v1 claim) | too large for one failing test (§4): Assert at least one integration/ruby spec compiles a .runar.rb source via the real Ruby compiler and de |
| F-453 | CL (CL-BUG-229) | * | 3.0% of 497 negative tests assert *why* the failure happened | too large for one failing test (§4): Change one Go example's recover-based negative test (e.g. TicTacToe_test.go's TestTicTacToe_MoveRejects |
| F-454 | CL (CL-BUG-240) | * | The analyzer conformance goldens pin stack depths the spec makes wrong, and a co | too large for one failing test (§4): Add `[Opcode.OP_RSHIFTNUM]: [2, 1]` to stack-analyzer.ts's STACK_EFFECTS and re-run the ec-demo fixture |
| F-455 | CL (CL-BUG-252) | sdk:ruby | 18 of 22 settle tests (81.8%) cannot fail if the winner-selection branch is inve | too large for one failing test (§4): packages/runar-rb/lib/runar/builtins.rb:26: raise 'runar: assertion failed' unless condition — identica |
| F-456 | CL (CL-GAP-028) | compiler:rust | Rust IR loader does no referential-integrity, duplicate-name, cycle, loop-count- | too large for one failing test (§4): Feed `compile_from_ir_str` an IR whose method body has two bindings both named "_t0" (duplicate binding |
| F-457 | CL (CL-GAP-122) | * | No generator in the partition can emit an EC expression, so the DCE defect class | too large for one failing test (§4): Add a new expression-generator arm that can produce an EC builtin call (e.g. `ecOnCurve(<Point literal  |
| F-458 | CL (CL-BUG-054) | * | ANF parity goldens self-bootstrap (test writes then asserts against its own outp | too large for one failing test (§4): Assert every golden under conformance/anf-interpreter/expected/*.json has a corresponding input file ca |
| F-459 | CL (CL-GAP-022) | compiler:ts | 37 not.toThrow() sites plus ~30 compile-only tests assert nothing about emitted  | too large for one failing test (§4): `grep -rn "not\.toThrow()" packages/runar-compiler/src/__tests__/*.ts / wc -l` returns 47 at HEAD (up f |
| F-460 | CL (CL-GAP-023) | compiler:ts | 01-parse-zig.test.ts covers only 5 narrow regressions; 12 tests vs 33-82 for its | too large for one failing test (§4): packages/runar-compiler/src/__tests__/01-parse-zig.test.ts still has 12 top-level it() blocks (same cou |
| F-461 | CL (CL-GAP-029) | compiler:rust | Six Rust tests accept Ok OR Err on the substantive question | too large for one failing test (§4): Pick any one, e.g. test_chained_rules_12_then_5: assert the result is ONLY `ANFValue::LoadConst` equal  |
| F-462 | CL (CL-GAP-031) | compiler:rust | Enumerated malformed-IR classes with no Rust test (referential integrity, raw_sc | too large for one failing test (§4): Add a test asserting `apply_constructor_args` rejects a constructorArgs value whose JSON type/byte-leng |
| F-463 | CL (CL-GAP-035) | compiler:rust | No op-count golden for the entire SHA-256 module plus p384 on_curve / encode_com | too large for one failing test (§4): Add `assert_eq!(count_op_tree(&ops), <measured constant>, "emit_sha256_compress op count drift")` (and  |
| F-464 | CL (CL-GAP-066) | compiler:rust | Rust: MAX_STACK_DEPTH is checked against a stack model that never sees the depth | too large for one failing test (§4): Construct (or find) a contract whose crypto block alone peaks well over 800 modelled stack slots but wh |
| F-465 | CL (CL-GAP-064) | compiler:rust | Rust: fiat_shamir_kb.rs is an orphan port — 291 lines compiled, zero call sites | too large for one failing test (§4): compilers/rust/src/codegen/fiat_shamir_kb.rs is still exactly 291 lines, still carries `#![allow(dead_c |
| F-466 | CX (CX-TODO-002) | compiler:ts | Lower-if contains acknowledged unproved dead/defensive code | too large for one failing test (§4): packages/runar-compiler/src/passes/05-stack-lower.ts:2540-2564 (line-shifted from the cited 2212-2235,  |
| F-467 | CL (CL-BUG-221, CL-BUG-222, CL-BUG-223) | compiler:go | README drift (LOW) | too large for one failing test (§4): compilers/go/README.md documents only --source/--hex/--emit-ir/--output (lines 98-107), while compilers |
| F-468 | CL (CL-BUG-227, CL-GAP-126) | * | Coverage holes pinned by tests | too large for one failing test (§4): conformance/fuzzer/spend-shapes.ts:72 — `export type ShapeType = 'bigint' / 'boolean' / 'ByteString' /  |
| F-469 | CL (CL-BUG-239, CL-GAP-133) | * | The supply chain is unpinned across the board | too large for one failing test (§4): At HEAD: 0 of 218 `uses:` refs across .github/workflows/*.yml are SHA-pinned (`grep -E 'uses:.*@[0-9a-f |

### Stale on arrival — fixed at HEAD, no commit (185)

| ID | Reviewer | Tier | Title | Reason |
|---|---|---|---|---|
| F-470 | CL+CX+GK (CL-BUG-001, CL-BUG-108, CX-BUG-096…) | compiler:ts | TS DCE's hasSideEffect classifies `if` and `loop` as pure; an unreferenced top-l | fixed at HEAD: 445e0f74 R-006: keep if/loop bindings whose nested bindings have side effects (TS DCE); test packages/runar-compiler/src/__te |
| F-471 | CL+CX (CL-BUG-243, CX-BUG-036) | compiler:java | Java: ExpandFixedArrays rebuilds every method through the 5-arg MethodNode const | fixed at HEAD: 1b71ea9e (R-025/R-026: stop the fixed-array expansion dropping AST node fields) + 00bdd6ec (R-075: duplicate of R-025 in Java |
| F-472 | CX+GK (CX-BUG-028, CX-BUG-039, GK-BUG-004) | compiler:java | Java Emit unconditionally writes hex `00` for PushCodeSepIndexOp instead of the  | fixed at HEAD: da867db9 (R-007: emit a deployable artifact from the Java compiler) — explicitly reconciles CL-BUG-044, the same underlying f |
| F-473 | GK (GK-BUG-004) | compiler:java | Java Emit unconditionally writes hex `00` for PushCodeSepIndexOp instead of the  | fixed at HEAD: da867db9 (R-007: emit a deployable artifact from the Java compiler) — Same as V004: Emit.java:525,542-545 record constructorS |
| F-474 | CX (CX-BUG-035, CX-BUG-043) | compiler:java | Java loop lowering has no maximum iteration/unroll ceiling anywhere in the pipel | fixed at HEAD: aebb8c19 (R-009: bound the loop iteration count on the source path in six tiers) + 4a5f55c6 (N-115: three tiers had no loop c |
| F-475 | CL (CL-BUG-242) | compiler:go | `addOutput` arity/type checking exists in only ONE tier (TS); Go/Python/Rust/Jav | fixed at HEAD: 162831dc "N-098: a ByteString in the satoshis slot became the covenant's output amount"; 5ab2aed4 "N-105a: a number in the sc |
| F-476 | CL (CL-BUG-242) | compiler:java | `addOutput` arity/type checking exists in only ONE tier (TS); Go/Python/Rust/Jav | fixed at HEAD: N-105a/N-105b (5ab2aed4, be69ec2d) + N-106/N-107 (e1ec4584) — ported the TS addOutput arity/type contract to Go, Python, Rust |
| F-477 | CL (CL-BUG-242) | compiler:rust | `addOutput` arity/type checking exists in only ONE tier (TS); Go/Python/Rust/Jav | fixed at HEAD: be69ec2d "N-105b: port the rest of the output-intrinsic contract, and refuse to average two conflicts" (also e1ec4584 "N-106  |
| F-478 | CL (CL-BUG-242) | compiler:python | `addOutput` arity/type checking exists in only ONE tier (TS); Go/Python/Rust/Jav | fixed at HEAD: be69ec2d "N-105b: port the rest of the output-intrinsic contract, and refuse to average two conflicts" — compilers/python/run |
| F-479 | CL (CL-BUG-269) | compiler:ruby | Cross-tier: the EC optimizer's fresh-constant helper never emits its binding int | fixed at HEAD: 606e22a0 N-028: bind the folded EC scalar into the method body in Python and Ruby — compilers/ruby/lib/runar_compiler/fronten |
| F-480 | CL (CL-BUG-269) | compiler:zig | Cross-tier: the EC optimizer's fresh-constant helper never emits its binding int | fixed at HEAD: 1eaaf072 N-034 (Zig); 606e22a0 N-028 (Python + Ruby) — compilers/zig/src/passes/ec_optimizer.zig:409-412 `freshConstName` now |
| F-481 | CL+CX (CL-BUG-203, CL-BUG-265, CL-BUG-269…) | compiler:python | Python EC optimizer's _fresh_const_name() writes the generated constant only int | fixed at HEAD: 606e22a0 "N-028: bind the folded EC scalar into the method body in Python and Ruby" — compilers/python/runar_compiler/fronten |
| F-482 | CX (CX-GAP-010) | compiler:java | Java: no emitter test exercises deferred code-separator-index resolution | fixed at HEAD: 8483d464 ("R-084: refuted as filed; the real defect was a placeholder not advancing opcodeIndex") — the commit that added R08 |
| F-483 | CX (CX-BUG-041) | compiler:java | Java: mutable `Sig`/`SigHashPreimage` fields are deserialized as variable-length | fixed at HEAD: 6dc1979b ("R-071: treat Sig and SigHashPreimage as variable-length state in every tier") — commit message documents exactly t |
| F-484 | CX (CX-BUG-042) | compiler:java | Java: mutable `RabinSig`/`RabinPubKey` fields are deserialized as fixed 8-byte v | fixed at HEAD: b7e91a19 ("N-067: write mutable Rabin state at the width the reader parses (5 tiers)") — StackLower.java's NUMERIC_STATE_TYPE |
| F-485 | CX (CX-BUG-044) | compiler:java | Java: for-loop updater expression is neither validated/type-checked nor semantic | fixed at HEAD: 051e98f2 ("R-065: reject a non-unit loop step instead of silently coercing it (6 tiers)") — Validate.java's validateForUpdate |
| F-486 | CX (CX-BUG-045) | compiler:java | Java: AnfLower's pre-scans for addOutput/addDataOutput/state-mutation don't recu | fixed at HEAD: 6922c44a ("R-021: descend into sub-expressions when deciding continuation shape (Zig, Ruby, Java)", fixing CL-BUG-155) — AnfL |
| F-487 | CX (CX-BUG-047) | compiler:java | Java: ANF loader's `asInt` truncates arbitrary-width integer fields (loop counts | fixed at HEAD: d55dac21 ("R-086: Java's IR loader truncated integers; same IR bytes, two different scripts") — AnfLoader.asInt (298-314) now |
| F-488 | CX (CX-BUG-049) | compiler:java | Java: the locktime-finality warning is suppressed by ANY matching sequence compa | fixed at HEAD: 94f5f31f ("fix(validate): locktime sequence guard must be asserted (F7)") — commit message: 'warnLocktimeWithoutSequenceGuard |
| F-489 | CL (CL-BUG-094) | compiler:rust | Rust: private method called inside an if/else branch drops to OP_0 (private_meth | fixed at HEAD: 4fcffcc5 "N-051: plumb privateMethods into branch-arm contexts (Go, Rust, Python)" — compilers/rust/src/codegen/stack.rs:2416 |
| F-490 | CL (CL-BUG-166, CL-BUG-259, CL-BUG-260) | compiler:rust | Rust DCE's has_side_effect() omits ANFValue::If/Loop, so branch/loop bindings (a | fixed at HEAD: 10beeb99 "R-005: keep if/loop bindings whose nested bindings have side effects (Rust DCE)" — compilers/rust/src/frontend/dce. |
| F-491 | CL (CL-BUG-025, CL-BUG-260) | compiler:rust | Rust DCE's has_side_effect() omits ANFValue::If/Loop, so branch/loop bindings (a | fixed at HEAD: 797c61ef "fix(compiler): port #113's constructorArgs validation + loop-outer-refs to 6 tiers" — compilers/rust/src/lib.rs:191 |
| F-492 | CL (CL-BUG-168) | compiler:rust | Rust tier's Java frontend clamps integer literals to i128 and silently substitut | fixed at HEAD: 86e6777c "BUG-001: parser support for new BigInteger() + oversize literals across 7 tiers" (plus 97c885ff "rust(ir): widen Bi |
| F-493 | CL (CL-BUG-258) | compiler:java | `extractVersion` is registered, typechecked and parser-mapped, but has no StackL | fixed at HEAD: 3b203195 ("R-069: close the Zig and Java builtin dispatch gaps") — StackLower.java's lowerExtractor switch now has a `case "e |
| F-494 | CL+GK (CL-BUG-264, GK-BUG-010) | compiler:rust | Rust stack-lowering's unknown-call-name fallback pushes OP_0 instead of refusing | fixed at HEAD: 411c995a "R-016: refuse an unresolvable function in Rust stack lowering" — compilers/rust/src/codegen/stack.rs:2052-2075 — th |
| F-495 | CL (CL-GAP-036) | compiler:rust | `unknown_anf_kind_tests.rs`: six tests, none actually drives an unknown ANF kind | fixed at HEAD: 430a0f0e R-177: delete the unreachable unknown-kind check, and say the words the peers say — compilers/rust/tests/unknown_anf |
| F-496 | CX (CX-BUG-091) | compiler:rust | IR compilation accepts programs with no public methods and returns an empty, suc | fixed at HEAD: 3e16266e N-113: five tiers accepted the malformed IR that Go had started rejecting; a9b108eb N-113: the --ir no-public-method |
| F-497 | CL+GK (CL-BUG-103, CL-BUG-191, GK-BUG-031) | compiler:go | exprCallsSP1Fri's AST switch (CallExpr/BinaryExpr/UnaryExpr only) misses Ternary | fixed at HEAD: 16fc35b6 "R-003: walk every expression form when refusing SP1 FRI" — compilers/go/frontend/sp1_fri_soundness_warning.go:159-1 |
| F-498 | CL+CX (CL-BUG-191, CX-BUG-024) | compiler:go | exprCallsSP1Fri's AST switch (CallExpr/BinaryExpr/UnaryExpr only) misses Ternary | fixed at HEAD: e40ee13a "R-147: the SP1-FRI acknowledgement was unhonourable on two surfaces" — compilers/go/frontend/parser.go:59-135 (`Par |
| F-499 | CL+CX+GK (CL-BUG-101, CL-BUG-182, CX-BUG-002…) | compiler:go | Go's default-ON constant folder rebuilds loop ANF nodes with only Kind/Count/Ite | fixed at HEAD: a5c09624 "N-128 go: constant folding erased a loop's Start and Step" — compilers/go/frontend/constant_fold.go:542-557 — the " |
| F-500 | CL+CX+GK (CL-BUG-102, CL-BUG-183, CX-BUG-001…) | compiler:go | Go's default-ON constant folder's foldMethod rebuilds ANFMethod without SigHashT | fixed at HEAD: 502a5757 "N-093: constant folding dropped sigHashType, making @sighash contracts unspendable via the SDK" — compilers/go/fron |
| F-501 | CL (CL-BUG-090) | * | The CI missing-binary guard (assertAllCompilersAvailableInCi) protects only the  | fixed at HEAD: ae7d062f "R-103 conformance: a local run can no longer hide a dropped tier or an empty fixture set" — conformance/runner/runn |
| F-502 | CX (CX-BUG-004) | compiler:go | Go DCE neither collects `add_raw_output`'s Satoshis/ScriptBytes references nor c | fixed at HEAD: aa5e35a8 "R-004: treat output and call ANF kinds as effectful in Go DCE"; 5f856e1e "R-030: collect the remaining operand refs |
| F-503 | CX (CX-BUG-005) | compiler:go | Go DCE neither collects `add_data_output`'s references nor classifies the node a | fixed at HEAD: aa5e35a8 "R-004: treat output and call ANF kinds as effectful in Go DCE"; 5f856e1e "R-030: collect the remaining operand refs |
| F-504 | CX (CX-BUG-006) | compiler:go | Go DCE's `add_output` case collects Satoshis/StateValues but omits the optional  | fixed at HEAD: 5f856e1e "R-030: collect the remaining operand refs in Go DCE" — compilers/go/frontend/dce.go's `add_output` case in `collect |
| F-505 | CX (CX-BUG-007) | compiler:go | Go DCE's `deserialize_state` case is marked effectful but does not collect its P | fixed at HEAD: 5f856e1e "R-030: collect the remaining operand refs in Go DCE" — compilers/go/frontend/dce.go's `deserialize_state` case in ` |
| F-506 | CX (CX-BUG-008) | compiler:go | Go DCE collects no references from `array_literal` elements, so an EC-triggered  | fixed at HEAD: 5f856e1e "R-030: collect the remaining operand refs in Go DCE" — compilers/go/frontend/dce.go's `array_literal` case in `coll |
| F-507 | CX (CX-BUG-009) | compiler:go | Go DCE categorically treats every `method_call` as pure without inspecting the c | fixed at HEAD: aa5e35a8 "R-004: treat output and call ANF kinds as effectful in Go DCE" — compilers/go/frontend/dce.go's `HasSideEffect` (:2 |
| F-508 | CX (CX-BUG-010) | compiler:go | EC-triggered DCE can remove the unused Groth16 verifier marker call (assertGroth | fixed at HEAD: aa5e35a8 R-004: treat output and call ANF kinds as effectful in Go DCE — compilers/go/frontend/dce.go:255-261 HasSideEffect() |
| F-509 | CX (CX-BUG-018) | compiler:go | CompileFromSource and the CLI read only validResult.Errors and discard validResu | fixed at HEAD: f703a6ac R-061: five CLIs computed validator warnings and threw them away — compilers/go/main.go:199 the CLI's compile path n |
| F-510 | CL (CL-BUG-061) | compiler:zig | Zig `reverseBytes` builtin emits zero opcodes (stack_lower.zig:2506-2514) | fixed at HEAD: ff4a19b7 R-022: emit the byte reversal in the Zig tier — compilers/zig/src/passes/stack_lower.zig:2858-2882 `lowerReverseByte |
| F-511 | CL (CL-BUG-120) | compiler:zig | Zig multi-method dispatch computes the `_codePart` prelude with a different pred | fixed at HEAD: c2846d87 R-010: authenticate _codePart against the executing script (all 7 tiers) — compilers/zig/src/passes/stack_lower.zig: |
| F-512 | CL (CL-BUG-121) | compiler:zig | Zig `compile-ir` on a zero-public-method ANF program produces an empty locking s | fixed at HEAD: 3e16266e N-113: five tiers accepted the malformed IR that Go had started rejecting — compilers/zig/src/ir/json.zig:~301-307 ` |
| F-513 | CL (CL-BUG-122) | compiler:zig | Zig `@intFromFloat` roundtrip guards sit after the cast that panics, so they nev | fixed at HEAD: c8c947d6 N-115: range-check every JSON float before narrowing it in the Zig IR loader (further tightened by 8c989dda N-131, w |
| F-514 | CL (CL-GAP-099) | * | CI's stated reason for excluding Zig from the stateful fuzz gate (`.runar.zig` m | fixed at HEAD: c69101ef "R-111 fuzzer: restore Zig to the stateful gate — the exclusion outlived its cause" — .github/workflows/fuzzer-night |
| F-515 | CX+GK (CX-BUG-120, GK-BUG-005) | compiler:zig | Zig public library API (`compiler_api.zig`'s `compileSourceWithOptions`) never c | fixed at HEAD: 4b439e15 R-027: give the Zig CLI and library one pipeline instead of two — compilers/zig/src/compiler_api.zig:14 imports `pas |
| F-516 | CX (CX-BUG-121) | compiler:zig | Zig `expand_fixed_arrays.zig`'s `rewriteMethod` drops `MethodNode.sighash_type`  | fixed at HEAD: f1691941 N-086: rebuild IR nodes by copy-then-overwrite; Zig's expansion dropped four fields — compilers/zig/src/passes/expan |
| F-517 | CX (CX-BUG-123) | compiler:zig | Zig fixed-array call-expression rewriting reconstructs `CallExpr` without `asm_r | fixed at HEAD: f1691941 "N-086: rebuild IR nodes by copy-then-overwrite; Zig's expansion dropped four fields" (also referenced by compilers/ |
| F-518 | CX (CX-BUG-126) | compiler:zig | Zig source for-loops have no maximum unroll-count bound and use unchecked signed | fixed at HEAD: aebb8c19 "R-009: bound the loop iteration count on the source path in six tiers" (Zig among them; commit message enumerates t |
| F-519 | CL (CL-BUG-224) | * | The repo's only 7-tier fold-ON conformance gate is a no-op — every --ir entry po | fixed at HEAD: 0c192829 "fix(fold): skip ANF constant-fold on --ir input across all 7 tiers" + d69aad2d "v1-readiness: fix RC artifact-schem |
| F-520 | CX (CX-BUG-017) | compiler:go | CompileFromSourceWithResult / CompileFromSourceStrWithResult never forward Compi | fixed at HEAD: 079b7e59 R-162: one compile body for the Go API, so the Groth16 key stops being dropped — compilers/go/compiler/compiler.go:2 |
| F-521 | CX (CX-BUG-027) | compiler:go | ValidateIR has no 'at least one public method' rule, so hand-authored IR contain | fixed at HEAD: eff90a3a R-081: IR with no public methods compiled to an empty, anyone-can-spend script — compilers/go/ir/loader.go:105-120 V |
| F-522 | CL+GK (CL-BUG-115, GK-GAP-003) | compiler:ts | TS DCE classifies `if`/`loop` ANF nodes as side-effect-free, letting dead-code e | fixed at HEAD: 445e0f74 R-006: keep if/loop bindings whose nested bindings have side effects (TS DCE); test packages/runar-compiler/src/__te |
| F-523 | CL (CL-BUG-036, CL-BUG-078) | compiler:go | Go: the stateful continuation's locking script is built from a spender-supplied  | fixed at HEAD: c2846d87 R-010: authenticate _codePart against the executing script (all 7 tiers) — companions 00d833f6, c21b444f (SIZE(_code |
| F-524 | CL+GK (CL-BUG-219, GK-BUG-010) | compiler:go | Go: `lowerCall`'s generic builtin dispatch silently pushes `OP_0` for any `call. | fixed at HEAD: 6601edad R-122 go: refuse an unknown call instead of emitting a silent OP_0 (companion 428f69e4 R-124 ruby,python: same fix,  |
| F-525 | CX+GK (CX-BUG-082, GK-BUG-010) | compiler:ruby | Python: unknown-builtin `call` on the `--ir` path silently pushes 0 instead of e | fixed at HEAD: 428f69e4 R-124 ruby,python: refuse an unknown call instead of emitting a silent OP_0 — compilers/ruby/lib/runar_compiler/code |
| F-526 | CX+GK (CX-BUG-056, CX-BUG-057, GK-BUG-010) | compiler:python | Python: an unrecognized function/call name in stack lowering silently compiles t | fixed at HEAD: 428f69e4 "R-124 ruby,python: refuse an unknown call instead of emitting a silent OP_0" and 4fcffcc5 "N-051: plumb privateMeth |
| F-527 | CX (CX-BUG-013) | compiler:go | Go: a private helper (`method_call`) invoked inside an `if`/`else` branch is not | fixed at HEAD: 4fcffcc5 N-051: plumb privateMethods into branch-arm contexts (Go, Rust, Python) — compilers/go/codegen/stack.go:2295-2331: t |
| F-528 | CL (CL-BUG-185) | compiler:ts | subContext() drops paramAliasStack, so an inlined helper's parameter silently al | fixed at HEAD: 2d0011c4 N-079: carry the argument alias into branch arms; five tiers inlined the wrong operand — packages/runar-compiler/src |
| F-529 | CL (CL-BUG-185) | compiler:go | subContext() drops paramAliasStack, so an inlined helper's parameter silently al | fixed at HEAD: 385b9dd7 (Go/Rust) + 2d0011c4 (ts/python/zig/ruby/java) — Go compilers/go/frontend/anf_lower.go:1030-1082 subContext() now de |
| F-530 | CL (CL-BUG-185) | compiler:python | subContext() drops paramAliasStack, so an inlined helper's parameter silently al | fixed at HEAD: 2d0011c4 "N-079: carry the argument alias into branch arms; five tiers inlined the wrong operand" — compilers/python/runar_co |
| F-531 | CL (CL-BUG-215) | compiler:python | for i in range(0, 10, 2) silently compiles to ten unit-step iterations instead o | fixed at HEAD: c6c82ed8 "feat(parse): the Python, Ruby and Rust surfaces can spell a countdown" — compilers/python/runar_compiler/frontend/p |
| F-532 | CX (CX-GAP-017) | compiler:python | Rule 10's test only asserts the generated name is a non-empty string, so it stru | fixed at HEAD: 606e22a0 "N-028: bind the folded EC scalar into the method body in Python and Ruby" (added test_n028_ec_fresh_const_binding.p |
| F-533 | CL (CL-GAP-116) | compiler:ts | TS tier's GO_CAST_TYPES unwraps runar.Sha256/Ripemd160/etc. as a type cast befor | fixed at HEAD: aca738e1 fix(parse-go): stop dropping Sha256 and Ripemd160 in the Go surface — packages/runar-compiler/src/passes/01-parse-go |
| F-534 | CL (CL-BUG-202, CL-BUG-267) | compiler:python | artifact_to_json raises an unhandled JSONDecodeError on 30 of 72 conformance fix | fixed at HEAD: 36080520 "fix(python): `--ir <file> --output <artifact>` died with a raw JSONDecodeError" — compilers/python/runar_compiler/c |
| F-535 | CX (CX-BUG-063, CX-BUG-075) | compiler:python | Artifact build_timestamp is taken from datetime.now(timezone.utc) and unconditio | fixed at HEAD: 6871de2d "R-212: six of seven tiers ignored SOURCE_DATE_EPOCH" — compilers/python/runar_compiler/compiler.py:115-129 (_build_ |
| F-536 | CX+GK (CX-BUG-064, GK-BUG-026) | compiler:python | compiler.py's private _parse_source dispatcher (used by compile_from_source, com | fixed at HEAD: e5faa304 "R-024: route every Python entry point through the guarded dispatcher" — compilers/python/runar_compiler/compiler.py |
| F-537 | CX+GK (CX-BUG-065, GK-BUG-026) | compiler:python | compiler.py's private _parse_source dispatcher (used by compile_from_source, com | fixed at HEAD: e5faa304 "R-024: route every Python entry point through the guarded dispatcher" — Same fix as V149 (both are GK-BUG-026 plus  |
| F-538 | CX (CX-BUG-073) | compiler:python | Ordinary CLI/library compile entry points inspect only valid_result.errors (not  | fixed at HEAD: f703a6ac "R-061: five CLIs computed validator warnings and threw them away" — compilers/python/runar_compiler/__main__.py:239 |
| F-539 | CL+CX (CL-BUG-271, CX-BUG-079) | compiler:ruby | Ruby CLI `--emit-ir` ANF serializer drops the per-call `sighashFlag`, changing t | fixed at HEAD: 11fa3200 N-094: derive the ANF wire format from the type; Ruby and Python were downgrading @sighash (further generalized by 6 |
| F-540 | CL (CL-BUG-271) | compiler:ruby | Ruby CLI `--emit-ir` ANF serializer drops the per-call `sighashFlag`, changing t | fixed at HEAD: 11fa3200 N-094: derive the ANF wire format from the type; Ruby and Python were downgrading @sighash (further generalized by 6 |
| F-541 | CL (CL-GAP-084) | * | `conformance/source-map/run.ts` is never invoked — the only byte-identity gate f | fixed at HEAD: cb68a5e2 "test: fail derived-artifact --check when analyzer, sdk-output, source-map, decompiler, or script-size lag" — confor |
| F-542 | CL+CX (CL-GAP-163, CX-GAP-019) | compiler:ruby | Ruby validation warnings (`Severity::WARNING`) are generated by the validator bu | fixed at HEAD: f703a6ac R-061: five CLIs computed validator warnings and threw them away — compilers/ruby/lib/runar_compiler/compiler.rb:569 |
| F-543 | CX (CX-BUG-080) | compiler:ruby | Ruby source-path `for` loops accept any literal bound with no maximum, unlike th | fixed at HEAD: aebb8c19 R-009: bound the loop iteration count on the source path in six tiers — compilers/ruby/lib/runar_compiler/frontend/a |
| F-544 | CX (CX-BUG-081) | compiler:ruby | Ruby IR loader accepted a program with zero public methods and emitted a success | fixed at HEAD: 3e16266e N-113: five tiers accepted the malformed IR that Go had started rejecting — compilers/ruby/lib/runar_compiler/ir/loa |
| F-545 | CX (CX-BUG-084) | compiler:ruby | Ruby: mutable `Sig`/`SigHashPreimage` state is parsed as length-prefixed but res | fixed at HEAD: 6dc1979b R-071: treat Sig and SigHashPreimage as variable-length state in every tier — compilers/ruby/lib/runar_compiler/code |
| F-546 | CX (CX-BUG-019) | compiler:go | Go: source loops bypass the IR path's `MaxLoopCount` bound entirely, and the `bi | fixed at HEAD: fcc95fb5 'R-013: range-check compile-time constants before narrowing them (Go)' (2026-09-09) — compilers/go/frontend/anf_lowe |
| F-547 | CL (CL-GAP-113) | compiler:python | Python: six crypto builtin dispatchers (`_lower_ec_builtin`, `_lower_nist_ec_bui | fixed at HEAD: debcf29c "R-128,R-163,R-165 compilers: validate builtin call arity on the --ir path, in every tier that accepted it" — The 6  |
| F-548 | CL+CX (CL-GAP-113, CX-BUG-062) | compiler:python | Python: six crypto builtin dispatchers (`_lower_ec_builtin`, `_lower_nist_ec_bui | fixed at HEAD: debcf29c "R-128,R-163,R-165 compilers: validate builtin call arity on the --ir path, in every tier that accepted it" (arity)  |
| F-549 | CX (CX-BUG-056) | compiler:python | Python: an unrecognized function/call name in stack lowering silently compiles t | fixed at HEAD: 4fcffcc5 "N-051: plumb privateMethods into branch-arm contexts (Go, Rust, Python)" and 428f69e4 "R-124 ruby,python: refuse an |
| F-550 | CX (CX-BUG-068) | compiler:python | Python: source-path `for` loops have no unroll cap and can exhaust compiler reso | fixed at HEAD: aebb8c19 "R-009: bound the loop iteration count on the source path in six tiers" — compilers/python/runar_compiler/frontend/a |
| F-551 | CL+CX (CL-BUG-272, CX-BUG-078) | compiler:ruby | Ruby: FixedArray expansion rebuilds CallExpr without asm_return_type, turning as | fixed at HEAD: 1b71ea9e R-025/R-026: stop the fixed-array expansion dropping AST node fields — compilers/ruby/lib/runar_compiler/frontend/ex |
| F-552 | CX (CX-BUG-104) | compiler:ts | TS: typechecker's for-statement branch never visits stmt.update, letting unknown | fixed at HEAD: 051e98f2 R-065: reject a non-unit loop step instead of silently coercing it (6 tiers); test packages/runar-compiler/src/__tes |
| F-553 | CX (CX-BUG-107) | compiler:ts | TS: recursion/call-graph construction in 02-validate.ts omits for-loop init and  | fixed at HEAD: 051e98f2 R-065: reject a non-unit loop step instead of silently coercing it (6 tiers) — The literal claim about `collectMetho |
| F-554 | CL (CL-BUG-075, CL-BUG-132) | sdk:go | Go SDK: mutable boolean state fields fall to push-data framing because sdk_state | fixed at HEAD: 4c21ef4e "R-248: fix the mutable `boolean` state encoding in five of seven SDKs" — packages/runar-go/sdk_state.go:421,612,644 |
| F-555 | CL (CL-BUG-075, CL-BUG-132) | sdk:java | Java SDK: mutable boolean state fields fall to push-data framing because StateSe | fixed at HEAD: 4c21ef4e "R-248: fix the mutable `boolean` state encoding in five of seven SDKs" — packages/runar-java/src/main/java/runar/la |
| F-556 | CL (CL-BUG-075, CL-BUG-123, CL-BUG-132) | sdk:python | Python SDK: mutable boolean state fields serialize as constant false and never r | fixed at HEAD: 4c21ef4e — R-248: fix the mutable `boolean` state encoding in five of seven SDKs (`git log -S "'bool', 'boolean'" -- packages |
| F-557 | CL (CL-BUG-075, CL-BUG-132) | sdk:rust | Rust SDK: mutable boolean state fields fall to push-data framing because state.r | fixed at HEAD: 4c21ef4e "R-248: fix the mutable `boolean` state encoding in five of seven SDKs" (Sep 14 2026) — landed the same fix, with th |
| F-558 | CL (CL-BUG-075, CL-BUG-132) | sdk:zig | Zig SDK: mutable boolean state fields fall to push-data framing because sdk_stat | fixed at HEAD: 4c21ef4ea243e8f886e98b4c590caf02b926418e — "R-248: fix the mutable `boolean` state encoding in five of seven SDKs" — packages |
| F-559 | CX (CX-BUG-111) | compiler:ts | Solidity-surface lexer (01-parse-sol.ts) silently discards unknown characters | fixed at HEAD: 7265167d R-041: make the TypeScript format parsers reject what they cannot parse — packages/runar-compiler/src/passes/01-pars |
| F-560 | CX (CX-BUG-112) | compiler:ts | Move-surface lexer (01-parse-move.ts) silently discards unknown characters | fixed at HEAD: 7265167d R-041: make the TypeScript format parsers reject what they cannot parse — packages/runar-compiler/src/passes/01-pars |
| F-561 | CX (CX-BUG-113) | compiler:ts | Python-surface lexer (01-parse-python.ts) silently discards unknown characters | fixed at HEAD: 7265167d R-041: make the TypeScript format parsers reject what they cannot parse — packages/runar-compiler/src/passes/01-pars |
| F-562 | CX (CX-BUG-114) | compiler:ts | Go-surface lexer (01-parse-go.ts) silently discards unknown characters | fixed at HEAD: 7265167d R-041: make the TypeScript format parsers reject what they cannot parse — packages/runar-compiler/src/passes/01-pars |
| F-563 | CX (CX-BUG-115) | compiler:ts | Rust-surface lexer (01-parse-rust.ts) silently discards unknown characters | fixed at HEAD: 7265167d R-041: make the TypeScript format parsers reject what they cannot parse — packages/runar-compiler/src/passes/01-pars |
| F-564 | CX (CX-BUG-116) | compiler:ts | Ruby-surface lexer (01-parse-ruby.ts) silently discards unknown characters | fixed at HEAD: 7265167d R-041: make the TypeScript format parsers reject what they cannot parse — packages/runar-compiler/src/passes/01-pars |
| F-565 | CX (CX-BUG-117) | compiler:ts | Zig-surface lexer (01-parse-zig.ts) silently discards unknown characters | fixed at HEAD: 7265167d R-041: make the TypeScript format parsers reject what they cannot parse — packages/runar-compiler/src/passes/01-pars |
| F-566 | CX (CX-BUG-118) | compiler:ts | Java-surface lexer (01-parse-java.ts) silently discards unknown characters | fixed at HEAD: 7265167d R-041: make the TypeScript format parsers reject what they cannot parse — packages/runar-compiler/src/passes/01-pars |
| F-567 | CL (CL-BUG-080, CL-GAP-063) | compiler:rust | Rust WOTS+ on-chain codegen (compilers/rust/src/codegen/wots.rs) emits no OP_SIZ | fixed at HEAD: 9ab6a29a fix(lean): emit R-135 WOTS exact signature-length gate — compilers/rust/src/codegen/wots.rs:114-119 emit_verify_wots |
| F-568 | CL (CL-BUG-080, CL-BUG-146) | compiler:go | TS/Go/Python/Ruby/Java/Zig WOTS+ on-chain codegen emits no OP_SIZE length gate ( | fixed at HEAD: f36f21a9 'fix(compilers): verifyWOTS accepted sig // junk — gate the exact length'. This single commit fixed ALL SEVEN tiers  |
| F-569 | CL (CL-BUG-080) | compiler:ruby | TS/Go/Python/Ruby/Java/Zig WOTS+ on-chain codegen emits no OP_SIZE length gate ( | fixed at HEAD: f36f21a9 fix(compilers): verifyWOTS accepted `sig // junk` — gate the exact length (R-135); regression test packages/runar-te |
| F-570 | CL (CL-BUG-080, CL-BUG-146) | compiler:ts | TS/Go/Python/Ruby/Java/Zig WOTS+ on-chain codegen emits no OP_SIZE length gate ( | fixed at HEAD: 9ab6a29a fix(lean): emit R-135 WOTS exact signature-length gate — All queried tiers now emit an `OP_SIZE` exact-length gate b |
| F-571 | CL (CL-BUG-080) | compiler:zig | TS/Go/Python/Ruby/Java/Zig WOTS+ on-chain codegen emits no OP_SIZE length gate ( | fixed at HEAD: f36f21a9 "fix(compilers): verifyWOTS accepted `sig // junk` — gate the exact length" — All seven WOTS+ on-chain emitters now  |
| F-572 | CL (CL-BUG-080) | compiler:java | TS/Go/Python/Ruby/Java/Zig WOTS+ on-chain codegen emits no OP_SIZE length gate ( | fixed at HEAD: 9ab6a29a ("fix(lean): emit R-135 WOTS exact signature-length gate") — compilers/java/src/main/java/runar/compiler/codegen/Wot |
| F-573 | CL (CL-BUG-080, CL-BUG-146) | compiler:python | TS/Go/Python/Ruby/Java/Zig WOTS+ on-chain codegen emits no OP_SIZE length gate ( | fixed at HEAD: f36f21a9 fix(compilers): verifyWOTS accepted `sig // junk` — gate the exact length (companion 9ab6a29a for the Lean spec) — w |
| F-574 | CL (CL-GAP-135) | * | sdk-bip143 conformance generator pins one sighash mode and one locktime although | fixed at HEAD: 2676af7d "R-206: cover every sighash mode, not just ALL/FORKID" — conformance/sdk-bip143/generate-fixtures.ts now defines all |
| F-575 | CL (CL-GAP-018) | compiler:ts | TS test-suite gap F-04: verifyWOTS/verifySLHDSA tested only at the raw emitter A | fixed at HEAD: bd68da10 R-106 + R-193 tests: 15 example contracts that asserted nothing now assert something — All 6 SLH-DSA parameter sets  |
| F-576 | CL (CL-GAP-104) | sdk:python | Python SDK's canonical_json has none of the TS reference implementation's DoS gu | fixed at HEAD: 01f88ef2 — fix(sdk): give canonicalJson the same three DoS guards in all seven tiers (`git log -S 'MAX_WIRE_NESTING' -- packa |
| F-577 | CL (CL-BUG-143) | compiler:python | Python's BN254 inline mixed-add omits Go's `strict` (R==0) test, so accumulator  | fixed at HEAD: 79992b56 R-055: bn254G1ScalarMul applied the wrong multiplier in five tiers (commit body explicitly states the reduce AND the |
| F-578 | GK (GK-GAP-003) | compiler:ts | TS DCE classifies `if`/`loop` ANF nodes as side-effect-free, letting dead-code e | fixed at HEAD: 445e0f74 R-006: keep if/loop bindings whose nested bindings have side effects (TS DCE) — packages/runar-compiler/src/optimize |
| F-579 | GK (GK-GAP-008) | * | Conformance comparison gate omits sourceLoc/Stack-IR-object/source-maps and the  | fixed at HEAD: bdb0ee66 (R-302: state what the byte-identical guarantee does not cover) and db4c14d0 (R-096 docs: the parity invariant now s |
| F-580 | GK (GK-BUG-023) | compiler:ts | TypeScript bn254G1ScalarMul does k+3r via three OP_ADD without reducing k mod r | fixed at HEAD: 79992b56 R-055: bn254G1ScalarMul applied the wrong multiplier in five tiers — packages/runar-compiler/src/passes/bn254-codege |
| F-581 | CL+GK (CL-BUG-142, GK-BUG-023) | compiler:python | Python bn254G1ScalarMul does k+3r via three OP_ADD without reducing k mod r; Go' | fixed at HEAD: 79992b56 R-055 (same commit that fixed V262/CL-BUG-143; the message explicitly states the reduce and strict test were ported  |
| F-582 | GK (GK-BUG-023) | compiler:ruby | Ruby bn254G1ScalarMul does k+3r via three OP_ADD without reducing k mod r | fixed at HEAD: 79992b56 R-055: bn254G1ScalarMul applied the wrong multiplier in five tiers — ts/rust/python/zig/ruby gained the mod-r reduct |
| F-583 | GK (GK-BUG-023) | compiler:rust | Rust bn254G1ScalarMul does k+3r via three OP_ADD without reducing k mod r | fixed at HEAD: 79992b56 R-055: bn254G1ScalarMul applied the wrong multiplier in five tiers — packages/runar-compiler/src/passes/bn254-codege |
| F-584 | CX (CX-GAP-003) | compiler:go | Shared peephole-rules.json still specifies the unguarded double-OP_NOT rewrite t | fixed at HEAD: 1e30145d 'R-139: the shared rule file declared an unsound rule neither tier implements' — optimizer/peephole-rules.json:9-10  |
| F-585 | CL+CX (CL-BUG-109, CX-BUG-100, CX-BUG-108) | compiler:ts | TS `BYTE_RETURNING_FUNCTIONS` hand-maintained heuristic misclassifies the numeri | fixed at HEAD: be3eefdb N-054: derive extractor byte-ness from the typecheck tables, not by hand — packages/runar-compiler/src/passes/04-anf |
| F-586 | CL (CL-DOC-001) | compiler:ts | peephole-rules.json labelled canonical but had zero consumers, hiding a stale un | fixed at HEAD: 1e30145d R-139: the shared rule file declared an unsound rule neither tier implements — packages/runar-compiler/src/optimizer |
| F-587 | CL (CL-BUG-234) | * | Script-size regression gate is a silent no-op: `pnpm --filter runar-conformance` | fixed at HEAD: f52d54f9 (N-053: the script-size CI gate never ran — pnpm --filter matched no project) — .github/workflows/script-size-benchm |
| F-588 | CL (CL-GAP-062) | compiler:rust | Rust `bn254G1Add` silently wrong for P + (-P); Rust `bn254G1OnCurve` lacks the G | fixed at HEAD: 7bd5457e (R-035: return the point at infinity from bn254G1Add when P == -Q) and 4d0a225d (fix(6 tiers): bn254G1OnCurve certif |
| F-589 | CL (CL-BUG-148) | compiler:python | Python `bn254G1OnCurve` accepts 36 non-canonical encodings of the same point bec | fixed at HEAD: 4d0a225d fix(6 tiers): bn254G1OnCurve certified any spelling of a point, and any length (R-141) — bn254.py:1246-1275 (emit_bn |
| F-590 | CX (CX-BUG-089) | compiler:rust | Rust: the rich-result compilation path calls the location-blind peephole optimiz | fixed at HEAD: 38409fc1 (R-166: the Rust source map was empty for every contract, not just crypto ones) — compilers/rust/src/lib.rs:799-801  |
| F-591 | CL (CL-BUG-107, CL-BUG-114) | compiler:ts | TS: the constant folder and the stack emitter implement `pow`/`sqrt`/`clamp`/`lo | fixed at HEAD: a3c4c0af fix(compilers): sqrt emitted 16 unconditional Newton rounds and was simply wrong; f98c0b7a fix(7 tiers): pow returne |
| F-592 | CL+GK (CL-BUG-204, GK-BUG-025) | compiler:python | Python's fixed-array expansion drops MethodNode.sighash_type, letting @sighash v | fixed at HEAD: 1b71ea9e R-025/R-026: stop the fixed-array expansion dropping AST node fields (companion 2966c65e R-229: regression coverage  |
| F-593 | CL (CL-GAP-057) | compiler:go | Go's BN254 G1 on-curve check has no coordinate-canonicity guard, unlike secp256k | fixed at HEAD: 4d0a225d fix(6 tiers): bn254G1OnCurve certified any spelling of a point, and any length — compilers/go/codegen/bn254.go:1495- |
| F-594 | GK (GK-BUG-006) | compiler:go | Generic BN254 pairing builtins (the recommended Groth16 path) never check G2 on- | fixed at HEAD: 65fcd3ee R-060: validate G1/G2 inputs in the general-purpose BN254 pairing builtins — compilers/go/codegen/bn254_point_valida |
| F-595 | CL (CL-GAP-081, CL-GAP-115) | * | `expand_fixed_arrays` has ZERO conformance coverage in any tier | fixed at HEAD: 681430ad (R-094 conformance: the first FixedArray fixture — runtime-index read, 8 surfaces) and 39a51cd3 (R-094 conformance:  |
| F-596 | CL+GK (CL-GAP-070, GK-BUG-003) | compiler:java | Java-tier Sol/Zig/Ruby(Rb) parsers emit an empty else-list instead of null, so A | fixed at HEAD: 7df5b4dd R-298: an empty else-list is "no else", so early returns fold again (2026-09-13, after both CX/GK@2b3af765 2026-08-3 |
| F-597 | CL (CL-BUG-206) | compiler:python | Python's typechecker accepts an undeclared identifier in a boolean position (`<u | fixed at HEAD: d78d4fe7 GK-BUG-009: an unresolvable identifier typechecked silently in six tiers — typecheck.py:685-699 (_infer_expr_type, I |
| F-598 | CL (CL-BUG-041) | compiler:go | Go: `merkleRootPoseidon2KB` discards 7 of 8 digest limbs, reducing the Merkle ro | fixed at HEAD: 19af042e R-056: merkleRootPoseidon2KB authenticated one limb of eight — compilers/go/codegen/stack.go:6592-6660 (`lowerMerkle |
| F-599 | CL (CL-BUG-040) | compiler:go | Go: unknown builtin compiles to OP_0 and strands its arguments, desyncing the st | fixed at HEAD: 6601edad R-122 go: refuse an unknown call instead of emitting a silent OP_0; 8ac3f96b fix(go): Groth16-WA preamble scan walks |
| F-600 | CL (CL-BUG-050) | compiler:python | Python `--ir` cannot emit an artifact for any stateful contract (JSONDecodeError | fixed at HEAD: 36080520 (fix(python): `--ir <file> --output <artifact>` died with a raw JSONDecodeError) — ir/types.py:315-330 (`_decode_con |
| F-601 | CL (CL-GAP-081) | * | `FixedArray` has zero conformance coverage despite owning a dedicated 03b pipeli | fixed at HEAD: 681430ad (R-094 conformance: the first FixedArray fixture — runtime-index read, 8 surfaces) and 39a51cd3 (R-094 conformance:  |
| F-602 | CX (CX-BUG-098) | compiler:ts | `subContext()` doesn't forward the side-effect summary, so nested output-produci | fixed at HEAD: 2e30b536 — "R-001: forward the side-effect summary into TypeScript subContext" — packages/runar-compiler/src/passes/04-anf-lo |
| F-603 | CX (CX-BUG-099) | compiler:ts | `subContext()` doesn't forward `sighashFlag`, so nested manual `checkPreimage` f | fixed at HEAD: f4e6c675 — "R-082: a manual checkPreimage in a branch lowered under the wrong sighash mode" — packages/runar-compiler/src/pas |
| F-604 | GK (GK-DOC-003) | * | Root README states an unqualified "all formats produce identical Bitcoin Script" | fixed at HEAD: eeb3af0c — R-230: the README's parity claim says which parity, and where it stops (adds regression guard tests/r230-readme-pa |
| F-605 | CL (CL-GAP-092) | * | Integration/regtest evidence is gathered with Chronicle opcodes activated (`chro | fixed at HEAD: 6321feb4 R-014: disclose the Chronicle opcode-policy requirement; a57e9d24 spec/docs: say what the compiler emits, not what i |
| F-606 | CL+GK (CL-BUG-140, GK-BUG-032) | sdk:ts | WalletProvider.getTransaction returns an empty {inputs:[],outputs:[]} shell on c | fixed at HEAD: 35f8e222 'R-151: WalletProvider.getTransaction stops inventing an empty transaction' — packages/runar-sdk/src/providers/walle |
| F-607 | CL (CL-GAP-082) | * | reverseBytes has zero conformance fixtures, zero example uses, and does not comp | fixed at HEAD: a5f69778 — N-056: fix Ruby's reverseBytes stack-model bookkeeping — compilers/ruby/lib/runar_compiler/codegen/stack.rb:1866-1 |
| F-608 | CL (CL-BUG-076) | * | `runar deploy` bakes `0n` into every constructor slot | fixed at HEAD: 84a6dbef — R-036: require constructor arguments on runar deploy — packages/runar-cli/src/commands/deploy.ts:50-167 parseConst |
| F-609 | CL (CL-BUG-184) | compiler:go | `subContext()` drops `sideEffects`, so a private output-helper called inside an  | fixed at HEAD: 385b9dd7 R-002: forward sideEffects and paramAliasStack into Go subContext — compilers/go/frontend/anf_lower.go:1030-1047 (`s |
| F-610 | CL (CL-BUG-002) | compiler:ts | @embedAlways preservation pair destroyed by DCE's fixed-point loop | fixed at HEAD: d06087d3 N-021: protect @embedAlways with a node flag in TypeScript and Go — packages/runar-compiler/src/passes/04-anf-lower. |
| F-611 | CL (CL-BUG-047) | compiler:rust | Rust: push_json_value HEX-decodes the JS-BigInt decimal wire encoding, silently  | fixed at HEAD: ba7cb0f5 (R-017: decode property initializers through the shared IR reader (Rust)) — compilers/rust/src/codegen/stack.rs:1648 |
| F-612 | CL (CL-BUG-081) | compiler:go | The only CLI-reachable Groth16 backend emits the verifier that does not bind pub | fixed at HEAD: a6f9ab5f (R-011: pin the public inputs into the deployable Groth16 verifier) and e7a36893 (feat(runar): close Groth16 WA soun |
| F-613 | CL (CL-BUG-113) | * | Six Zig StateCovenant tests silently PASS when setup fails | fixed at HEAD: 7833afcb — test(integration/zig): a swallowed deploy must not report PASS — integration/zig/src/state_covenant_test.zig: all  |
| F-614 | CL (CL-BUG-170) | compiler:rust | EC optimizer Rule 9 truncates the folded scalar through `i64`, turning `ecMul(ec | fixed at HEAD: 41b77f1c (R-033: decode oversize load_const scalars in Rust's EC optimizer) — compilers/rust/src/frontend/anf_optimize.rs:172 |
| F-615 | CL (CL-BUG-194) | compiler:go | Unguarded `big.Int → int` on the loop count: a bound ≥ 2⁶³ silently runs the loo | fixed at HEAD: fcc95fb5 (R-013: range-check compile-time constants before narrowing them (Go)) — compilers/go/frontend/anf_lower.go (~1841-1 |
| F-616 | CL (CL-BUG-231) | compiler:ruby | A full-sweep frontend run finds 6 Python and 3 Ruby failures across all 667 exam | fixed at HEAD: b6e63ec9 N-122: withdrew the two invalid *.v2.runar.java FixedArray fixtures that produced the java-related failures. — Full- |
| F-617 | CL (CL-BUG-231) | compiler:python | A full-sweep frontend run finds 6 Python and 3 Ruby failures across all 667 exam | fixed at HEAD: d517e411 (N-020, Rust [T;N] array parsing) and 5c9d8383 (R-114, .runar.sol auto-constructor super()) — Two of the concrete Py |
| F-618 | CL (CL-BUG-254) | compiler:go | `/api/compile` is a one-request process kill, and the missing cap is in the comp | fixed at HEAD: 38c70b2a (R-048: bound the playground compile endpoint's body, deadline and connections) — examples/end2end-example/webapp/ma |
| F-619 | CL (CL-GAP-001) | compiler:ts | TS EC optimizer applies two rules tagged supported:["ts"] that Go skips | fixed at HEAD: 411d1985 R-031: gate ec-mulgen-linear on constant scalars in Go, matching the other six tiers; 8a5b1a81 N-035: enable EC rule |
| F-620 | CL (CL-GAP-094) | * | The release path publishes with zero tests run | fixed at HEAD: bae01245 (R-045: make release.sh compose with bump-version.sh and gate on tests), 413eec64 (R-049: fix publish-all.sh's retur |
| F-621 | CL (CL-BUG-022) | compiler:rust | The loader's KNOWN_KINDS check is tautological — kind_name is exhaustive over a  | fixed at HEAD: 430a0f0e R-177: delete the unreachable unknown-kind check, and say the words the peers say — loader.rs:141-150 (`kind_name`)  |
| F-622 | CL (CL-BUG-023) | compiler:rust | compile_from_ir* silently ignores constructor_args, returning unbaked OP_0 place | fixed at HEAD: 5d222a8c feat(go,rust,python): add constructorArgs option to compile pipeline — compilers/rust/src/lib.rs:96-147 (`apply_cons |
| F-623 | CL (CL-BUG-026) | compiler:rust | The two public compile APIs produce different sourceMap fidelity; the comment cl | fixed at HEAD: 38409fc1 R-166: the Rust source map was empty for every contract, not just crypto ones — compilers/rust/src/lib.rs:527-573 (` |
| F-624 | CL (CL-BUG-043) | compiler:go | Go: sqrt (16 Newton iters) and pow (32 unrolled) silently return wrong values ou | fixed at HEAD: a3c4c0af (fix(compilers): sqrt emitted 16 unconditional Newton rounds and was simply wrong) and f98c0b7a (fix(7 tiers): pow r |
| F-625 | CL (CL-BUG-048) | compiler:rust | Rust: 14 crypto call sites push straight into self.ops, breaking the ops/source_ | fixed at HEAD: 38409fc1 R-166: the Rust source map was empty for every contract, not just crypto ones — compilers/rust/src/codegen/stack.rs: |
| F-626 | CL (CL-BUG-098) | * | (see ledger) | fixed at HEAD: abfcf650 (fix(6 tiers): the Merkle index was unbounded and the proof remainder unread — R-120) — packages/runar-testing/src/i |
| F-627 | CL (CL-BUG-171) | compiler:rust | `make_load_const_int` emits bare JSON numbers above `JS_MAX_SAFE_INTEGER`, break | fixed at HEAD: 41b77f1c R-033: decode oversize load_const scalars in Rust's EC optimizer — compilers/rust/src/frontend/anf_optimize.rs:172-1 |
| F-628 | CL (CL-BUG-226) | * | The negatives harness is stage-blind, and covers five of seven tiers | fixed at HEAD: 4e74e565 (R-100: the rejection gate was scoring two dead tiers as perfect, and skipped the reference tier), 0360264b (R-101), |
| F-629 | CL (CL-BUG-237) | * | The TypeScript tier has no dependency-vulnerability scanning, and a workflow com | fixed at HEAD: c3353f5b (R-108 ci: the TypeScript tier had no dependency scanning at all) — .github/workflows/dependency-audit.yml now has a |
| F-630 | CL (CL-GAP-002) | compiler:ts | ec-add-negate-cancel-reversed declared in rule data, unimplemented in TS | fixed at HEAD: 8cd3a0dd R-034: port the 13th EC rule to six tiers, and make Zig run the optimizer at all — packages/runar-compiler/src/optim |
| F-631 | CL (CL-GAP-085) | * | `conformance/analyzer/run.ts` likewise never invoked; its missing-wrapper path s | fixed at HEAD: 1cfe6dc0 R-219: the analyzer gate was not just unwired, it was unrunnable — conformance/analyzer/run.ts:1-27 (header) now say |
| F-632 | CL (CL-GAP-142) | * | Two vector corpora have no executing consumer anywhere | fixed at HEAD: 202644a2 R-110 ci: run the repo-root tests/ directory — 1383 assertions ran nowhere — tests/merkle-vectors.test.ts (existed s |
| F-633 | CL (CL-BUG-011) | compiler:go | CompileGroth16WA ignores SOURCE_DATE_EPOCH — the one artifact path that cannot b | fixed at HEAD: 7efcb8ea "R-176: the Groth16 verifier was the one artifact SOURCE_DATE_EPOCH did not reach" — compilers/go/compiler/groth16_w |
| F-634 | CL (CL-DOC-002) | compiler:ts | ec-rules.json documents ecMul with two different argument orders | fixed at HEAD: 8a5b1a81 N-035: enable EC rules 9 and 11 in Go, and un-transpose rule 11's operands — optimizer/ec-rules.json and compilers/g |
| F-635 | CL (CL-DOC-006) | compiler:ts | Skip inventory: 0 .skip/.only/xit; 11 governed describe.skipIf; 1 vacuous body i | fixed at HEAD: 2e7a3351 lint(test-skips): site-level audit + Rust wallet ignore migration — scripts/audit-test-skips.py now performs a full  |
| F-636 | CL (CL-DOC-012) | compiler:rust | Rust: extractInputIndex returns the prevout's vout, not the spending input's ind | fixed at HEAD: 7d9edb98 fix: correct 31 review findings, replace invalid OP_REVERSE opcode, and fix log2 accuracy — compilers/rust/src/codeg |
| F-637 | CL (CL-GAP-059) | compiler:go | Go: big.Int -> int narrowing via Int64() happens BEFORE the range check at three | fixed at HEAD: fcc95fb5 R-013: range-check compile-time constants before narrowing them (Go) — Fixed by commit fcc95fb5 ('R-013: range-check |
| F-638 | CL (CL-GAP-061) | compiler:go | Go: loop iteration variable leaks one dead stack slot per unrolled iteration whe | fixed at HEAD: 62f9f309 R-186 + R-292: the loop iteration variable leaked one stack slot per iteration — Fixed by commit 62f9f309 ('R-186 +  |
| F-639 | CL (CL-BUG-052) | compiler:java | 3. **CL-BUG-052 (Java compiler emits no deployable artifact) | fixed at HEAD: da867db9 R-007: emit a deployable artifact from the Java compiler (2026-09-09, after CX/GK@2b3af765 2026-08-31 and CL@8937c1a |
| F-640 | CL (CL-BUG-249) | compiler:rust | - **CL-BUG-249 — a FixedArray property flips `OP_EQUAL` to `OP_NUMEQUAL` on an u | fixed at HEAD: 1b71ea9e R-025/R-026: stop the fixed-array expansion dropping AST node fields — compilers/rust/src/frontend/expand_fixed_arra |
| F-641 | GK (GK-BUG-001) | compiler:ts | check_preimage.sighashFlag is on compiler ANF but missing from ir-schema type an | fixed at HEAD: 5c97628c ("R-089: the JSON Schema rejected valid IR, and 11 goldens could never have validated") — packages/runar-ir-schema/s |
| F-642 | GK (GK-BUG-002) | compiler:ts | Artifact JSON Schema rejects abi.methods[].sigHashType that the assembler emits | fixed at HEAD: 5c97628c (same commit as V611 — it fixed both the ANF-IR and the Artifact schema gaps for non-default @sighash in one pass) — |
| F-643 | GK (GK-GAP-006) | compiler:ts | Nested-if inherited-slot reorder remains documented OPEN (funds-safety) | fixed at HEAD: 9cfd953f ("fix(stack-lower): restore inherited slot order after adopting declared results") — packages/runar-compiler/docs/mu |
| F-644 | GK (GK-DOC-002) | * | SDK READMEs advertise runar.build / runar.run; in-repo playground language menu  | fixed at HEAD: 5b376163 R-154: serve a real template per language instead of Java for seven of nine — examples/end2end-example/webapp/static |
| F-645 | GK (GK-BUG-012) | compiler:ts | extractSequence/extractLocktime BIN2NUM without sign-pad; recommended sequence g | fixed at HEAD: 3cecdc11 ("fix(compilers): decode the four 32-bit preimage fields as unsigned" — 7-tier fix with a real-Spend-interpreter reg |
| F-646 | GK (GK-GAP-011) | sdk:ts | TS interpreter checkMultiSig always returns false; comment says unused | fixed at HEAD: 3d773f37 R-112 testing: the interpreter's crypto is a mixture, not a mock — say so, and stop answering for checkMultiSig — pa |
| F-647 | GK (GK-BUG-027) | compiler:ts | Oversize Point (G‖extra) is on-curve as G and ecEncodeCompressed of it is −G | fixed at HEAD: ea79620a ("fix(ec): a Point was never length-checked, in any tier") and 164388ad ("fix(ec): a Point's coordinates were never  |
| F-648 | CX (CX-BUG-038) | compiler:java | Fixed-array rewriting drops expression-form asm return types | fixed at HEAD: 1b71ea9e R-025/R-026: stop the fixed-array expansion dropping AST node fields (2026-09-10, after CX/GK@2b3af765 2026-08-31) — |
| F-649 | CX (CX-BUG-072) | compiler:python | IR compilation accepts a contract with no spending entry point and emits an empt | fixed at HEAD: 3e16266e — "N-113: five tiers accepted the malformed IR that Go had started rejecting" — compilers/python/runar_compiler/ir/l |
| F-650 | CX (CX-BUG-119) | compiler:ts | Artifacts are nondeterministic because assembly always injects wall-clock time | fixed at HEAD: 6871de2d ("R-212: six of seven tiers ignored SOURCE_DATE_EPOCH") — packages/runar-compiler/src/artifact/assembler.ts:295-317  |
| F-651 | CL (CL-BUG-221, CL-BUG-222, CL-BUG-223) | compiler:go | `CompileGroth16WA` ignores `SOURCE_DATE_EPOCH` | fixed at HEAD: 7efcb8ea R-176: the Groth16 verifier was the one artifact SOURCE_DATE_EPOCH did not reach — Fixed by commit 7efcb8ea ('R-176: |
| F-652 | CL (CL-BUG-227, CL-GAP-126) | * | `metamorphic-fuzz.ts` has no non-vacuity guard | fixed at HEAD: 4747e4e5 fuzzer(metamorphic): a run that compared nothing is not a pass — conformance/fuzzer/metamorphic-fuzz.ts:255-257 trac |
| F-653 | CL (CL-BUG-227, CL-GAP-126) | * | A crashed tier is laundered into agreement | fixed at HEAD: 9b9eeeb8 fuzzer(canonical): a tier that DIED is not a tier that rejected — The `--canonical` mode lives in conformance/fuzzer |
| F-654 | CL (CL-BUG-239, CL-GAP-133) | * | `scripts/release.sh` cannot complete | fixed at HEAD: bae01245 (R-045: 'make release.sh compose with bump-version.sh and gate on tests'), refined by 413eec64 (R-049) — scripts/rel |

## Approval gate — user decisions (2026-09-22)

- **goldens**: restamp only via the golden-provenance gate (route A/B), flagged GOLDEN RESTAMP
- **D1**: keep FixedArray OOB reads as v1 by-design
- **D2**: SDKs + shared schema match the compiler (fixed 8-byte Rabin state fields)
- **red_baseline**: fix first as F-000
- **cadence**: per item: component suite + golden + targeted multi-format (both fold modes); full multi-format both modes every 10 items and at the end
- **concurrency**: up to 3 items in isolated worktrees, different tiers, no shared files

Applying them: D1 items → REJECTED (by design); D2 items → one cross-SDK item (G6); byte-moving families whose bytes all tiers share → one cross-tier item each (G1–G5, since no single tier can move alone without breaking byte-identical conformance); F-000 added for the red baseline test. IDs renumbered once and **frozen**.

## Queue (396 items, frozen order)

| ID | Sev | Cat | Conf | Tier | Model | Goldens | Sources | Title |
|---|---|---|---|---|---|---|---|---|
| F-000 | MEDIUM | BUG | SINGLE | * | top |  |  | tests/golden-provenance-gate-is-cwd-independent.test.ts fails on any tree with no golden d |
| F-001 | CRITICAL | BUG | MAJORITY | * (compiler:go,compiler:java,compiler:python,compiler:rust,compiler:ts) | top | restamp | CL-BUG-006, CL-BUG-044, CL-BUG-096, CL-BUG-116… | Numeric-identity peephole rules (PUSH 0;OP_ADD / PUSH 0;OP_SUB / OP_NEGATE;OP_NEGATE) dele |
| F-002 | CRITICAL | BUG | MAJORITY | compiler:ts | top |  | CL-BUG-224, CX-DOC-004 | TS: `compileFromANF`'s `--ir`/ANF entry point unconditionally skips constant folding regar |
| F-003 | CRITICAL | BUG | SINGLE | compiler:go | top |  | CL-BUG-167 | Rust `.runar.go` parser: *= /= %= &= /= ^= <<= >>= are missing from the two-char operator  |
| F-004 | CRITICAL | BUG | SINGLE | compiler:go | top | restamp | CL-BUG-084, CL-BUG-216, CL-BUG-217, CL-GAP-005 | CompileFromProgram (the `--ir` entry point) never calls frontend.Validate, so every valida |
| F-005 | CRITICAL | BUG | SINGLE | compiler:go | top | restamp | CL-BUG-186 | Go lowerForStatement never merges the loop body's addOutput/addRawOutput refs back into th |
| F-006 | CRITICAL | BUG | SINGLE | compiler:go | top | restamp | CL-BUG-199 | Zig: a failed while→for merge in parser_zig.go silently drops the increment, freezing the  |
| F-007 | CRITICAL | BUG | SINGLE | compiler:go | top | restamp | CL-BUG-037 | Go: verifySP1FRI emits a verifier that checks no FRI query opening at all and then pushes  |
| F-008 | CRITICAL | BUG | SINGLE | compiler:go | top | restamp | CL-BUG-085 | The SP1-FRI locking script enforces no proof property at all; the one binding it does emit |
| F-009 | CRITICAL | BUG | SINGLE | compiler:go | top |  | CL-BUG-187 | The TypeScript surface parser maps every unrecognised compound assignment to `+` |
| F-010 | CRITICAL | BUG | SINGLE | compiler:go | top |  | CL-BUG-188 | The Go-DSL parser accepts exported value-receiver methods on *unrelated* types as public s |
| F-011 | CRITICAL | BUG | SINGLE | compiler:go | top | restamp | CL-BUG-196 | Go's Python tokenizer lets an unterminated string literal run to EOF, silently swallowing  |
| F-012 | CRITICAL | BUG | SINGLE | compiler:go | top |  | CL-BUG-197 | Ruby `=begin`/`=end` block comments are not lexed, so `=end` closes the class body and eve |
| F-013 | CRITICAL | BUG | SINGLE | compiler:python | top | restamp | CL-BUG-214 | IndexAccessExpr assignment on a non-FixedArray property is silently discarded and ships a  |
| F-014 | CRITICAL | BUG | SINGLE | compiler:python | top | restamp | CL-BUG-266 | compile_from_ir / compile_from_ir_bytes skip _validate, _type_check, and _expand_fixed_arr |
| F-015 | CRITICAL | BUG | SINGLE | compiler:python | top | restamp | CX-BUG-059 | Python: `if`-branch lowering contexts do not inherit the parent's `renamed_params` map, so |
| F-016 | CRITICAL | BUG | SINGLE | compiler:python | top |  | CL-BUG-200 | Python's `parser_ts.py` compiles the FIRST class in a `.runar.ts` file as the contract reg |
| F-017 | CRITICAL | BUG | SINGLE | compiler:python | top |  | CL-BUG-201 | `py_convert_name` is non-injective: two distinct locals alias to one ANF binding, turning  |
| F-018 | CRITICAL | BUG | SINGLE | compiler:ruby | top |  | CL-BUG-257 | Ruby `=begin`/`=end` block comments are not lexed, PROVED BY EXECUTION |
| F-019 | CRITICAL | BUG | SINGLE | compiler:rust | top | restamp | CL-BUG-167 | Rust `.runar.go` parser: *= /= %= &= /= ^= <<= >>= are missing from the two-char operator  |
| F-020 | CRITICAL | BUG | SINGLE | compiler:rust | top |  | CL-BUG-245 | - **CL-BUG-245 — Go DSL silently no-ops ALL EIGHT of `*= /= %= &= /= ^= <<= >>=`.** The co |
| F-021 | CRITICAL | BUG | SINGLE | compiler:rust | top |  | CL-BUG-246 | - **CL-BUG-246 — `asm()` in a for-loop's update clause bypasses the UnsafeSmartContract ga |
| F-022 | CRITICAL | BUG | SINGLE | compiler:rust | top | restamp | CL-BUG-247 | - **CL-BUG-247 — Solidity accepts an unknown base class and emits an unenforced mutable-st |
| F-023 | CRITICAL | BUG | SINGLE | compiler:rust | top |  | CL-BUG-248 | - **CL-BUG-248 — `while` → `for` folding produces a wrong ITERATION COUNT on three surface |
| F-024 | CRITICAL | BUG | SINGLE | compiler:ts | top | restamp | CL-BUG-079 | The auto-injected stateful continuation conserves no value: `_newAmount`/`_changeAmount`/` |
| F-025 | CRITICAL | BUG | SINGLE | compiler:zig | top |  | CL-BUG-060, CL-BUG-106 | Zig: `bound_is_const` is wired in only 1 of 9 format parsers, so a runtime/identifier for- |
| F-026 | CRITICAL | BUG | SINGLE | compiler:zig | top | restamp | CL-BUG-198 | Zig and Python: `0b…` / `0o…` literals silently evaluate to `0` |
| F-027 | CRITICAL | BUG | SINGLE | sdk:go | top |  | CL-BUG-071 | GorillaPool satoshi/BTC magnitude heuristic, shared by ≥5 SDK tiers, with tests pinning it |
| F-028 | CRITICAL | BUG | SINGLE | sdk:java | top |  | CL-BUG-071 | GorillaPool satoshi/BTC magnitude heuristic, shared by ≥5 SDK tiers, with tests pinning it |
| F-029 | CRITICAL | BUG | SINGLE | sdk:python | top |  | CL-BUG-071 | GorillaPool satoshi/BTC magnitude heuristic, shared by ≥5 SDK tiers, with tests pinning it |
| F-030 | CRITICAL | BUG | SINGLE | sdk:ruby | top |  | CL-BUG-071 | GorillaPool satoshi/BTC magnitude heuristic, shared by ≥5 SDK tiers, with tests pinning it |
| F-031 | CRITICAL | BUG | SINGLE | sdk:rust | top |  | CL-BUG-071 | GorillaPool satoshi/BTC magnitude heuristic, shared by ≥5 SDK tiers, with tests pinning it |
| F-032 | CRITICAL | BUG | SINGLE | sdk:ts | top |  | CL-BUG-071 | GorillaPool satoshi/BTC magnitude heuristic, shared by ≥5 SDK tiers, with tests pinning it |
| F-033 | CRITICAL | BUG | SINGLE | sdk:zig | top |  | CL-BUG-104 | Zig contract-runtime percentOf divides by 100 instead of 10000 (basis points), diverging f |
| F-034 | HIGH | BUG | MAJORITY | * (compiler:go,compiler:java,compiler:python,compiler:ruby,compiler:rust,compiler:ts,compiler:zig) | top | restamp | CL-BUG-051, CL-BUG-077, GK-BUG-013 | SLH-DSA-SHA2-256f uses FORS height a=8; FIPS 205 requires a=9 — all 7 compiler tiers + gol |
| F-035 | HIGH | BUG | MAJORITY | * (*,compiler:ts,sdk:go,sdk:java,sdk:python,sdk:ruby,sdk:rust,sdk:ts) | top |  | CL-BUG-038, CL-BUG-070, CL-BUG-124, CL-BUG-133… | RabinSig/RabinPubKey state fields: shared schema + all 7 SDK codecs push-data-frame them w |
| F-036 | HIGH | BUG | MAJORITY | compiler:go | top | restamp | CL-BUG-039, GK-BUG-008 | Go Groth16 MSM public-input-binding scalar ladder does not reduce the attacker-supplied sc |
| F-037 | HIGH | BUG | MAJORITY | compiler:java | top |  | CL-BUG-243, CX-BUG-037 | Java: ExpandFixedArrays rebuilds every method through the 5-arg MethodNode constructor, si |
| F-038 | HIGH | BUG | MAJORITY | compiler:python | top | restamp | CL-BUG-268, CX-BUG-070 | --emit-ir's _IR_EXCLUDED_FIELDS drops synthetic_array_chain (and parent_class), so FixedAr |
| F-039 | HIGH | BUG | MAJORITY | compiler:rust | top |  | CL-BUG-174, CX-BUG-086 | A malformed `@sighash` directive (e.g. missing whitespace, trailing punctuation) is silent |
| F-040 | HIGH | BUG | MAJORITY | sdk:go | top |  | CL-BUG-072, GK-BUG-007 | WhatsOnChain provider's `getUtxos` returns an empty locking script (`script: ''`), which f |
| F-041 | HIGH | BUG | MAJORITY | sdk:python | top |  | CL-BUG-072, GK-BUG-007 | WhatsOnChain provider's `getUtxos` returns an empty locking script (`script: ''`), which f |
| F-042 | HIGH | BUG | MAJORITY | sdk:ruby | top |  | CL-BUG-158, GK-BUG-029 | Ruby WalletProvider#broadcast reports success for a rejected or unsent ARC transaction |
| F-043 | HIGH | BUG | MAJORITY | sdk:ruby | top |  | CL-BUG-157, GK-BUG-030 | Ruby build_p2pkh_script lacks the 66/130-char compressed/uncompressed pubkey branch Go/Pyt |
| F-044 | HIGH | BUG | MAJORITY | sdk:ruby | top |  | CL-BUG-072, GK-BUG-007 | WhatsOnChain provider's `getUtxos` returns an empty locking script (`script: ''`), which f |
| F-045 | HIGH | BUG | MAJORITY | sdk:ts | top |  | CL-BUG-137, GK-BUG-024 | TokenWallet.transfer/.merge BIP-143-sign a preliminary throwaway transaction, then contrac |
| F-046 | HIGH | BUG | MAJORITY | sdk:ts | top |  | CL-BUG-072, GK-BUG-007 | WhatsOnChain provider's `getUtxos` returns an empty locking script (`script: ''`), which f |
| F-047 | HIGH | BUG | SINGLE | * (compiler:go,compiler:java,compiler:python,compiler:ruby,compiler:rust,compiler:ts,compiler:zig) | top | restamp | GK-BUG-021 | On-chain Rabin verify compares the unreduced SHA-256 digest (off-chain reduces mod n) — al |
| F-048 | HIGH | BUG | SINGLE | * (compiler:go,compiler:java,compiler:python,compiler:ruby,compiler:rust,compiler:ts,compiler:zig) | top | restamp | GK-BUG-018 | On-chain SLH-DSA treeAddr8 packs idx_tree with OP_NUM2BIN 8; 256f indices in [2^63,2^64) n |
| F-049 | HIGH | BUG | SINGLE | * | top |  | CL-BUG-088 | Fold-ON conformance step reports a false PASS for single-tier fixtures because both parity |
| F-050 | HIGH | BUG | SINGLE | * | top |  | CL-BUG-089 | Unrecognised/typo compiler id in a fixture's `compilers` allowlist collapses the supported |
| F-051 | HIGH | BUG | SINGLE | * | top |  | CL-BUG-100 | `updateGoldenFiles` ignores the `compilers` allowlist and stamps Go-only-scoped goldens fr |
| F-052 | HIGH | BUG | SINGLE | * | top |  | CL-BUG-225 | Negative-fixture corpus (conformance/negatives) is TypeScript-only; 8 of 9 surface formats |
| F-053 | HIGH | BUG | SINGLE | * | top |  | CL-BUG-235 | The three strongest CI gates (cross-compiler-bytewise, differential, golden-provenance-gat |
| F-054 | HIGH | BUG | SINGLE | * | top |  | CL-BUG-236 | 37 Rust integration tests have no runner — ci.yml's `cargo test --release -- --ignored` on |
| F-055 | HIGH | BUG | SINGLE | * | top |  | CL-BUG-073 | The strongest off-chain oracle (`real-crypto-execution.ts`'s stateless-signed leg, plus `s |
| F-056 | HIGH | BUG | SINGLE | * | top |  | CL-BUG-253 | Webapp re-init handlers overwrite live keypairs with no game-phase guard, permanently bric |
| F-057 | HIGH | BUG | SINGLE | * | top |  | CL-BUG-232 | Three Rust example suites (tic-tac-toe, token-ft, token-nft) test a hand-written reimpleme |
| F-058 | HIGH | BUG | SINGLE | * | top |  | CL-BUG-082 | Shipped DSL Groth16Verifier contract skips G2 on-curve/subgroup checks before pairing |
| F-059 | HIGH | BUG | SINGLE | * | top |  | CL-BUG-110 | The published decompiler silently loses ~95% of its capability and reports success |
| F-060 | HIGH | BUG | SINGLE | * | top |  | CL-BUG-230 | Two of seven compilers reject a checked-in example contract; five have no code path for it |
| F-061 | HIGH | BUG | SINGLE | * | top |  | CL-BUG-233 | Three Python negatives swallow their own failure signal; the BUG-001 malleability gate is  |
| F-062 | HIGH | BUG | SINGLE | * | top |  | CL-BUG-053 | 5. **CL-BUG-053 (six parsers silently turn a leading-zero decimal into 0) |
| F-063 | HIGH | BUG | SINGLE | compiler:go | top |  | CL-BUG-190 | ArrayLiteralExpr is missing from four Go AST walkers (validator.go's recursion/hex-length  |
| F-064 | HIGH | BUG | SINGLE | compiler:go | top |  | CX-BUG-026 | parseStatement's default case silently returns nil for syntactically valid but unrecognize |
| F-065 | HIGH | BUG | SINGLE | compiler:go | top | restamp | CX-BUG-020 | ANFMethod.SigHashType is tagged json:"-", so a source-to-IR-to-artifact round-trip cannot  |
| F-066 | HIGH | BUG | SINGLE | compiler:go | top | restamp | CX-BUG-021 | ANFProgram.ParentClass is tagged json:"-", so a source-to-IR-to-artifact round-trip loses  |
| F-067 | HIGH | BUG | SINGLE | compiler:go | top | restamp | CX-BUG-014 | Go: array-literal metadata (`arrayElements`/`arrayLengths`) built before a conditional is  |
| F-068 | HIGH | BUG | SINGLE | compiler:go | top | restamp | CL-BUG-218 | Go: `check_preimage.sighashFlag` is a plain `int` from JSON with no range/validity check,  |
| F-069 | HIGH | BUG | SINGLE | compiler:go | top |  | CL-BUG-251 | The Move variant of the flagship nine-format end2end example compiles to a materially diff |
| F-070 | HIGH | BUG | SINGLE | compiler:go | top | restamp | CL-BUG-008 | `--ir` artifacts always omit parentClass, flipping the SDK's issue-#42/#44 sighash-subscri |
| F-071 | HIGH | BUG | SINGLE | compiler:go | top | restamp | CL-BUG-009 | Recursive private method in IR causes an unrecoverable stack overflow; checkNoRecursion is |
| F-072 | HIGH | BUG | SINGLE | compiler:go | top | restamp | CL-BUG-042 | Go: lowerCall's assert/exit/super paths register a stack slot no opcode produces |
| F-073 | HIGH | BUG | SINGLE | compiler:go | top |  | CL-BUG-189 | The Go-DSL parser merges the properties of *every* contract struct in a file into the last |
| F-074 | HIGH | BUG | SINGLE | compiler:go | top |  | CL-BUG-192 | `mapGoOp` returns `"+"` for any unmapped Go binary operator |
| F-075 | HIGH | BUG | SINGLE | compiler:go | top |  | CL-BUG-193 | Crit-3 and the `requireOutputP2PKH(0)` collision guard do not follow private helpers, whil |
| F-076 | HIGH | BUG | SINGLE | compiler:go | top |  | CL-BUG-195 | Go's Python tokenizer panics (uncaught, exit 2) on a file ending with a backslash inside a |
| F-077 | HIGH | BUG | SINGLE | compiler:go | top | restamp | GK-BUG-022 | WA G2 affine add documents a Qx≠Tx abort and does not emit it; doubling-collision accepts  |
| F-078 | HIGH | BUG | SINGLE | compiler:go | top |  | CX-BUG-003 | Constant propagation retains stale values across same-name rebindings |
| F-079 | HIGH | BUG | SINGLE | compiler:java | top | restamp | GK-BUG-015 | Java's ANF-level AnfMethod record has no sighashType field at all, and the CLI never emits |
| F-080 | HIGH | BUG | SINGLE | compiler:java | top | restamp | CX-BUG-029 | Java: `_codePart` discovery (`methodUsesCodePart`) does not recurse into private helper me |
| F-081 | HIGH | BUG | SINGLE | compiler:java | top | restamp | CX-BUG-030 | Java: branch subcontexts discard outer arrayLengths/arrayElements metadata required by che |
| F-082 | HIGH | BUG | SINGLE | compiler:java | top |  | CX-BUG-031 | Java: ConstantFold's environment keeps a stale constant value after a same-name rebinding  |
| F-083 | HIGH | BUG | SINGLE | compiler:java | top | restamp | CX-BUG-040 | Java: state pushdata encoder/decoder omit PUSHDATA4, so values >= 65536 bytes (which input |
| F-084 | HIGH | BUG | SINGLE | compiler:java | top | restamp | CX-BUG-046 | Java: ANF loader silently converts missing or wrongly-typed required collections (properti |
| F-085 | HIGH | BUG | SINGLE | compiler:java | top |  | CL-BUG-238 | The tier-version drift gate cannot match the current version family |
| F-086 | HIGH | BUG | SINGLE | compiler:python | top |  | CX-BUG-052 | EC-generated fresh-constant names (__ec_opt_N) can collide with an existing body binding o |
| F-087 | HIGH | BUG | SINGLE | compiler:python | top | restamp | CX-BUG-067 | FixedArray expansion generates synthetic property names (e.g. board__0) without reserving  |
| F-088 | HIGH | BUG | SINGLE | compiler:python | top | restamp | CX-BUG-071 | The generic CLI IR serializer's _SNAKE_TO_CAMEL table has no mapping for sighash_type, so  |
| F-089 | HIGH | BUG | SINGLE | compiler:python | top | restamp | CX-BUG-058 | Python: `if`-branch lowering contexts do not inherit the parent's `array_elements`/`array_ |
| F-090 | HIGH | BUG | SINGLE | compiler:python | top | restamp | CX-BUG-069 | Python: `checkMultiSig` accepts untyped and heterogeneous array literals because `_infer_e |
| F-091 | HIGH | BUG | SINGLE | compiler:python | top | restamp | CL-BUG-144 | Python `bn254G1Add` returns a silently different, still on-curve point for constructible ω |
| F-092 | HIGH | BUG | SINGLE | compiler:python | top | restamp | CL-BUG-145 | Python: `merkleRootPoseidon2KB` discards 7 of its 8 root limbs (compilers/python/runar_com |
| F-093 | HIGH | BUG | SINGLE | compiler:python | top | restamp | CL-BUG-205 | `@sighash SINGLE` multi-output validation undercounts a loop body |
| F-094 | HIGH | BUG | SINGLE | compiler:python | top |  | CL-BUG-207 | Python's Zig parser does not lower `runar.hexToBytes(...)`; a checked-in in-repo contract  |
| F-095 | HIGH | BUG | SINGLE | compiler:python | top |  | CX-BUG-054 | Constant facts survive nonconstant same-name rebindings |
| F-096 | HIGH | BUG | SINGLE | compiler:python | top | restamp | CX-BUG-061 | `_codePart` discovery does not recurse through private helpers that build outputs |
| F-097 | HIGH | BUG | SINGLE | compiler:ruby | top | restamp | CX-BUG-083 | Ruby: a `false`-valued property initializer is treated as absent by stack lowering's truth |
| F-098 | HIGH | BUG | SINGLE | compiler:ruby | top |  | CL-BUG-270 | Ruby: FixedArray expansion drops @embedAlways when rebuilding PropertyNode for each array  |
| F-099 | HIGH | BUG | SINGLE | compiler:ruby | top |  | CL-BUG-273 | Ruby: checkMultiSig accepts bigint arrays because array literals have no inferred type, so |
| F-100 | HIGH | BUG | SINGLE | compiler:ruby | top |  | CX-BUG-077 | Ruby: FixedArray-generated slot/temp names (__idx_N, __val_N, property__N) can collide wit |
| F-101 | HIGH | BUG | SINGLE | compiler:rust | top | restamp | CL-BUG-261, CL-GAP-038 | Rust `constructor_args` values are baked into properties with no type or length validation |
| F-102 | HIGH | BUG | SINGLE | compiler:rust | top | restamp | CL-BUG-262 | Rust `--ir` path lets the script-level sighash flag diverge from the ABI's declared sigHas |
| F-103 | HIGH | BUG | SINGLE | compiler:rust | top |  | CX-BUG-087 | Rust: `constructor_args` in `CompileOptions` is silently ignored by the ANF-IR and direct- |
| F-104 | HIGH | BUG | SINGLE | compiler:rust | top |  | CL-BUG-020 | Rust `--ir` silently drops parentClass AND sighashType (both `#[serde(skip)]`), so the SDK |
| F-105 | HIGH | BUG | SINGLE | compiler:rust | top | restamp | CL-BUG-021 | Hostile IR panics the compiler via an unguarded `panic!` in assemble_artifact, outside eve |
| F-106 | HIGH | BUG | SINGLE | compiler:rust | top | restamp | CL-BUG-095 | Rust tier: issue-#130 shadow renaming is lost inside branches |
| F-107 | HIGH | BUG | SINGLE | compiler:rust | top | restamp | CL-BUG-263 | `--ir` compiles a validator-rejected readonly-hijack to an anyone-can-spend script, and th |
| F-108 | HIGH | BUG | SINGLE | compiler:ts | top | restamp | GK-BUG-019 | TS DCE has no "last binding is live" root: an ANF method's final (implicit-result) binding |
| F-109 | HIGH | BUG | SINGLE | compiler:ts | top |  | GK-BUG-035 | TS EC optimizer's ec-add-identity-left/right rules treat O (point at infinity) as a group  |
| F-110 | HIGH | BUG | SINGLE | compiler:ts | top | restamp | CX-BUG-106 | TS: affine-value tracking analyzes a loop body only once, missing repeated Sig/SigHashPrei |
| F-111 | HIGH | BUG | SINGLE | compiler:ts | top | restamp | CX-BUG-110 | `requireBaked` only proves a property was referenced pre-optimization; the post-emission c |
| F-112 | HIGH | BUG | SINGLE | compiler:ts | top | restamp | CX-BUG-097 | TS: `ConstEnv` has no delete/invalidate operation, so rebinding an ANF name previously rec |
| F-113 | HIGH | BUG | SINGLE | compiler:ts | top |  | CL-BUG-251 | The Move variant of the flagship nine-format end2end example compiles to a materially diff |
| F-114 | HIGH | BUG | SINGLE | compiler:ts | top | restamp | CL-BUG-086 | `blake3Compress`/`sha256Compress` accept mis-sized operands in all 7 tiers, enabling a sec |
| F-115 | HIGH | BUG | SINGLE | compiler:ts | top |  | CL-BUG-003 | TS EC optimizer single-pass vs Go fixed-point; chained rewrites diverge |
| F-116 | HIGH | BUG | SINGLE | compiler:ts | top |  | CL-BUG-205 | `@sighash SINGLE` multi-output validation undercounts a loop body |
| F-117 | HIGH | BUG | SINGLE | compiler:ts | top | restamp | CX-BUG-102 | FixedArray expansion can collide with user-declared `name__index` properties |
| F-118 | HIGH | BUG | SINGLE | compiler:zig | top | restamp | CL-BUG-134 | Zig's --ir path always emits parentClass:"SmartContract" (an unconditional struct default) |
| F-119 | HIGH | BUG | SINGLE | compiler:zig | top |  | CL-BUG-062 | Zig Move-format `loop { }` fabricates a hardcoded 1000-iteration bound (parse_move.zig:140 |
| F-120 | HIGH | BUG | SINGLE | compiler:zig | top | restamp | CL-BUG-118 | Zig `compileFromIR` never runs the `sighash_validate` pass (or any validate/typecheck pass |
| F-121 | HIGH | BUG | SINGLE | compiler:zig | top | restamp | CL-BUG-119 | Zig `compile-ir` path drops `ANFMethod.sighash_type` in the IR loader, so the artifact ABI |
| F-122 | HIGH | BUG | SINGLE | compiler:zig | top |  | CX-BUG-122 | Zig `expand_fixed_arrays.zig` strips `@embedAlways` (`embed_always`) from synthetic scalar |
| F-123 | HIGH | BUG | SINGLE | compiler:zig | top |  | CX-BUG-125 | Zig fixed-array expansion generates `<root>__<index>` synthetic property names with no uni |
| F-124 | HIGH | BUG | SINGLE | sdk:go | top |  | CL-BUG-093 | Go ScriptVM never passes WithTx, so it cannot execute any script containing a signature-ch |
| F-125 | HIGH | BUG | SINGLE | sdk:go | top |  | CL-BUG-082 | Shipped DSL Groth16Verifier contract skips G2 on-curve/subgroup checks before pairing |
| F-126 | HIGH | BUG | SINGLE | sdk:go | top |  | CL-BUG-092 | `sp1fri.Verify` panics on a zero-query proof before any cryptographic check |
| F-127 | HIGH | BUG | SINGLE | sdk:go | top |  | GK-BUG-009 | SDK real pairing wrapper comment claims identity rejected; gnark IsOnCurve accepts (0,0) i |
| F-128 | HIGH | BUG | SINGLE | sdk:go | top |  | GK-BUG-011 | Off-chain blake3Hash silently truncates messages >64 bytes; on-chain script aborts (mock/s |
| F-129 | HIGH | BUG | SINGLE | sdk:java | top |  | CL-BUG-228 | checkPreimage is unconditionally true in all 7 tiers' mock crypto, and TS's checkMultiSig  |
| F-130 | HIGH | BUG | SINGLE | sdk:java | top |  | GK-BUG-016 | SHA2-256f tree-index mask computed as 1<<(h-hp) with h-hp=64: Java's `1L << 64` (JLS shift |
| F-131 | HIGH | BUG | SINGLE | sdk:java | top |  | CL-BUG-176 | Java analyzer opcode table omits every Chronicle opcode its own toolchain emits (Opcodes.j |
| F-132 | HIGH | BUG | SINGLE | sdk:java | top |  | CL-BUG-177 | PathAnalyzer returns zero paths on an unbalanced OP_IF/OP_ENDIF, silently disabling NO_SIG |
| F-133 | HIGH | BUG | SINGLE | sdk:python | top |  | CL-BUG-164 | Python SDK verifies SLH-DSA against a real upstream FIPS 205 library (SHA-512, a=9) while  |
| F-134 | HIGH | BUG | SINGLE | sdk:python | top |  | CL-BUG-127 | Python's runar/builtins.py (floor division) and runar/sdk/anf_interpreter.py (truncate-tow |
| F-135 | HIGH | BUG | SINGLE | sdk:python | top |  | GK-BUG-034 | Python hash160/ripemd160 calls hashlib.new('ripemd160') with no OpenSSL-3 legacy-provider  |
| F-136 | HIGH | BUG | SINGLE | sdk:python | top |  | GK-BUG-011 | Off-chain blake3Hash silently truncates messages >64 bytes; on-chain script aborts (mock/s |
| F-137 | HIGH | BUG | SINGLE | sdk:ruby | top |  | CL-BUG-155 | Ruby SDK's LocalSigner fallback preimage builder never received the issue-#123 non-default |
| F-138 | HIGH | BUG | SINGLE | sdk:ruby | top |  | CL-BUG-159, CL-BUG-241 | Ruby's verify_envelope rejects high-S ECDSA signatures that TS/Go/Python/Zig/Java accept;  |
| F-139 | HIGH | BUG | SINGLE | sdk:ruby | top |  | GK-BUG-011 | Off-chain blake3Hash silently truncates messages >64 bytes; on-chain script aborts (mock/s |
| F-140 | HIGH | BUG | SINGLE | sdk:rust | top |  | GK-BUG-016 | SHA2-256f tree-index mask computed as 1<<(h-hp) with h-hp=64: Java's `1L << 64` (JLS shift |
| F-141 | HIGH | BUG | SINGLE | sdk:rust | top |  | GK-BUG-028 | Rust BIP-143 signer always hashes ALL prevouts/sequences/outputs regardless of requested s |
| F-142 | HIGH | BUG | SINGLE | sdk:rust | top |  | CL-BUG-087 | Rust `sha256_finalize` is wrong for `remaining` ∈ [64,119] and panics at exactly 64 |
| F-143 | HIGH | BUG | SINGLE | sdk:ts | top |  | CL-BUG-134 | Zig's --ir path always emits parentClass:"SmartContract" (an unconditional struct default) |
| F-144 | HIGH | BUG | SINGLE | sdk:ts | top |  | GK-BUG-036 | Rabin padding/sig/n pushed as unsigned little-endian bytes are consumed as signed Bitcoin  |
| F-145 | HIGH | BUG | SINGLE | sdk:ts | top |  | CL-BUG-135 | TS ANF interpreter (packages/runar-sdk) fails OPEN on unknown ANF kinds/builtins and divis |
| F-146 | HIGH | BUG | SINGLE | sdk:ts | top |  | GK-BUG-033 | TS WalletSigner.getAddress returns hash160 hex instead of Base58Check, violating the Signe |
| F-147 | HIGH | BUG | SINGLE | sdk:ts | top |  | GK-BUG-011 | Off-chain blake3Hash silently truncates messages >64 bytes; on-chain script aborts (mock/s |
| F-148 | HIGH | GAP | SINGLE | * | top |  | CL-GAP-141 | The one contract (PriceBet) hand-written in all nine formats is not wired into the conform |
| F-149 | HIGH | GAP | SINGLE | * | top |  | CL-GAP-100 | `cargo test -- --ignored` runs ONLY the gated set; 37 Rust tests have no runner |
| F-150 | HIGH | GAP | SINGLE | compiler:go | mid |  | GK-GAP-004 | No constructed small-order G2 test for Groth16/pairing; MapToCurve2 off-r-torsion is not s |
| F-151 | HIGH | GAP | SINGLE | compiler:ruby | mid |  | CL-GAP-040 | test_conformance_goldens.rb silently passes fixtures with no .runar.rb source and vacuousl |
| F-152 | HIGH | GAP | SINGLE | compiler:rust | mid |  | CL-GAP-030 | (Appears misfiled in this bucket) Whole-area absence of Rust tests for sourceMap/code-sepa |
| F-153 | HIGH | GAP | SINGLE | compiler:ts | mid |  | CL-GAP-016 | Go, Solidity and Move parsers have ZERO malformed-input rejection tests across 110 tests |
| F-154 | HIGH | GAP | SINGLE | compiler:ts | mid |  | CL-GAP-017 | 13 documented builtins have no TS test at any level; sha1, ripemd160, checkSigVerify, chec |
| F-155 | HIGH | GAP | SINGLE | sdk:ts | mid |  | GK-GAP-012 | Public runar-lang verifyRabinSig omits the padding-range bound; sig=0, padding=SHA256(msg) |
| F-156 | MEDIUM | GAP | SINGLE | compiler:go | mid |  | CL-GAP-056 | Go: lowerAddOutput silently truncates when stateValues and the mutable-property list disag |
| F-157 | MEDIUM | GAP | SINGLE | compiler:ruby | mid |  | CL-GAP-049 | Ruby multi-format hex-parity test suite covers 8 of 9 formats; .runar.java has no parity t |
| F-158 | MEDIUM | BUG | MAJORITY | compiler:rust | mid | restamp | CL-BUG-027, CX-BUG-094 | `catch_refusal` swaps the process-global panic hook unsynchronized — a race under concurre |
| F-159 | MEDIUM | BUG | MAJORITY | compiler:ts | top | restamp | CL-BUG-117, CX-GAP-024 | TS peephole `optimizeNestedIf` unconditionally rebuilds every `if` op as a bare `{op:'if', |
| F-160 | MEDIUM | BUG | MAJORITY | compiler:ts | top | restamp | CL-BUG-004, GK-BUG-020 | Constant-fold's `===`/`!==` on ByteString literals compares hex source text case-sensitive |
| F-161 | MEDIUM | BUG | MAJORITY | compiler:ts | top |  | CL-BUG-017, GK-GAP-013 | `examples.test.ts`'s primary "compiles through the TS compiler" test tolerates compile fai |
| F-162 | MEDIUM | BUG | SINGLE | * | top |  | CL-BUG-255 | The flagship end2end PriceBet webapp's settle path is provably unspendable and never exerc |
| F-163 | MEDIUM | BUG | SINGLE | * | top |  | CL-BUG-091 | The golden-provenance CI gate resolves the base commit from the unpinned pull_request.base |
| F-164 | MEDIUM | BUG | SINGLE | * | top |  | CL-BUG-055 | `executeStrict` does not mock `check_preimage` despite PROTOCOL.md and two doc comments pr |
| F-165 | MEDIUM | BUG | SINGLE | * | mid |  | CL-BUG-099 | (see ledger) |
| F-166 | MEDIUM | BUG | SINGLE | * | mid |  | CL-BUG-111 | `runar test` interpolates the user pattern into a shell string (command injection) |
| F-167 | MEDIUM | BUG | SINGLE | * | mid |  | CL-BUG-130 | `bitwise-ops` and `shift-ops` are unfalsifiable at the *contract* level, not the test leve |
| F-168 | MEDIUM | BUG | SINGLE | * | mid |  | CL-BUG-131 | `examples/zig/state-covenant`: the tier's only real proof-verification covenant is tested  |
| F-169 | MEDIUM | BUG | SINGLE | * | mid |  | CL-BUG-227, CL-GAP-126 | `differential.ts` compares the TS CLI's human-readable chatter against six tiers' ANF JSON |
| F-170 | MEDIUM | BUG | SINGLE | * | mid |  | CL-BUG-227, CL-GAP-126 | - **The `JSON.stringify(obj, Object.keys(obj).sort(), 2)` allow-list bug is still live in |
| F-171 | MEDIUM | BUG | SINGLE | * | mid |  | CL-BUG-227, CL-GAP-126 | `entry.oracle` is never validated and silently downgrades |
| F-172 | MEDIUM | BUG | SINGLE | * | mid |  | CL-BUG-227, CL-GAP-126 | The mutation scorecard is self-referential |
| F-173 | MEDIUM | BUG | SINGLE | * | top |  | CL-BUG-227, CL-GAP-126 | The 231-line delta-debugging shrinker is never invoked by any harness |
| F-174 | MEDIUM | BUG | SINGLE | * | mid |  | CL-BUG-239, CL-GAP-133 | `lean-verify.sh` has drifted from the CI job it declares it must mirror |
| F-175 | MEDIUM | BUG | SINGLE | * | mid |  | CL-BUG-239, CL-GAP-133 | A CI step writes hardcoded pass results into the job summary on failure |
| F-176 | MEDIUM | BUG | SINGLE | compiler:go | mid | restamp | CX-BUG-022 | Artifact statefulness is computed as `len(stateFields) > 0` instead of from the declared P |
| F-177 | MEDIUM | BUG | SINGLE | compiler:go | top |  | CX-BUG-025 | The documented 4 MiB source-size guard (assertSourceBytesUnderLimit) is only invoked from  |
| F-178 | MEDIUM | BUG | SINGLE | compiler:go | top | restamp | CL-BUG-010 | Intent-intrinsic "opcode-sequence audit" assertions are nibble-unaligned hex substring sea |
| F-179 | MEDIUM | BUG | SINGLE | compiler:go | top | restamp | CX-BUG-012, CX-BUG-023 | Go peephole replacements and reconstructed nested `if` operations discard SourceLoc, corru |
| F-180 | MEDIUM | BUG | SINGLE | compiler:go | top | restamp | CL-BUG-014, CL-GAP-119 | `regroupSyntheticRuns`'s 1024-pass iteration cap panics on a ~41KB flat-array IR payload,  |
| F-181 | MEDIUM | BUG | SINGLE | compiler:go | mid |  | CL-BUG-220 | The only Go test comparing `--ir` output to source output swallows every failure as a log  |
| F-182 | MEDIUM | BUG | SINGLE | compiler:go | top | restamp | CL-BUG-221, CL-BUG-222, CL-BUG-223 | Stale test exclusions (LOW-MEDIUM) |
| F-183 | MEDIUM | BUG | SINGLE | compiler:go | top | restamp | CL-BUG-221, CL-BUG-222, CL-BUG-223 | Silent flag precedence (LOW) |
| F-184 | MEDIUM | BUG | SINGLE | compiler:go | top |  | CL-BUG-221, CL-BUG-222, CL-BUG-223 | `loadGroth16WAConfig` zero-fills IC slots |
| F-185 | MEDIUM | BUG | SINGLE | compiler:java | top |  | CX-BUG-033 | Java: EC-generated binding names come from a process-global AtomicInteger never reset per  |
| F-186 | MEDIUM | BUG | SINGLE | compiler:java | top | restamp | CX-BUG-034 | Java: recursive peephole optimization of nested `if`/`loop` reconstructs IfOp via location |
| F-187 | MEDIUM | BUG | SINGLE | compiler:java | mid |  | CX-BUG-048 | Java: Validate.run's returned warnings are discarded by both CLI and daemon compilation mo |
| F-188 | MEDIUM | BUG | SINGLE | compiler:java | top | restamp | CX-BUG-050 | Java: AnfLower's branch-property-update lifting generates new bindings with sourceLoc unif |
| F-189 | MEDIUM | BUG | SINGLE | compiler:java | mid |  | CL-BUG-244 | `.runar.java`'s unsuffixed `0xFFFFFFFF` parses as Java `int` -1, diverging from TS's `0xFF |
| F-190 | MEDIUM | BUG | SINGLE | compiler:java | mid |  | CL-BUG-256 | A second, javac-invalid `PriceBet.runar.java` is the copy the playground serves |
| F-191 | MEDIUM | BUG | SINGLE | compiler:python | top |  | CX-BUG-053 | Process-global _fresh_counter never resets between compilations, so optimized ANF for the  |
| F-192 | MEDIUM | BUG | SINGLE | compiler:python | mid |  | CX-BUG-074 | is_stateful (and therefore is_terminal / artifact.anf) is derived from len(state_fields) i |
| F-193 | MEDIUM | BUG | SINGLE | compiler:python | top | restamp | CL-BUG-147 | Python: crypto op caches (`_get_compress_ops` in sha256.py/blake3.py) return the same shar |
| F-194 | MEDIUM | BUG | SINGLE | compiler:python | top | restamp | CL-BUG-149 | Python: `emit_push_data_encode` has no `OP_PUSHDATA4` (0x4E) branch, silently truncating a |
| F-195 | MEDIUM | BUG | SINGLE | compiler:python | top | restamp | CX-BUG-060 | Python: `if`-branch lowering contexts do not inherit the parent's `const_values` map, so a |
| F-196 | MEDIUM | BUG | SINGLE | compiler:python | top | restamp | CL-BUG-150 | BabyBear field operations' documented non-negativity premise is not enforced; `bbFieldAdd( |
| F-197 | MEDIUM | BUG | SINGLE | compiler:python | mid |  | CL-BUG-208, CL-BUG-209, CL-BUG-210, CL-BUG-211… | `parser_go.py` uses the C ladder, not Go's |
| F-198 | MEDIUM | BUG | SINGLE | compiler:python | mid |  | CL-BUG-208, CL-BUG-209, CL-BUG-210, CL-BUG-211… | Leading-zero decimals |
| F-199 | MEDIUM | BUG | SINGLE | compiler:python | mid |  | CL-BUG-208, CL-BUG-209, CL-BUG-210, CL-BUG-211… | `parse_go` appends a bare `str` to a `list[Diagnostic]` |
| F-200 | MEDIUM | BUG | SINGLE | compiler:python | mid |  | CL-BUG-208, CL-BUG-209, CL-BUG-210, CL-BUG-211… | `parser_sol.py` strips the leading underscore from *method* params |
| F-201 | MEDIUM | BUG | SINGLE | compiler:python | mid |  | CL-BUG-208, CL-BUG-209, CL-BUG-210, CL-BUG-211… | `parser_sol._rewrite_bare_props` misses `IncrementExpr`/`DecrementExpr`/`MemberExpr` |
| F-202 | MEDIUM | BUG | SINGLE | compiler:python | mid | restamp | CL-BUG-208, CL-BUG-209, CL-BUG-210, CL-BUG-211… | `parser_move.py` turns odd-length `0x` literals into integers |
| F-203 | MEDIUM | BUG | SINGLE | compiler:python | mid |  | CL-BUG-208, CL-BUG-209, CL-BUG-210, CL-BUG-211… | `parser_python.py` decodes `\0` |
| F-204 | MEDIUM | BUG | SINGLE | compiler:python | mid |  | CL-BUG-208, CL-BUG-209, CL-BUG-210, CL-BUG-211… | `#[runar::unsafe_contract]` is silently downgraded |
| F-205 | MEDIUM | BUG | SINGLE | compiler:python | mid |  | CL-BUG-208, CL-BUG-209, CL-BUG-210, CL-BUG-211… | `parser_java.py` |
| F-206 | MEDIUM | BUG | SINGLE | compiler:python | mid |  | CL-BUG-208, CL-BUG-209, CL-BUG-210, CL-BUG-211… | `parser_ruby.py` |
| F-207 | MEDIUM | BUG | SINGLE | compiler:python | mid |  | CL-BUG-208, CL-BUG-209, CL-BUG-210, CL-BUG-211… | `parser_zig.py` |
| F-208 | MEDIUM | BUG | SINGLE | compiler:ruby | mid |  | CL-BUG-275 | Ruby: typecheck accepts a bound local variable used as a function call (Rúnar has no first |
| F-209 | MEDIUM | BUG | SINGLE | compiler:ruby | top | restamp | CL-BUG-274 | Ruby: the EC alias resolver tests the wrong ANF kind (`load_param` instead of `load_const` |
| F-210 | MEDIUM | BUG | SINGLE | compiler:ruby | mid |  | CL-BUG-034 | The Rakefile counts a file that runs ZERO tests as a pass, and `$?` is nil-unsafe when spa |
| F-211 | MEDIUM | BUG | SINGLE | compiler:rust | top | restamp | CL-BUG-056 | Rust (236) and Zig (272) emit far more source-map mappings than the other five tiers (8-10 |
| F-212 | MEDIUM | BUG | SINGLE | compiler:rust | mid |  | CL-BUG-169 | Rust tier's Java frontend has no hex-literal path; `0xFF` is a parse error where five othe |
| F-213 | MEDIUM | BUG | SINGLE | compiler:rust | top |  | CL-BUG-172 | No nesting-depth bound in the Rust frontend: ~4-6 KB of deeply nested source SIGABRTs the  |
| F-214 | MEDIUM | BUG | SINGLE | compiler:rust | top |  | CL-BUG-173 | `.runar.go` reinterprets `& / ^ << >>` against Go's own operator precedence, silently, in  |
| F-215 | MEDIUM | BUG | SINGLE | compiler:rust | mid |  | CX-BUG-090 | Stateful identity (parentClass) and terminal ABI metadata (is_terminal) diverge for a zero |
| F-216 | MEDIUM | BUG | SINGLE | compiler:rust | mid |  | CX-BUG-092 | Heterogeneous multisig array literals (e.g. [sig, 1n]) are type-checked using only their f |
| F-217 | MEDIUM | BUG | SINGLE | compiler:rust | mid |  | CX-BUG-088 | Rust: `parse_only`/`validate_only`/`typecheck_only` stop-after-pass options are honored on |
| F-218 | MEDIUM | BUG | SINGLE | compiler:rust | mid |  | CL-BUG-028 | Six Rust driver tests assert less than their names claim, including source-vs-IR hex parit |
| F-219 | MEDIUM | BUG | SINGLE | compiler:rust | top | restamp | CL-BUG-115 | DCE (`eliminateDeadBindings`) only runs when the always-on EC optimizer reports a change,  |
| F-220 | MEDIUM | BUG | SINGLE | compiler:rust | top | restamp | CL-BUG-024 | --emit-ir / --emit-ir-to discard every validator warning incl. the H2 locktime-bypass advi |
| F-221 | MEDIUM | BUG | SINGLE | compiler:rust | top |  | CX-BUG-093 | Debug script failure returns process exit status 0 |
| F-222 | MEDIUM | BUG | SINGLE | compiler:ts | top |  | CX-BUG-105 | TS: affine-value tracking uses one shared consumedValues set across sequential if/else arm |
| F-223 | MEDIUM | BUG | SINGLE | compiler:ts | mid |  | CX-BUG-109 | TS: `compileFromANF` aliases its input with `const anf = program` and writes constructor v |
| F-224 | MEDIUM | BUG | SINGLE | compiler:ts | top | restamp | CL-BUG-005 | Peephole rewrites drop sourceLoc; emitter mis-attributes every fused opcode |
| F-225 | MEDIUM | BUG | SINGLE | compiler:ts | mid |  | CL-BUG-015 | multi-format.test.ts swallows a fixture's source.json parse failure at collection, silentl |
| F-226 | MEDIUM | BUG | SINGLE | compiler:ts | top | restamp | CL-BUG-016 | Three vacuity holes: assertions inside a conditional that can never be entered, incl. the  |
| F-227 | MEDIUM | BUG | SINGLE | compiler:ts | top | restamp | CL-BUG-097 | Interpreter `checkSig` returns `false` where the script ABORTS; branching contracts diverg |
| F-228 | MEDIUM | BUG | SINGLE | compiler:zig | top | restamp | CL-BUG-056 | Rust (236) and Zig (272) emit far more source-map mappings than the other five tiers (8-10 |
| F-229 | MEDIUM | BUG | SINGLE | compiler:zig | mid |  | CX-BUG-127 | Zig CLI rejects source files above 1 MiB via a hardcoded `readFileAlloc` limit, despite th |
| F-230 | MEDIUM | BUG | SINGLE | compiler:zig | mid |  | CX-BUG-128 | Zig library API (`compiler_api.zig`) silently falls back to the Zig-format parser for unkn |
| F-231 | MEDIUM | BUG | SINGLE | compiler:zig | mid |  | CX-BUG-129 | Zig library API (`CompileResult`) has no diagnostics field and never surfaces validation w |
| F-232 | MEDIUM | BUG | SINGLE | sdk:go | top |  | CL-BUG-165 | SLHDSA.verify (Ruby + Go off-chain verifiers) accepts trailing garbage: every length guard |
| F-233 | MEDIUM | BUG | SINGLE | sdk:go | top |  | CL-BUG-083 | A standalone `groth16-wa` UTXO is unsigned and its spend is replayable by any observer |
| F-234 | MEDIUM | BUG | SINGLE | sdk:java | top |  | CL-BUG-178 | SigAnalyzer's three signature checks are all defeated by substituting OP_2DROP for OP_DROP |
| F-235 | MEDIUM | BUG | SINGLE | sdk:java | mid |  | CL-BUG-179 | STACK_UNDERFLOW check is unreachable from every production caller (all pass initialDepth=0 |
| F-236 | MEDIUM | BUG | SINGLE | sdk:java | mid |  | CL-BUG-180 | Java analyzer diverges from TS/Python: no INEFFICIENT_PUSH finding on truncated PUSHDATA h |
| F-237 | MEDIUM | BUG | SINGLE | sdk:python | mid |  | CL-BUG-126 | Python SDK: fixed-width state encoder/decoder (state.py:423) fails open on a wrong-sized o |
| F-238 | MEDIUM | BUG | SINGLE | sdk:python | mid |  | CL-BUG-125 | Python SDK: `_read_script_element` raises bare `ValueError` and silently truncates on prov |
| F-239 | MEDIUM | BUG | SINGLE | sdk:python | mid |  | CL-BUG-128 | Python SDK: generated typed wrappers raise `TypeError` on every stateful call passing opti |
| F-240 | MEDIUM | BUG | SINGLE | sdk:ruby | top |  | CL-BUG-165 | SLHDSA.verify (Ruby + Go off-chain verifiers) accepts trailing garbage: every length guard |
| F-241 | MEDIUM | BUG | SINGLE | sdk:ruby | top |  | CL-BUG-156 | Ruby accepts Base58Check change addresses with neither a checksum nor a version-byte check |
| F-242 | MEDIUM | BUG | SINGLE | sdk:ruby | top |  | CL-BUG-160 | Ruby's DER parser accepts trailing bytes inside the declared length and un-prefixed high-b |
| F-243 | MEDIUM | BUG | SINGLE | sdk:ruby | top |  | CL-BUG-161 | Ruby's `ec_on_curve` omits the coordinate range checks its own comment says the emitted sc |
| F-244 | MEDIUM | BUG | SINGLE | sdk:ruby | mid |  | CL-BUG-162 | Ruby's `truncate_div` routes through a Float, losing precision above 2^53 and raising `Flo |
| F-245 | MEDIUM | BUG | SINGLE | sdk:ts | mid |  | CL-BUG-139 | Generated SDK wrappers pass intent-intrinsic witness params (_prevOutScript_<i>, _serialis |
| F-246 | MEDIUM | BUG | SINGLE | sdk:ts | mid |  | CL-BUG-138 | Published npm package runar-sdk exports ./codegen but its Mustache templates live outside  |
| F-247 | MEDIUM | BUG | SINGLE | sdk:ts | mid |  | CL-BUG-136 | `finalizeCall` broadcasts a 72-byte all-zero placeholder when a declared `sigIndices` slot |
| F-248 | MEDIUM | BUG | SINGLE | sdk:ts | top |  | CL-BUG-141 | `WalletProvider.ensureFunding` swallows both the BEEF parse failure and the funding broadc |
| F-249 | LOW | BUG | SINGLE | * (compiler:go,compiler:python,compiler:ruby,compiler:rust,compiler:ts,compiler:zig) | top | restamp | CL-BUG-153 | Merkle codegen emits three consecutive OP_ROTs (an identity) per level — 6 compiler tiers  |
| F-250 | LOW | BUG | SINGLE | * | mid |  | CL-BUG-227, CL-GAP-126 | An empty regression corpus is a green run |
| F-251 | LOW | BUG | SINGLE | * | mid |  | CL-BUG-227, CL-GAP-126 | Six of 28 mutants have no baseline entry |
| F-252 | LOW | BUG | SINGLE | * | mid |  | CL-BUG-227, CL-GAP-126 | Nine false documentation claims across five files |
| F-253 | LOW | BUG | SINGLE | * | mid |  | CL-BUG-239, CL-GAP-133 | `pnpm test:ci`'s "green here → green CI" contract is violated in both directions |
| F-254 | LOW | BUG | SINGLE | compiler:go | mid | restamp | CL-BUG-045 | Go: `lowerBindings` panics on an empty public-method body |
| F-255 | LOW | BUG | SINGLE | compiler:go | top | restamp | CL-BUG-013 | --emit-ir silently ignores --emit-source-map, exiting 0 having written nothing |
| F-256 | LOW | BUG | SINGLE | compiler:go | mid |  | CL-BUG-012 | mergeOptions silently discards all but the first variadic CompileOptions |
| F-257 | LOW | BUG | SINGLE | compiler:go | mid | restamp | CL-BUG-046 | Go: optimizeNestedIf discards the SourceLoc of every `if` op |
| F-258 | LOW | BUG | SINGLE | compiler:python | top | restamp | CL-BUG-151 | Four silent-OP_0 fallbacks remain in Python stack lowering, all `--ir`-reachable (stack.py |
| F-259 | LOW | BUG | SINGLE | compiler:python | top | restamp | CL-BUG-152 | Python's `_lower_loop` does not set `current_source_loc` per unrolled binding |
| F-260 | LOW | BUG | SINGLE | compiler:python | top | restamp | CL-BUG-154 | `merkleRootPoseidon2KB`'s depth guard (1..64) is wider than its emitter accepts (1..32) |
| F-261 | LOW | BUG | SINGLE | compiler:ruby | mid | restamp | CL-BUG-031 | `assert_equal 'UnsafeSmartContract', 'UnsafeSmartContract'` — a literal compared to itself |
| F-262 | LOW | BUG | SINGLE | compiler:ruby | mid |  | CL-BUG-032 | test_empty_contract_no_methods_yields_warning_or_error asserts neither |
| F-263 | LOW | BUG | SINGLE | compiler:ruby | top |  | CL-BUG-033 | test_sighash.rb:253 asserts a strict substring of the preceding assertion |
| F-264 | LOW | BUG | SINGLE | compiler:ruby | mid |  | CL-BUG-035 | find_ruby_source rescues StandardError (subsuming JSON::ParserError), so any failure degra |
| F-265 | LOW | BUG | SINGLE | compiler:rust | mid | restamp | CL-BUG-175 | Two missed compile-time rejections in the Rust frontend: ByteString property initializers  |
| F-266 | LOW | BUG | SINGLE | compiler:rust | top | restamp | CL-BUG-029 | Nondeterministic diagnostic text from HashMap key iteration (script bytes unaffected) |
| F-267 | LOW | BUG | SINGLE | compiler:rust | mid |  | CL-BUG-030 | parse_const_value silently truncates JSON float constants via `f64 as i128` |
| F-268 | LOW | BUG | SINGLE | compiler:rust | mid | restamp | CL-BUG-049 | Rust: `&s[..5]` byte-slices a UTF-8 string, panicking on a non-ASCII constant |
| F-269 | LOW | BUG | SINGLE | compiler:ts | top | restamp | CL-BUG-007 | EC optimizer does not resolve through its own @ref: aliases; unchecked name minting |
| F-270 | LOW | BUG | SINGLE | compiler:ts | top | restamp | CL-BUG-018 | blake3-output.test.ts uses an it() block as a fixture; five tests depend on order |
| F-271 | LOW | BUG | SINGLE | compiler:ts | mid |  | CL-BUG-019 | assembler.test.ts mutates a compiled artifact in place and asserts on the value it just wr |
| F-272 | LOW | BUG | SINGLE | sdk:java | mid |  | CL-BUG-181 | Java analyzer diverges from TS on numeric rounding (Math.rint vs toFixed(1)) and whitespac |
| F-273 | LOW | BUG | SINGLE | sdk:python | mid |  | CL-BUG-129 | Python SDK: RunarContract.from_txid accepts a negative output_index, silently binding to t |
| F-274 | LOW | BUG | SINGLE | sdk:ruby | top |  | CL-BUG-163 | Ruby's right(data, 0) returns the whole string, and right/left fail open out of range wher |
| F-275 | HIGH | GAP | MAJORITY | compiler:java | mid |  | CX-DOC-001, CX-GAP-007, GK-GAP-003 | Java's Cli.optimizeAnf never runs standalone DCE for non-EC programs, and the pipeline's ' |
| F-276 | HIGH | GAP | SINGLE | * | mid |  | GK-GAP-010 | Java (and Ruby) on-chain integration tests broadcast TypeScript-compiler artifacts, not na |
| F-277 | HIGH | GAP | SINGLE | * | top |  | CL-GAP-095 | conformance/ is outside the pnpm workspace, so 8 of its test suites (incl. wire-primitives |
| F-278 | HIGH | GAP | SINGLE | * | top |  | GK-GAP-005 | Conformance corpus has zero BN254/Groth16 fixtures despite the Go-only policy naming BN254 |
| F-279 | HIGH | GAP | SINGLE | * | mid |  | CL-GAP-129 | 28 of 540 vitest-collectable files are unreachable from any workflow, including the gates  |
| F-280 | HIGH | GAP | SINGLE | compiler:go | mid |  | CL-GAP-006 | Two of three all-conformance sweeps silently skip the golden comparison when the golden is |
| F-281 | HIGH | GAP | SINGLE | compiler:go | mid |  | CL-GAP-071 | 6. **CL-GAP-071 (Go-DSL `x += 1` compiles to `x = 1`) is REAL but currently LATENT |
| F-282 | HIGH | GAP | SINGLE | compiler:java | mid |  | CL-GAP-140 | Java TsParser silently drops a @sighash directive when the member shares a line with the p |
| F-283 | HIGH | GAP | SINGLE | compiler:ruby | mid |  | CL-GAP-164 | Ruby `--ir` loader bounds each loop's iteration count individually but never the product a |
| F-284 | HIGH | GAP | SINGLE | compiler:ruby | mid |  | CL-GAP-149 | The BUG-100 preimage blob is guarded by LENGTH ONLY, in both tiers |
| F-285 | HIGH | GAP | SINGLE | compiler:rust | mid |  | CL-GAP-033, CL-GAP-154 | `conformance_goldens.rs` cannot fail on a missing golden or on lost fixture coverage |
| F-286 | HIGH | GAP | SINGLE | compiler:ts | mid |  | GK-GAP-014 | TS: verifyRabinSig's RabinPubKey parameter is unconstrained (may be a method parameter, no |
| F-287 | HIGH | DOC | SINGLE | compiler:ts | cheap |  | GK-DOC-001 | runar-compiler README states constant folding is disabled by default; `compile()`'s `disab |
| F-288 | HIGH | DOC | SINGLE | compiler:ts | cheap |  | CL-DOC-013 | The TypeScript format guide documents the exact semantics that were a fund-loss defect |
| F-289 | HIGH | GAP | SINGLE | compiler:ts | mid |  | CL-GAP-015 | ir-loader.test.ts validates a loader implemented inside the test file; 19 tests exercise z |
| F-290 | HIGH | GAP | SINGLE | compiler:ts | mid |  | CL-GAP-109 | 19 of the 100 opcodes the emitter can produce appear in ZERO checked-in golden, including  |
| F-291 | HIGH | GAP | SINGLE | compiler:ts | mid |  | CL-GAP-147 | Six state-serialisation shapes are guarded ONLY by `not.toThrow()`, with no byte-level gol |
| F-292 | MEDIUM | GAP | SINGLE | * | mid |  | CL-GAP-150 | Java compiler's committed Gradle wrapper jar is not actually Gradle 8.5, and CI bypasses t |
| F-293 | MEDIUM | GAP | SINGLE | * | mid |  | CL-GAP-137 | Source-map anchor oracle validates each mapping independently and certifies a 30x mapping- |
| F-294 | MEDIUM | GAP | SINGLE | * | mid |  | CL-GAP-107 | Zig example test root is a hand-maintained @import list with no completeness check |
| F-295 | MEDIUM | GAP | SINGLE | * | top |  | CL-GAP-090 | The golden-provenance CI gate only triggers on pull_request, so 87 of the last 100 first-p |
| F-296 | MEDIUM | GAP | SINGLE | * | mid |  | CL-GAP-088 | `sdk-envelope` has no "too-large" fixture; the DoS size bound is hard-coded separately per |
| F-297 | MEDIUM | GAP | SINGLE | * | top |  | CL-GAP-087 | conformance/sdk-codegen suite has runners for only 3 of 7 tiers, missing Rust |
| F-298 | MEDIUM | DOC | SINGLE | * | cheap |  | CL-DOC-019 | `CLAUDE.md` is stale on mock crypto, and the stale belief is why the branch-blind tests lo |
| F-299 | MEDIUM | GAP | SINGLE | * | mid |  | CL-GAP-086 | `sdk-bip143` covers ONLY SIGHASH_ALL |
| F-300 | MEDIUM | GAP | SINGLE | * | mid |  | CL-GAP-096 | The 7-tier parity fuzzer has never compiled a countdown or closed-bound loop |
| F-301 | MEDIUM | GAP | SINGLE | * | mid |  | CL-GAP-128 | The move surface is a copy-paste of sol, and its one content divergence drops four asserti |
| F-302 | MEDIUM | GAP | SINGLE | * | mid |  | CL-GAP-083 | - **CL-GAP-083 — `sha1`, `checkSigVerify`, `checkMultiSigVerify`, `byteLen`, `toByteString |
| F-303 | MEDIUM | GAP | SINGLE | compiler:go | mid |  | CX-GAP-001 | The advertised standalone EliminateDeadCode pass is not wired into any compiler entrypoint |
| F-304 | MEDIUM | GAP | SINGLE | compiler:go | mid |  | CX-GAP-002 | EC algebraic optimization (optimizeMethodEC) only examines each method's top-level binding |
| F-305 | MEDIUM | GAP | SINGLE | compiler:go | mid |  | CX-GAP-004 | The Go CLI exposes no flag to set Groth16WAVKey, so witness-assisted Groth16 mode is unrea |
| F-306 | MEDIUM | GAP | SINGLE | compiler:go | mid |  | CX-GAP-005 | EmitResult.RawScriptSpans (opaque asm/raw-script byte-range and arity metadata) is compute |
| F-307 | MEDIUM | GAP | SINGLE | compiler:go | mid |  | CL-GAP-007 | Go's TestCompile_BasicP2PKH and four siblings name the expected hex in a comment and never |
| F-308 | MEDIUM | GAP | SINGLE | compiler:go | mid |  | CL-GAP-118 | `compilers/go` cannot be built as a standalone Go module (missing go.sum entries / no requ |
| F-309 | MEDIUM | GAP | SINGLE | compiler:go | mid |  | CX-GAP-006 | `runar debug` (Go) ignores artifact source maps and cannot produce source-line-annotated t |
| F-310 | MEDIUM | DOC | SINGLE | compiler:go | cheap |  | CL-DOC-004 | Go README CLI docs incomplete; documented conformance command excludes the real golden tes |
| F-311 | MEDIUM | GAP | SINGLE | compiler:go | mid |  | CL-GAP-008 | TestBranchMergeK1AndDeadArm_ConstAndRuntimeConditionsAgree discards every result it compil |
| F-312 | MEDIUM | GAP | SINGLE | compiler:go | mid |  | CL-GAP-010 | readConformanceFormat still skips where its hardened twin was fixed to fail — the whole mu |
| F-313 | MEDIUM | GAP | SINGLE | compiler:go | mid |  | CL-GAP-011 | integration_test.go is build-tag gated; the only CLI-level `--ir` test never runs in CI's  |
| F-314 | MEDIUM | GAP | SINGLE | compiler:go | mid |  | CL-GAP-012 | loadGroth16WAConfig silently zero-fills IC slots for non-5-public-input VKs, emitting an o |
| F-315 | MEDIUM | GAP | SINGLE | compiler:go | mid |  | CL-GAP-120 | `--ir` golden coverage is pinned at 27 of 72 fixtures, and a missing golden counts as a pa |
| F-316 | MEDIUM | GAP | SINGLE | compiler:java | mid |  | CX-GAP-009, CX-GAP-012 | RawBytesOp (raw `asm` spans) carries no source-location field, so opaque asm bytes get no  |
| F-317 | MEDIUM | GAP | SINGLE | compiler:java | mid |  | CX-GAP-008 | Java: EC optimizer's nested-call detector finds EC calls inside `if`/`loop` bodies but `op |
| F-318 | MEDIUM | GAP | SINGLE | compiler:java | mid |  | CX-GAP-011 | Java: the advertised 12-rule EC optimizer has no rule-level tests; existing AnfOptimize te |
| F-319 | MEDIUM | GAP | SINGLE | compiler:java | mid |  | CL-GAP-139 | Java's ANF IR is order-dependent through the compile daemon: a process-global AtomicIntege |
| F-320 | MEDIUM | GAP | SINGLE | compiler:python | mid |  | CX-GAP-014, CX-GAP-018 | Standalone DCE (_eliminate_dead_code, Pass 4.75) exists but is never invoked by any produc |
| F-321 | MEDIUM | GAP | SINGLE | compiler:python | mid |  | CX-GAP-015 | EC call discovery and optimization scan only top-level method bindings; a program whose EC |
| F-322 | MEDIUM | GAP | SINGLE | compiler:python | mid |  | CL-GAP-117, CL-GAP-159 | Loop-iteration cap is enforced only on the IR entry path (ir/loader.py MAX_LOOP_COUNT=10_0 |
| F-323 | MEDIUM | GAP | SINGLE | compiler:python | mid |  | CL-GAP-160 | The Python golden harness has **three** ways to report green on a fixture it never checked |
| F-324 | MEDIUM | GAP | SINGLE | compiler:python | mid |  | CL-GAP-161 | `test_cli_debug.py`'s 4 tests are skipped in CI, and the skip-auditor is blind to the mech |
| F-325 | MEDIUM | GAP | SINGLE | compiler:python | mid |  | CX-GAP-016 | Code-separator tests do not exercise placeholder-slot resolution |
| F-326 | MEDIUM | GAP | SINGLE | compiler:ruby | mid |  | CX-GAP-020 | Ruby: the documented standalone dead-code-elimination safety pass (`_eliminate_dead_code`) |
| F-327 | MEDIUM | GAP | SINGLE | compiler:ruby | mid |  | CL-GAP-047 | Ruby codegen test gap F-RB-T-09: five of six SLH-DSA parameter sets have no Ruby codegen g |
| F-328 | MEDIUM | GAP | SINGLE | compiler:ruby | mid |  | CL-GAP-041 | `test_compiler.rb` pins a hard-coded 28-fixture list against a 72-fixture conformance corp |
| F-329 | MEDIUM | GAP | SINGLE | compiler:ruby | mid |  | CL-GAP-044 | Ruby checkMultiSig hex-pin test is an unaligned 2-char substring search over a two-opcode  |
| F-330 | MEDIUM | GAP | SINGLE | compiler:ruby | mid |  | CL-GAP-042 | Seven Ruby parser tests named *_does_not_crash contain ZERO assertions |
| F-331 | MEDIUM | GAP | SINGLE | compiler:ruby | mid |  | CL-GAP-046 | codeSeparatorIndex test asserts respond_to? on a three-way disjunction, never the value th |
| F-332 | MEDIUM | GAP | SINGLE | compiler:ruby | mid |  | CL-GAP-048 | Seven EC + seven NIST-EC builtins covered only by emitter-level goldens — a mis-wired stac |
| F-333 | MEDIUM | GAP | SINGLE | compiler:ruby | mid |  | CL-GAP-050 | deserialize_state claims a 14-type allowlist, tests 7, all compile-only; cannot distinguis |
| F-334 | MEDIUM | GAP | SINGLE | compiler:ruby | mid |  | CL-GAP-053 | The Ruby compiler ships no gemspec, Gemfile or lockfile — the only tier with an undeclared |
| F-335 | MEDIUM | GAP | SINGLE | compiler:ruby | mid |  | CL-GAP-054 | Ruby CLI test covers 4 of 10 flags; --source + --ir together silently resolves to --source |
| F-336 | MEDIUM | GAP | SINGLE | compiler:rust | mid |  | CL-DOC-008, CL-GAP-155 | The declared Rust conformance gate (`cargo test --test compiler_tests`) only exercises 27  |
| F-337 | MEDIUM | GAP | SINGLE | compiler:rust | mid |  | CL-GAP-156 | Source maps are degenerate (collapsed to a single (1,0) mapping) for 6 of 9 surfaces inclu |
| F-338 | MEDIUM | GAP | SINGLE | compiler:rust | mid |  | CL-GAP-158 | Missing op-count goldens for large Rust emitters, including the entirely ungated 453K-op e |
| F-339 | MEDIUM | GAP | SINGLE | compiler:rust | mid |  | CL-GAP-034, CL-GAP-157 | Rust driver's SLH-DSA op-count canary uses the flat ops.len() metric the same file documen |
| F-340 | MEDIUM | GAP | SINGLE | compiler:rust | mid |  | CL-GAP-032 | Rust driver: five weak parser negatives pass when the parser fails silently (contract-less |
| F-341 | MEDIUM | GAP | SINGLE | compiler:rust | mid |  | CX-GAP-021 | TypeScript source maps collapse every source statement to line 1, column 0 |
| F-342 | MEDIUM | GAP | SINGLE | compiler:ts | mid |  | CL-GAP-110 | Six of seven tiers ship a compile-from-IR entry point that TypeScript (the reference tier) |
| F-343 | MEDIUM | GAP | SINGLE | compiler:ts | mid |  | CX-GAP-023 | TS EC optimizer (anf-ec.ts): rewritten bindings and freshly generated helper-scalar bindin |
| F-344 | MEDIUM | GAP | SINGLE | compiler:ts | mid |  | CX-GAP-022 | TS EC optimizer (`optimizeMethodEC`) only walks a method's top-level binding list — it nev |
| F-345 | MEDIUM | GAP | SINGLE | compiler:ts | mid |  | CX-GAP-025 | The 'exhaustive' peephole sweep compares each documentation-table pattern directly against |
| F-346 | MEDIUM | GAP | SINGLE | compiler:ts | mid |  | CX-GAP-026 | The CHECKSIG+VERIFY peephole fusion rule is marked `skip` in the exhaustive sweep, and the |
| F-347 | MEDIUM | GAP | SINGLE | compiler:ts | mid |  | CX-GAP-027 | The CHECKMULTISIG+VERIFY peephole fusion rule is marked `skip` in the exhaustive sweep, an |
| F-348 | MEDIUM | GAP | SINGLE | compiler:ts | mid |  | CL-GAP-080 | `@sighash` directive has zero conformance coverage; independently confirmed dropped on mul |
| F-349 | MEDIUM | GAP | SINGLE | compiler:ts | mid |  | CL-GAP-019 | Seven example-contracts-compile-*.test.ts files silently generate zero test cases if disco |
| F-350 | MEDIUM | GAP | SINGLE | compiler:ts | mid |  | CL-GAP-021 | 05-stack-lower-state-types.test.ts asserts only "does not throw" for the five state types  |
| F-351 | MEDIUM | GAP | SINGLE | compiler:ts | mid |  | CL-GAP-026 | Six SHA-256 / BLAKE3 tests assert opcode presence in ASM only — no value, no execution, no |
| F-352 | MEDIUM | GAP | SINGLE | compiler:ts | mid |  | CL-GAP-148 | Four mutable-state shapes have exactly one cross-tier witness each |
| F-353 | MEDIUM | TODO | SINGLE | compiler:ts | mid |  | CL-TODO-001 | optimizer.test.ts pins a behaviour its own comment labels a POTENTIAL BUG and a cross-tier |
| F-354 | MEDIUM | GAP | SINGLE | compiler:ts | mid |  | CX-GAP-028 | Mutable-state type tests assert only that compilation does not throw |
| F-355 | MEDIUM | GAP | SINGLE | compiler:ts | mid |  | CX-GAP-029 | Multiple `check_preimage`/`OP_CODESEPARATOR` interactions lack coverage |
| F-356 | MEDIUM | DOC | SINGLE | compiler:ts | cheap |  | CX-DOC-003 | `compileCheck` documentation promises a second typecheck that never runs |
| F-357 | MEDIUM | GAP | SINGLE | compiler:zig | mid |  | CL-GAP-102 | Zig IR loader performs no referential-integrity check; six fields (result_type, sighashFla |
| F-358 | MEDIUM | GAP | SINGLE | sdk:go | mid |  | GK-GAP-007 | Go mock Bn254MultiPairing4/3 always return true, a false-accept oracle for native tests |
| F-359 | MEDIUM | GAP | SINGLE | sdk:ts | mid |  | CL-GAP-111 | TypeScript SDK's envelope implementation has no injectable clock, so it is the one tier th |
| F-360 | MEDIUM | DOC | SINGLE | sdk:ts | cheap |  | CL-DOC-018 | The docstring justifying `dryRun` default-OFF rests on a disagreement that cannot exist at |
| F-361 | LOW | GAP | SINGLE | compiler:go | mid |  | CL-GAP-058 | Go: push-data encode/decode silently misencode ByteString state fields >= 64 KiB (no OP_PU |
| F-362 | LOW | GAP | SINGLE | compiler:python | mid |  | CL-GAP-162 | Twelve test assertions check for a 2-hex-character opcode substring anywhere in the full s |
| F-363 | LOW | GAP | SINGLE | compiler:python | mid |  | CL-GAP-114 | Five `roll` emissions carry `depth = d + 1` while their paired push carries `d`, defeating |
| F-364 | LOW | DOC | SINGLE | compiler:ts | mid |  | CX-DOC-002 | rule-loader.ts header still claims a four-compiler architecture; repo now has seven tiers |
| F-365 | LOW | DOC | SINGLE | compiler:ts | cheap |  | CL-DOC-014 | `index.ts:440-441` documents a DCE behaviour that does not exist, and is the reason the re |
| F-366 | LOW | GAP | SINGLE | compiler:ts | mid |  | CL-GAP-003 | --disable-peephole / --disable-ec-optimizer exist in API, absent from CLI |
| F-367 | LOW | DOC | SINGLE | sdk:python | cheap |  | CL-DOC-016 | Python SDK: find_last_op_return actually returns the first OP_RETURN; last_pos is dead cod |
| F-368 | MEDIUM | GAP | SINGLE | compiler:ts | mid |  | GK-GAP-015 | Rabin script never range-checks `sig < n`, so `sig + k·n` (and `-sig mod n`) is a mempool- |
| F-369 | MEDIUM | GAP | SINGLE | sdk:ts | mid |  | CL-GAP-112 | `PreparedCall.opPushTxSig` is documented public surface that nothing consumes, and acting  |
| F-370 | LOW | TODO | SINGLE | * | mid |  | GK-TODO-001 | Standalone Script static analyzer and generative differential fuzzing are partial: ir-diff |
| F-371 | LOW | DOC | SINGLE | compiler:go | cheap |  | CL-DOC-003 | TestParseSource_DispatchesRustFormat documents a false premise and asserts nothing |
| F-372 | LOW | DOC | SINGLE | compiler:go | cheap |  | CL-DOC-005 | Stale "needs deeper work" stateful exclusions in the multi-format conformance tests |
| F-373 | LOW | GAP | SINGLE | compiler:go | mid |  | CL-GAP-009 | TestPushDataEncoding names PUSHDATA1/2 boundaries and tests none of them |
| F-374 | LOW | GAP | SINGLE | compiler:go | mid |  | CL-GAP-013 | TestEncodeScriptNumber carries a wantAsm column it never asserts |
| F-375 | LOW | GAP | SINGLE | compiler:go | mid |  | CL-GAP-014 | TestSp1Fri_AllPresetsCompile claims byte-identity between aliases and compares sizes |
| F-376 | LOW | GAP | SINGLE | compiler:ruby | mid |  | CL-GAP-055 | Ruby: eight parser negatives use contract.nil? // !errors.empty?, satisfied by a silent no |
| F-377 | LOW | GAP | SINGLE | compiler:ruby | mid |  | CL-GAP-043 | `assert true` in the accept-branch of the Rust non-contract parser test |
| F-378 | LOW | GAP | SINGLE | compiler:ruby | mid |  | CL-GAP-045 | test_checksig_terminal_assert_folds_to_verify asserts the opposite of its name |
| F-379 | LOW | GAP | SINGLE | compiler:ruby | mid |  | CL-GAP-051 | test_bigint_literal_preserved greps the inspect() of every binding for the 2-char string ' |
| F-380 | LOW | GAP | SINGLE | compiler:ruby | mid |  | CL-GAP-052 | Two addDataOutput compile-only tests left in place after the comment said they were replac |
| F-381 | LOW | DOC | SINGLE | compiler:rust | mid |  | CL-DOC-011 | Artifact build_timestamp is taken from datetime.now(timezone.utc) and unconditionally seri |
| F-382 | LOW | DOC | SINGLE | compiler:rust | cheap |  | CL-DOC-007 | `--disable-constant-folding` is a silent no-op on the `--ir` path and this is undocumented |
| F-383 | LOW | DOC | SINGLE | compiler:rust | cheap |  | CL-DOC-009 | ec_optimizer_tests.rs claims "all 12 EC rules"; rules 9 and 11 have no test |
| F-384 | LOW | DOC | SINGLE | compiler:rust | cheap |  | CL-DOC-010 | bsv-sdk pulled with an open version range `>=0.1, <0.3` in a published crate; no MSRV |
| F-385 | LOW | GAP | SINGLE | compiler:rust | mid |  | CL-GAP-037 | Two exact duplicate test pairs |
| F-386 | LOW | GAP | SINGLE | compiler:rust | mid |  | CL-GAP-039 | debug subcommand: --script/--artifact conflict resolved silently; five untested error path |
| F-387 | LOW | GAP | SINGLE | compiler:rust | mid |  | CL-GAP-065 | Rust: merkleRootPoseidon2KB is routed by lower_call but absent from the typechecker table  |
| F-388 | LOW | GAP | SINGLE | compiler:ts | mid |  | CL-GAP-004 | test-vectors.json covers 11 of 28 peephole rules; one rule name has no test coverage at al |
| F-389 | LOW | GAP | SINGLE | compiler:ts | mid |  | CL-GAP-025 | No TS test coverage for push-encoding.ts, parser-core.ts, codegen-emitter.ts, compiler-res |
| F-390 | LOW | GAP | SINGLE | compiler:ts | mid |  | CL-GAP-024 | Duplicate describe('error handling') in 01-parse-ruby.test.ts; four Ruby tests guarantee o |
| F-391 | LOW | GAP | SINGLE | compiler:ts | mid |  | CL-GAP-027 | expect.hasAssertions() vacuity guard exists in exactly 1 of 93 test files, despite a docum |
| F-392 | LOW | GAP | SINGLE | compiler:ts | mid |  | CX-GAP-030 | Opcode-form ROLL/PICK sequences are knowingly excluded from simplification |
| F-393 | LOW | DOC | SINGLE | compiler:zig | cheap |  | CL-DOC-015 | `readonly_inference.zig`'s doc comment justifies an unguarded property-assignment case by  |
| F-394 | LOW | GAP | SINGLE | compiler:zig | mid |  | CL-GAP-103 | `frontend/readonly_inference.zig` carries no `test` block and is not imported by the Zig t |
| F-395 | LOW | DOC | SINGLE | sdk:java | cheap |  | CL-DOC-017 | Three Java example-test javadocs assert facts contradicted by MockCrypto.java (claim a ver |

## Folded into cross-tier items

- F-635 (was F-427) → folded into cross-SDK item G6 (D2)
- F-636 (was F-083) → folded into cross-tier item G5
- F-637 (was F-001) → folded into cross-tier item G5
- F-638 (was F-428) → folded into cross-SDK item G6 (D2)
- F-639 (was F-429) → folded into cross-SDK item G6 (D2)
- F-640 (was F-430) → folded into cross-SDK item G6 (D2)
- F-641 (was F-431) → folded into cross-SDK item G6 (D2)
- F-642 (was F-432) → folded into cross-SDK item G6 (D2)
- F-643 (was F-433) → folded into cross-SDK item G6 (D2)
- F-644 (was F-065) → folded into cross-tier item G1
- F-645 (was F-108) → folded into cross-tier item G1
- F-646 (was F-441) → folded into cross-tier item G1
- F-647 (was F-139) → folded into cross-tier item G1
- F-648 (was F-442) → folded into cross-tier item G1
- F-649 (was F-113) → folded into cross-tier item G1
- F-650 (was F-094) → folded into cross-tier item G1
- F-651 (was F-434) → folded into cross-SDK item G6 (D2)
- F-652 (was F-066) → folded into cross-tier item G2
- F-653 (was F-109) → folded into cross-tier item G2
- F-654 (was F-125) → folded into cross-tier item G2
- F-655 (was F-140) → folded into cross-tier item G2
- F-656 (was F-086) → folded into cross-tier item G2
- F-657 (was F-114) → folded into cross-tier item G2
- F-658 (was F-095) → folded into cross-tier item G2
- F-659 (was F-067) → folded into cross-tier item G5
- F-660 (was F-435) → folded into cross-SDK item G6 (D2)
- F-661 (was F-436) → folded into cross-SDK item G6 (D2)
- F-662 (was F-243) → folded into cross-tier item G5
- F-663 (was F-068) → folded into cross-tier item G3
- F-664 (was F-110) → folded into cross-tier item G3
- F-665 (was F-126) → folded into cross-tier item G3
- F-666 (was F-141) → folded into cross-tier item G3
- F-667 (was F-087) → folded into cross-tier item G3
- F-668 (was F-115) → folded into cross-tier item G3
- F-669 (was F-096) → folded into cross-tier item G3
- F-670 (was F-199) → folded into cross-tier item G5
- F-671 (was F-240) → folded into cross-tier item G5
- F-672 (was F-278) → folded into cross-tier item G4
- F-673 (was F-287) → folded into cross-tier item G4
- F-674 (was F-296) → folded into cross-tier item G4
- F-675 (was F-297) → folded into cross-tier item G4
- F-676 (was F-292) → folded into cross-tier item G4
- F-677 (was F-281) → folded into cross-tier item G4
- F-678 (was F-102) → folded into cross-tier item G5

## Remediation outcome (2026-11-02)

Final state after the remediation run, generated from `COMBINED-findings.json` and `remediation-logs/state.json`. Per-item detail (tier history, review notes) is in `REMEDIATION-progress.md`; dispatcher and user decisions are in `remediation-logs/dispatcher-resolutions.md`.

Final battery `remediation-logs/checkpoint-final` @ `ecf4b332e`: GREEN 42/42 — vitest 32845 passed / 3 skipped, golden 99, multi-format fold-off 887 and fold-on 887 (0 vacuous), Lean 79 byte-exact, IR round-trip 99. N-384 (Lean-only, R197/R198) landed afterwards as `85d76f1bb`; its full `lake build`, pipelineGolden (79/99), TCB-drift and pipeline-conformance checks pass.

| Outcome | Items |
|---|---:|
| DEFERRED | 6 |
| DONE | 789 |
| GROUPED | 46 |
| REJECTED | 23 |
| SKIPPED | 31 |
| STALE | 314 |

`remediation-logs/state.json` records 814 completions: the 789 DONE items above, 23 follow-up items (`*-FU`, `CK*-FU*`, `PL*-FU*`) tracked only in the state file, and 2 items (F-169, N-426) recorded twice.

Deferred:

- F-096 — `_codePart` discovery does not recurse through private helpers that build outputs
- F-132 — PathAnalyzer returns zero paths on an unbalanced OP_IF/OP_ENDIF, silently disabling NO_SIG_CHECK and UNCONDITIONALLY_SUCCEEDS
- F-197 — `parser_go.py` uses the C ladder, not Go's
- N-034 — @embedAlways on a FixedArray property is dropped for its expanded literal slots in all 7 tiers (documented choice at 1b71ea9e; Rust comment 'synthetic array leaves are not @embedAlways targets')
- N-204 — RELEASE: compilers/go and packages/runar-go tags are stale and form a tag cycle (runar-go@v0.4.5 lacks bn254witness/sp1fri; compilers/go v1.0.0-rc.1 unpublished); downstream go get is broken
- N-394 — Audit Go/Python/Zig/Ruby/Java source maps against TS per opcode (sub-context loc inheritance, method-tail clears, FixedArray dispatch locs)

### Items logged during remediation (533, not in the tables above)

| ID | Outcome | Title |
|---|---|---|
| N-044 | DONE  | On-chain state reader decodes PUSHDATA1/PUSHDATA2 lengths with bare (signed) OP_BIN2NUM: a 128-byte mutable ByteString reads as length 0 and shifts every later field (stranger becomes `owner`); 129-255 B and >=32768 B lengths brick the UTXO — all 7 tiers |
| N-045 | DONE  | Fixed-width mutable state fields (Sha256, PubKey, Addr, Ripemd160, Point, P256Point, P384Point, …) are written into the continuation with no width check; with any later variable-length field the forward reader takes the declared width and a 65-byte `root` makes the next `owner` read the attacker's key — all 7 tiers |
| N-046 | DONE  | A block-scoped redeclaration (`if (c) { let x = … }`) is merged into the outer same-named local by if-branch reconciliation, so `let ok = checkSig(…); if (t) { let ok = true; } assert(ok)` accepts any signature — all 7 tiers |
| N-047 | STALE | Locals of an inlined (output-emitting) private helper are emitted into the caller's binding namespace unrenamed, so a helper `const valid = …` replaces the caller's `const valid = checkSig(…)` for the caller's later `assert(valid)` — all 7 tiers |
| N-048 | DONE  | Fixed-array expansion hoists a computed runtime index (`__idx_N`) into a statement-level prelude ahead of earlier side effects in the same statement (`assert(++this.cursor > 0n && this.enabled[this.cursor % 2n] === 1n)` reads the pre-increment slot) — all 7 tiers |
| N-050 | DONE  | `static` methods are silently compiled as public spending entry points (TS parseMethod never checks isStatic): `public static requirePositive(n)` becomes an unsigned spend path — .ts surface fail-open in TS/Go/Rust, .java `@Public static` in TS/Rust/Zig/Java/Python/Ruby, .py `@staticmethod` in TS/Rust/Ruby |
| N-037 | DONE  | runar-verification PipelineGolden exact gates (expectedFixtureTotal 82, expectedByteExact 64 + bucket lists) drift after N-016's new fixture and the F-024/N-027 golden moves — Lean CI gate fails |
| N-016 | DONE  | A local with the same name as a property makes a later `this.<prop>` read resolve to the local (always-true guard) — all 7 tiers |
| N-027 | DONE  | TicTacToe.join and Auction.bid never bind the claimed bet/bid to the value actually paid — after F-024 only the `>= input` floor applies |
| N-002 | DONE  | Index assignment to a non-FixedArray target (ByteString property, local, parameter) is silently lowered as a read and the write dropped — TS, Go, Rust, Zig (Ruby, Java unchecked); Python fixed by F-013 |
| N-007 | DONE  | A method parameter that shadows a mutable property reads the stale on-chain state inside an if-arm (branch contexts drop renamedParams) — TS, Go, Rust, Zig, Ruby; Python fixed by F-015, Java already correct |
| N-011 | DONE  | Zig, Ruby and Java .runar.ts parsers compile the FIRST class in the file as the contract (decoy-class fail-open), accept a lone non-extending class, and silently take the first of several valid classes |
| N-005 | DONE  | An assert() followed by a terminal asm() in an UnsafeSmartContract is never enforced: all 7 tiers emit <2a> OP_NUMEQUAL OP_1 OP_NIP (012a9c5177), so the method is spendable with any witness |
| N-006 | DONE  | Output intrinsics inside a loop body escape the continuation hash via an array literal (`const xs = [this.addRawOutput(...)]` defeats R-127) — TS reference confirmed, other tiers likely; Go fixed by F-005 |
| N-008 | DONE  | Zig tier compiles a non-adjacent .runar.zig while-loop that every other tier refuses, and ignores the declared start value (silent miscompile) |
| N-022 | STALE | A user local named like a compiler temp (`t<N>`) collides with the generated temp binding in ANF |
| N-023 | DONE  | Java surface: a bare field assignment `count = count + 1` inside a method lowers to a local rebind — no update_prop, no state continuation |
| N-025 | DONE  | GorillaPool providers call endpoints that do not exist (404 indistinguishable from a nonsense route) and map the 404 to empty/null/"0" — UTXO, balance, inscription and raw-tx queries silently report nothing in all 7 SDKs |
| N-029 | DONE  | Constant folder folds clamp(v, lo, hi) as `v<lo?lo:(v>hi?hi:v)` while the emitted script computes min(max(v,lo),hi): fold-ON and fold-OFF disagree when lo > hi (clamp(5,10,0): fold 10, script 0) |
| N-030 | DONE  | Native contract runtimes diverge from on-chain math in Python, Ruby, TS runar-lang, Go, Rust, Java and the TS SDK ANF interpreter (percentOf/mulDiv/divmod floor vs truncate, safediv/safemod by 0 return 0 instead of abort, pow exponent bound, clamp lo>hi, log2(<=0)) |
| N-038 | DONE  | A well-formed stateful @sighash SINGLE\|FORKID method with an explicit addOutput fails Spend whenever the TS SDK call adds a change output ('top stack element must be truthy') |
| N-041 | DONE  | WhatsOnChain: getContractUtxo still returns script '' in all tiers; getTransaction's `raw` is always empty (GET /tx/hash has no hex field) and satoshis come from float value*1e8; ExternalSigner and Java OpPushTx.preimage do not guard an empty subscript |
| N-049 | DONE  | Output intrinsics inside a ternary arm (`c ? this.addRawOutput(…) : this.addRawOutput(…)`) are lowered but never registered with the parent's output refs, so the method's hashOutputs commitment omits them (payout can be dropped; the honest spend is rejected) — all 7 tiers |
| N-052 | DONE  | Go .runar.ts parseExpression default case returns nil; nested nil sub-expressions become 0 or vanish (comma expr, arrow fn, extra assert arg) — Go accepts what TS refuses |
| N-004 | DONE  | Ruby-surface parser silently accepts stray tokens (e.g. an indented =begin lexed as = then begin, trailing tokens after the class end) with zero errors, so an indented =begin/=end backdoor still compiles — widened by R11 to all 7 tiers (TS reference also silently skips unknown class-body tokens, e.g. `42 + ?`, stray `= end` closes the class early) |
| N-001 | DONE  | Zig alone implements peephole reassociation rules 29/30 (PUSH a OP_ADD PUSH b OP_SUB → PUSH(a-b) OP_ADD): `x + 5n - 3n` compiles to 5293009c in Zig vs 55935394009c in the other six tiers, both fold modes |
| N-009 | DONE `8811ead33` | A user variable literally named `__while_no_init` collides with the while-merge placeholder in all 7 tiers and unrolls from start 0 |
| N-015 | STALE | Python tier crashes ('str' object has no attribute 'format_message') on a .runar.go contract with an unknown base |
| N-018 | DONE `992f57c36` | Go-DSL `init`/`main` free functions: TS keeps them as private methods, the other tiers skip them |
| N-026 | DONE `e0e605094befe0695b3a2bd42040caaae9657a41` | Non-constant for-loop bound diagnostics differ from the TS reference in Go, Rust, Python, Ruby and Java (all refuse; wording/identifier-vs-runtime sentence differs) |
| N-039 | DONE `3d271c136` | `@sighashSINGLE\|FORKID` (no space before an uppercase flag) is read as prose and silently defaults to ALL\|FORKID in all 7 tiers |
| N-043 | DONE `61e868b55dadf038148b82bfba5a4ec2e120590f` | get_utxos empty-locking-script policy differs across SDKs (TS drops, Ruby/Go/Python keep; Ruby returns script ''), and Zig maps every address-decode failure to error.OutOfMemory |
| N-055 | DONE `431e8598b0eefebcef9ba9cdb9bd497564d5e482` | Hand-written --ir where a public method delegates add_output/add_raw_output/add_data_output to a private method_call fails with an internal "_codePart not found on stack" in all 7 tiers |
| N-057 | DONE  | Zig: binOpFromCompoundAssign ends in `else => .add` in all 9 surface parsers (unreachable today: guarded by isCompoundAssignOp) |
| N-058 | DONE  | integration/ts/helpers type errors (pre-existing): compile.ts reads CompileResult.errors (TS2339 x2), crypto.ts Buffer<ArrayBufferLike> vs Buffer<ArrayBuffer> (TS2322) |
| N-042 | DONE `c94574c01` | TokenWallet's assumed ABI (state supply/holder, transfer(sig, Addr), merge(sig, otherSupply, otherHolder)) matches no shipped contract: examples/ts/token-ft has a different ABI and runar-lang's FungibleToken is stateless |
| N-012 | DONE `56f6157ff` | Validator expression walkers skip for-loop init/update (and Zig also the condition) in all 7 tiers — unreachable today, defense in depth |
| N-003 | DONE `4fc0cb56f` | The conformance fuzzer's `--anf --fold-on` mode is a no-op: every tier's --ir path forces constant folding off, so the 'fold-on' gate is a byte-for-byte duplicate of fold-off, and its help text claims otherwise |
| N-010 | DONE `b1f24a861` | Rust .runar.go parser's parse_block recovery silently skips tokens it cannot parse, so malformed Go source the reference refuses compiles with exit 0 |
| N-013 | DONE `47891714b` | TS SDK deploy with a constructor arg for a DCE-eliminated readonly property leaves the arg in executable position (spend fails clean-stack) |
| N-014 | DONE `942664ec0` | Unknown base class after `is` in .runar.sol: TS and Rust fold it to SmartContract, Go/Python/Zig/Ruby/Java reject at parse ('unknown parent class') — accept/reject split on read-only contracts |
| N-017 | DONE `3f66a23dc` | Python-surface local named like a builtin (`safe_div`): TS/Rust map it to `safeDiv` and refuse (builtin clash), Go/Zig map it to `safediv` and compile — accept/reject split |
| N-019 | DONE `e90ce8a01` | Terminated "..." string literals in .runar.sol/.runar.move: TS refuses ('Unexpected character'), Go/Rust/Python/Zig/Java accept, Ruby .move skips the quote silently |
| N-024 | DONE `5179faa38` | Ruby tier: lifted conditional update (`let x = n; if (c) { x = x + 1n; this.count = this.count + x } else {...}`) fails to compile ('t15 referenced by t45 is not on the stack') |
| N-031 | DONE `be1823034` | examples/zig/tic-tac-toe v1 uses runar.hexToBytes(...) property initializers: TS and Zig accept, Go/Rust/Python/Ruby/Java refuse ('initializer must be a literal value') |
| N-032 | DONE `11e515cdd` | .runar.py contract whose only properties have initializers and no __init__: TS/Python/Java refuse ('constructor must call super()'), Go/Rust/Zig/Ruby accept |
| N-033 | DONE `7ff189e6b` | Remaining silent absorbing paths: .py class-body loop skips unknown tokens / stray identifier lines (TS + tiers); .zig field, param and struct-init lists accept a missing comma |
| N-036 | DONE `92b1076f3` | Mixed nested FixedArray write `this.grid[1n][i] = v` (literal outer, runtime inner): TS/Go/Rust/Ruby/Java refuse with an internal stack-lowering message, Python and Zig accept |
| N-040 | DONE `9ae3a5475` | ARC broadcast has no request timeout in TS/Go/Rust (a hung ARC blocks forever); injected-broadcaster paths (TS, Rust) return the broadcaster's txid unchecked; Zig WalletProvider broadcasts via createAction with the raw hex as the description |
| F-396 | SKIPPED | Ruby: systemic <unknown>-type inference gaps make 8 subtype? call sites (including assert()'s boolean check and the universal builtin argument-subtype loop) vacuous |
| F-397 | SKIPPED | Seven of the ten compiler-supported state-field types (boolean, Addr, Ripemd160, Sha256, Point, P256Point, P384Point, plus RabinSig/RabinPubKey) have zero conformance/test coverage anywhere in the repo, which is why the boolean and width-table SDK bugs went undetected |
| F-398 | SKIPPED | Java example test suite: 70 of 151 tests (46.4%) never falsify contract logic |
| F-399 | SKIPPED | Zig example test suite: 92 of 204 tests (45.1%) never falsify contract logic |
| F-400 | SKIPPED | sdk-output conformance suite exercises only 3 of 12 compiler-supported state field types across a 98-fixture denominator |
| F-401 | SKIPPED | sdk-codegen's one mandatory requirement is met by only 1 of 3 runners, 4 of 7 tiers have none, and RUNAR-SDK-PARITY.md:33 documents the opposite of the actual runners/ layout |
| F-402 | SKIPPED | 100% of Bitcoin Script bytes ever executed by any conformance engine are TypeScript-tier output; the other six tiers are validated only by byte-equality with a TS-produced golden, never independently executed |
| F-403 | SKIPPED | The flagship end2end PriceBet webapp's settle path is provably unspendable and never exercised on-chain |
| F-404 | SKIPPED | Eleven enumerated TS test sites assert strictly less than the test name or comment claims |
| F-405 | SKIPPED | `placeholder` and `push_codesep_index` peephole ops are safe only by accident — no explicit barrier guard, unlike `raw_bytes` |
| F-406 | SKIPPED | Altstack round-trip peephole optimization is deliberately disabled pending full stack-depth simulation |
| F-407 | SKIPPED | The large majority of integration negative tests pass on any error (including the node never being reached) and none assert a specific consensus-rejection reason |
| F-408 | SKIPPED | Zig ANF interpreter: 81 of 129 builtins unimplemented, evalCall falls through to anf_none (fails OPEN) |
| F-409 | SKIPPED | CRITICAL (v1 claim) |
| F-410 | SKIPPED | 3.0% of 497 negative tests assert *why* the failure happened |
| F-411 | SKIPPED | The analyzer conformance goldens pin stack depths the spec makes wrong, and a corrected opcode table would FAIL the suite |
| F-412 | SKIPPED | 18 of 22 settle tests (81.8%) cannot fail if the winner-selection branch is inverted |
| F-413 | SKIPPED | Rust IR loader does no referential-integrity, duplicate-name, cycle, loop-count-cap, or initialValue-type validation |
| F-414 | SKIPPED | No generator in the partition can emit an EC expression, so the DCE defect class is unreachable by construction |
| F-415 | SKIPPED | ANF parity goldens self-bootstrap (test writes then asserts against its own output) |
| F-416 | SKIPPED | 37 not.toThrow() sites plus ~30 compile-only tests assert nothing about emitted bytes or execution |
| F-417 | SKIPPED | 01-parse-zig.test.ts covers only 5 narrow regressions; 12 tests vs 33-82 for its six peers, no structural skeleton |
| F-418 | SKIPPED | Six Rust tests accept Ok OR Err on the substantive question |
| F-419 | SKIPPED | Enumerated malformed-IR classes with no Rust test (referential integrity, raw_script hex, constructor_args value shape, …) |
| F-420 | SKIPPED | No op-count golden for the entire SHA-256 module plus p384 on_curve / encode_compressed / verifyEcdsa |
| F-421 | SKIPPED | Rust: MAX_STACK_DEPTH is checked against a stack model that never sees the depth consumed inside a crypto block; alt-stack unmodelled |
| N-059 | DONE  | --ir loaders in TS, Rust, Python, Zig, Ruby and Java accept any check_preimage sighashFlag and truncate it to a byte (Go fixed in F-068); shared IR schema allows 0..255 |
| N-060 | DONE  | Stack-lowering internal slot names (_codePart, __param_<name>, __merge$<i>, __shadowed_*) are not checked against --ir binding/param names in any tier |
| N-061 | DONE  | examples/end2end-example/tsconfig.json paths point to ../packages (resolves to examples/packages); tsc -p fails for every file there |
| N-062 | DONE `3318f5d9a` | Rust .runar.ts parser refuses `export default class X extends SmartContract` (TS and the other 5 tiers accept it, a80087); Rust also scans non-exported classes before exported ones |
| N-063 | DONE `4906335a7` | Recursive private methods in --ir crash the TS, Rust, Zig, Ruby and Java compilers (stack overflow / segfault / uncaught error); Python fails closed only via RecursionError (Go fixed by F-071) |
| N-064 | DONE  | Constant folding keeps a stale constant after a name is rebound to a non-constant, in TS, Go, Rust, Python, Zig and Ruby: source-reachable miscompile in the DEFAULT fold-ON mode (unsatisfiable guard folds to OP_TRUE) |
| N-065 | DONE  | User identifiers can collide with compiler-minted temp names (t<N>) in every tier; accepted silently |
| N-068 | DONE `c9e4b51a0` | Zig constant_fold.zig mergeEnv is dead code implementing the unsound add-only branch merge |
| N-069 | DONE  | Zig and Ruby --ir emit anyone-can-spend scripts for a public method with body omitted (Zig '51', Ruby empty); Zig panics and Python/Ruby raise raw errors on wrongly-typed required fields |
| N-070 | DONE `e175aafc5` | requireOutputP2PKH inside a private helper fails to compile in every tier (the _serialisedOutputs witness is injected only for direct calls): fail-closed, legitimate terminal methods refused |
| N-071 | DONE  | --ir public method with `body: []` or no terminal assert emits an anyone-can-spend script in TS, Rust, Java, Ruby ("") and Zig ("51"); only Go (F-004) and Python (F-014) refuse |
| N-072 | DONE `f079e6474` | Stack lowering of a non-uniform if (then arm asserts, else arm does not) emitted a then-arm sequence 76 77 75 00 that leaves 0 when checkSig succeeds: possible branch-arm stack-model miscompile, reachable shapes unknown |
| N-073 | DONE `bd9ba4d99` | SDK constructor-arg encoders accept wrong-width fixed-width values (N-045 left this out: fromUtxo/fromTxId build contracts with placeholder 0 constructor args in TS/Go/Python/Ruby) |
| N-074 | DONE  | conformance/codepart_authenticity_test.go honest-spend controls fail since F-024 (spend 9000 of a 10000-sat input, rejected by value conservation), so CI's `go test .` (ci.yml:1502) is red and the file's hijack rejections are partly vacuous |
| N-075 | DONE `a995467a6` | SDK multi-output continuation path omits the 1sat inscription envelope (TS, Python, Ruby) |
| N-076 | DONE `77c4354b1` | TokenWallet get_utxos prefix match is wrong for any artifact with constructor/codesep/code-part-length slots |
| N-077 | DONE `1d548e59d` | Go .runar.py: on a class-less file the tokenizer's 'unterminated string literal' is dropped (only 'expected class keyword' reported; all other tiers report it); F-011 test lacks the backslash-at-EOF shape |
| N-078 | DONE `c6ffe5110` | Diagnostic columns: make every tier print 0-based columns (R88a); fix the 1-based tokenizer outliers and Rust 1-based AST columns |
| N-080 | DONE  | bump-version --check still does not read the 4 Ruby Gemfile.lock files (RubyGems spells 1.0.0.pre.rc.1 vs 1.0.0-rc.1) or the hard-coded version expectations in assembler.test.ts, compiler_test.go, integration_test.go, compiler_tests.rs, test_compiler.py |
| N-081 | DONE `63174fff8` | TS SDK RunarContract.getLockingScript does not bounds-check constructorSlots paramIndex against constructorArgs: splices the literal 'undefined' into the hex instead of throwing |
| N-082 | DONE `d2094e6f6` | Off-chain BN254 G1 add mocks (runar-go Bn254G1AddP and peers) probably return the true sum on the omega-partner pair where the compiled script now aborts (F-091): mock/script divergence |
| N-083 | DONE  | go-only-executing-coverage still lists bn254G1Add as REMAINING although F-091 executes it on Spend: its EXECUTING detector only scans *execution_test.go and r141_*.go |
| N-084 | DONE `d4c3b8b8d` | SDK num2bin state encode path fails open: Go toInt64 returns 0 for a non-decimal string or unknown type, Zig encodes a .bytes value as 0, Python encodes None as 0 (now reachable for Rabin fields after F-035) |
| N-085 | DONE `2fdec642b` | TS SDK under-pays the 100 sat/KB fee floor on a zero-mutable-field StatefulSmartContract call (57 of 99 sats), even with a --source artifact |
| N-087 | DONE  | --ir accepts a SmartContract whose property is declared readonly:false: the property gets no constructor slot and is never baked, so the guard compares against an attacker-supplied value - ANYONE-CAN-SPEND in all 7 tiers (also: --ir loaders don't check parentClass/body consistency; TS/Ruby/Zig/Java don't refuse readonly writes) |
| N-088 | DONE  | conformance runner --update-golden exits 0 when a fixture fails or is refused (prints 'Failed: <dir>' and continues) |
| N-089 | STALE | --ir merkleRootPoseidon2KB: Ruby crashes (NoMethodError make_stack_op in Poseidon2Merkle) and still carries the 7x nip limb drop; Zig refuses with a bare InvalidBuiltin; Python's depth gate says 64 vs Go's 32 |
| N-090 | DONE  | Go, Rust, Ruby and Java Zig-surface parsers do not lower runar.hexToBytes(...): the checked-in examples/zig/tic-tac-toe/TicTacToe.runar.zig fails to compile in 4 of 7 tiers; no conformance fixture covers it |
| N-091 | DONE  | sdk-output runner matches refusal reasons against the Rust driver's whole stderr, so a first-run cargo build ('Compiling ...', warnings) makes expected-refusal cases FAIL |
| N-092 | DONE `3cadb8f2e` | runar-verification/README.md says 'Conformance fixtures discovered 82/82' while goldenLoad finds 85 (86 after F-098): the CI step 'Assert README discovered-count matches goldenLoad' fails |
| N-095 | DONE `da5c48a35` | Audit Go, Python, Ruby, Zig and Java IR/direct-program compile entry points for silently ignored constructorArgs (Rust fixed in F-103) |
| N-096 | DONE  | Hostile/deep syntheticArrayChain via --ir: Go PANICS (regroupSyntheticRuns iteration cap, exit 2); tiers disagree otherwise (Rust/Ruby refuse, Python/Java publish `deep` as a scalar ctor param, Zig drops it from the ABI) |
| N-097 | DONE `1d3991c9d` | DCE gate diverges across tiers: Go runs DCE only on EC-rewritten methods, the other 6 on every method once any rewrite fires -> a public method with a dead pure binding in a contract with an EC rewrite elsewhere could emit different bytes in Go |
| N-099 | DONE  | Java stateless explicit checkPreimage(SigHashPreimage) in ContractSimulator.call is still stubbed true (CovenantVault, R1K1Wallet reach it with a 32-byte fake preimage); the stateless simulator has no transaction model |
| N-100 | STALE | Go (slh_dsa.go SLHVerify) and Ruby (slh_dsa.rb verify) SDK SLH-DSA verifiers only lower-bound the signature length; TS (BUG-011), Python (F-133) and the on-chain verifier require an exact length -> a valid signature with trailing bytes is accepted off-chain but rejected on chain |
| N-101 | DONE  | --ir trust boundary: the F-107 anyone-can-spend IR relabelled parentClass StatefulSmartContract (or carrying a dead stateful-only node) still compiles to 76767b8777 in all 7 tiers and the attacker spend is ACCEPTED; no syntactic rule can prove an IR's continuation is enforced |
| N-102 | DONE `00d7d1621b6b9405a3093af3d97598c619c17601` | SDK ANF interpreters return 0 for the binary / and % operators on a zero divisor (Python/Ruby confirmed, others likely; Go BigintBigDiv/BigintBigMod too, pinned by bigintbig_ops_test.go:111) while the script's OP_DIV/OP_MOD abort; native // in .runar.py floors |
| N-103 | DONE `a0fa0adee` | log2: the compiled script caps at 64 (log2(2^70) = 64) and returns 0 for n <= 0, while docs/language-reference.md claims exact floor(log2(n)), spec/grammar.md says approximate, every runtime returns the exact value, and the TS/Java runtimes throw for n <= 0 |
| N-104 | DONE  | EC optimizer rewrites R1-R4 (ecAdd(q,O)->q, ecAdd(O,q)->q, ecMul(q,1)->q, ecMul(q,0)->O) drop the operand validation the unoptimized builtin performs (width, coordinate canonicity, on-curve-or-O): a malformed/off-curve q is accepted optimized but aborts unoptimized; plus docs/language-reference.md:748 still calls O a sentinel, contradicting R-053 |
| N-105 | DONE `5af387eb1` | Zig CLI reads --ir/compile-ir input with a 10 MiB limit (main.zig ~270) so json.zig's documented 16 MiB MAX_IR_BYTES guard is dead; IR of 10-16 MiB fails with a read error in Zig but is accepted by TS (fail-closed cross-tier inconsistency) |
| N-108 | DONE  | Python LocalSigner's default bsv-sdk backend (_sign_with_bsv) ignores sighash_type: signs via P2PKH().unlock(priv), always ALL\|FORKID with 0x41 suffix, so every non-default sighash method signs the wrong digest whenever bsv-sdk is installed |
| N-109 | DONE `21d0bcbca` | Affine checker is intra-method in all 7 tiers: consuming a Sig/SigHashPreimage through a private helper (this.h(sig); this.h(sig); or this.h(sig) inside a repeating loop) is accepted although the inlined script consumes it twice |
| N-110 | DONE `dd8af38b8` | affineAdd doubling branch with y=0 computes lambda=0 instead of returning O: ecAdd(q,q) for an off-curve q=(x,0) returns (p-2x mod p, 0); EC optimizer R8/R8r (ecAdd(x,ecNegate(x))->O) therefore disagrees with the unoptimized script on such points; contradicts the R-157 comment in ec-codegen.ts |
| N-111 | DONE  | TestContract / ANF source interpreters apply no R-157 / R-117 EC operand gates: ecMul/ecAdd accept off-curve or non-canonical points the compiled script rejects (checkMulIdentity with off-curve pt passes off-chain) |
| N-112 | DONE  | EC optimizer constant-scalar fusion helper bindings named differently per tier (TS <b>_k, Go <b>_sum with _r10_N suffix, Python/Ruby/Zig/Java __ec_opt_N): ANF-IR divergence, hex identical, no fixture exercises it |
| N-114 | STALE | golden-provenance gate on pull_request diffs from github.event.pull_request.base.sha (can be stale), sweeping in goldens other PRs merged meanwhile -> false failures; the wire-format gate documents the same hazard |
| N-116 | DONE `1a744ff71` | Possible TS fail-open (unverified): .runar.zig `var i=3; while (i<5) : (i) {...}` - bare-identifier continue sets fold target i with a no-op update; TS may compile an unrolled loop for a source loop that never terminates |
| N-117 | STALE | runar-zig CLI: `--source X --disable-constant-folding --hex` prints nothing (exit 0) while `--hex --disable-constant-folding` prints hex - flag-order-dependent silent output |
| N-118 | DONE  | webapp-blackjack strands contract UTXOs without a phase change: handleDeal can fail after deploying some players' contracts leaving phase 'ready'; handleDealer sets 'settlement' even when a settle broadcast failed; handleNewRound wipes game.Contracts without checking SettleTxid |
| N-119 | DONE `003feef35` | Zig refuses asm `push(-36893488147419103231)` (65-bit magnitude) with 'push() argument is not a valid integer literal' while TS and the five other tiers accept it |
| N-120 | DONE `a97b2c044` | `FixedArray<bigint, 0x2>` in .runar.ts: TS and Go refuse ('FixedArray size must be a positive integer literal, got 0x2'), Rust/Python/Zig/Ruby/Java accept as size 2 - refusal-vs-accept frontend divergence |
| N-121 | DONE `8fbe2116e` | Optional chaining `this?.t` in .runar.ts: TS and Go accept it (compiled as this.t), Rust/Python/Zig/Ruby/Java refuse - frontend parity gap; policy call whether TS accepting it is the bug |
| N-123 | DONE `5ebff9c33` | Zig peephole vs TS: rule 1 treats placeholder / push_codesep_index as pushes (TS does not remove `placeholder; drop`); rules 17/20/21 fire on any op_roll/op_pick (TS only on typed Roll/Pick with matching depth); stale 'Applies 30 rewrite rules' header |
| N-124 | DONE `bc8dbd6ca` | Go, Rust, Python, Zig and Java conformance golden harnesses share F-151's defects: missing-source collected but never asserted, missing golden silently passes (Java skips a missing hex golden and checks no IR golden) |
| N-125 | DONE  | examples/python/schnorr-zkp/test_schnorr_zkp.py::test_compile fails when the file runs alone (RuntimeError: runar_compiler package not available) - depends on another module putting compilers/python on sys.path |
| N-126 | DONE `b506c7ac1` | examples.test.ts findExampleContracts (~45-47) has an empty catch that silently drops a subdirectory whose read fails mid-scan |
| N-127 | DONE `0babac6dd` | Per-tier multi-format golden tests miss formats: Go compiler_multiformat_test.go lacks .runar.java; Rust multiformat_tests.rs and Python test_multiformat.py lack .runar.zig and .runar.java |
| N-129 | DONE  | Zig .runar.java: a method that reassigns a parameter (`count = count.plus(ONE); this.count = count;`) compiles to 1402 hex vs 1404 in the other six tiers (pre-existing byte divergence) |
| N-130 | DONE  | Java tier refuses every compound assignment on .runar.java (`this.x += ...` -> 'unsupported expression kind PLUS_ASSIGNMENT') while the other six tiers accept it - frontend parity gap |
| N-132 | DONE  | .runar.ts for-loop with an EMPTY update `for (let i = 0n; i < 3n; )`: TS and Rust refuse; Go, Python, Zig, Ruby and Java accept (5-tier fail-open, loop never advances in source); and .runar.sol empty update accepted by Zig alone (parse_sol.zig never sets header_requires_update) |
| N-133 | DONE  | Go .runar.ts for-update `i++, this.count++` (comma): Go accepts and drops the this.count++ state write (938 hex, same as plain i++); also Go accepts `i += 1n` which TS refuses; Rust alone accepts .runar.sol `i += 1` |
| N-134 | DONE  | .runar.java compound operators <<= >>= &= \|= ^= are refused by the Go, Rust, Python, Zig and Ruby parsers (e.g. 'unsupported expression token Eq', 'unexpected token =') while TS and Java (N-130) accept them - frontend parity gap; also Java/Go ANF sourceLoc columns are 0-based vs TS 1-based |
| N-135 | DONE `163fcba01` | .runar.ts for-loop with an EMPTY condition `for (let i = 0n; ; i++)`: TS refuses ('For loop must have a condition'); Go, Python, Ruby and Java substitute `false` (Zig skipSemicolons suspect) - probe whether their validators refuse; possible fail-open |
| N-136 | DONE  | Source-size cap bypass via exported per-format parsers in Rust (8 pub fn parse_* hardcode source_size_err: None), Python (9 parse_* skip the guard; only parse_source checks), Zig (even compiler_api parseSource skips it - only runPipeline Pass 0 guards), Ruby (9 parse_* skip), Java (9 Parser.parse statics skip; only ParserDispatch guards) |
| N-137 | DONE  | Java tier .runar.sol: bare `count++` / `count--` / `++count` / `--count` (and in if/for bodies) in a StatefulSmartContract compiles WITHOUT the state write (silent miscompile; Java hex == Python's pre-F-201 wrong hex) |
| N-138 | DONE `e3ac5556e` | Constant folding leaves the original operand push behind in all 7 tiers: fold-ON `a > -1n` compiles to 51 4f 7b 7c a0 77 (push 1, push folded -1, then ROT/SWAP/NIP away the dead 1) - correct but wasteful |
| N-139 | DONE  | Zero-mutable-field StatefulSmartContract artifact flags diverge: TS gates artifact.anf on stateFields.length (assembler.ts ~896) while isTerminal follows parentClass; Go (compiler.go isStateful := len(stateFields)>0 gates IsTerminal AND ANF), Ruby (same, both), Rust (isTerminal gated on state_fields; anf always present), Zig (no isTerminal key at all - possibly never set even for ordinary stateful contracts) |
| N-140 | DONE  | docs/formats/go.md does not document operator precedence or the N-056 refusal of precedence-ambiguous unparenthesised expressions |
| N-141 | DONE `188e9c585` | .runar.sol for-init loop variable shadowing differs: TS resolvePropertyAccess adds the for-init variable to the OUTER paramNames set (keeps shadowing the property after the loop); Java uses a copied forParams set - `for (bigint count = ...;...){}` then bare `count` after the loop resolves differently; probe all tiers and decide whether TS's leak is itself a bug |
| N-142 | DONE  | Go (parser_sol.go:1041), Zig (parse_sol.zig:1174) and Java (SolParser.java:809) .runar.sol strip the leading underscore from METHOD params (TS strips only constructor params): `check(bigint _x){require(_x == target);}` fails 'Undefined variable'; `inc(bigint _count){count++;}` - Java silently miscompiles (state write skipped, eebf35e...), Zig emits a third wrong script, Go fails closed |
| N-143 | DONE  | Ruby generated typed wrappers: codegen.rb:341 to_call_options emits `satoshis.positive? ? satoshis : nil` and contract.rb:1648 `opts.satoshis.positive?` is unguarded -> every stateful call with options but no satoshis raises NoMethodError (Ruby twin of F-239) |
| N-144 | DONE  | Java generated typed wrapper's {Contract}StatefulCallOptions.satoshis is never read on stateful calls (TypedContractGenerator emits only newState; RunarContract.callInternal ignores options.satoshis) - the satoshis override is silently a no-op |
| N-145 | DONE  | Java SDK prepareCall / finalizeCall non-terminal path never runs the ANF interpreter and ignores both CallOptions.satoshis and explicit addOutput satoshis (G1) - always uses currentUtxo.satoshis, diverging from callWithOptions and TS prepareCall |
| N-146 | DONE  | spec/script-analyzer-format.md §6.1 justifies silently truncating malformed pushes as 'observable through STACK_UNDERFLOW findings downstream', which §8.2's own guard makes impossible - correct the justification (or specify a dedicated finding) |
| N-147 | DONE  | Zig artifact emits stateFields: [] and codeSeparatorIndex: 0 for stateless contracts where TS omits both keys (artifact shape parity) |
| N-148 | DONE  | Go GenerateGo codegen is broken for every artifact: renderSection expands innermost sections first against the root context, wiping {{#isTerminal}} / {{#isStatefulMethod}} / {{#userParams}} inside {{#methods}} - every generated method has an empty body and no user params; the Go tier has no codegen test |
| N-149 | DONE `0b1a7f749` | SDK codegen/call leftovers: Rust codegen emits `pub fn move(` for a method named move (keyword) and Ruby/Rust lack reserved-name escaping; Zig prepareCall drops SigHashPreimage even on stateless contracts (diverges from Zig call() and TS); multi-contract.ts arity filter uses its own AUTO_PARAM_NAMES without stateful gating |
| N-150 | DONE `b734bfef2` | .runar.ts surface: TS (ts-morph frontend) refuses compound assignment <<= >>= &= \|= ^= ('Unsupported binary operator') while +=, -=, *=, /=, %= work; other tiers' .runar.ts behaviour unprobed - decide support vs refuse and align 7 tiers |
| N-151 | DONE  | rawScriptSpans is never emitted by the Go, Java and Zig artifacts even for real asm({...}) raw-script contracts (data loss: SDK/analyzer metadata TS, Rust, Python, Ruby provide) |
| N-152 | DONE `9cf700ac2` | Artifact shape leftovers: Java artifact has no `asm` field; Zig never emits buildTimestamp; Rust --source embeds a debug `ir` snapshot by default; Go/Java omit sourceMap unless --emit-source-map; TS-only templateDigest and enriched constructorSlots[].name/type/valueEncoding |
| N-153 | DONE  | Statement-level parity gaps on other surfaces: .sol `;` (Zig accepts, TS refuses); .move `;` (Rust refuses, others accept); .move `abort 0;` (only Zig accepts, 00695177); .go bare `{...}` block (Go/Zig refuse, others accept); .go `;` (Rust/Python/Java accept, TS refuses); .rs `;` (Zig 5177 / Ruby accept, TS refuses); .rs bare `{ assert!(...); }` - Ruby alone accepts with mangled bytes 007c009c77 (trailing assert!(true) vanished - suspicious); .runar.go `_ = y` (local) Zig 76009d5177 vs others 76009d76517777 |
| N-154 | DONE `7509981e2` | .runar.go same-line `;` separator (`a := 1; b := 2`, `runar.Assert(x);`) refused by TS/Zig/Ruby, accepted by Go/Rust/Python/Java |
| N-155 | DONE `2893fa7ea` | Empty post-codeSeparator scriptCode (codeSeparatorIndex on last byte) refused only by Java OpPushTx.preimage; TS/Go/Rust/Py/Rb/Zig accept |
| N-156 | DONE  | go-only-executing-coverage still lists bn254FieldAdd/Sub/Mul/Inv/Neg as REMAINING although go-only-parity now executes all five on Spend (F-196) |
| N-157 | DONE `5510d4a42` | packages/runar-java test resource artifacts/stateful-counter.runar.json predates #123's sighash-type prologue and lacks the isAutoInjectedStateCheck marker on its exit assert |
| N-158 | DONE `060cbab38` | Java source map: in stateful-counter the second method's statements are mapped to opcodes 324-330 (inside its checkPreimage prologue) instead of 339-345, and if-else maps 15/16 and 21/22 to line 27 |
| N-159 | DONE `9a9982f82` | Funding UTXO selection can spend 1-sat ordinal / BSV-20 outputs: GorillaPool getUtxos (and other providers) return inscription-bearing outputs unfiltered |
| N-160 | DONE `335624254` | No permanent test pins SLH-DSA-256f acceptance on BOTH sides of treeIdx 2^63 (F-034 witness has only the >=2^63 signature + tamper) |
| N-161 | DONE `2f4913f8ae75b28322b6fc9c74ec20d34e2e9c5a` | Native off-chain blake3Compress (runar-go runar.go and peers) does not size-check its operands, unlike the TS interpreter and the on-chain script after F-114 |
| N-162 | STALE | SDK ANF interpreters still compute clamp as v<lo?lo:(v>hi?hi:v) (Go anf_interpreter.go, Zig sdk_anf_interpreter.zig, Java MockCrypto.clamp) and log2/gcd unroll caps are unchecked, unlike the script and the TS interpreter after N-029 |
| N-163 | DONE `026163912` | Rust SDK ANF interpreter converts SdkValue::BigInt to i64 with unwrap_or(0) (values beyond i64 silently become 0); Zig SDK interpreter is i64 with wrapping multiplies in pow/mulDiv/percentOf |
| N-164 | DONE  | Zig .runar.java treats every (ident) as a cast: (value) - other miscompiled as -other (8f00a077 vs TS 9400a0); (((value))) refused |
| N-165 | DONE  | Go checkGoNumericLiterals is quadratic: 85-111 s on a 1 MiB .runar.go with 340k literals (DoS) |
| N-166 | DONE `5c457ee8c` | conformance/anf-interpreter cross-interpreter suites silently skip the rust/zig/java drivers unless built or RUNAR_ANF_DRIVERS_STRICT=1, so 7-tier interpreter parity can drop to 4 tiers in CI and checkpoints |
| N-167 | DONE  | find_last_op_return / findLastOpReturn misnomer (first-match walk documented as 'last') in TS/Go/Rust/Zig/Ruby/Java SDKs; Go and Ruby keep a dead lastPos accumulator |
| N-168 | DONE `bdf6716ea` | RunarContract.deployWithWallet (contract.ts) swallows the deploy-tx BEEF parse failure and the deploy broadcast failure via warnNonFatal, the shape F-248 fixed in ensureFunding |
| N-169 | DONE  | packages/runar-py/tests/test_signer.py bsv_mocked fixture monkeypatches ls_module.PrivateKey/BsvTransaction/P2PKH/Script/TransactionOutput but restores only _BSV_SDK_AVAILABLE; later tests get mocked keys (test_fixed_array_anf_boundary: invalid address length: 24) depending on order |
| N-170 | DONE  | Go, Zig and TS LocalSigners (and Java's digest path) are not replayed against conformance/sdk-bip143 six-mode sigHex vectors; only Python, Rust and Ruby are |
| N-171 | DONE  | split / substr ANF-interpreter and native implementations share the OP_SPLIT fail-open shape F-274 fixed for left/right (Ruby substr, Go/Rust/Python/Java substr; TS split unmodelled) |
| N-172 | DONE `bc1b1a73a` | Live project version pinned in files bump-version neither writes nor checks: conformance/sdk-vertical cases/*/input.json and artifacts/*.json, packages/runar-go sdk_unsound_primitives_test.go / sdk_codepart_length_pin_test.go, packages/runar-zig sdk_contract.zig PinFixture |
| N-173 | DONE `56e8462c3` | Zig runtime builtins (blake3Hash, blake3Compress, sha256Compress/Finalize, ecPointX/Y) panic without the shared 'got N' diagnostic suffix, and no test pins the panic text |
| N-174 | DONE  | conformance/sdk-vertical/runner/sdk-tools.ts runs the Go and Rust tools with `go run` / `cargo run`, mixing build logs into the driver output the runner matches (same shape as N-091) |
| N-175 | DONE `247ebb6e8` | Java MockCrypto class javadoc says signature verification is mocked and always returns success; checkSig is a null check and Rabin/WOTS+/SLH-DSA/P-256/P-384 verifiers are real |
| N-176 | DONE  | Analyzer hex decoders in Rust (decode_hex), Ruby (to_i(16)) and Python (parse_script fallback) silently accept or truncate non-hex characters instead of refusing like TS/Java/Go/Zig |
| N-177 | STALE | @sighash directive has a spelling only on the .runar.ts surface; the other 8 parsers refuse it, so sighash-mode contracts cannot be written in .sol/.move/.go/.rs/.py/.zig/.rb/.java (frontend-parity gap) |
| N-178 | DONE `ac8519b3b` | Lean pipeline model ignores check_preimage.sighashFlag (always 0x41) so non-ALL sighash fixtures cannot be byte-exact (issue #123 gap) |
| N-179 | DONE `8d949d50b` | Add the sighash-single-stateful conformance fixture (N-038) on all 9 surfaces with its real-crypto witness, sdk-output case and derived artifacts, after N-177 and N-178 |
| N-180 | DONE `2f8815cbd` | A flat source with a long chain of private helper methods (m0->m1->...->mN, N=2000-8000) crashes Rust (SIGABRT), Zig (segfault), Ruby (SystemStackError), Java (StackOverflowError) in validate/ANF/inline passes; Go hangs >156 s CPU; Rust check_no_recursion is quadratic |
| N-181 | DONE `2fbe71f10` | Quadratic compile time on adversarial sources under the 4 MiB cap: Go .runar.ts tree-sitter error recovery on unbalanced openers, Go .runar.rb unterminated string + parens, Rust .runar.go `a = a = ...` / nested ternary / `int[][]...` (>60 s CPU) |
| N-182 | DONE `72bce98d0` | Zig native ecPointX/ecPointY return i64 (low 8 bytes of a 256-bit coordinate) |
| N-183 | DONE `5eba481a48b112c7244b92b29ddd9c78901a892e` | R-156 ecMakePoint field-element gate (0 <= v < p) not mirrored by the TS interpreter, runar-lang, Python, Ruby, Java (Go/Rust check only sign and width) |
| N-184 | DONE  | Native ecOnCurve on a wrong-width blob raises where the script returns false |
| N-185 | DONE  | Zig sdk_oppushtx.computeOpPushTxWithSigHash signs via bsvz signDigest256 (non-RFC6979 nonce), so its OP_PUSH_TX signature differs from every other tier's |
| N-186 | DONE `4a23ac279` | Remaining silent --emit-source-map drops: Zig --hex --emit-source-map returns before the map is written; --ir <file> --emit-source-map in Zig compileFromIR (and unverified Rust/Python/Ruby) has the same unconditional-return shape |
| N-187 | DONE `a4beed5f4` | No single test asserts parentClass AND isTerminal together on every tier's --ir artifact for a zero-mutable-field StatefulSmartContract (covered only transitively by ir-artifact-roundtrip + artifact-flag-parity) |
| N-188 | DONE `10b5b3793` | Java Preimage.extractOutputHash(Preimage) returns the first 32 bytes of the raw preimage (version+hashPrevouts), not hashOutputs; TicTacToe reaches it via the empty-field fallback |
| N-189 | DONE `127fba9a9` | R67/N-171 scriptCode intent used for off-chain state prediction is the bare template code part, not the deployed locking script (omits serialized state), so it differs from the real BIP-143 scriptCode whenever state is non-empty |
| N-190 | DONE `94e386b91` | Zig sdk_codegen emits a fromTxId wrapper that calls provider.getUtxo, which the Zig Provider vtable does not have; generated SDK code for any contract cannot compile that method |
| N-191 | STALE | merkleRootPoseidon2KB depth gate allows 1..64 in Ruby (stack.rb ~3548) while the emitter supports 1..32; Rust/Zig generic {func} gate unchecked for P2KB |
| N-192 | STALE | peephole-exhaustive sweep executes only the documentation mirror (peephole-rules.ts) for 23 of 25 rules, never peephole.ts, so a mutation in the real matcher goes uncaught |
| N-193 | DONE `fc33b87d9` | conformance runner readFixtureCompilerAllowlist swallows a malformed/unreadable source.json (catch { return null }) — same fail-open F-225/F-264 removed |
| N-194 | DONE `92e5737b0` | Go CompileFromSourceCollectingWarnings / CompileSourceToIR ignore ParseOnly/ValidateOnly/TypecheckOnly (same gap F-217 fixed in Rust) |
| N-195 | STALE | Java's EC-optimizer DCE gate is syntactic (hasEcCalls over EC_FUNCS incl. ecOnCurve/ecPointX/…) while TS/Go run DCE only when an EC rewrite rule fired; a method calling only a non-rule EC predicate plus a dead pure binding emits different hex in Java vs TS (3 bytes) |
| N-196 | STALE | TestCompilerParity_AllConformance (compiler_test.go ~1300) gates the --ir round-trip check behind os.Stat(irPath), so a fixture missing expected-ir.json silently skips it |
| N-197 | DONE `9cfcf7150` | SDK ANF interpreters (on-chain mode, all 7) return false on a malformed sig/pubkey encoding where the script aborts; OR/if arms diverge from the chain |
| N-198 | DONE `517eca817` | Model NULLFAIL: a non-empty signature that fails checkSig/checkMultiSig verification must abort (as real nodes/ARC do) in TestContract and all 7 SDK interpreters |
| N-199 | DONE `38e43412b` | A @sighash/@embedAlways comment sharing a line with the preceding token is silently ignored by the TS reference (ts-morph trivia rules) — compiles with the default flag, no diagnostic — R75: REFUSE in all 7 tiers |
| N-201 | DONE `c28d4931c` | EC algebraic optimizer never rewrites EC calls inside if-arms or loop bodies (TS reference and all tiers); nested ecMulGen(0n) etc. ship ~850KB unreduced scripts |
| N-200 | STALE | Rust's issue-#109 probe warns 'readonly field b is not referenced in any method body and was eliminated by DCE' for a field that IS referenced (in a dead chain) |
| N-202 | DONE  | Source path has no nested-loop product bound: a source contract whose nested loop counts multiply past MAX_LOOP_COUNT compiles from source, but its emitted IR is refused on --ir replay (F-283) |
| N-204 | DEFERRED | RELEASE: compilers/go and packages/runar-go tags are stale and form a tag cycle (runar-go@v0.4.5 lacks bn254witness/sp1fri; compilers/go v1.0.0-rc.1 unpublished); downstream go get is broken |
| N-203 | DONE `dc5a65096` | docs/runar-whitepaper.tex (~877-927) argues constant folding is 'disabled by default'; production default is ON (fold-OFF only for golden replay); checked-in PDF carries the same claim |
| N-205 | DONE `a6619e263` | verifyRabinSig key provenance residuals after F-286: (a) a stateful method can write a spender-supplied value into a MUTABLE key property that a later spend trusts; (b) --ir input bypasses the frontend rule |
| N-206 | STALE | Malformed hex ByteString property initializer is reported late (stack lowering, no location; Ruby says 'compiler bug') in Go/Python/Zig/Ruby/Java; TS/Rust now report it at validate time (F-265) |
| N-207 | DONE `ca12126d5` | --ir loaders accept empty identifiers (contractName, method/param/property names and types) and duplicate param names; a method with two params both named '' compiles (TS hex 767c9c77) — possible slot aliasing |
| N-208 | DONE `914cd2749` | --ir loaders accept wrong-typed optional fields: bin_op.result_type (py, rb — flips byte compare to numeric), assert.isAutoInjectedStateCheck (py, rb, java), add_output.preimage (py, rb) |
| N-209 | DONE `76acb0409` | test_cli_debug.py and test_f092 poseidon2 tests skip silently again if CI drops bsv-sdk/PYTHONPATH; port test_script_vm.py's $CI-is-set pytest.fail guard |
| N-210 | DONE `bb1102e70` | Upstream @bsv/sdk 2.0.7 Spend OP_RIGHT uses buf.slice(size-len, len) (wrong for 0<n<len); TS ScriptVM / runar debug / oracles mis-evaluate OP_RIGHT |
| N-211 | DONE `ebaae99b6` | Stateful real-crypto witnesses are not independent of the SDK: runStatefulSpend (real-crypto-execution.ts:~645) builds the spend via contract.call(..., {dryRun:true}), so the 'independent oracle' shares the SDK's tx modelling |
| N-212 | DONE `e7c5a58cb` | --ir loaders: a bare JSON integer beyond f64's 53-bit mantissa (e.g. a 256-bit constant written as a number) is rounded at JSON parse time and silently compiled to a DIFFERENT value (Rust: serde_json without arbitrary_precision; check every tier) |
| N-213 | DONE `82e60092f` | Remove the dead PreparedCall.opPushTxSig field (and its wasted ECDSA sign per stateful call) from Go/Rust/Python/Ruby/Zig SDKs, as F-369 did for TS (R81) |
| N-214 | DONE `3b9808326` | Tokenizers silently drop unrecognized characters (Ruby sol/move/go surfaces; Go and Zig lexers per N-004) instead of refusing as the TS tokenizers do |
| N-215 | DONE `ac576b911` | TS --from-ir (loadANFFromJSON/compileFromANF) lacks the IR validations the other 6 tiers have: I15 public-constructor-only compiles to an anyone-can-spend empty script; I05/I06/I10 raw_script/no-public-method/builtin-arity; I19/I21/I23 floats; I28-I31 unparseable loop.start defaults to 0 |
| N-216 | DONE `1021bc444` | Roll depth d+1 at five lowering sites prevents push/roll peephole folds in all 7 tiers; fix to d (moves ~15 goldens) |
| N-217 | DONE `325602e5e` | Rust conformance_goldens.rs find_rust_source / fixture_allowlisted_for_rust swallow source.json read/parse errors (same pattern F-264/F-323 closed) |
| N-218 | DONE `668b64391` | EC optimizer helper/gate bindings carry no sourceLoc in Go/Rust/Python/Zig/Ruby/Java (TS fixed by F-343); gate opcodes unmapped in source maps |
| N-219 | DONE `40059b49d` | Zig readonly_inference.zig swallows OOM (catch {} at ~107,158,159) and its for_stmt arm never walks the loop update clause |
| N-220 | DONE `0b24d910c` | TS/Python/Rust/Zig/Java CLIs silently pick one input when given both source and IR (Go/Ruby refuse); Ruby also silently prefers --hex over --asm |
| N-221 | STALE | TS hand-written surface parsers (.sol/.py/.rs/.java/.go/...) emit 1-based source-map columns; ts-morph and every native-tier golden are 0-based |
| N-222 | DONE `f39b17e42` | Rust maps branch-body opcodes to the enclosing if on all nine surfaces (if-else: 20 mappings/3 distinct vs TS 14/5); committed rs source-map golden pins it |
| N-223 | DONE `c8f621a87` | Out-of-range constructorSlots paramIndex: TS adjustCodeSepOffset unguarded; Ruby splices OP_0 (nil); Java silently skips the slot; Go/Rust/Zig/Python crash with a raw index error |
| N-224 | DONE `c869a4f49` | Ruby test_rake_test_runner.rb:53,95 pass via conditional `assert true` |
| N-225 | DONE `d9626c959` | Ruby .runar.rs parser returns an empty placeholder contract with no diagnostic for non-contract source; Go returns nil plus an error |
| N-226 | DONE `de728964d` | Go crypto_codegen_test.go has no op-count golden for EmitVerifyECDSA_P384, P384MulGen or P384Negate (Rust pins them) |
| N-227 | DONE `9173dcaa9` | Zero-mutable-field StatefulSmartContract calls: check the other 6 SDKs for the N-085 fee underpay; TS stateless branch builds no per-input unlocks for additionalContractInputs |
| N-228 | DONE `c30df8206` | fuzzer-nightly.yml PR-gate --anf steps pass no --time-budget-ms, so F-173's shrinker is unbounded on a failing PR run; finding dirs are named by ms timestamp and can collide |
| N-229 | DONE `c4456598e` | Java abi.constructor.params publishes N scalar params for a readonly FixedArray instead of one fixedArray param (Go/TS regroup ctorEntries) |
| F-171-FU | DONE `7b82dad6a` | conformance/fuzz-regressions/replay.test.ts (F-171) is not reachable from any CI workflow; tests/conformance-tests-reachable-from-ci.test.ts fails |
| CK16-FU1 | DONE  | diagnostic-coverage.test.ts fails: 02-validate.ts:1994 makeDiagnostic(RABIN_PUBKEY_PROVENANCE_MESSAGE) (F-286) is a const the diagnostic-site extractor cannot flatten |
| CK16-FU2 | DONE  | tests/ir-loader-consumes-conformance-goldens.test.ts expects loadANFFromJSON to REJECT 9007199254740993; N-212 (user: parse exactly) now decodes it exactly — stale expectation |
| CK16-FU3 | DONE  | NEW-010 substr(b, -1, 1) runtime-reject test now hits F-265's compile-time refusal of a negative literal start |
| N-230 | DONE `0b9462c5a` | fuzz-regressions rule 3 'entries are never deleted' is unenforced for single-entry deletion (needs a base-ref diff of conformance/fuzz-regressions/entries/) |
| N-231 | GROUPED | 05-stack-lower.ts branch-reconciliation sinkBelow sites (~3097/3182/3211/3238) push d but tag roll.depth = d+1, hiding them from the depth-0/1/2 peephole fusions (6 unreduced OP_2 OP_ROLL in assert-false-guard) |
| N-232 | DONE `631bc25c6` | Go bn254witness BuildFromProofWithInputs/computePreparedInputs reduce pub_i mod r; under R86a the script rejects non-canonical inputs, so the SDK must refuse them too |
| N-233 | DONE `1076d8898` | Negatives where tiers point their diagnostic at different AST nodes (column differs by more than 1): N15-N17, N175-N179, N200-N209, N220-N228 |
| N-234 | DONE `dc15b9e61` | TS compile() accepts a ByteString literal assigned to a bigint property (array or non-array); check typecheck strictness on literal type coercion across tiers |
| N-066-FU | DONE `6213bf739` | docs/test-skips.md:142 still lists the f005_loop_output_refs_test.go skip removed by N-066; R50 skip audit red |
| N-235 | DONE `1def698a7` | Go debug subcommand silently prefers --script over --artifact (exit 0); Rust now refuses the pair (F-386) |
| N-236 | DONE `968cdb87d` | ~30 conformance tests detect CI with process.env.CI === 'true' (CI=1 drops tiers silently); int-literal-parity uses bare process.env.CI — unify on N-166's driver-gate predicate |
| N-237 | DONE `6f18a669a` | Rust --ir merkleRootPoseidon2KB crashes on lower_merkle_root's 4-arg assert (variadic 8*depth+10); poseidon2_merkle emitter is dead code; depth limits disagree (Rust 1-64, Python 1-32, Go 1-64) |
| N-238 | DONE `e8efca0e7` | Rust typechecker says 'unknown function' for 7 Go-only builtins (bn254Pairing, assertGroth16WitnessAssisted(+WithMSM), groth16PublicInput, bn254MultiPairing3/4, verifySP1FRI); Python names the policy (R-258/R-259) |
| N-239 | DONE `1a6afcf14` | TokenWallet's assumed ABI (merge(sig, otherSupply, otherHolder), transfer(sig, Addr)) is inherently unsound: merge cannot authenticate its companion input (supply inflation); transfer cannot re-key the PubKey holder |
| N-240 | STALE | Go CompileGroth16WA never validates VK G2 constants (GammaNegG2, DeltaNegG2) as on-curve / in-subgroup; the Miller-loop chord-step safety argument (N-079) assumes they are |
| N-241 | DONE `1d2cd319c` | Python deploy_with_wallet wraps raw_tx parsing in bare `except Exception: pass` (contract.py ~548-561): a malformed wallet tx is silently ignored |
| N-242 | DONE `787b02dbb` | 01-parse-ruby.test.ts 'missing end keyword' and 'lambda syntax' tests assert only .not.toThrow() |
| N-243 | DONE `03e2fbacf` | Flaky Rust test f158_catch_refusal_hook_race_tests::concurrent_catch_refusal_does_not_corrupt_or_suppress_unrelated_panic_hook ('sentinel fired 792 times for 800') under full-suite parallelism |
| CK17-FU1 | DONE `c7470700a` | decompiler roundtrip: examples/ts/token-wallet-naive-INSECURE (N-042) has no coverage-baseline.json row |
| CK17-FU2 | DONE `68d914030` | zig-parser-examples: no examples/zig/token-wallet-naive-INSECURE/WalletToken.runar.zig (N-042) and no ZIG_PORT_PENDING entry |
| CK17-FU3 | DONE `c87d44e30` | R-289: Java now regroups FixedArray leaves (N-086/N-229) but lacks the R-289 malformed-synthetic-array-run refusal the other re-grouping tiers have |
| CK17-FU4 | DONE `4d2479f98` | scripts/bump-version.sh --check crashes with SIGTRAP (rc=133) under macOS /bin/bash 3.2 on the current tip; tests/version-consistency.test.ts fails locally |
| N-244 | DONE `d8cab19d8` | Non-TS surfaces' @sighash guards use `@sighash\b` with per-tier messages, so a glued `@sighashSINGLE` on .sol/.py/etc. is still silently accepted (N-039 fixed .runar.ts only) |
| N-245 | DONE `c5302db50` | TS runtime mock extractOutputHash (packages/runar-lang/src/runtime/preimage.ts) echoes the first 32 bytes instead of hashOutputs; Java Builtins.extractOutputHash falls back to ZERO_32 instead of refusing when no preimage is active |
| N-246 | DONE `4c2a13962` | Native mock extractOutputHash disagrees across tiers: TS and Java now return hashOutputs (N-188/N-245), while Go/Rust/Python/Zig/Ruby native mocks echo the leading 32 bytes (documented as test-mode convention, e.g. packages/runar-go/runar.go:731) |
| N-247 | DONE `4a3958394` | Issue-#109 readonly-field warning says the field 'was eliminated by DCE' in all 7 tiers even when the compiled script keeps the load_prop and a constructor slot (the probe runs its own unconditional DCE on a copy; the real pipeline's DCE is gated on optimizeEC anyChanged) |
| N-248 | DONE `138068994` | Ruby stack.rb merkleRootPoseidon2KB depth gate allows 1..64 while its emitter is bounded at 32; Ruby/Zig --ir refuse Go's Poseidon2 Merkle IR with an internal error / bare InvalidBuiltin instead of a named diagnostic |
| N-249 | STALE | Rust bsv-sdk 0.2.89 Spend (Rust ScriptVM) rejects OP_2MUL/OP_2DIV as DisabledOpcode while @bsv/sdk, Go and Python SDKs accept them, so the Rust tier cannot execute EC/KoalaBear/BN254 scripts that use OP_2MUL |
| N-250 | DONE `021aaa3e9` | isCiEnv lives in conformance/anf-interpreter/driver-gate.ts but after N-236 is imported by ~44 unrelated conformance suites plus analyzer/run.ts and runner/runner.ts; move it to a neutral conformance/env.ts |
| N-251 | DONE `b20bff878` | EC optimizer rule R8/R8r (ecAdd(x, ecNegate(x)) -> O) disagrees with the unoptimized adder for x=(a,0): unoptimized now aborts (N-110) while optimized returns O |
| N-252 | DONE `a3b6c6802` | NIST P-256/P-384 c_affine_add likely has the same y=0 tangent hole N-110 fixed for secp256k1 (doubling branch with a Fermat inverse of 2y=0) |
| N-253 | DONE `a1d5488e0` | Stateful prepareCall still computes (and discards) a k=1 OP_PUSH_TX ECDSA signature in all 7 SDKs via the shared ComputeOpPushTx helpers; add a preimage-only variant |
| N-254 | DONE `0bd3de10f` | Zig stack_lower.zig builtin_map keys the Poseidon2 Merkle lowering as 'poseidon2MerkleRoot' while every IR emits 'merkleRootPoseidon2KB', so poseidon2_merkle.zig is dead code and real IR fails with a bare InvalidBuiltin |
| N-255 | DONE `daa87f13d` | SDK ANF interpreters (on-chain mode, all 7) accept a bare-DER checkSig signature with no trailing sighash-type byte, which Spend/OP_CHECKSIG aborts on; also checkMultiSig is not encoding-gated |
| N-256 | DONE `4bfd5f687` | Rust ScriptVm OP_2MUL refusal is pinned (mock_script_agreement.rs:1420) but OP_2DIV, also emitted by Rust codegen (ec/bn254/p256_p384/merkle) and refused by the same bsv-sdk branch, is not |
| N-257 | DONE `b1c0e70ac` | Python crashes 'value t13 not found on stack' on a TS-surface tuple-form this.addOutput(1000n, [this.count, x]); check whether a legitimate tuple-form addOutput also crashes |
| N-258 | DONE `644d1b19f` | Port Zig/Java's unified per-input-unlock merge path for zero-mutable-field StatefulSmartContract calls with additionalContractInputs to TS, Go, Rust, Python and Ruby (currently fail-closed per N-227) |
| N-259 | DONE `225c1cf7c` | On-chain-mode checkMultiSig answers false for every input (including a valid multisig) in 6 of 7 SDK ANF interpreters, because array_literal is unmodeled (TS returns undefined, Go nil, Rust hard-coded false, Python/Ruby/Java unhandled); only Zig models arrays |
| N-260 | DONE `98d8fc11d` | Zig WalletProvider.broadcastImpl discards the signed tx and calls BRC-100 createAction(tx_hex as description, zero outputs), returning an unrelated txid as if the given tx was broadcast |
| N-261 | DONE `de072c1b3` | Legal terminal if whose arms rebind a local that is dead afterwards (let k = 0n; if (c) { k = 1n; assert(a); } else { k = 2n; assert(b); }) is refused by every tier (branch result layout mismatch / StackLowerFailed / Go IR validation) |
| N-262 | DONE `fe7ab074b` | Port Go's phase-3 'conditional needs N placeholder push(es) to balance a NON-EMPTY arm' fail-closed invariant to the other 6 tiers' lowerIf (they pad silently) |
| N-263 | DONE `e8935520d` | conformance/ci-predicate-sweep.test.ts (added by N-236) is not reachable from any CI workflow; tests/conformance-tests-reachable-from-ci.test.ts fails on the integration branch |
| N-264 | DONE `6842a0cf7` | Composite shape D call-chain links x 120 nested ifs each overflows the host stack (Rust 2 MiB SIGABRT at D=8): F-213's per-method nesting bound and N-180's call-depth bound compose multiplicatively after inlining |
| N-265 | DONE `cd45a0ee3` | --ir path bypasses N-180's call-depth bound and (outside Go's recursive F-071 checkIRNoRecursion) the recursion check: an externally supplied ANF chain is unbounded in 6 tiers |
| N-266 | DONE `87c8213f9` | Zig locktime-warning BFS is O(N^2) in method count (4.6 s CPU at 20000 methods) |
| N-267 | DONE `31e86dafe` | packages/runar-zig/README.md (~799-838) shows deployWithWallet as broadcasting a real deploy over the BRC-100 wallet path; after N-260 (R100) the wallet provider refuses raw broadcast, so the example is wrong |
| CK18-FU1 | DONE `d2d25f2a4` | script-size-baseline.json not restamped after N-110/N-252: conformance/runner/__tests__/script-size-check.test.ts expects 0 warns, gets 7 (5 EC fixtures + p256/p384-primitives at +12 bytes per add) |
| CK18-FU2 | DONE `d32b55980` | decompiler fingerprint for ecAdd no longer matches after N-110's 12-byte y=0 guard: fingerprints.test.ts 'recognizes ecAdd when followed by ecPointX' fails |
| CK18-FU3 | DONE `7eb2fbad9` | diagnostic-coverage.test.ts throws: 02-validate.ts:2216 makeDiagnostic(rabinKeyWriteMessage(w.prop)) (added by N-205) cannot be reduced to a template by the diagnostic-sites extractor |
| CK18-FU4 | DONE `b8d7de921` | ec-field-builtin-arity.test.ts R-063 control for p256Add pins the pre-N-252 sha256 of its compiled hex (e16038ed... vs now 9a8b40c3...) |
| CK18-FU5 | DONE `dbb9b2aac` | golden-provenance-allowlist-consistency: 3 new stale pins (ec-unit, p256-primitives, p384-primitives expected-script.hex): those goldens moved under route A (N-110/N-252) and their old allowlist entries still carry the old sha |
| CK18-FU6 | DONE `c16b5e74d` | r195-ts-only-examples.test.ts expects token-wallet-naive-INSECURE to be TS-only, but CK17-FU2 added its Zig port |
| CK18-FU7 | DONE `4ec48880d` | Rust r067_fixed_arity_delegate_arity_tests (2 tests) build synthetic IR whose verifyRabinSig 4th argument is a load_param; N-205's --ir key-provenance rule now correctly refuses it |
| N-268 | DONE `5d0cb5ba9` | @embedAlways guard messages on non-TS surfaces still differ per tier in Zig, Ruby and Java (same shape N-244 fixed for @sighash) |
| CK18-FU8 | DONE `37ab362d8` | packages/runar-rb/spec/sdk/issue100_spec.rb writes its source to a fixed shared path File.join(Dir.tmpdir, 'StateRead.runar.ts'), so concurrent or full-suite rspec runs collide (checkpoint-18 sdk-ruby: nil uses_code_part; passes alone) |
| N-269 | DONE `67a1dd350` | Ruby specs bind bare constants inside RSpec.describe (REPO_ROOT in compile_check_spec.rb:11 and analyzer/conformance_spec.rb:18); they land in Object and collide across files (benign today, same value) |
| N-270 | DONE `f5f3f3da8` | Stateless-branch OP_PUSH_TX code-separator index: TS and Go use method index 0 (methodIndex only set when isStateful) while Python, Rust and Ruby use the real method index; diverges for a multi-method zero-mutable-field contract |
| N-271 | DONE `be145646a` | A call with terminalOutputs plus additionalContractInputs neither merges nor refuses: the extra inputs are silently dropped (TS, probably others) |
| N-272 | STALE | Decompiler coverage regressed after N-252: p256-primitives and p384-primitives go from byte-match/template to byte-match/raw_script (coverage-matrix --check red; coverage.json last regenerated at N-042) |
| N-273 | STALE | CI has no drift check for packages/decompiler/fingerprints.json or coverage.json (only templates-data.json); fingerprints went stale for the 4th time behind a byte-moving EC change |
| PL23-FU1 | DONE `8751e07de` | Mutation corpus entry sdksplice-constructor-slot-wrong-length is stale: N-223 rewrote packages/runar-sdk/src/contract.ts constructor-slot splicing (resolveConstructorArg) so its find string occurs 0x; mutant-staleness.test.ts fails |
| N-274 | DONE `e0adf6bab` | docs/testing-guide.md 'Testing Rust Contracts' (~line 1220) says the native Rust prelude's check_sig/check_multi_sig/check_preimage/verify_rabin_sig/verify_wots always return true, contradicting the same guide's table (~653: Rust real check_sig) |
| N-275 | DONE `4d29b5953` | Rust ANF interpreter Val::from_sdk maps SdkValue::Array(_) to Val::Undefined, so a caller passing pre-built sig/pk lists to checkMultiSig via args gets false (fail-closed); Val::Array now exists (N-259) |
| N-276 | DONE `606063419` | Zig call()/prepareCall() on a plain stateless SmartContract (non-terminal) silently drop additional_contract_inputs; the other six SDKs refuse (N-227 guard) |
| N-277 | DONE `619a89f93` | Zig prepareCall/prepareCallStateful (two-phase API) never read additional_contract_inputs outside the terminal check: a stateful merge via prepareCall/finalizeCall silently drops the extra inputs (call() supports it) |
| N-278 | DONE `a5cd8b15b14b4bf188f4e05140aeb135e71ebafe` | No typed-wrapper generator (any of 7 tiers, incl. TS reference) emits from_utxo / attach_inscription though MANIFEST.md requires them and every untyped RunarContract supports both; Rust wrapper also lacks outputs/OutputSpec and state accessors |
| N-279 | DONE `af2bee698` | Zig anf_lower MAX_PRIVATE_CALL_DEPTH=64 makes mutatesState/addOutput/addDataOutput/requireOutputP2PKH predicates give up after 64 hops while N-180 admits 128: a mutation or output behind >=65 helpers classifies the method terminal in Zig only |
| N-280 | DONE `2bf6bc915ce9566e78d897c6c24afb31aa39bde4` | Zig compile memory grows quadratically in nested-if/helper depth: each optimized arm's flat instruction list is copied into its parent and the compile arena retains every copy (1.66 GB RSS at D=8, 4.5 GB at D=32, OOM-kill at D=127) |
| N-281 | DONE `9b4981844` | Rust and Zig SDK ANF interpreters still wrap on i64 overflow of + and - (wrapping_add/sub, +%/-%) and Rust abs(i64::MIN) wraps; on chain these produce the exact bigint, so post-state prediction silently diverges |
| N-282 | DONE `d438fd4b7` | Rust json_to_val and Zig parseJSONToANFValue turn a beyond-i64 "<digits>n" ANF literal into a ByteString that toInt reads as 0: wide load_const literals compute as 0 (same class as N-163, different entry point) |
| N-283 | DONE `503297573` | pnpm test:ci vs .github/workflows/ci.yml drift: the 'green here -> green CI' contract is unchecked (F-253 cited ~18 CI gates test:ci does not run, and 1 script CI does not run); not re-counted |
| N-284 | DONE `b6e171876` | TS .runar.rs parser fails open: a source with no #[runar::contract] struct, just a bare `impl Foo { pub fn bar(&self, x: i64) { assert!(x == 1); } }`, compiles successfully as contract 'UnnamedContract' with real ANF and no diagnostics (01-parse-rust.ts:508 placeholder name) |
| N-285 | DONE `965204170` | Rust catch_refusal's one-time hook install has a take_hook()/set_hook() window in which the stdlib default hook is active: an unrelated panic on another thread during the first concurrent catch_refusal bypasses the embedder's hook (stable Rust cannot close it; update_hook is unstable) |
| N-286 | DONE `a9f8301f0` | Zig two-phase API (prepareCall/prepareCallStateful + finalizeCall) cannot merge additional contract inputs: it now refuses them (N-277) where TS/Go/Rust/Python/Ruby/Java build a real per-input OP_PUSH_TX unlock; no conformance fixture exercises a stateful merge through prepareCall/finalizeCall in any tier |
| N-287 | DONE `b4d30efb3` | Mutation corpus has no mutant on packages/runar-compiler/src/optimizer/peephole.ts (the walk/emission logic N-264 and F-392 changed) or passes/side-effect-summary.ts; existing peephole mutants target only the declarative peephole-rules.ts |
| N-288 | DONE `09e03b8cf` | Affine consumption of a PROPERTY through a private helper is untracked in all 7 tiers: a helper doing checkSig(this.sig, ..) or checkPreimage(this.txPreimage), called twice, still compiles (N-109 covers parameters only) |
| N-289 | DONE `d9971148a` | runar-rs native prelude abs (packages/runar-rs/src/prelude.rs, `if n < 0 { -n } else { n }` on i64) overflows on i64::MIN: panics in debug, wraps in release |
| N-290 | DONE `ea309cf5fde8790e25ecf17d1aef027ca9bb4703` | ~60 ci.yml commands that need no merge-base, network or service ('addable-locally' in tests/n283-test-ci-mirrors-ci-contract.test.ts) are not run by pnpm test:ci, so 'green here' does not imply 'green in CI' |
| N-291 | DONE `c79cc2417` | Shared two-phase stateful-merge vector (conformance/sdk-call/stateful-merge-prepared.json), reproduced by TS/Go/Rust/Python/Ruby |
| N-292 | DONE `6b8f54f47` | Java prepareCall/finalizeCall with additionalContractInputs broadcasts the extra contract input with an unsigned all-zero Sig (layoutPushTx derives extraSigIndices from r.get(j)==null after planCall already placeholdered the Sig) and pays the fee from the second contract input instead of adding a funding input |
| N-293 | DONE `fdea9fe82` | Zig call() stateful merge with additional contract inputs computes a fee 72 sat below TS's on the shared merge vector (change 109620 vs 109548), so every unlock differs from TS |
| N-294 | DONE `8c975c635` | Java layoutPushTx funding candidates exclude only currentUtxo, not the additionalContractInputs outpoints (TS excludes them under F-045): an extra contract UTXO at the signer's address can be selected as funding, spending the same outpoint twice |
| N-295 | DONE `81c9660a2` | Zig call() stateful merge funding candidates exclude only the primary contract UTXO, not the additional_contract_inputs outpoints (sdk_contract.zig ~805-835): an extra contract UTXO at the signer's address can be spent twice, once as funding |
| N-296 | DONE `ac36d3e5b` | Merge per-input Sig override semantics diverge: when additional_contract_input_args carries an explicit non-zero Sig, Zig keeps the caller's value while TS overwrites every auto-sign Sig slot with the signer's signature; no Zig integration merge test covers the default (no-override) path |
| N-297 | DONE `63aa53e89` | No cross-tier negative pins a DIRECT double checkPreimage(this.txPreimage) in a StatefulSmartContract; Zig accepted it until N-288 added the implicit txPreimage origin key |
| N-298 | DONE `056d02660` | Two mutation survivors are real gate gaps: peephole-f392-roll0-opcode-form-matches-pick (no gate exercises F-392's small-depth opcode-form ROLL/PICK rules) and sideeffect-ifstmt-skip-else-branch (no witness puts a helper's only side effect inside an else branch) |
| N-299 | DONE `5af4ec76e` | Mutant sdkstate-decode-opn-as-length lists state-push-framing-vm in expectCaughtBy but only c28-state-strict fires, so a full run-mutation.ts exits 1 under F-172's partially-caught policy |
| N-300 | DONE `bd96f3065` | //runar:sighash above a package-level init/main func: Go and Rust report the directive as 'lost', TS and Java as 'non-public' (Python/Zig/Ruby unchecked) — same refusal, divergent diagnostic |
| N-301 | DONE `d536af327` | Every tier's .runar.rb parser silently ignores unknown `prop` options, so a typo like `embed_alwyas: true` is dropped instead of refused |
| N-302 | DONE `183715c24` | The readonly-field DCE warning (N-247) still tells users to 'annotate it /** @embedAlways */', a spelling refused on the 8 non-TS surfaces since N-093 |
| N-303 | DONE `0ddfc2bac` | Python, Java and Zig route a decorated `def __init__` through the method path in the .runar.py parser, unlike TS; runar-rb hover.rb lacks runar_sighash/embed_always; runar-rs lib.rs does not re-export unsafe_contract |
| N-304 | DONE `2a3efec52` | The .runar.zig parsers put the `ctx: runar.StatefulContext` param into the artifact ABI (e.g. bump: [ctx, txPreimage]); hex and ANF are unaffected, but the ABI differs from the other surfaces (also auction, tic-tac-toe); abi-cross-tier-parity only compares the .runar.ts ABI |
| N-305 | DONE `e4047d34f09f3fcca72d0eca454a6bb448aae406` | runar-verification/README.md carries older stale counts outside the gated header (lines ~62-63 '74 discovered / 52 baseline + 20 crypto-pending', ~151/293/340/469 '63 fixtures', '64 fixtures', '0/64 VERIFIED-direct', '64/64 VERIFIED-modulo'); row 17 'ANF JSON round-trip 64/64' unverified |
| N-306 | DONE `8424f109f` | Python, Ruby and Java .runar.ts parsers accept a for-loop with a non-`let` initializer (`for (i = 0n; ...)`) by silently substituting `_i = 0`; TS refuses with 'For loop must have a variable declaration initializer' |
| N-307 | DONE `c0ca55d41` | FixedArray size literal divergences in .runar.ts: `2n` is accepted by TS/Python/Zig/Ruby/Java but refused by Go/Rust; `1_0` is read as 1 by TS (parseInt stops at '_') and as 10 by the F-026 tiers, so TS can silently compile a 1_0 array as length 1 |
| PL27-FU2 | DONE `1b80f72bb` | tests/abi-cross-tier-parity.test.ts 'TypeScript reference' cases run under vitest's default 5000 ms timeout while their first statement is a cold `await import('runar-compiler')`; under host load they time out (post-land-27, and alone at load ~16) although compile itself takes <110 ms; the native-tier cases in the same file allow 300 s |
| N-308 | DONE `50bbba29a` | Three bracket-free .runar.ts shapes stay quadratic inside vendored tree-sitter C error recovery in the Go tier at 4 MiB (closure_rs `\|\| \|\| …` >162 s, lambda_py `lambda: …` >147 s, logic_py `a and a …` >137 s CPU; ts_subtree_summarize_children under ts_parser__recover) |
| N-309 | DONE `1555b88d3` | Go parser_move.go snakeToCamel grows a string with += and is quadratic on a long `a_a_a…` identifier (20k 0.1 s, 80k 0.8 s) |
| N-310 | DONE `54cadfc1e` | The TS reference refuses the 4 MiB .runar.go `a = a = …` and nested-ternary shapes with a caught 'Maximum call stack size exceeded' instead of a canonical depth/size diagnostic |
| N-311 | DONE `84512ec07` | Go .runar.ts ref_type_rs shape (F-213 sweep) parses, then uses 2.9 GB RSS and 36 s CPU in typecheck |
| N-312 | DONE `56c04d24b` | TS compile() still spreads validation, typecheck and expand diagnostics with push(...) (index.ts ~293/294/329/364); a large enough list overflows the JS stack and the catch replaces all diagnostics with 'Maximum call stack size exceeded'. Diagnostic-flood size also diverges across tiers (Go caps, TS/Rust/Python do not) |
| N-313 | DONE `4f402f7da` | Malformed values of known .runar.rb prop options are silently ignored in all 7 tiers (e.g. `readonly: maybe`, `embed_always: 1`) |
| N-314 | DONE `6243172f4` | No BN254/Groth16 conformance fixture: a real one needs a ~4.8 MB script golden in 9 surfaces plus a new witness kind that runs Go-compiled precompiled hex on @bsv/sdk Spend (route A for Go-only fixtures) |
| N-315 | DONE `9f0a033ce` | extractPrevOutputScript called from a private helper almost certainly strands its auto-injected `_prevOutScript_<i>` witness on the helper (same defect class as N-070); no tier's side-effect summary has a flag for it |
| N-316 | DONE `3138de5da` | matchesArtifact in all 7 SDKs compares the code part literally when an artifact has no constructorSlots, ignoring codeSepIndexSlots and codePartLenSlots, so a stateful artifact with only those slots never matches its own honest deployment (TokenWallet and fromUtxo inherit this) |
| N-317 | DONE `68197d977` | Security review of N-076: TokenWallet.getUtxos can be made to throw by one hostile UTXO (DoS) in TS (findLastOpReturn runs outside the try) and Java (only IllegalArgumentException is caught), and Java's new ScriptUtils.matchesArtifact may parse scripts differently from TS (parser differential) |
| N-318 | DONE `15b09157f` | Security review of N-316: matchesArtifact accepts ANY script element at a codeSepIndex slot, though the SDK bakes a deterministic value there, so a lookalike script with a forged codeSep index matches as genuine (fail-open, now reachable for codeSep-only artifacts) |
| N-319 | DONE `4c282876d` | Ruby-surface parsers in every tier accept a class with no closing `end` (match('end') silently returns false at EOF): unterminated class parses with zero diagnostics |
| N-320 | DONE `6f9ea880d` | Hostile-script parsing outside getUtxos: Java Integer.parseInt accepts '+'/'-' opcodes (SIOOBE via fromTxId state parsing), Rust find_last_op_return slices &str by byte index (panic in from_utxo/from_txid on non-ASCII), Python find_last_op_return raises ValueError on non-hex via contract.from_utxo |
| N-321 | DONE `a8682150c` | Go typecheck diagnostics echo the full source type text unbounded: a 4 MiB annotation yields a ~4 MiB error message |
| N-322 | DONE `b3f0a1802` | Ruby SDK deploy resolved_code_sep_slot_values neither sorts codeSep slots nor adds earlier codeSep slots' expansion, diverging from the other 6 SDKs (and from Ruby's own matcher since N-318) |
| N-323 | DONE `41be9b0d6` | Zig accepts a local `let` whose type annotation names an unknown type (`let q: TTT = a;` compiles); Go/TS/Rust/Python/Ruby refuse with "type 'bigint' is not assignable to type 'TTT'" (Java unestablished) |
| N-324 | DONE `3552001cb` | Zig SDK magnitudeToDecimal is quadratic: a 1 MiB script-number constructor arg makes fromUtxo run ~100 min (64 KiB = 24 s); std.math.big toString is also quadratic |
| N-325 | DONE `60c5ce543` | Unknown type names outside initialized local annotations (uninitialized `var q TTT` / Java declarations, parameters, return types) — per-tier acceptance not established; Zig's N-323 check sits only in the initializer branch |
| N-326 | DONE `5d504fa84` | conformance/scripts/__tests__/bip143-fixture-locktime.test.ts (added by F-299) is reached by no CI step; tests/conformance-tests-reachable-from-ci.test.ts fails |
| N-327 | DONE `8a9e6d1fd` | Rust ts_nesting::the_corpus_stays_far_below_the_limit counts the deliberately over-limit negative N285-ts-type-operator-nesting.runar.ts (estimate 406) |
| N-328 | DONE `e520d8daf` | packages/runar-py/tests/test_n075_multi_output_inscription.py uses the always-ack MockProvider without an allowlist entry; test_always_ack_allowlist fails |
| N-329 | DONE `ba368350f` | Go SDK NewRunarContract accepts a non-hex ByteString constructor arg and splices raw bytes into the locking script; examples pass raw runar.Alice.PubKeyHash and build corrupt scripts |
| N-330 | DONE `4a0f84a9d` | SDK constructor args of non-string kinds (Uint8Array, bytearray, nil, numbers) for ByteString-family params fall through the encoder fallback (String(v)/%v/str()/to_s) unvalidated |
| N-331 | DONE `4195ade74` | Unknown type names in method RETURN-type positions are accepted by all 7 tiers on every surface that has one; no tier keeps the return annotation in its AST |
| N-332 | DONE `3642770d2d273a531e79ce8a986a98b534536814` | A public method with a declared return type (.runar.rs `-> T`) is accepted by go/rust/zig but refused by ts/python/ruby/java |
| N-333 | DONE `f6dd56fad6f1e1078ee0a98769f192dfabd81679` | Native Go type names on .runar.go (int64, int, bool, []byte, string, uint64) are mapped inconsistently across tiers as param and return types; docs/formats/go.md lists int64 and bool as valid |
| N-334 | DONE `cfc63d428cd9fa6f3564959cd1ca5a5d6f9b03eb` | N-283 ci.yml-vs-test:ci drift test fails: N-326 added the bip143-fixture-locktime vitest step to the wire-format job but test:ci / EXPECTED_UNCOVERED was not updated |
| N-335 | DONE `6d10a69f571da206f3ba1b539d9b64a254ccc74d` | R-036 CONTROL test in runar-cli deploy-constructor-args.test.ts passes 0n for an Addr ctor arg, now refused by N-330/N-073 |
| N-336 | DONE `84732354a2b5d2cf543d31b865e647c1f6ab798d` | runar-py native sha256_compress guards operand sizes with `assert`, which python -O strips, so wrong-size state/block is accepted there |
| N-337 | DONE `3044c51745399a2a2b8ad8fbab78cab53c363f24` | runar-py RPCProvider narrows JSON-RPC node responses with `assert isinstance(...)` (rpc_provider.py:87,112,119,146); under python -O a malformed node response is not refused there |
| N-338 | DONE `8fd5b4d476006494df2b58a6c9577be4547d424e` | Native Go type names the docs do not list (int, uint, uint64, []byte, string) are accepted by some tiers and refused by others on .runar.go |
| N-339 | DONE `ce873336c323a1494b39ba9ed9dfc6344f48c1ad` | Go TestEcOnCurve_RejectsNonCanonicalX panics: it builds the x = p+1 alias with EcMakePoint, which N-183 now refuses |
| N-340 | DONE `ae0936ed760de926195dbb9d40268c5f6243dcb6` | TS generateZig (codegen/templates/wrapper.zig.mustache) emits no fromUtxo / attachInscription delegation, unlike the Zig SDK's own generator |
| N-341 | STALE | Move `while` loop rejections quote a different synthetic iterator name per tier (Rust MOVE_WHILE_STUB_ITER vs the TS placeholder) |
| N-342 | DONE `2e950b4dd8945be95bdd4dde3b79c978db6fa267` | Java TS-surface parser drops let/const mutability in its AST: is `const` reassignment on .runar.ts refused by all 7 tiers? |
| N-343 | DONE `f19ba32ff` | Zig compile time is quadratic in nested-if depth: each level re-runs the peephole over its whole subtree and copies it (D=127 x 120: 50 s vs Go 2.7 s) |
| N-344 | DONE `3df353f27` | Immutable locals on the .runar.rs (let without mut) and .runar.zig (const) surfaces can be reassigned: all 7 tiers accept |
| N-345 | DONE `de1297b21` | `toByteString(a) === toByteString(b)` lowers to OP_NUMEQUAL in TS and Rust but OP_EQUAL in Go, Python, Zig, Ruby and Java |
| N-346 | DONE `d47e48d54` | Zig .runar.ts parser refuses `'aa' as ByteString` inside a method body ("Undefined variable 'as'"); the other six tiers accept it |
| N-347 | DONE `269521e95` | Byte-typedness of builtin calls is a hand-written per-tier list that drifts from the typechecker return table |
| N-348 | DONE `e71e78b16` | Comments still quote the pre-F-167 tautological shift-ops/bitwise-ops contract shape |
| N-349 | DONE `679b50680` | Remaining Go compiler tests use nibble-unaligned hex substring opcode checks |
| N-350 | DONE `39600df70` | liftBranchUpdateProps drops sourceLoc on synthesized bindings in TS, Go, Rust, Python, Zig and Ruby |
| N-351 | DONE `144b9207b` | TS and Ruby SHA-256/BLAKE3 codegen stamp source locations onto shared cached ops (F-193 in two more tiers) |
| N-352 | STALE | EC rule R8 matches operand names that were rebound, folding ecAdd(q, ecNegate(p)) to INFINITY |
| N-353 | DONE `56d1c1676` | Go EC rule engine treats two const bindings with equal payloads as the same $x; other tiers use name equality |
| N-354 | DONE `9a68f6ef9` | After F-269 the ec-unit fixture no longer exercises the runtime P+(-P) and doubling adder paths |
| N-355 | STALE | EC optimizer dead-binding elimination runs under different conditions per tier |
| N-356 | DONE `ed1684d83` | Reassigning a method parameter is silently dropped in Python, Ruby, Zig and Java ANF lowering |
| N-357 | DONE `55f411e6b` | taffytail pinRuns scans script hex byte-wise without skipping push data |
| N-358 | DONE `fcf0e34ce` | Stale lower-divergence comments in runar-verification/tests/PipelineGolden.lean |
| N-359 | DONE `219f1f009` | .runar.ts `as number` and `as const` are accepted or refused differently across tiers |
| N-360 | DONE `3a22a351a` | A parameter reassigned in both arms of if/else is not merged; reads after the if see the caller argument (all 7 tiers) |
| N-361 | DONE `0eb92aaf5` | Stale bucket-count comment in PipelineGolden.lean (~765 "57 = baselineMatches (49)...") |
| N-362 | DONE `4174e8e66` | Reassigning its own param inside an ANF-inlined, output-emitting private helper is ignored (all 7 tiers + SDK interpreters) |
| N-363 | DONE `a2ef91d47` | N-360 landed two new expected-strict goldens without golden-provenance entries (checkpoint-29 provenance gate red) |
| N-364 | STALE | Zig diverged from the other 6 tiers on an inlined property-named reassigned helper param at HEAD of N-362 (not root-caused) |
| N-365 | DONE `eb95231f5` | Go refuses `x as number` only by accident (numeric-literal pre-check matches the `number` keyword token), with a misleading diagnostic |
| N-366 | STALE | conformance/negatives/N33-number-type.runar.ts:10 comment quotes Go's pre-N-365 'number' message |
| N-367 | DONE `ae130537a` | const-reassign helper header comments in Go/Rust/Python/Ruby/Zig/Java still say ".runar.ts only" after N-344 |
| N-368 | DONE `ea1edfe58` | Zig stateful-counter source map maps ~422 injected-preamble opcodes (from opcode 7) onto one user anchor (12:20) |
| N-369 | STALE | Zig if-else source map maps opcodes 0, 17 and 23 (unmapped in TS) onto the `if` line |
| N-370 | DONE `6d1b1df1a` | F-293 whole-map shape check gates only committed goldens; conformance/source-map/run.ts (live compiles) does not call it |
| N-371 | DONE `6362536e7` | 33 examples/zig .runar.zig contract directories have no *_test.zig |
| N-372 | DONE `8efd617c9` | No CI workflow runs the live source-map runner conformance/source-map/run.ts |
| N-373 | DONE `dda0d92fd` | Conformance runner INCOMPLETE COVERAGE footer says "This PASS covers N tiers" even when the run FAILED |
| N-374 | DONE `b8abc63de` | Conformance runner reports the Java tier "available" while every Java spawn fails with ENOENT |
| N-375 | DONE `22196e234` | runar-zig native package gaps keep 17 example contracts compile-check only (missing re-exports, intrinsics, builtins; hex-literal semantics) |
| N-376 | DONE `f84abcbbb` | Identity ROT run before the Merkle prologue from argument marshalling (load_param roll + bringToTop roll) |
| N-377 | DONE `a34ab9641` | Rust tests/cli_debug_tests.rs tempdir() named by nanosecond timestamp collides across parallel tests |
| N-378 | GROUPED | runar-verification/README.md still quotes 91/91 fixtures and 72/91 byte-exact after F-352 grew the corpus to 97 (78/97) |
| N-379 | DONE `bd3c9aa85` | F-352-FU: corpus counts in docs/SDK comments and CI reachability after the six new fixtures |
| N-380 | DONE `2f0c61b41` | F-368-FU: off-chain Rabin verifiers still accept sig + k*n that the on-chain script now aborts on |
| N-381 | DONE `8ec3dbcb5` | `go test ./...` in conformance fails setup in conformance/negatives (mixed .runar.go package names) |
| N-382 | DONE `f13c58e46` | Stale Rabin opcode counts in docs after F-047/F-144/F-368 ("15-opcode") |
| N-383 | DONE `361002809` | F-368-FU: Rust r067 CORRECT_ARITY_FINGERPRINTS still pins verifyRabinSig at 45 ops (now 50) |
| N-384 | DONE `85d76f1bb` | N-103-FU: AgreesA4 log2 isSome theorem is vacuous after the exact-log2 lowering |
| N-385 | DONE `4b5ed21bc` | Rust source map attributes method-tail and inline-tail cleanup ops to the last statement |
| N-386 | DONE `a78b02d44` | Stale header in compilers/rust/tests/f211_source_map_attribution_tests.rs |
| N-387 | DONE `d16d9d75b` | Python compiler conformance-goldens harness ignores the source.json compilers allowlist (checkpoint-39 red after N-314) |
| N-388 | DONE `fb67e1757` | README.md:500 still lists four Go-only fixtures; bn254-pairing makes five |
| N-389 | DONE `51f890704` | Ruby and Rust conformance-golden harnesses skip every allowlist-excluded fixture, dropping byte checks on Go-only fixtures those tiers compile in agreement with Go |
| N-390 | DONE `74abcd641` | Go .runar.ts parser rejects `a < (-93n & -95n)`: comparison whose right operand is a parenthesised expression starting with a negative literal |
| N-391 | DONE `b5f2bcc07` | Zig conformance-goldens harness runs only under `zig build conformance-goldens`, which neither CI nor `zig build test` invokes |
| N-392 | DONE `70b74aec2` | Zig and Java golden harnesses swallow a malformed or unreadable source.json (fail-open) |
| N-393 | DONE `53b1a0ddc` | Rust source map adds extra mappings on ops inside &&/\|\| short-circuit and some branch lowering where TS leaves them unmapped |
| N-394 | DEFERRED | Audit Go/Python/Zig/Ruby/Java source maps against TS per opcode (sub-context loc inheritance, method-tail clears, FixedArray dispatch locs) |
| N-395 | DONE `83b0dd207` | Fuzzer `--anf` fold-off gate (nightly) red since N-087: ANF generator emits mutable props / update_prop in a SmartContract IR that every tier now refuses |
| N-396 | DONE `cb3883a8e` | `pnpm run conformance:typecheck` (CI step) fails on conformance/tests/bn254-pairing/Bn254Pairing.runar.ts: bn254MultiPairing4 not exported by runar-lang (N-314 regression) |
| N-397 | DONE `039094cf6` | Constant folding on the source path often emits LONGER scripts than fold-off (dead operand bindings survive), and the TS folder does not see through @ref: alias bindings |
| N-398 | DONE `412595b6a` | TS compiler typechecker has no entry for bn254Pairing / bn254MultiPairing3 / bn254MultiPairing4 while runar-lang exports them and builtin-arity.ts lists them |
| N-399 | DONE `c71dbfb62` | No fuzzer compares fold-ON output across tiers for contracts with branches or loops |
| N-400 | DONE `f622c6726` | No fuzzer generates add_raw_output, add_data_output, method_call or raw_script; anf-differential.ts header lists only 8 of its 10 absent kinds |
| N-401 | DONE `63fe2424c` | Method-call collectors and readonly-write walkers still skip for-loop init/update/condition in all tiers (Zig collectMethodCalls / walkReadonlyWrites too) |
| N-402 | DONE `25033b4d7` | Unknown-parent-class diagnostic wording differs across tiers on .ts/.py/.rb/.java surfaces |
| N-403 | DONE `703c2a77d` | TS typecheck reports the other five Go-only builtins (verifySP1FRI, merkleRootPoseidon2KB, assertGroth16WitnessAssisted, assertGroth16WitnessAssistedWithMSM, groth16PublicInput) as 'Unknown function' |
| N-404 | DONE `e8b39b7bd` | N-017-FU: .runar.py private method (and possibly property) named like a builtin: TS/Rust declare via snakeToCamel but bare calls resolve via mapBuiltinName |
| N-405 | DONE `97cc96eb1` | runar-lang exports no stubs for the Go-only builtins verifySP1FRI, merkleRootPoseidon2KB, assertGroth16WitnessAssisted, assertGroth16WitnessAssistedWithMSM, groth16PublicInput |
| N-406 | DONE `316b8c14b` | Tokenizer position bugs: Rust .rs tokenizer over-counts the column after a multi-line block comment; Go .rs tokenizer does not advance the line on a newline inside a string literal |
| N-407 | DONE `c73bc5123` | Go and Rust tokenizers accept non-ASCII letters/whitespace in identifiers (unicode.IsLetter / is_alphabetic) that the TS reference refuses |
| N-408 | DONE `976e9a90e` | --ir loaders: legacy empty-identifier checks in Go/Rust/Python/Ruby are now shadowed by N-207's shared check; 'binding[i] has empty name' exists only in those 4 tiers |
| N-409 | DONE `d6d4ecdc1` | .runar.py accept/reject splits: `a ** 2` refused by TS and Ruby but accepted by Go, Python, Zig and Java; `-> None` return annotation refused by Rust only |
| N-410 | DONE `da5437f40` | Remaining silent absorbing paths: tokens after the .py class are ignored (N-004 fixed only .rb); the .zig struct-body loop skips unknown tokens; optional leading `.` in .zig struct-init fields |
| N-411 | DONE `3ee80b2f7` | SDK stateful flag for SDK-supplied params differs by path: contract.ts prepareCall uses stateFields.length > 0, multi-contract.ts (N-149) uses parentClass; a zero-mutable StatefulSmartContract (e.g. OutputBinder) disagrees |
| N-412 | DONE `4914266fb` | TS (and possibly other SDKs) stateless call: real unlocking script omits intent-witness pushes; only the size-estimation placeholder includes witnessHex (contract.ts ~1330, ~1974, finalizeCall stateless ~2214) |
| N-413 | DONE `6a9242165` | .runar.rb `default:` parses only a unary expression and skips the rest of the line in all 7 tiers: `default: 1 + 2` silently becomes 1; examples/ruby/tic-tac-toe `default: '00' * 33` (PubKey) silently becomes '00'; trailing junk after a boolean option is skipped too |
| N-414 | DONE `2fb0ed291` | .runar.rb default: nil is accepted as bigint 0 in all 7 tiers; odd-length hex ByteString literal (default: "x") refused by TS and Rust, accepted by Go, Python, Zig, Ruby, Java |
| N-415 | DONE `6fb572c5a` | TS parseOnly accepts conformance/negatives N227-rb-rabin-pubkey-param and N93-rb-index-assign-bytestring-prop while the 6 native tiers refuse them under --parse-only |
| N-416 | DONE `b54dc50ba` | `nil` in a .runar.rb method body is lowered to bigint 0 in all 7 tiers (not a Rúnar literal) |
| N-417 | DONE `08b3ae116` | Java stateless call() adds no P2PKH funding input and pays the fee out of the contract input, unlike the other 6 SDKs (whole-tx divergence on conformance/sdk-call/stateless-witness.json) |
| N-418 | DONE `7e3b962ec` | Java stateless call path takes no CallOptions: fundingSigner, changeAddress, maxFundingInputs and locktime are ignored, unlike TS |
| N-419 | DONE `ce3643f0b` | IR validation leftovers: Go ValidateIR / Python validate_ir keep legacy empty-name wording on the direct API; empty binding `kind` refused only by Go/Python/Ruby with per-tier text |
| N-420 | DONE `b54d16df0` | check-derived-artifacts does not cover packages/decompiler/fingerprints.json; a byte-moving codegen change leaves the EC fingerprint templates stale with every gate green |
| N-421 | DONE `d9029584c` | Zig .runar.move accepts a non-adjacent `let` before `while` (fail-open: loop starts at 0, not the declared value); the other six tiers refuse |
| N-422 | DONE `6318d57c0` | Move `while` refusal wording splits: non-literal left bound (Zig shape sentence vs 'Cannot determine loop bound'), non-literal start used after the loop (Python/Zig 'Cannot determine loop start' vs 'Undefined variable') |
| N-423 | DONE `d8b23d077` | .runar.ts: non-ASCII identifiers and whitespace split 5/7 vs 2/7 (TS/ts-morph accepts Unicode ID_Start/ID_Continue and Zs whitespace; Zig/Ruby refuse identifiers; Python/Zig/Ruby/Java refuse whitespace) - needs a decision |
| N-424 | DONE `feb114be8` | .runar.move tokenizers: Python and Java accept non-ASCII letters in identifiers and Rust accepts U+00A0/U+2003 as whitespace; TS refuses (N-407 analogue) |
| N-425 | DONE `490d5aaee` | Java stateful call ignores CallOptions.changeAddress (added by N-418, stateless-only); check what TS does for the stateful change output and converge |
| N-426 | DONE `fc376dc60` | Stateful call with changeAddress but no changePubKey silently builds a covenant spend the network rejects (TS/Go/Rust/Python/Java); Ruby has no changePubKey and Zig's contract SDK has neither |
| N-427 | DONE `8a8ebdafd` | Java typed wrapper <Contract>StatefulCallOptions declares changeAddress/changePubKey but never maps them into CallOptions (silently dropped) |
| N-428 | DONE `50a8053f2` | Typed wrappers still declare-but-drop `outputs` (Java: CallOptions has no stateful multi-output field; Zig: sdk.CallOptions.outputs exists but the wrapper's OutputSpec is a different type) and Zig `change_pub_key` (sdk.CallOptions lacks it; see N-426) |
| N-429 | DONE `db8dd4ed3` | Zig --parse-only accepts a non-ASCII string literal (`const s = "é";`) on .runar.ts while the other tiers refuse at ByteString validation |
| N-430 | DONE `327da2dde` | Java SDK CallOptions has no stateful multi-output field, so the generated Java stateful wrapper declares `outputs` (List<OutputSpec>) and drops it |
| N-431 | DONE `7d3b53049` | Zig generated typed wrapper `init(allocator, artifact, args)` does not compile for any contract with constructor params (emits bare `count` instead of `args.count`; ctor_count = ctor_args.len / 2 looks wrong) |
| N-432 | DONE `bf78518fb` | ByteString-literal hex diagnostics carry no line:col in Go, Rust, Python, Zig, Ruby and Java (TS prints file:line:col) |
| N-433 | DONE `7176ec828` | Stateless needsOpPushTx and zero-mutable extra-input unlock paths still compute an OP_PUSH_TX k=1 signature in TS, Go, Rust, Python, Ruby and Zig |
| N-434 | DONE `0b1c42767` | Zig sdk_oppushtx.zig frees buffers twice (errdefer plus manual free) on its encode-failure paths |
| N-435 | DONE `610f4e36a` | .runar.go runar.ByteString("é") is accepted by all tiers but compiles to different bytes: ts/python/java push 01e9, go/rust/zig/ruby push 02c3a9 |
| N-436 | DONE `84bf77e74` | Non-ASCII ByteString literal diagnostics use different length units: Go/Rust count bytes, Python/Ruby code points, TS UTF-16 units; Go prints mojibake for .rb/.zig sources |
| N-094-FU | DONE `7b34add74` | N-094 added a second --ir diagnostic for output intrinsics reached through a private method_call; it preempts N-055's shared sentence and breaks n055-ir-output-delegation-parity (24 failures) |
| N-437 | DONE `6ad1a7558` | .runar.go string literals: octal, \u escapes and backtick raw strings decode differently across tiers inside runar.ByteString("...") |
| N-438 | DONE `28f0d20ed` | .runar.sol compound assignment: TS refuses *= /= %= while the other 6 tiers accept them; all 7 refuse &= \|= ^= <<= >>= |
| N-439 | DONE `a33158f5d` | .runar.go bare quoted literals outside ByteString(...): Zig and Ruby do not decode "\x41" on the hex path (Go/TS do); bare backtick literals accepted by go/rust, refused by ts/python/java/zig/ruby |
| N-440 | DONE `4885dab8e` | Python reads source with universal newlines, so a lone CR inside a .runar.go backtick literal becomes LF; Go and the other tiers discard it |
| N-441 | DONE `30f1837af` | Zig sdk-output tool fails r062-wallet-ordinary and r062-wallet-unsound-acknowledged with DeployFailed when rebuilt; batteries passed only because conformance/sdk-output/tools/zig-sdk-tool/zig-out was a stale Oct 4 build |
| N-442 | DONE `9af2941bd` | N-300's accepting control N300-go-sighash-public-method.runar.go sits in conformance/negatives/ under the N\d+- name the rejection-parity scan treats as must-reject: 7 tiers red in rejection-parity.test.ts |
| N-443 | DONE `f319c6670` | N-138 fallout: fold-ON test pins in f160-bytestring-case-fold-parity and n345-bytestring-builtin-equality-parity still encode the orphaned operand pushes, and fold-execution.test.ts's 'folding changes the bytes' premise no longer holds (fold-ON == fold-OFF == 0055939c) |
| N-444 | DONE `4acf6028b` | N-441's ci.yml conformance line added sdk-runner-stale-tool.test.ts that pnpm test:ci does not run: n283-test-ci-mirrors-ci-contract.test.ts red |
| N-445 | DONE `8a6e51ef8` | N-152 fallout: the Go CLI's default sourceMap makes the Bn254Pairing artifact 831 MB (sourceMap 566 MB): the --ir-roundtrip runner's 256 MiB capture cap kills it and no JS consumer can JSON.parse it |
| N-446 | DONE `ed80bb58b` | Go refuses valid contracts under fold-ON (the default): "conditional needs 1 placeholder push(es) to balance a NON-EMPTY then/else arm" on constant-condition if branches |
| N-447 | DONE `aed52e922` | runar-zig has no native self.addOutput/addDataOutput; 7 examples/zig contracts stay compile-check only |
| N-448 | DONE `fdccb6142` | ByteString literal "006a" is hex to the compiler but 4 ASCII bytes natively (Zig and Go native packages) |
| N-449 | DONE `71d7e45ed` | ByteString-literal hex diagnostics have no line:col on the 8 non-.ts surfaces in TS (and so in all tiers); Python falls back to the statement location |
| N-450 | DONE `f762808bc` | stack-frame-mutation-pins fold-ON pins for BranchResidue and EmptyElseGuard are stale after N-446 |
| N-451 | DONE `c646db81c` | Decompiler templates-data.json and coverage.json stale after N-446; StackTrackerReproV10min recovery fell from template to raw_script |
| N-452 | STALE | conformance/mutation registry (mutants.json, run-mutation.ts, README) cites stale 05-stack-lower.ts lines 1125/2406 for the stack-frame pins |
| N-453 | DONE `c3942072c` | A StatefulContext parameter on a private helper is counted as a real parameter: Zig fails with "method parameter 'ctx' is not on the stack ... SilentOpZeroRefused" |
| N-454 | DONE `ee28daa67` | Ruby Zig parser "unknown parent class" message interpolates undefined @file (should be @file_name) |
| N-455 | DONE `0262f911e` | lean-golden RED: N-382 comment edits moved the Lean model fingerprint; 3 live anchors (babybear, merkle-proof, state-covenant) carry the old fingerprint |
| N-456 | DONE `9c0b82fb8` | No conformance golden contains the fused OP_CHECKMULTISIGVERIFY (0xaf); peephole fusion of assert(checkMultiSig(...)) is unpinned across tiers |
| N-457 | DONE `d662746f9` | Lean pipeline never applies the proved checkMultiSigVerifyFuse: emits OP_CHECKMULTISIG OP_VERIFY (ae 69) where all 7 tiers emit OP_CHECKMULTISIGVERIFY (af) |
| N-458 | DONE `f3e14ac47` | Java BuiltinRegistry "Sha256Hash" row is accepted by typecheck but StackLower rejects it as an unknown builtin (dead alias; GoParser maps Sha256Hash to sha256) |
| N-459 | DONE `cac874519` | Ruby typecheck table declares computeStateOutput; a source call passes typecheck then fails in stack lowering with an unclear "value _codePart not found on stack" instead of a refusal diagnostic |
| N-460 | DONE `29fefac4d` | EC fusing rules R10/R11 stay net-negative (~+400 KB) when an inner ecMul/ecMulGen is still referenced elsewhere |
| N-461 | DONE `67a90ba59` | Three landed conformance tests are run by nothing in CI (checkmultisigverify-golden-pin, ec-optimizer/ec-fusion-dce, ec-optimizer/ec-nested-rewrite) |
| N-462 | DONE `2f2b78f5b` | Rust .runar.zig typecheck diagnostics for the N-447 ctx-variant point at 112:4 / 116:0 where the other 6 tiers say 107:8 / 113:8 |
| N-463 | DONE `6a67f9a57` | Typecheck diagnostics on .runar.ts point at the statement/method (or nowhere) instead of the offending expression in Go/Rust/Python/Ruby/Java/Zig (N15-N17, N200-N209) |
| N-464 | DONE `366a37e26` | verifyRabinSig 4th-argument validator anchors at different nodes across tiers and surfaces (N220-N228) |
| N-465 | DONE `319f696de` | N-460 removability guard gives up shared-inner wins (n112 shape 424,655 -> 848,481; two R9 readers 848,169 -> 1,272,003) |
| N-466 | DONE `35b172bb2` | Python and Ruby source maps emit 0:0 on 284 tic-tac-toe opcodes where TS maps lines 147 and 172-179 (FixedArray synthetic statements) |
| N-467 | DONE `a9b8a32e9` | Zig source maps diverge from TS on 34 examples: ~1,054 opcodes TS maps are unmapped (per-arm locs, method-tail ops, FixedArray dispatch) and ~3.9M expanded-builtin opcodes inherit the surrounding binding loc where TS leaves them unmapped; boolean-logic max opcode index 31 vs TS 32 |
| N-468 | DONE `59e9b0ee6` | Java source maps diverge from TS on 32 examples: ~77.8k builtin-expansion opcodes TS maps are unmapped, and 220 opcodes TS leaves unmapped are mapped (boolean-logic, fixed-array-*, nested-if, conditional-data-output, companion-verifier, tic-tac-toe, token-ft) |
| N-469 | DONE `2d140c5d3` | Zig Rabin pubkey-provenance collector matches mc.object=="this" but parse_zig.zig keeps method-call objects as "self", so Zig over-refuses a private helper param bound to self.pk (RabinPosPlain.runar.zig; other 6 tiers accept, md5 b6197d95...) |
| N-470 | DONE `b5a10bc9c` | `_ = ctx;` (native-Zig idiom for an unused StatefulContext param) is refused by all 7 tiers as "Undefined variable 'ctx'", so a native .runar.zig contract with an unused ctx param cannot be compile-checked |
| N-471 | DONE `faad43a8a` | Java AnfLower.lowerStatement still differs from TS in two latent source-location rules (restores prevLoc in finally; keeps inherited loc when stmt has none) |
| N-472 | DONE `5fd01aab2` | Residual typecheck anchor gaps after N-463: unary operands, parenthesised composites, literal left operands, Zig ctx-dropped call args |
| N-473 | DONE `d11150d02` | 45 mf-on (fold-ON multi-format) rows are VACUOUS: 5 Go-only fixtures x 9 formats verify nothing |
| N-474 | DONE `f8bc684d1` | 150 vitest tests skip in the full run; triage each skipped file to run, gate in CI, or delete |
| N-475 | DONE `2b4f1eda6` | Zig stateful-artifact `anf` JSON prints sourceLoc columns 1-based where TS prints 0-based |
| N-476 | DONE `aa520ddb3` | Zig frontend/input_limits.zig statementLoc returns null for return statements, so input-limit diagnostics on a return lose their anchor |
| N-477 | DONE `66fdb7588` | runar-rb issue100/106/123 specs turn a FAILED compile into `skip 'Ruby compiler CLI unavailable'` (fail-open) |
| N-478 | DONE `e3b6facc1` | compilers/go tests skip on 'source not found', so a moved/renamed fixture becomes a silent skip |
| N-479 | DONE `f93fd3c6e` | evm-guest proof.postcard (3 Go skip sites) is not in git and no CI job regenerates it, so those tests never run |
| N-480 | DONE `8d0112f32` | Live BRC-100 wallet tests never run: add an in-repo mock BRC-100 wallet server to the CI integration job |
| N-481 | DONE `75166c8cc` | Zig artifact anf: constructor super(...) bindings carry no sourceLoc where TS gives them the super statement's location |
| N-482 | DONE `fd4b660a3` | N-474 gate-classification test flags its own skipIf/runIf patterns once committed |
| N-483 | DONE `b80e1c9a7` | Rust wallet-client live test passes silently when RUNAR_WALLET_ENDPOINT is unset under --ignored |
| N-484 | DONE `91da4daef` | Ruby wallet_client_spec sentinel example passes with no assertions |
| N-485 | DONE `337cd9cbf` | Zig SDK RUN_LIVE_HTTP tests depend on httpbin.org and are skipped in CI |
| N-486 | DONE `f848e23d0` | evm-guest fixture README states the wrong proof.postcard size |
| N-487 | DONE `9b6dd62a7` | Zig tier: constructor super bindings on .runar.sol/.runar.zig (and synthesized go/rs/move) lack sourceLoc vs TS |
| N-488 | DONE `1d4958133` | addOutput state-value argument diagnostics anchor at the statement in non-TS tiers |
| N-489 | DONE `345f45021` | Remaining binary/unary operand anchor shapes not pinned after N-472 |
| N-490 | DONE `60c95efc1` | Synthesized constructors carry a fake sourceLoc 1:0 instead of the contract declaration position |
| N-491 | DONE `27d143492` | TS: non-.ts surface parsers do not record operand source locations like .runar.ts does |
| N-492 | DONE `d358f75f9` | Zig tier: operand type-error anchors on non-.ts surfaces diverge from TS |
| N-493 | DONE `ce0133d08` | Go tier: operand type-error anchors on non-.ts surfaces diverge from TS |
| N-494 | DONE `f52a9cb1c` | Rust tier: operand type-error anchors on non-.ts surfaces diverge from TS |
| N-495 | DONE `41ea8f119` | Python tier: operand type-error anchors on non-.ts surfaces diverge from TS |
| N-496 | DONE `7e49e3848` | Ruby tier: operand type-error anchors on non-.ts surfaces diverge from TS |
| N-497 | DONE `6ebcb9d65` | Java tier: operand type-error anchors on non-.ts surfaces diverge from TS |
| N-498 | DONE `303215f1f` | Python and Ruby artifacts carry no ANF sourceLoc on any binding |
| N-499 | DONE `34756cb9b` | Rust ANF sourceLoc columns are 1-based while TS emits 0-based |
| N-500 | DONE `38d6e4039` | Rust .runar.zig parser takes MethodNode.source_location after parsing the body |
| N-501 | DONE `059caef32` | Zig tier refuses a stateful .runar.zig contract with no init while the other six tiers accept it |
| N-502 | DONE `483c2d2c0` | Rust .runar.zig parser adds no implicit param-to-property assignments for an init without struct-return |
| N-503 | DONE `9b1df961f` | Several tiers Rust-DSL parsers accept only attributed structs; TS also accepts a bare struct |
| N-504 | STALE | Rust tier accepts an if-expression operand in .runar.rs that TS and most tiers refuse to parse |
| N-505 | DONE `ecf4b332e` | Comparison/equality operands (==, !=, <, <=, >, >=) are outside the N-491 anchor matrix; Rust Java-surface comparisons are unlocated |
| N-506 | DONE `a10679271` | Stale doc comments: AST sourceLocation "only the .runar.ts parser sets it" after N-491..N-497 |
| N-507 | DONE `8d8fcea73` | Other Rust surface parsers may locate methods/constructors after the body |
| N-508 | DONE `85d542cc7` | Zig prints no location for method-anchored validation errors |
| N-509 | DONE `ff8d5ed71` | conformance/n498-python-ruby-anf-sourceloc.test.ts is not executed by any CI workflow |
| N-510 | DONE `04c885de3` | Rust compiler is ~40x slower than Go on the N-264 D=32x120 composite-nesting input; n264 parity test times out under load |
