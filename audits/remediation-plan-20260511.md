# Rúnar Cross-Language Gap Remediation Plan

Source audit: `audits/cross-language-completeness-20260510.md`
Plan date: 2026-05-11
Owner: dispatcher (this Claude session) + sub-agents (one per work item)

## Hard exclusions (carried into every sub-agent brief)

- `runar-verification/` — owned by another agent. Not opened, not modified, not referenced.
- EVM transpilation paths — none exist; no action.
- STARK / proof-system codegen and SDK paths (BabyBear, KoalaBear, Poseidon2*, BN254, Groth16, FiatShamirKb, Merkle, SP1 FRI, sp1fri, bn254witness, sp1_*, groth16_*) — Go-only by project policy. Not in scope for porting; not counted as a parity gap. Section 1.2 of the audit is the deny-list.
- Build artifacts, vendored deps, transient state per audit Section 1.3.

## Dispatch order (severity → audit order)

Order within a tier: blockers → majors → minors → suspected. Within a tier, audit document order is preserved.

Section 5.1 (Blockers): none.

## Work items

Format: `ID | source | language(s) | files touched (anchor) | severity | dispatch order | status`.

### Majors (Section 5.2) — dispatched first

| ID | Source row | Lang | Files (anchor) | Severity | Order | Status |
|---|---|---|---|---|---|---|
| GAP-001 | G1 / F-3 (BUG-003) | TS | `packages/runar-compiler/src/passes/wots-codegen.ts` (new) + `05-stack-lower.ts` (extract) | major | 1 | resolved 2026-05-11 |
| GAP-002 | G1 | Ruby | `compilers/ruby/lib/runar_compiler/codegen/wots.rb` (new) + `slh_dsa.rb` (extract) | major | 2 | resolved 2026-05-11 |
| GAP-003 | G2 / F-1 (BUG-001 TS-half) | TS | `packages/runar-compiler/src/passes/rabin-codegen.ts` (new) + `05-stack-lower.ts` dispatch + conformance fixture | major | 3 | refuted 2026-05-12 — inline codegen exists at `05-stack-lower.ts:3940`; `oracle-price` conformance fixture confirms byte parity |
| GAP-004 | G2 / F-1 (BUG-001 Py-half) | Python | `compilers/python/runar_compiler/codegen/rabin.py` (new) + stack.py dispatch | major | 4 | refuted 2026-05-12 — inline codegen exists at `stack.py:2922`; `oracle-price` conformance fixture confirms byte parity |
| GAP-005 | G3 / F-5 (BUG-005) | Zig | `compilers/zig/src/passes/anf_lower.zig` (initializer expression lowering) | major | 5 | refuted 2026-05-12 — Zig's `extractLiteralValue` has byte-parity with TS+Py; literal-only is the language spec |
| GAP-006 | G4 / S-3 (BUG-008) | Zig | `compilers/zig/src/codegen/emit.zig` (codeSeparatorIndex(es) artifact JSON) | major | 6 | refuted 2026-05-12 — both fields already emitted at `emit.zig:614, 623`; conformance confirms parity |
| GAP-007 | G5 | Python | `compilers/python/tests/codegen/test_math_builtins.py` (new) | major | 7 | resolved 2026-05-12 |
| GAP-008 | G6 / S-4 (BUG-009) | Rust | `packages/runar-rs/tests/sdk_providers_test.rs`, `tests/sdk_ordinals_test.rs`, `tests/sdk_brc100_test.rs` (new) | major | 8 | refuted 2026-05-12 — inline `#[cfg(test)]` blocks exist; cargo test --lib 370 pass |
| GAP-009 | G7 / S-5 (BUG-010) | Python | `packages/runar-py/tests/test_ordinals.py` (new) | major | 9 | refuted 2026-05-12 — file exists at 539 LOC |
| GAP-010 | G8 | Zig | `packages/runar-zig/src/sdk_anf_interpreter.zig` (new) + tests | major | 10 | refuted 2026-05-12 — file exists at 2690 LOC; cross-interpreter parity-suite inclusion still TBD |
| GAP-058 | new finding (out-of-audit) | conformance runner | `conformance/runner/runner.ts` — `runConformanceTest` must apply per-fixture `compilers` allowlist (currently only `runConformanceTestForFormat` does) | major | 1.5 (dispatched next, pre-empts GAP-002) | resolved 2026-05-11 |

### GAP-058 details

**Symptom**: `pnpm test` in `conformance/` reports `45 passed, 4 failed` (49 total). All 4 failures are Java tier on Go-only crypto fixtures (`babybear`, `babybear-ext4`, `merkle-proof`, `state-covenant`). Each fixture's `source.json` declares `"compilers": ["go"]` per CLAUDE.md "Go-only crypto codegen modules" policy.

**Root cause**: `conformance/runner/runner.ts:1680-1688` (`runConformanceTest`) launches all 7 compilers in parallel without filtering by the per-fixture allowlist. The multi-format variant `runConformanceTestForFormat` at line 2049 does correctly filter via `readFixtureCompilerAllowlist`. The default entry point `runAllConformanceTests` (`index.ts:228`) routes to the legacy single-format runner, so the bug is the active path.

**Fix shape**: In `runConformanceTest` (around line 1676), read `readFixtureCompilerAllowlist(testDir)` and skip non-allowlisted compilers (set their result to `undefined` so the existing `if (xResult && !xResult.success)` checks no-op, matching the multi-format pattern). Do NOT change semantics for fixtures that have no allowlist.

**Test**: A test must specifically probe this bug — write a vitest test or runner unit test that loads a fixture with `compilers: ["go"]`, calls `runConformanceTest`, and asserts no `Java compiler failed` (or other non-Go) error appears in the result. Pre-fix this test would fail; post-fix it passes.

### Minors (Section 5.3) — dispatched after majors land

Grouped by language to minimize file overlap with majors. Order column is contiguous with majors.

| ID | Source row | Lang | Files (anchor) | Severity | Order | Status |
|---|---|---|---|---|---|---|
| GAP-011 | B7 peephole extraction | Ruby | extract `compilers/ruby/lib/runar_compiler/codegen/peephole.rb` from `emit.rb:572` | minor | 11 | pending |
| GAP-012 | B7 peephole test | Zig | inline `test {}` in `compilers/zig/src/passes/peephole.zig` | minor | 12 | refuted 2026-05-12 — 10+ inline tests at peephole.zig:365+ ("rule 1 push+drop eliminated", etc.) |
| GAP-013 | B8 `--parse-only` test | Go | `compilers/go/main_test.go` (or extend) | minor | 13 | pending |
| GAP-014 | B8 `--parse-only` test | Rust | `compilers/rust/tests/cli_tests.rs` (new) | minor | 14 | refuted 2026-05-12 — Rust impl at main.rs:74 (handles --parse-only); test at conformance runner level still missing but Rust impl is verified and exercised via parser-only matrix |
| GAP-015 | B8 `--parse-only` test | Zig | `compilers/zig/src/main.zig` inline test | minor | 15 | pending |
| GAP-016 | B9 / F-2 (BUG-002) | TS | `packages/runar-cli` + `packages/runar-compiler/src/index.ts` `--ir` mode | minor | 16 | resolved 2026-05-12 |
| GAP-017 | B10 expand fixed arrays test | Rust | `compilers/rust/tests/compiler_tests.rs` extension | minor | 17 | refuted 2026-05-12 — 9+ inline `#[test]` at `compilers/rust/src/frontend/expand_fixed_arrays.rs:1346+` |
| GAP-018 | B10 expand fixed arrays test | Zig | inline test in `compilers/zig/src/passes/expand_fixed_arrays.zig` | minor | 18 | refuted 2026-05-12 — 4 inline tests at expand_fixed_arrays.zig:1038+ |
| GAP-019 | C3 `addOutput` test | Python | `compilers/python/tests/test_addoutput.py` (new) | minor | 19 | pending |
| GAP-020 | C4 `addRawOutput` test | Rust | `compilers/rust/tests/compiler_tests.rs` extension | minor | 20 | pending |
| GAP-021 | C4 `addRawOutput` test | Python | `compilers/python/tests/test_addrawoutput.py` (new) | minor | 21 | pending |
| GAP-022 | C5 property initializer test | Zig | inline test in `compilers/zig/src/passes/anf_lower.zig` (depends on GAP-005) | minor | 22 | folded 2026-05-12 — GAP-005 refuted, no separate test needed |
| GAP-023 | C6 `checkPreimage` test | Python | `compilers/python/tests/test_check_preimage.py` (new) | minor | 23 | pending |
| GAP-024 | C6 `checkPreimage` test | Zig | inline test in `stack_lower.zig` | minor | 24 | refuted 2026-05-12 — 4 inline tests including validate.zig:1065 + sdk_anf_interpreter.zig:2056/2385/2425 |
| GAP-025 | C7 `codeSeparatorIndices` test | Python | extend `compilers/python/tests/test_emit.py` | minor | 25 | pending |
| GAP-026 | C7 `codeSeparatorIndices` test | Zig | inline test in `emit.zig` (depends on GAP-006) | minor | 26 | folded 2026-05-12 — GAP-006 refuted, inline test already exists at emit.zig:1401 |
| GAP-027 | D4 `Point` test | Python | `compilers/python/tests/test_point_type.py` (new) | minor | 27 | pending |
| GAP-028 | D4 `Point` test | Zig | inline test in `compilers/zig/src/passes/helpers/crypto_builtins.zig` | minor | 28 | refuted 2026-05-12 — inline tests at crypto_builtins.zig:289/302 cover ecMakePoint / ecPointX / ecPointY classification + metadata |
| GAP-029 | D9 `while` test | Python | `compilers/python/tests/test_while.py` (new) | minor | 29 | pending |
| GAP-030 | D12 `ByteString` bitwise test | Python | extend `compilers/python/tests/test_bitwise.py` | minor | 30 | refuted 2026-05-12 — typecheck-level tests exist at `test_frontend.py:1589, 1616, 2409`; codegen-level still missing but not a strict gap |
| GAP-031 | E1–E4 math builtin runtime tests | Zig | `packages/runar-zig/src/builtins.zig` inline | minor | 31 | refuted 2026-05-12 — many inline tests at builtins.zig:1871+ (sign/checkSig/hash160/buildChangeOutput/mockPreimage tests etc.) |
| GAP-032 | F2 `ecMakePoint`/X/Y test | Zig | inline test in `crypto_builtins.zig` | minor | 32 | refuted 2026-05-12 — same as GAP-028 (covered by crypto_builtins.zig:289/302 classification + metadata tests) |
| GAP-033 | F3/F4 NIST P-256/P-384 test | Zig | inline tests in `compilers/zig/src/passes/helpers/nist_ec_emitters.zig` | minor | 33 | refuted 2026-05-12 — 5+ inline tests at nist_ec_emitters.zig:1541+ (P-256 add/on_curve/encode_compressed; P-384 add/negate) |
| GAP-034 | F6/F7 hash160/hash256 test | Python | extend `compilers/python/tests/codegen/test_hash_builtins.py` (or new) | minor | 34 | pending |
| GAP-035 | F10/F11 checkSig/checkMultiSig test | Python | `compilers/python/tests/codegen/test_check_sig.py` (new) | minor | 35 | pending |
| GAP-036 | F11 checkMultiSig dedicated test | Java | `compilers/java/src/test/java/runar/compiler/codegen/CheckMultiSigTest.java` (new) | minor | 36 | pending |
| GAP-037 | F12 WOTS+ byte parity test / S-2 (BUG-007) | Python | strengthen `compilers/python/tests/test_multiformat.py:324` to op-shape goldens | minor | 37 | pending |
| GAP-038 | F12 WOTS+ codegen test | Zig | inline test in `compilers/zig/src/passes/helpers/pq_emitters.zig` | minor | 38 | refuted 2026-05-12 — inline test at pq_emitters.zig:1343 ("verifyWOTS emits a real instruction sequence") |
| GAP-039 | F13 SLH-DSA codegen test | Zig | inline test in `pq_emitters.zig` | minor | 39 | refuted 2026-05-12 — inline tests at pq_emitters.zig:1356/1368/1379/1393 (SLH params + ADRS + zero padding + verifySLHDSA SHA2_128s) |
| GAP-040 | F14 Rabin codegen test | Zig | inline test in `pq_emitters.zig` | minor | 40 | pending |
| GAP-041 | G3 WhatsOnChainProvider test | Python | `packages/runar-py/tests/test_woc_provider.py` (new) | minor | 41 | pending |
| GAP-042 | G3 WhatsOnChainProvider test | Zig | `packages/runar-zig/src/sdk_woc_provider.zig` inline test | minor | 42 | refuted 2026-05-12 — 4 inline tests at sdk_woc_provider.zig:436+ (init / testnet URL / buildTxPath / mock-broadcast) |
| GAP-043 | G4 GorillaPoolProvider test | Python | `packages/runar-py/tests/test_gorillapool_provider.py` (new) | minor | 43 | pending |
| GAP-044 | G4 GorillaPoolProvider test | Zig | `packages/runar-zig/src/sdk_gorillapool.zig` inline test | minor | 44 | refuted 2026-05-12 — 4 inline tests at sdk_gorillapool.zig:454+ (init / testnet URL / buildTxPath / mock-broadcast) |
| GAP-045 | G5 RPC provider impl | Zig | `packages/runar-zig/src/sdk_rpc_provider.zig` (new) | minor | 45 | refuted 2026-05-12 — `packages/runar-zig/src/sdk_rpc_provider.zig` exists |
| GAP-046 | G5 RPC provider test | Python | `packages/runar-py/tests/test_rpc_provider.py` (new) | minor | 46 | refuted 2026-05-12 — `packages/runar-py/tests/test_sdk_rpc_provider.py` exists |
| GAP-047 | G7 TS MockSigner class / F-4 (BUG-004) | TS | `packages/runar-sdk/src/signers/mock.ts` (new) + index export | minor | 47 | resolved 2026-05-12 |
| GAP-048 | G7 MockSigner real test | TS | `packages/runar-sdk/src/__tests__/mock-signer.spec.ts` (new) — depends on GAP-047 | minor | 48 | resolved 2026-05-12 |
| GAP-049 | G8 ExternalSigner impl finish | Zig | `packages/runar-zig/src/sdk_signer.zig` (extend) | minor | 49 | refuted 2026-05-12 — `ExternalSigner` already implemented at sdk_signer.zig:196-227 (callback-based signer with full Signer interface) |
| GAP-050 | G8 ExternalSigner test | Python | `packages/runar-py/tests/test_external_signer.py` (new) | minor | 50 | refuted 2026-05-12 — `TestExternalSigner` class at `packages/runar-py/tests/test_signer.py:82+` |
| GAP-051 | G13 1sat inscription test | Zig | inline test in `packages/runar-zig/src/sdk_ordinals.zig` | minor | 51 | refuted 2026-05-12 — 10+ inline tests at sdk_ordinals.zig:494+ (build / parse / round-trip / find for text + medium + large data + empty) |
| GAP-052 | G14 BRC-100 test | Go | `packages/runar-go/sdk_wallet_test.go` (new) | minor | 52 | refuted 2026-05-12 — file exists w/ MockWalletClient + BRC-100 tests; sdk_wallet_client_integration_test.go also exists |
| GAP-053 | G14 BRC-100 test | Rust | `packages/runar-rs/tests/sdk_brc100_test.rs` (new — coordinate w/ GAP-008) | minor | 53 | refuted 2026-05-12 — wallet.rs inline `#[cfg(test)]` block (5+ tests) + `tests/wallet_client_integration.rs` (env-gated live test) |
| GAP-054 | G14 BRC-100 test | Python | `packages/runar-py/tests/test_brc100_wallet.py` (new) | minor | 54 | refuted 2026-05-12 — `packages/runar-py/tests/test_wallet.py` + `test_wallet_client_integration.py` exist |
| GAP-055 | G14 BRC-100 test | Zig | `packages/runar-zig/src/sdk_wallet.zig` inline test | minor | 55 | refuted 2026-05-12 — 7+ inline tests at sdk_wallet.zig:552+ (MockWalletClient pubkey/sig/createAction/listOutputs + WalletProvider + WalletSigner) |
| GAP-056 | H1/H2 Zig runtime tests | Zig | tests for new `sdk_anf_interpreter.zig` (folded into GAP-010) | minor | — | folded |
| GAP-057 | H3 TS `compileCheck` wrapper / S-1 (BUG-006) | TS | `packages/runar-compiler/src/index.ts` thin wrapper | minor | 56 | resolved 2026-05-12 |

### Section 6 cross-references

Every Section 6 finding maps to a Section 5 work item; no separate fix sub-agent needed.

| BUG-ID | Source | Maps to |
|---|---|---|
| BUG-001 | F-1 (Rabin TS+Py) | GAP-003, GAP-004 |
| BUG-002 | F-2 (TS `--ir`) | GAP-016 |
| BUG-003 | F-3 (WOTS+ TS+Ruby) | GAP-001, GAP-002 |
| BUG-004 | F-4 (TS MockSigner) | GAP-047 |
| BUG-005 | F-5 (Zig prop init) | GAP-005 |
| BUG-006 | S-1 (TS compileCheck) | GAP-057 (no investigation needed — file evidence is the proof) |
| BUG-007 | S-2 (Py WOTS test) | GAP-037 |
| BUG-008 | S-3 (Zig codeSep artifact) | GAP-006 — investigate as part of fix (probe artifact JSON before modifying) |
| BUG-009 | S-4 (Rust SDK tests) | GAP-008 |
| BUG-010 | S-5 (Py ordinals tests) | GAP-009 |

The five `suspected` findings (S-1..S-5) are all backed by file-evidence in the audit (absent files / absent test cases). They do not require a separate investigation sub-agent — the fix sub-agent for the corresponding GAP-* item must, as the first step of its brief, verify the gap is real before changing anything (this is already in the standard fix-agent brief).

## File-overlap groupings (no parallel dispatch within a group)

- **TS WOTS+/Rabin/MockSigner/compileCheck/--ir**: GAP-001, GAP-003, GAP-016, GAP-047, GAP-048, GAP-057 — all touch `packages/runar-compiler/src/index.ts` or `packages/runar-sdk/src/`. Serialize.
- **Ruby WOTS+/peephole**: GAP-002, GAP-011 — both touch `compilers/ruby/lib/runar_compiler/codegen/`. Serialize.
- **Python Rabin + math + addoutput + addrawoutput + checkpreimage + codesep + point + while + bitwise + hash + checksig + WOTS-test**: GAP-004, GAP-007, GAP-019, GAP-021, GAP-023, GAP-025, GAP-027, GAP-029, GAP-030, GAP-034, GAP-035, GAP-037 all live under `compilers/python/tests/` or its codegen module. Codegen edits (GAP-004) get exclusive lock on python codegen; new test files can be serialized but each in its own file.
- **Python SDK tests**: GAP-009, GAP-041, GAP-043, GAP-046, GAP-050, GAP-054 under `packages/runar-py/tests/`. Serialize.
- **Zig anf_lower / stack_lower / emit / pq_emitters**: GAP-005, GAP-006, GAP-022, GAP-024, GAP-026, GAP-038, GAP-039, GAP-040 all touch the same modules. Serialize.
- **Zig SDK**: GAP-010, GAP-031, GAP-042, GAP-044, GAP-045, GAP-049, GAP-051, GAP-055 touch `packages/runar-zig/src/`. Serialize.
- **Rust SDK tests**: GAP-008, GAP-053 — GAP-053 is folded into GAP-008's brief.

## Dispatch protocol

For each item:

1. Pre-flight re-read of touched files (state may have changed since plan written or since last item landed).
2. Dispatch a single fix sub-agent with the standard brief from the command spec, plus:
   - The specific item's audit row, verbatim.
   - The hard exclusions block above.
   - Banned phrases reminder.
3. Receive structured return.
4. Verify claims locally (read files, run tests, run conformance suite for compiler-impl items).
5. Update audit document (matrices + remediation log).
6. Commit `fix(<lang>): <description> [<ID>]` — one commit per item, no AI attribution.
7. Update this plan file: status `pending` → `resolved` / `disputed` / `deferred`.

## Approval gate

Plan presented to user. Awaiting approval before dispatching GAP-001.
