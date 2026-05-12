# Rúnar Cross-Language Completeness & Correctness Audit

Date: 2026-05-10 (UTC, audit start)
Scope: Read-only analysis of the seven shipping language implementations of the Rúnar TypeScript-to-Bitcoin Script compiler, their SDKs, examples, and integration tests. EVM/STARK proof-system primitives and the Lean4 verification project are explicitly excluded per project policy (see Section 1).

---

## Remediation log

Tracks the work of `audits/remediation-plan-20260511.md`. One row per resolved/refuted/deferred item, in chronological order. Maps 1:1 to git history.

| Date | ID | Status | Commit | One-line summary |
|---|---|---|---|---|
| 2026-05-11 | GAP-001 / BUG-003 (TS half) | resolved | `977168ed` | TS WOTS+ codegen extracted to `packages/runar-compiler/src/passes/wots-codegen.ts`; byte-frozen golden test added; conformance `post-quantum-wots` passes. |
| 2026-05-11 | GAP-058 (new finding) | resolved | `8f774f3f` | `runConformanceTest` now applies the per-fixture `compilers` allowlist (mirrors `runConformanceTestForFormat`). 4 prior failures (`babybear`, `babybear-ext4`, `merkle-proof`, `state-covenant` — Java tier on Go-only crypto) now pass. New regression test at `conformance/runner/__tests__/allowlist-filter.test.ts`. Conformance: 49/49 pass. |
| 2026-05-11 | GAP-002 / BUG-003 (Ruby half) | resolved | `c5c76a98` | Ruby WOTS+ codegen extracted to `compilers/ruby/lib/runar_compiler/codegen/wots.rb` (230 LOC); dispatch in `stack.rb:2121`. Frozen-fingerprint regression test added. Ruby compiler tests + conformance 49/49 pass. |
| 2026-05-12 | GAP-003 / GAP-004 / BUG-001 (F-1) | refuted | (no commit; doc only) | TS + Python both have inline Rabin codegen (`05-stack-lower.ts:3940` + `stack.py:2922`) the audit author missed. Conformance fixture `oracle-price` exercises `verifyRabinSig` and the 49/49 cross-tier hex parity check passes — TS / Python / Go / Zig emit byte-identical Rabin Script vs Ruby/Java/Rust. Architectural inline-vs-module distinction noted in updated F14 row; not extracted in this cycle (user-confirmed scope decision). |
| 2026-05-12 | GAP-005 / BUG-005 / F-5 | refuted | `d6cf1cd0` | Zig's `extractLiteralValue` (`anf_lower.zig:197-213`) has byte-for-byte parity with TS's (`04-anf-lower.ts:84-101`) and Python's (`anf_lower.py:224-237`). All three handle BigIntLiteral / BoolLiteral / ByteStringLiteral / unary `-` of BigIntLiteral; non-literal initializers are rejected by the language spec, not a Zig limitation. Conformance `property-initializers` passes 49/49. |
| 2026-05-12 | GAP-006 / S-3 / BUG-008 | refuted | `d6cf1cd0` | Zig's `compilers/zig/src/codegen/emit.zig:614, 623` already emits both `codeSeparatorIndex` and `codeSeparatorIndices` JSON fields (matches TS shape); inline test at line 1401 asserts presence; conformance 49/49 confirms cross-tier byte parity. |
| 2026-05-12 | GAP-009 / S-5 / BUG-010 | refuted | `d6cf1cd0` | `packages/runar-py/tests/test_ordinals.py` exists at 539 LOC. Audit author missed the file (or it landed mid-audit). |
| 2026-05-12 | GAP-010 | refuted | `d6cf1cd0` | `packages/runar-zig/src/sdk_anf_interpreter.zig` exists at 2690 LOC. Audit author missed the file (or it landed mid-audit). Cross-interpreter parity-suite inclusion (`conformance/anf-interpreter/cross-interpreter*.test.ts`) needs separate verification before this can be marked fully resolved at the test-coverage level (Section 4 H1/H2 row remains ⚠️ pending that check). |
| 2026-05-12 | GAP-007 | resolved | `6d1c86c2` | Added `compilers/python/tests/codegen/test_math_builtins.py` (351 LOC, 65 per-builtin tests). All 16 math builtins now have op-count goldens + load-bearing tail assertions + unrolled-iteration-count assertions (pow=32, sqrt=16, gcd=256, log2=64). Python suite 820→885 (+65). |
| 2026-05-12 | GAP-008 / S-4 / BUG-009 | refuted | `0d38e3a0` | Audit applied TS/Python convention (separate `tests/` files) to Rust where inline `#[cfg(test)] mod tests` is the standard idiom. Each cited SDK module has a working inline test block (woc_provider, gorillapool, rpc_provider, signer, ordinals, wallet). `cargo test --lib` for `packages/runar-rs` shows 370 passed / 0 failed including these blocks. Sections 3 (G3, G4, G5, G8, G11, G12, G14) Rust cells upgraded from ❌ to ✅. |
| 2026-05-12 | GAP-052 | refuted | `0d38e3a0` | Go BRC-100 tests exist at `packages/runar-go/sdk_wallet_test.go` (MockWalletClient + BRC-100 round-trip) + `sdk_wallet_client_integration_test.go`. Section 4 G14 Go cell upgraded from ⚠️ to ✅. |
| 2026-05-12 | GAP-053 | refuted | `0d38e3a0` | Rust BRC-100 tests exist via `packages/runar-rs/src/sdk/wallet.rs` inline `#[cfg(test)]` block (5+ tests) plus `packages/runar-rs/tests/wallet_client_integration.rs` (env-gated live BRC-100 round-trip). |
| 2026-05-12 | GAP-022 / GAP-026 / GAP-056 | folded | (no commit) | Each is a "test for X" minor whose underlying X was refuted under GAP-005 / GAP-006 / GAP-010 respectively. No separate test work needed. |
| 2026-05-12 | GAP-030 | refuted | (no commit) | Python ByteString bitwise has typecheck-level coverage at `compilers/python/tests/test_frontend.py:1589` (`test_typecheck_bitwise_on_bytestring_ok`), `:1616` (NOT variant), and `:2409` (mixed-type rejection). Audit's "no dedicated test" claim was overstated; codegen-level dedicated test still missing but the typecheck cell is no longer a gap. |
| 2026-05-12 | GAP-016 / F-2 / BUG-002 + GAP-047 / F-4 / BUG-004 + GAP-048 + GAP-057 / S-1 / BUG-006 (TS architectural batch) | resolved | `0aa914df` | TS now ships: (a) `compile --from-ir <path> [--hex]` CLI input mode wired to new `compileFromANF` + `loadANFFromJSON` exports in `packages/runar-compiler/src/index.ts:401, 452` — flag named `--from-ir` not `--ir` because `--ir` is already an output flag; (b) public `MockSigner` class in `packages/runar-sdk/src/signers/mock.ts` exported from signers + SDK barrel (deterministic fixed pubkey + fixed 72-byte DER-shaped sig); (c) `compileCheck(source, fileName?, options?)` named export in `packages/runar-compiler/src/index.ts:495` (frontend-only — parse/validate/typecheck, throws on diagnostic). 22 new tests pass: compile-check (9), mock-signer (10), compile-from-ir (3). vitest packages/runar-compiler+sdk+cli: 3109 passed. Conformance: 49/49. |
| 2026-05-12 | GAP-019 / 021 / 023 / 025 / 027 / 029 / 034 / 035 / 037 / 041 / 043 (Python test batch) | resolved | `1ac08bf0` | Added 11 new dedicated assertion-grade Python tests (125 tests total, +80 compiler / +45 SDK). Files: `tests/codegen/{test_addoutput,test_addrawoutput,test_check_preimage,test_codeseparator,test_point_type,test_hash_builtins,test_check_sig,test_wots_byte_parity}.py` + `tests/test_while.py` + `packages/runar-py/tests/{test_woc_provider,test_gorillapool_provider}.py`. Op-count goldens, opcode-shape assertions, and (for WOTS+) byte-identical hex against the conformance fixture's expected-script.hex. Python compiler suite: 965 passed (was 885, +80). Python SDK: 471 passed, 1 skipped (was 426, +45). Conformance: 49/49 (one flake on first run, recovered on re-run). |
| 2026-05-12 | GAP-012/014/017/018/024/028/031/032/033/038/039/042/044/045/046/049/050/051/054/055 (batch) | refuted | `aca625e4` | Audit applied wrong-language test convention (separate test files for Rust + Zig) where inline `#[test]` (Rust) or inline `test "name" {}` (Zig) blocks are the standard idiom. Per-item file:line citations in `audits/remediation-plan-20260511.md`. Highlights: GAP-012 peephole.zig:365+, 014 main.rs:74, 017 expand_fixed_arrays.rs:1346+, 018 expand_fixed_arrays.zig:1038+, 024 sdk_anf_interpreter.zig:2056/2385/2425, 028+032 crypto_builtins.zig:289/302, 031 builtins.zig:1871+, 033 nist_ec_emitters.zig:1541+, 038 pq_emitters.zig:1343, 039 pq_emitters.zig:1356/1393, 042 sdk_woc_provider.zig:436+, 044 sdk_gorillapool.zig:454+, 045 sdk_rpc_provider.zig (file exists), 049 sdk_signer.zig:196 ExternalSigner impl, 050 test_signer.py:82 TestExternalSigner, 051 sdk_ordinals.zig:494+, 055 sdk_wallet.zig:552+, 046 test_sdk_rpc_provider.py, 054 test_wallet.py + test_wallet_client_integration.py. |
| 2026-05-12 | GAP-011 | refuted | (pending) | Ruby ships `compilers/ruby/lib/runar_compiler/codegen/optimizer.rb` (`RunarCompiler::Codegen.optimize_stack_ops`) as a SEPARATE peephole module — not "embedded in emit phase" as the audit claimed. The `emit.rb:572` reference the audit cited is a one-line comment ("Note: peephole optimization … is handled by optimize_stack_ops in optimizer.rb, which runs before emit") pointing to the actual implementation. Section 3 row B7 Ruby cell upgraded from ⚠️ to ✅. |

---

## 1. Excluded paths

These paths are excluded from analysis by the audit charter and/or the project policy in `CLAUDE.md`. Every path is enumerated; if any new STARK/proof-system path is discovered mid-audit, it is appended here with the note "added during audit".

### 1.1. Lean4 verification project (charter exclusion #1)
- `runar-verification/` — entire directory. Owned by another agent. No file in this tree was opened, read for analysis, or counted.

### 1.2. STARK / EVM / proof-system primitives (charter exclusion #2; project policy: Go-only)

#### TypeScript proof-system codegen (partial ports, not conformance targets)
- `packages/runar-compiler/src/passes/babybear-codegen.ts`
- `packages/runar-compiler/src/passes/koalabear-codegen.ts`
- `packages/runar-compiler/src/passes/poseidon2-koalabear-codegen.ts`
- `packages/runar-compiler/src/passes/poseidon2-merkle-codegen.ts`
- `packages/runar-compiler/src/passes/bn254-codegen.ts`
- `packages/runar-compiler/src/passes/fiat-shamir-kb-codegen.ts`
- `packages/runar-compiler/src/passes/merkle-codegen.ts`
- `packages/runar-compiler/src/__tests__/babybear.test.ts`
- `packages/runar-compiler/src/__tests__/babybear-integration.test.ts`
- `packages/runar-compiler/src/__tests__/merkle.test.ts`
- `packages/runar-compiler/src/__tests__/merkle-integration.test.ts`
- `packages/runar-compiler/dist/**` (build output that mirrors the above)

#### Go proof-system codegen (Go-only — reference implementation, not part of cross-language comparison)
- `compilers/go/codegen/babybear.go`
- `compilers/go/codegen/koalabear.go`
- `compilers/go/codegen/poseidon2_koalabear.go`
- `compilers/go/codegen/poseidon2_koalabear_test.go`
- `compilers/go/codegen/poseidon2_merkle.go`
- `compilers/go/codegen/bn254.go`
- `compilers/go/codegen/bn254_ext.go`
- `compilers/go/codegen/bn254_flat.go`
- `compilers/go/codegen/bn254_flat_test.go`
- `compilers/go/codegen/bn254_generic_test.go`
- `compilers/go/codegen/bn254_differential_test.go`
- `compilers/go/codegen/bn254_frobenius_test.go`
- `compilers/go/codegen/bn254_pairing.go`
- `compilers/go/codegen/bn254_pairing_export_test.go`
- `compilers/go/codegen/bn254_groth16.go`
- `compilers/go/codegen/bn254_groth16_test.go`
- `compilers/go/codegen/bn254_groth16_subgroup_test.go`
- `compilers/go/codegen/fiat_shamir_kb.go`
- `compilers/go/codegen/fiat_shamir_kb_test.go`
- `compilers/go/codegen/merkle.go`
- `compilers/go/codegen/sp1_fri.go`
- `compilers/go/codegen/sp1_fri_test.go`
- `compilers/go/codegen/sp1_fri_ext4.go`
- `compilers/go/codegen/sp1_fri_ext4_test.go`
- `compilers/go/codegen/msm_bind_ifstruct_test.go`
- `compilers/go/compiler/groth16_wa.go`
- `compilers/go/compiler/groth16_wa_test.go`
- `compilers/go/compiler/groth16_wa_msm_expose_test.go`
- `compilers/go/compiler/sp1_fri_compile_test.go`
- `compilers/go/groth16_wa_cli_test.go`

#### Rust proof-system codegen (partial ports)
- `compilers/rust/src/codegen/babybear.rs`
- `compilers/rust/src/codegen/koalabear.rs`
- `compilers/rust/src/codegen/poseidon2_koalabear.rs`
- `compilers/rust/src/codegen/poseidon2_merkle.rs`
- `compilers/rust/src/codegen/bn254.rs`
- `compilers/rust/src/codegen/fiat_shamir_kb.rs`
- `compilers/rust/src/codegen/merkle.rs`

#### Python proof-system codegen (partial ports)
- `compilers/python/runar_compiler/codegen/babybear.py`
- `compilers/python/runar_compiler/codegen/koalabear.py`
- `compilers/python/runar_compiler/codegen/poseidon2_koalabear.py`
- `compilers/python/runar_compiler/codegen/poseidon2_merkle.py`
- `compilers/python/runar_compiler/codegen/bn254.py`
- `compilers/python/runar_compiler/codegen/fiat_shamir_kb.py`
- `compilers/python/runar_compiler/codegen/merkle.py`

#### Zig proof-system codegen (partial ports)
- `compilers/zig/src/passes/helpers/babybear_emitters.zig`
- `compilers/zig/src/passes/helpers/koalabear_emitters.zig`
- `compilers/zig/src/passes/helpers/poseidon2_koalabear.zig`
- `compilers/zig/src/passes/helpers/poseidon2_merkle.zig`
- `compilers/zig/src/passes/helpers/bn254_emitters.zig`
- `compilers/zig/src/passes/helpers/fiat_shamir_kb.zig`
- `compilers/zig/src/passes/helpers/merkle_emitters.zig`

#### Ruby proof-system codegen (partial ports)
- `compilers/ruby/lib/runar_compiler/codegen/babybear.rb`
- `compilers/ruby/lib/runar_compiler/codegen/koalabear.rb`
- `compilers/ruby/lib/runar_compiler/codegen/poseidon2_koalabear.rb`
- `compilers/ruby/lib/runar_compiler/codegen/poseidon2_merkle.rb`
- `compilers/ruby/lib/runar_compiler/codegen/bn254.rb`
- `compilers/ruby/lib/runar_compiler/codegen/fiat_shamir_kb.rb`
- `compilers/ruby/lib/runar_compiler/codegen/merkle.rb`

#### Java proof-system codegen
- Java has no proof-system codegen files in `compilers/java/` (verified by `find compilers/java -iname "*babybear*" -o -iname "*bn254*" -o -iname "*groth16*"` returning empty). This is consistent with the Go-only project policy. The matrices in Section 3/4 do not include rows for these families.

#### Go SDK proof-system support
- `packages/runar-go/bn254.go`
- `packages/runar-go/bn254_identity_safety_test.go`
- `packages/runar-go/bn254_real_pairing.go`
- `packages/runar-go/bn254_real_pairing_test.go`
- `packages/runar-go/bn254_vectors_test.go`
- `packages/runar-go/babybear_ext4_test.go`
- `packages/runar-go/babybear_vectors_test.go`
- `packages/runar-go/koalabear_vectors_test.go`
- `packages/runar-go/poseidon2_kb_test.go`
- `packages/runar-go/sdk_groth16.go`
- `packages/runar-go/sdk_groth16_test.go`
- `packages/runar-go/bn254witness/` (entire subdirectory: `sp1.go`, `groth16_script_test.go`, `sp1_script_test.go`)
- `packages/runar-go/sp1fri/` (entire subdirectory: `air_fib.go`, `fri.go`, `koalabear.go`, `koalabear_test.go`, `poseidon2.go`, `poseidon2_test.go`, `verify.go`)

#### Repo-root research vectors
- `tests/babybear-vectors.test.ts`
- `tests/babybear-ext4-vectors.test.ts`
- `tests/fri-colinearity-vectors.test.ts`
- `tests/merkle-vectors.test.ts`
- `tests/vectors/babybear_*.json`, `tests/vectors/koalabear_*.json`, `tests/vectors/bn254_*.json`, `tests/vectors/fri_colinearity.json`, `tests/vectors/poseidon2_koalabear.json`
- `tests/vectors/sp1/**`
- `tests/generate-vectors/**` (Rust/Go vector generators)

#### Integration: STARK / Groth16 / SP1 tests
- `integration/go/babybear_test.go`
- `integration/go/babybear_vectors_test.go`
- `integration/go/koalabear_vectors_test.go`
- `integration/go/poseidon2_kb_vectors_test.go`
- `integration/go/bn254_vectors_test.go`
- `integration/go/fri_colinearity_vectors_test.go`
- `integration/go/groth16_test.go`
- `integration/go/groth16_wa_test.go`
- `integration/go/groth16_wa_msm_test.go`
- `integration/go/groth16_wa_sdk_test.go`
- `integration/go/groth16_wa_stateful_test.go`
- `integration/go/sp1_fri_poc_test.go`
- `integration/go/helpers/groth16.go`
- `integration/go/contracts/Groth16Verifier.runar.go`
- `integration/go/contracts/StatelessGroth16WA.runar.go`
- `integration/go/contracts/RollupGroth16WA.runar.go`
- `integration/go/contracts/RollupGroth16WAMSM.runar.go`
- `integration/go/contracts/Sp1FriVerifierPoc.runar.go`
- `integration/go/contracts/BasefoldVerifier.runar.go`
- `integration/python/test_babybear.py`
- `integration/ts/babybear.test.ts`
- `integration/ts/babybear-vectors.test.ts`
- `integration/rust/tests/babybear.rs`
- `integration/zig/src/babybear_test.zig`
- `integration/ruby/spec/babybear_spec.rb`

#### Examples: STARK demo contracts
- `examples/go/babybear/**`
- `examples/go/babybear-ext4/**`
- `examples/go/merkle-proof/**`
- `examples/go/sp1_verifier_main.go`
- `examples/go/sp1_fri_verifier_main.go`
- `examples/go/SP1Verifier_README.md`
- `examples/go/SP1Verifier.groth16.vk.json`
- `examples/{ts,sol,move,python,rust,java,ruby,zig}/babybear/**`
- `examples/{ts,sol,move,python,rust,java,ruby,zig}/babybear-ext4/**`
- `examples/{ts,sol,move,python,rust,java,ruby,zig}/merkle-proof/**`

#### Documentation
- `docs/sp1-proof-format.md`
- `docs/sp1-fri-verifier.md`
- `docs/fri-verifier-measurements.md`
- `spec/groth16_wa_vk.schema.json`

### 1.3. Build artifacts / vendored dependencies / transient state (not source)
- `node_modules/` (all locations)
- `compilers/rust/target/`, `compilers/python/dist/`, `packages/*/dist/`, `packages/runar-rs/target/`, `packages/runar-rs-macros/target/`
- `compilers/zig/zig-out/`, `compilers/zig/.zig-cache/`, `packages/runar-zig/zig-out/`, `packages/runar-zig/.zig-cache/`
- `compilers/java/build/`, `compilers/java/.gradle/`, `packages/runar-java/build/`, `packages/runar-java/.gradle/`
- `compilers/python/.pytest_cache/`, `compilers/python/runar_compiler/__pycache__/` and any `__pycache__`
- `compilers/python/runar_compiler.egg-info/`, `packages/runar-py/runar.egg-info/`
- `packages/runar-zig/zig-pkg/bsvz-0.1.0-wvsL-bhiFQBIsxHKnVuig_LNW5O19aGntcqbZu3XWfjZ/` (vendored `bsvz` library — third-party SPV/BSV utilities, not Rúnar code)
- `examples/end2end-example/zig/zig-pkg/bsvz-…/`
- `examples/zig/zig-pkg/bsvz-…/`
- `integration/zig/zig-pkg/bsvz-…/`
- `.git/`, `.changeset/`, `.idea/`, `.turbo/`, `.pytest_cache/`, `.planning/`, `.claude/`
- `conformance/.tmp/` (transient runner artifacts — temporary fixtures emitted by the conformance runner; not part of the source tree)
- `conformance/node_modules/`

### 1.4. EVM
No EVM bytecode emission, EVM transpiler, or EVM-targeted codegen exists in this repository. The only references to "EVM" found are documentation comments contrasting the BSV UTXO model against EVM (`docs/cross-covenant-pattern.md:93`, `docs/formats/solidity.md:13,396`) and a one-line comment in `packages/runar-testing/src/__tests__/analyzer.test.ts:28`. These are kept in scope — they are descriptive prose, not code paths.

---

## 2. Implementation inventory

There are seven shipping language implementations of the Rúnar compiler. Each has a compiler under `compilers/<lang>/`, an SDK under `packages/runar-<lang>/`, contract examples under `examples/<lang>/`, and on-chain integration tests under `integration/<lang>/`. All LOC counts below are **after excluding Section 1 paths** (proof-system primitives, `runar-verification/`, build outputs, vendored deps). LOC = total physical lines via `wc -l`; not SLOC.

### TypeScript (reference)
- **Compiler path:** `packages/runar-compiler/` (with shared types from `packages/runar-ir-schema/`, base classes from `packages/runar-lang/`, interpreter/VM in `packages/runar-testing/`, CLI in `packages/runar-cli/`)
- **SDK path:** `packages/runar-sdk/`
- **Examples:** `examples/ts/`, `examples/sol/`, `examples/move/`
- **Integration:** `integration/ts/`
- **Build/test commands:**
  - Build: `pnpm install && pnpm run build` (uses turbo + tsc)
  - Tests: `npx vitest run`
- **Test framework:** vitest 1.x
- **Compiler LOC (excl. proof codegen):** src=31,990 test=20,920
- **TS support packages LOC:**
  - `runar-sdk`: src=7,171 test=8,772
  - `runar-testing`: src=10,212 test=6,679
  - `runar-lang`: src=3,027 test=1,477
  - `runar-ir-schema`: src=1,287 test=697
  - `runar-cli`: src=2,364 test=909

### Go
- **Compiler path:** `compilers/go/` (subdirs: `frontend/`, `ir/`, `codegen/`, `compiler/`)
- **SDK path:** `packages/runar-go/`
- **Examples:** `examples/go/`
- **Integration:** `integration/go/`
- **Build/test commands:**
  - Build (compiler): `cd compilers/go && go build ./...`
  - Tests (compiler): `cd compilers/go && go test ./...`
  - Tests (SDK): `cd packages/runar-go && go test ./...`
- **Test framework:** stdlib `testing`
- **Compiler LOC (excl. proof codegen):** src=34,001 test=20,745
- **SDK LOC (excl. proof support):** src=12,045 test=7,056

### Rust
- **Compiler path:** `compilers/rust/` (`src/{frontend,ir,codegen}`, integration-style tests under `compilers/rust/tests/`)
- **SDK path:** `packages/runar-rs/` (plus `packages/runar-rs-macros/` proc-macro crate)
- **Examples:** `examples/rust/`
- **Integration:** `integration/rust/`
- **Build/test commands:**
  - Build: `cd compilers/rust && cargo build`
  - Tests: `cd compilers/rust && cargo test`
  - SDK tests: `cd packages/runar-rs && cargo test`
- **Test framework:** built-in `#[test]` + `cargo test`
- **Compiler LOC (excl. proof codegen):** src=45,939 test=9,172
- **SDK LOC:** `runar-rs` src=18,141 test=292; `runar-rs-macros` src=103 test=92

### Python
- **Compiler path:** `compilers/python/runar_compiler/` (subdirs: `frontend/`, `ir/`, `codegen/`); tests in `compilers/python/tests/`
- **SDK path:** `packages/runar-py/runar/`
- **Examples:** `examples/python/`
- **Integration:** `integration/python/`
- **Build/test commands:**
  - Tests (compiler): `cd compilers/python && python3 -m pytest`
  - Tests (SDK): `cd packages/runar-py && python3 -m pytest`
- **Test framework:** pytest (declared in `pyproject.toml`)
- **Compiler LOC (excl. proof codegen):** src=30,621 test=14,425
- **SDK LOC:** src=9,286 test=5,696

### Zig
- **Compiler path:** `compilers/zig/` (`src/{ir,passes,codegen,tests}`); test entry `src/test_main.zig`
- **SDK path:** `packages/runar-zig/src/`
- **Examples:** `examples/zig/`
- **Integration:** `integration/zig/`
- **Build/test commands:**
  - Build: `cd compilers/zig && zig build`
  - Tests: `cd compilers/zig && zig build test`
  - SDK tests: `cd packages/runar-zig && zig build test`
- **Test framework:** Zig built-in `test {}` blocks
- **Compiler LOC (excl. proof codegen):** src=46,828 test=2,137
  - Note: Zig tests live inside source files as `test {}` blocks, not in separate files. The 2,137 test figure counts only the `src/tests/*.zig`, `test_main.zig`, and `test_conformance.zig` files. Inline test blocks are counted in the src figure.
- **SDK LOC:** src=17,340 test=1,016

### Ruby
- **Compiler path:** `compilers/ruby/lib/runar_compiler/` (subdirs: `frontend/`, `ir/`, `codegen/`); tests in `compilers/ruby/test/`
- **SDK path:** `packages/runar-rb/lib/`
- **Examples:** `examples/ruby/`
- **Integration:** `integration/ruby/`
- **Build/test commands:**
  - Tests (compiler): `cd compilers/ruby && rake test`
  - Tests (SDK): `cd packages/runar-rb && bundle exec rspec` (or `rake spec`)
- **Test framework:** Minitest (compiler, files named `test_*.rb`); RSpec (SDK, under `spec/`)
- **Compiler LOC (excl. proof codegen):** src=31,214 test=5,868
- **SDK LOC:** src=10,689 test=8,039

### Java
- **Compiler path:** `compilers/java/src/main/java/runar/compiler/` (subdirs: `frontend/`, `ir/`, `passes/`, `codegen/`, `canonical/`, `builtins/`); tests in `compilers/java/src/test/java/`
- **SDK path:** `packages/runar-java/src/main/java/runar/lang/`
- **Examples:** `examples/java/`
- **Integration:** `integration/java/`
- **Build/test commands:**
  - Build: `cd compilers/java && gradle build`
  - Tests (compiler): `cd compilers/java && gradle test`
  - Tests (SDK): `cd packages/runar-java && gradle test`
  - System gradle: 9.4.1 (verified via `gradle --version`); CLAUDE.md notes "no wrapper committed; gradle 8.5+ required"
- **Test framework:** JUnit 5 (Jupiter)
- **Compiler LOC (excl. proof codegen, which Java does not ship):** src=30,308 test=10,759
- **SDK LOC:** src=11,421 test=6,799

### Inventory summary table

| Language    | Compiler src | Compiler test | SDK src | SDK test | Test framework |
|-------------|-------------:|--------------:|--------:|---------:|----------------|
| TypeScript  | 31,990       | 20,920        | 7,171   | 8,772    | vitest         |
| Go          | 34,001       | 20,745        | 12,045  | 7,056    | stdlib testing |
| Rust        | 45,939       | 9,172         | 18,141  | 292      | cargo test     |
| Python      | 30,621       | 14,425        | 9,286   | 5,696    | pytest         |
| Zig         | 46,828       | 2,137¹        | 17,340  | 1,016    | zig test       |
| Ruby        | 31,214       | 5,868         | 10,689  | 8,039    | Minitest+RSpec |
| Java        | 30,308       | 10,759        | 11,421  | 6,799    | JUnit 5        |

¹ Zig inline `test {}` blocks live inside source files and are counted under "src"; the "test" column is only the separate test entry files.

---

## Methodology note for sections 3 and 4

Sections 3 and 4 cover seven language implementations × ~88 feature rows × two dimensions (implementation + test), i.e. ~1,232 cells per matrix. Population workflow:

1. Seven `Explore` agents each enumerated one language. Each returned a candidate file:line for every row.
2. The audit author re-verified every cell flagged as suspicious during synthesis (round line numbers, claims that contradicted `CLAUDE.md`, ABSENT/PARTIAL calls that conflicted with other agents). Specific verifications run during synthesis are noted in Section 6 ("Correctness findings → Agent-report inaccuracies").
3. Citations are at **file granularity** by default. A **`file:line` citation indicates a line that was directly read and verified** during synthesis (>40 such verifications were performed). A **bare `file` citation** indicates the file exists and contains the feature at some line in the file, verified by `grep -l` or `find`, but the specific line was not personally read.
4. Where the audit author found an agent's PRESENT/ABSENT call to be wrong, the cell reflects the corrected status and the divergence is logged in Section 6.

Status symbols in section 3 (implementation):
- `✅` — implemented, with file (and line where verified)
- `⚠️` — partial implementation, with reason
- `❌` — absent
- `N/A` — feature does not apply to this language

Status symbols in section 4 (tests):
- `✅` — tested with direct assertions on output bytes / opcodes / behavior, with test file path
- `⚠️` — test exists but assertions are weak (e.g. only "doesn't throw", only length, no expected output comparison)
- `❌` — no test
- `N/A` — feature absent in this implementation (matches a `❌` or `N/A` in section 3)

Columns: **TS** = TypeScript (runar-compiler + runar-sdk + runar-testing + runar-lang + runar-ir-schema + runar-cli, per the user gate decision); **Go**; **Rs** = Rust; **Py** = Python; **Zig**; **Rb** = Ruby; **Ja** = Java.

---

## 3. Feature matrix

### A. Frontend parsers (9 surface formats × 7 compilers)

The conformance charter requires every compiler to parse every format, even those whose IR/hex output is gated by a `compilers` allowlist. The all-tier `--parser-only` matrix is enforced in CI (`conformance/runner/runner.ts`).

| Row | Feature | TS | Go | Rs | Py | Zig | Rb | Ja |
|-----|---------|----|----|----|----|----|----|----|
| A1 | Parse `.runar.ts` | ✅ packages/runar-compiler/src/passes/01-parse.ts:72 | ✅ compilers/go/frontend/parser.go | ✅ compilers/rust/src/frontend/parser.rs:43 | ✅ compilers/python/runar_compiler/frontend/parser_ts.py | ✅ compilers/zig/src/passes/parse_ts.zig:63 | ✅ compilers/ruby/lib/runar_compiler/frontend/parser_ts.rb:409 | ✅ compilers/java/src/main/java/runar/compiler/frontend/TsParser.java:44 |
| A2 | Parse `.runar.sol` | ✅ packages/runar-compiler/src/passes/01-parse-sol.ts | ✅ compilers/go/frontend/parser_sol.go | ✅ compilers/rust/src/frontend/parser_sol.rs | ✅ compilers/python/runar_compiler/frontend/parser_sol.py | ✅ compilers/zig/src/passes/parse_sol.zig | ✅ compilers/ruby/lib/runar_compiler/frontend/parser_sol.rb:352 | ✅ compilers/java/src/main/java/runar/compiler/frontend/SolParser.java |
| A3 | Parse `.runar.move` | ✅ packages/runar-compiler/src/passes/01-parse-move.ts | ✅ compilers/go/frontend/parser_move.go | ✅ compilers/rust/src/frontend/parser_move.rs | ✅ compilers/python/runar_compiler/frontend/parser_move.py | ✅ compilers/zig/src/passes/parse_move.zig | ✅ compilers/ruby/lib/runar_compiler/frontend/parser_move.rb:378 | ✅ compilers/java/src/main/java/runar/compiler/frontend/MoveParser.java |
| A4 | Parse `.runar.go` | ✅ packages/runar-compiler/src/passes/01-parse-go.ts | ✅ compilers/go/frontend/parser_gocontract.go | ✅ compilers/rust/src/frontend/parser_gocontract.rs | ✅ compilers/python/runar_compiler/frontend/parser_go.py | ✅ compilers/zig/src/passes/parse_go.zig | ✅ compilers/ruby/lib/runar_compiler/frontend/parser_go.rb:471 | ✅ compilers/java/src/main/java/runar/compiler/frontend/GoParser.java |
| A5 | Parse `.runar.rs` | ✅ packages/runar-compiler/src/passes/01-parse-rust.ts | ✅ compilers/go/frontend/parser_rustmacro.go | ✅ compilers/rust/src/frontend/parser_rustmacro.rs | ✅ compilers/python/runar_compiler/frontend/parser_rust.py | ✅ compilers/zig/src/passes/parse_rust.zig | ✅ compilers/ruby/lib/runar_compiler/frontend/parser_rust.rb:477 | ✅ compilers/java/src/main/java/runar/compiler/frontend/RustParser.java |
| A6 | Parse `.runar.py` | ✅ packages/runar-compiler/src/passes/01-parse-python.ts | ✅ compilers/go/frontend/parser_python.go | ✅ compilers/rust/src/frontend/parser_python.rs | ✅ compilers/python/runar_compiler/frontend/parser_python.py | ✅ compilers/zig/src/passes/parse_python.zig | ✅ compilers/ruby/lib/runar_compiler/frontend/parser_python.rb:556 | ✅ compilers/java/src/main/java/runar/compiler/frontend/PyParser.java |
| A7 | Parse `.runar.zig` | ✅ packages/runar-compiler/src/passes/01-parse-zig.ts | ✅ compilers/go/frontend/parser_zig.go | ✅ compilers/rust/src/frontend/parser_zig.rs | ✅ compilers/python/runar_compiler/frontend/parser_zig.py | ✅ compilers/zig/src/passes/parse_zig.zig | ✅ compilers/ruby/lib/runar_compiler/frontend/parser_zig.rb:386 | ✅ compilers/java/src/main/java/runar/compiler/frontend/ZigParser.java |
| A8 | Parse `.runar.rb` | ✅ packages/runar-compiler/src/passes/01-parse-ruby.ts | ✅ compilers/go/frontend/parser_ruby.go | ✅ compilers/rust/src/frontend/parser_ruby.rs | ✅ compilers/python/runar_compiler/frontend/parser_ruby.py | ✅ compilers/zig/src/passes/parse_ruby.zig | ✅ compilers/ruby/lib/runar_compiler/frontend/parser_ruby.rb:653 | ✅ compilers/java/src/main/java/runar/compiler/frontend/RbParser.java |
| A9 | Parse `.runar.java` | ✅ packages/runar-compiler/src/passes/01-parse-java.ts | ✅ compilers/go/frontend/parser_java.go | ✅ compilers/rust/src/frontend/parser_java.rs | ✅ compilers/python/runar_compiler/frontend/parser_java.py | ✅ compilers/zig/src/passes/parse_java.zig | ✅ compilers/ruby/lib/runar_compiler/frontend/parser_java.rb:439 | ✅ compilers/java/src/main/java/runar/compiler/frontend/JavaParser.java |

### B. Pipeline passes and CLI

| Row | Feature | TS | Go | Rs | Py | Zig | Rb | Ja |
|-----|---------|----|----|----|----|----|----|----|
| B1 | Validate pass | ✅ packages/runar-compiler/src/passes/02-validate.ts:32 | ✅ compilers/go/frontend/validator.go | ✅ compilers/rust/src/frontend/validator.rs | ✅ compilers/python/runar_compiler/frontend/validator.py | ✅ compilers/zig/src/passes/validate.zig:48 | ✅ compilers/ruby/lib/runar_compiler/frontend/validator.rb:12 | ✅ compilers/java/src/main/java/runar/compiler/passes/Validate.java |
| B2 | Typecheck pass | ✅ packages/runar-compiler/src/passes/03-typecheck.ts:33 | ✅ compilers/go/frontend/typecheck.go | ✅ compilers/rust/src/frontend/typecheck.rs:29 | ✅ compilers/python/runar_compiler/frontend/typecheck.py:44 | ✅ compilers/zig/src/passes/typecheck.zig:44 | ✅ compilers/ruby/lib/runar_compiler/frontend/typecheck.rb:12 | ✅ compilers/java/src/main/java/runar/compiler/passes/Typecheck.java |
| B3 | ANF lowering pass | ✅ packages/runar-compiler/src/passes/04-anf-lower.ts:45 | ✅ compilers/go/frontend/anf_lower.go:17 | ✅ compilers/rust/src/frontend/anf_lower.rs:35 | ✅ compilers/python/runar_compiler/frontend/anf_lower.py:66 | ✅ compilers/zig/src/passes/anf_lower.zig:52 | ✅ compilers/ruby/lib/runar_compiler/frontend/anf_lower.rb:28 | ✅ compilers/java/src/main/java/runar/compiler/passes/AnfLower.java |
| B4 | Stack lowering pass | ✅ packages/runar-compiler/src/passes/05-stack-lower.ts | ✅ compilers/go/codegen/stack.go:3856 | ✅ compilers/rust/src/codegen/stack.rs | ✅ compilers/python/runar_compiler/codegen/stack.py | ✅ compilers/zig/src/passes/stack_lower.zig:4037 | ✅ compilers/ruby/lib/runar_compiler/codegen/stack.rb:3416 | ✅ compilers/java/src/main/java/runar/compiler/passes/StackLower.java |
| B5 | Hex emit pass | ✅ packages/runar-compiler/src/passes/06-emit.ts | ✅ compilers/go/codegen/emit.go:509 | ✅ compilers/rust/src/codegen/emit.rs | ✅ compilers/python/runar_compiler/codegen/emit.py | ✅ compilers/zig/src/codegen/emit.zig | ✅ compilers/ruby/lib/runar_compiler/codegen/emit.rb:578 | ✅ compilers/java/src/main/java/runar/compiler/passes/Emit.java |
| B6 | Constant folding optimizer (`--disable-constant-folding`) | ✅ packages/runar-compiler/src/optimizer/constant-fold.ts:442 | ✅ compilers/go/frontend/constant_fold.go:557 | ✅ compilers/rust/src/lib.rs:211 | ✅ compilers/python/runar_compiler/frontend/constant_fold.py | ✅ compilers/zig/src/passes/constant_fold.zig:545 | ✅ compilers/ruby/lib/runar_compiler/frontend/constant_fold.rb:516 | ✅ compilers/java/src/main/java/runar/compiler/passes/ConstantFold.java |
| B7 | Peephole optimizer | ✅ packages/runar-compiler/src/optimizer/peephole.ts:448 | ✅ compilers/go/codegen/optimizer.go:16 | ✅ compilers/rust/src/codegen/optimizer.rs | ✅ compilers/python/runar_compiler/codegen/optimizer.py | ✅ compilers/zig/src/passes/peephole.zig:82 | ✅ compilers/ruby/lib/runar_compiler/codegen/optimizer.rb (`RunarCompiler::Codegen.optimize_stack_ops` — separate file; `emit.rb:572` is a comment pointing to it) | ✅ compilers/java/src/main/java/runar/compiler/passes/Peephole.java |
| B8 | CLI `--parse-only` mode | ✅ packages/runar-compiler/src/index.ts:69 | ✅ compilers/go/main.go:44 | ✅ compilers/rust/src/main.rs:44 | ✅ compilers/python/runar_compiler/__main__.py:64 | ✅ compilers/zig/src/main.zig:51 | ✅ compilers/ruby/lib/runar_compiler/cli.rb:79 | ✅ compilers/java/src/main/java/runar/compiler/Cli.java:136 |
| B9 | CLI `--ir` input mode (IR JSON) | ✅ packages/runar-cli/src/bin.ts (`compile --from-ir <path> [--hex]`) → `compileFromANF` + `loadANFFromJSON` exports in `packages/runar-compiler/src/index.ts:401, 452` | ✅ compilers/go/main.go:38 | ✅ compilers/rust/src/main.rs:18 | ✅ compilers/python/runar_compiler/__main__.py:34 | ✅ compilers/zig/src/main.zig:80 | ✅ compilers/ruby/lib/runar_compiler/cli.rb:55 | ✅ compilers/java/src/main/java/runar/compiler/Cli.java:37 |
| B10 | Expand-fixed-arrays pass | ✅ packages/runar-compiler/src/passes/03b-expand-fixed-arrays.ts:105 | ✅ compilers/go/frontend/expand_fixed_arrays.go | ✅ compilers/rust/src/frontend/expand_fixed_arrays.rs | ✅ compilers/python/runar_compiler/frontend/expand_fixed_arrays.py:97 | ✅ compilers/zig/src/passes/expand_fixed_arrays.zig:68 | ✅ compilers/ruby/lib/runar_compiler/frontend/expand_fixed_arrays.rb:63 | ✅ compilers/java/src/main/java/runar/compiler/passes/ExpandFixedArrays.java |

### C. Contract model

| Row | Feature | TS | Go | Rs | Py | Zig | Rb | Ja |
|-----|---------|----|----|----|----|----|----|----|
| C1 | `SmartContract` base class detection | ✅ packages/runar-compiler/src/ir/runar-ast.ts:62 | ✅ compilers/go/frontend/parser.go | ✅ compilers/rust/src/frontend/parser.rs:78 | ✅ compilers/python/runar_compiler/frontend/anf_lower.py:265 | ✅ compilers/zig/src/types/base.zig | ✅ compilers/ruby/lib/runar_compiler/frontend/typecheck.rb:283 | ✅ packages/runar-java/src/main/java/runar/lang/SmartContract.java:20 |
| C2 | `StatefulSmartContract` base class detection | ✅ packages/runar-compiler/src/ir/runar-ast.ts:65 | ✅ compilers/go/frontend/parser.go | ✅ compilers/rust/src/frontend/parser.rs:163 | ✅ compilers/python/runar_compiler/frontend/anf_lower.py:266 | ✅ compilers/zig/src/types/base.zig | ✅ compilers/ruby/lib/runar_compiler/frontend/typecheck.rb:283 | ✅ packages/runar-java/src/main/java/runar/lang/StatefulSmartContract.java:23 |
| C3 | `addOutput` intrinsic (multi-output continuation) | ✅ packages/runar-compiler/src/passes/03-typecheck.ts:963 | ✅ compilers/go/codegen/stack.go:2594 (lowerAddOutput) | ✅ compilers/rust/src/codegen/stack.rs | ✅ compilers/python/runar_compiler/frontend/anf_lower.py:922 | ✅ compilers/zig/src/types/base.zig:163 | ✅ compilers/ruby/lib/runar_compiler/frontend/typecheck.rb:774 | ✅ packages/runar-java/src/main/java/runar/lang/SmartContract.java:32 |
| C4 | `addRawOutput` intrinsic | ✅ packages/runar-compiler/src/passes/03-typecheck.ts:619 | ✅ compilers/go/codegen/stack.go (lowerAddRawOutput) | ✅ compilers/rust/src/codegen/stack.rs | ✅ compilers/python/runar_compiler/frontend/anf_lower.py:932 | ✅ compilers/zig/src/types/base.zig:183 | ✅ compilers/ruby/lib/runar_compiler/frontend/typecheck.rb:778 | ✅ packages/runar-java/src/main/java/runar/lang/SmartContract.java:55 |
| C5 | Property initializers (default values) | ✅ packages/runar-compiler/src/ir/runar-ast.ts:76 | ✅ compilers/go/frontend/parser.go | ✅ compilers/rust/src/frontend/parser.rs:132 | ✅ compilers/python/runar_compiler/frontend/anf_lower.py:71 | ✅ compilers/zig/src/passes/anf_lower.zig:184-213 — `extractLiteralValue` matches TS+Py byte-for-byte; literal-only restriction is the language spec, not a Zig gap | ✅ compilers/ruby/lib/runar_compiler/frontend/anf_lower.rb:400 | ✅ compilers/java/src/main/java/runar/compiler/ir/ast/PropertyNode.java |
| C6 | `checkPreimage` auto-injection at stateful method entry | ✅ packages/runar-compiler/src/passes/03-typecheck.ts:80 | ✅ compilers/go/codegen/stack.go | ✅ compilers/rust/src/codegen/stack.rs:4707 | ✅ compilers/python/runar_compiler/frontend/anf_lower.py:285 | ⚠️ compilers/zig/src/passes/stack_lower.zig — runtime templates present, full auto-injection partial | ✅ compilers/ruby/lib/runar_compiler/frontend/typecheck.rb:45 | ✅ compilers/java/src/main/java/runar/compiler/passes/Typecheck.java |
| C7 | OP_CODESEPARATOR auto-insertion + `codeSeparatorIndex(es)` in artifact | ✅ packages/runar-compiler/src/ir/artifact.ts:163 | ✅ compilers/go/codegen/emit.go:226 | ✅ compilers/rust/src/codegen/stack.rs | ✅ compilers/python/runar_compiler/codegen/emit.py:210 | ✅ compilers/zig/src/codegen/emit.zig:614, 623 (both `codeSeparatorIndex` + `codeSeparatorIndices` JSON fields; inline test at line 1401) | ✅ compilers/ruby/lib/runar_compiler/compiler.rb:350 | ✅ compilers/java/src/main/java/runar/compiler/passes/StackLower.java |

### D. Type system and language constructs

| Row | Feature | TS | Go | Rs | Py | Zig | Rb | Ja |
|-----|---------|----|----|----|----|----|----|----|
| D1 | `bigint` | ✅ packages/runar-compiler/src/ir/runar-ast.ts:24 | ✅ compilers/go/frontend/ast.go | ✅ compilers/rust/src/frontend/ast.rs | ✅ compilers/python/runar_compiler/frontend/ast_nodes.py | ✅ compilers/zig/src/ir/types.zig | ✅ compilers/ruby/lib/runar_compiler/frontend/ast_nodes.rb:221 | ✅ compilers/java/src/main/java/runar/compiler/ir/types/PrimitiveTypeName.java |
| D2 | `bool` | ✅ packages/runar-compiler/src/ir/runar-ast.ts:25 | ✅ compilers/go/frontend/ast.go | ✅ compilers/rust/src/frontend/ast.rs | ✅ compilers/python/runar_compiler/frontend/ast_nodes.py | ✅ compilers/zig/src/ir/types.zig | ✅ compilers/ruby/lib/runar_compiler/frontend/ast_nodes.rb:222 | ✅ compilers/java/src/main/java/runar/compiler/ir/types/PrimitiveTypeName.java |
| D3 | `ByteString` | ✅ packages/runar-compiler/src/ir/runar-ast.ts:26 | ✅ compilers/go/frontend/ast.go | ✅ compilers/rust/src/frontend/ast.rs | ✅ compilers/python/runar_compiler/frontend/ast_nodes.py | ✅ compilers/zig/src/ir/types.zig | ✅ compilers/ruby/lib/runar_compiler/frontend/ast_nodes.rb:223 | ✅ compilers/java/src/main/java/runar/compiler/ir/types/PrimitiveTypeName.java |
| D4 | `Point` (64-byte secp256k1) | ✅ packages/runar-compiler/src/ir/runar-ast.ts:35 | ✅ compilers/go/frontend/ast.go | ✅ packages/runar-rs/src/prelude.rs:62 | ✅ compilers/python/runar_compiler/codegen/ec.py | ✅ compilers/zig/src/ir/types.zig | ✅ compilers/ruby/lib/runar_compiler/frontend/ast_nodes.rb:233 | ✅ compilers/java/src/main/java/runar/compiler/ir/types (Point CustomType) |
| D5 | Fixed-size arrays (`FixedBytes`) | ✅ packages/runar-compiler/src/ir/runar-ast.ts:45 | ✅ compilers/go/frontend/ast.go | ✅ compilers/rust/src/frontend/expand_fixed_arrays.rs | ✅ compilers/python/runar_compiler/frontend/expand_fixed_arrays.py:98 | ✅ compilers/zig/src/passes/expand_fixed_arrays.zig | ✅ compilers/ruby/lib/runar_compiler/frontend/expand_fixed_arrays.rb:63 | ✅ compilers/java/src/main/java/runar/compiler/ir/types/FixedArrayType.java |
| D6 | `assert` (+ message) | ✅ packages/runar-compiler/src/ir/runar-ast.ts | ✅ compilers/go/frontend/typecheck.go | ✅ compilers/rust/src/codegen/stack.rs | ✅ compilers/python/runar_compiler/codegen/stack.py | ✅ compilers/zig/src/passes/anf_lower.zig | ✅ compilers/ruby/lib/runar_compiler/frontend/ast_nodes.rb:159 | ✅ compilers/java/src/main/java/runar/compiler/passes/StackLower.java |
| D7 | `if`/`else` | ✅ runar-ast.ts | ✅ compilers/go/codegen/stack.go | ✅ compilers/rust/src/codegen/stack.rs | ✅ compilers/python/runar_compiler/frontend/anf_lower.py | ✅ compilers/zig/src/passes/anf_lower.zig | ✅ compilers/ruby/lib/runar_compiler/frontend/ast_nodes.rb:121 | ✅ compilers/java/src/main/java/runar/compiler/ir/ast/IfStatement.java |
| D8 | `if` without `else` (control-flow merge) | ✅ packages/runar-compiler/src/__tests__/if-without-else.test.ts (impl traced via 04-anf-lower) | ✅ compilers/go/codegen/stack.go | ✅ compilers/rust/src/codegen/stack.rs | ✅ compilers/python/runar_compiler/frontend/anf_lower.py | ✅ compilers/zig/src/passes/anf_lower.zig | ✅ compilers/ruby/lib/runar_compiler/frontend/ast_nodes.rb | ✅ compilers/java/src/main/java/runar/compiler/passes/AnfLower.java |
| D9 | `while` loops | ✅ runar-ast.ts | ✅ compilers/go/codegen/stack.go | ✅ compilers/rust/src/codegen/stack.rs | ✅ compilers/python/runar_compiler/frontend/anf_lower.py | ✅ compilers/zig/src/passes/anf_lower.zig | ✅ compilers/ruby/lib/runar_compiler/frontend/ast_nodes.rb:130 | ✅ compilers/java/src/main/java/runar/compiler/ir/ast (ForStatement WHILE) |
| D10 | `for` / `for-of` loops | ✅ packages/runar-compiler/src/ir/runar-ast.ts:151 | ✅ compilers/go/codegen/stack.go | ✅ compilers/rust/src/codegen/stack.rs | ✅ compilers/python/runar_compiler/frontend/anf_lower.py | ✅ compilers/zig/src/passes/anf_lower.zig | ✅ compilers/ruby/lib/runar_compiler/frontend/ast_nodes.rb:138 | ✅ compilers/java/src/main/java/runar/compiler/ir/ast/ForStatement.java |
| D11 | Bitwise `& \| ^ ~` on `bigint` | ✅ 05-stack-lower.ts | ✅ compilers/go/codegen/stack.go | ✅ compilers/rust/src/codegen/stack.rs | ✅ compilers/python/runar_compiler/codegen/stack.py:158 | ✅ compilers/zig/src/passes/anf_lower.zig | ✅ compilers/ruby/lib/runar_compiler/codegen/stack.rb | ✅ compilers/java/src/main/java/runar/compiler/passes/StackLower.java |
| D12 | Bitwise `& \| ^ ~` on `ByteString` | ✅ 05-stack-lower.ts | ✅ compilers/go/codegen/stack.go | ✅ compilers/rust/src/codegen/stack.rs | ✅ compilers/python/runar_compiler/codegen/stack.py | ✅ compilers/zig/src/passes/anf_lower.zig | ✅ compilers/ruby/lib/runar_compiler/codegen/stack.rb | ✅ compilers/java/src/main/java/runar/compiler/passes/StackLower.java |
| D13 | Shift `<<` / `>>` | ✅ 05-stack-lower.ts | ✅ compilers/go/codegen/stack.go | ✅ compilers/rust/src/codegen/stack.rs | ✅ compilers/python/runar_compiler/codegen/stack.py:159 | ✅ compilers/zig/src/passes/anf_lower.zig | ✅ compilers/ruby/lib/runar_compiler/codegen/stack.rb | ✅ compilers/java/src/main/java/runar/compiler/passes/StackLower.java |

### E. Math builtins

All 16 math builtins are documented in `CLAUDE.md` as a single closed set. For brevity the table cites the registry/dispatch site per language.

| Row | Builtin | TS | Go | Rs | Py | Zig | Rb | Ja |
|-----|---------|----|----|----|----|----|----|----|
| E1 | `abs` | ✅ 03-typecheck.ts:93 | ✅ frontend/typecheck.go | ✅ codegen/stack.rs:164 | ✅ codegen/stack.py | ✅ stack_lower.zig | ✅ builtins.rb:460 | ✅ BuiltinRegistry.java |
| E2 | `min` | ✅ ditto | ✅ ditto | ✅ codegen/stack.rs:166 | ✅ ditto | ✅ ditto | ✅ stack.rb:1155 | ✅ ditto |
| E3 | `max` | ✅ ditto | ✅ ditto | ✅ codegen/stack.rs:166 | ✅ ditto | ✅ ditto | ✅ stack.rb:1155 | ✅ ditto |
| E4 | `within` | ✅ ditto | ✅ ditto | ✅ codegen/stack.rs:167 | ✅ ditto | ✅ compilers/zig/src/passes/stack_lower.zig:1438 (lowerWithin) | ✅ builtins.rb:542 | ✅ ditto |
| E5 | `safediv` | ✅ ditto | ✅ ditto | ✅ packages/runar-rs/src/prelude.rs:619 | ✅ ditto | ✅ packages/runar-zig/src/builtins.zig:397 | ✅ builtins.rb:460 | ✅ ditto |
| E6 | `safemod` | ✅ ditto | ✅ ditto | ✅ prelude.rs:625 | ✅ ditto | ✅ builtins.zig:402 | ✅ builtins.rb:471 | ✅ ditto |
| E7 | `clamp` | ✅ ditto | ✅ ditto | ✅ prelude.rs:631 | ✅ ditto | ✅ builtins.zig:393 | ✅ builtins.rb:480 | ✅ ditto |
| E8 | `sign` | ✅ ditto | ✅ ditto | ✅ prelude.rs:636 | ✅ ditto | ✅ builtins.zig:407 | ✅ builtins.rb:487 | ✅ ditto |
| E9 | `pow` | ✅ ditto | ✅ ditto | ✅ prelude.rs:641 | ✅ ditto | ✅ builtins.zig | ✅ builtins.rb:494 | ✅ ditto |
| E10 | `mulDiv` | ✅ ditto | ✅ ditto | ✅ prelude.rs:653 | ✅ ditto | ✅ builtins.zig:426 | ✅ builtins.rb:498 | ✅ ditto |
| E11 | `percentOf` | ✅ ditto | ✅ ditto | ✅ prelude.rs:662 | ✅ ditto | ✅ builtins.zig:431 | ✅ stack.rb:1180 | ✅ ditto |
| E12 | `sqrt` | ✅ ditto | ✅ ditto | ✅ prelude.rs:670 | ✅ ditto | ✅ builtins.zig:435 | ✅ builtins.rb:507 | ✅ ditto |
| E13 | `gcd` | ✅ ditto | ✅ ditto | ✅ prelude.rs:687 | ✅ ditto | ✅ builtins.zig | ✅ builtins.rb:520 | ✅ ditto |
| E14 | `divmod` | ✅ ditto | ✅ ditto | ✅ prelude.rs:699 | ✅ codegen/stack.py:130 | ✅ compilers/zig/src/passes/stack_lower.zig:1454 (lowerDivMod) | ✅ builtins.rb:528 | ✅ ditto |
| E15 | `log2` | ✅ ditto | ✅ ditto | ✅ prelude.rs:705 | ✅ ditto | ✅ builtins.zig | ✅ builtins.rb:532 | ✅ ditto |
| E16 | `bool()` cast | ✅ ditto | ✅ codegen/stack.go | ✅ prelude.rs:714 | ✅ codegen/stack.py:134 | ✅ stack_lower.zig | ✅ stack.rb:1100 | ✅ BuiltinRegistry.java |

### F. Crypto + hash + EC builtins (in-scope only)

| Row | Feature | TS | Go | Rs | Py | Zig | Rb | Ja |
|-----|---------|----|----|----|----|----|----|----|
| F1 | secp256k1 EC builtins (`ecAdd`, `ecMul`, `ecMulGen`, `ecNegate`, `ecOnCurve`, `ecModReduce`, `ecEncodeCompressed`) | ✅ packages/runar-compiler/src/passes/ec-codegen.ts | ✅ compilers/go/codegen/ec.go | ✅ packages/runar-rs/src/ec.rs:53 | ✅ compilers/python/runar_compiler/codegen/ec.py | ✅ compilers/zig/src/passes/helpers/ec_emitters.zig:86 | ✅ compilers/ruby/lib/runar_compiler/codegen/ec.rb:124 | ✅ compilers/java/src/main/java/runar/compiler/codegen/Ec.java:47 |
| F2 | `ecMakePoint` / `ecPointX` / `ecPointY` | ✅ 03-typecheck.ts:127 | ✅ compilers/go/codegen/stack.go:4581 (EmitEcMakePoint) | ✅ packages/runar-rs/src/ec.rs:80 | ✅ compilers/python/runar_compiler/codegen/ec.py | ✅ compilers/zig/src/passes/helpers/crypto_builtins.zig:22 | ✅ compilers/ruby/lib/runar_compiler/codegen/ec.rb:145 | ✅ compilers/java/src/main/java/runar/compiler/codegen/Ec.java |
| F3 | NIST P-256 codegen | ✅ packages/runar-compiler/src/passes/p256-p384-codegen.ts | ✅ compilers/go/codegen/p256_p384.go | ✅ compilers/rust/src/codegen/p256_p384.rs | ✅ compilers/python/runar_compiler/codegen/p256_p384.py | ✅ compilers/zig/src/passes/helpers/nist_ec_emitters.zig | ✅ compilers/ruby/lib/runar_compiler/codegen/p256_p384.rb:862 | ✅ compilers/java/src/main/java/runar/compiler/codegen/P256P384.java |
| F4 | NIST P-384 codegen | ✅ p256-p384-codegen.ts | ✅ p256_p384.go | ✅ p256_p384.rs | ✅ p256_p384.py | ✅ nist_ec_emitters.zig | ✅ p256_p384.rb:938 | ✅ P256P384.java |
| F5 | `sha256` | ✅ 03-typecheck.ts:68 | ✅ frontend/typecheck.go | ✅ packages/runar-rs/src/prelude.rs:213 | ✅ codegen/stack.py:117 | ✅ packages/runar-zig/src/builtins.zig:147 | ✅ builtins.rb:40 | ✅ BuiltinRegistry.java:58 |
| F6 | `hash160` | ✅ 03-typecheck.ts:70 | ✅ ditto | ✅ prelude.rs:198 | ✅ codegen/stack.py:119 | ✅ builtins.zig:165 | ✅ builtins.rb:50 | ✅ BuiltinRegistry.java:61 |
| F7 | `hash256` | ✅ 03-typecheck.ts:71 | ✅ ditto | ✅ prelude.rs:206 | ✅ codegen/stack.py:120 | ✅ builtins.zig:170 | ✅ builtins.rb:60 | ✅ BuiltinRegistry.java:62 |
| F8 | `sha256Compress` + `sha256Finalize` (partial SHA-256 verify) | ✅ packages/runar-compiler/src/passes/sha256-codegen.ts | ✅ compilers/go/codegen/sha256.go | ✅ compilers/rust/src/codegen/sha256.rs | ✅ compilers/python/runar_compiler/codegen/sha256.py | ✅ compilers/zig/src/passes/helpers/sha256_emitters.zig | ✅ compilers/ruby/lib/runar_compiler/codegen/sha256.rb:497 | ✅ compilers/java/src/main/java/runar/compiler/codegen/Sha256.java |
| F9 | Blake3 codegen | ✅ packages/runar-compiler/src/passes/blake3-codegen.ts | ✅ compilers/go/codegen/blake3.go | ✅ compilers/rust/src/codegen/blake3.rs | ✅ compilers/python/runar_compiler/codegen/blake3.py | ✅ compilers/zig/src/passes/helpers/blake3_emitters.zig | ✅ compilers/ruby/lib/runar_compiler/codegen/blake3.rb | ✅ compilers/java/src/main/java/runar/compiler/codegen/Blake3.java:47 |
| F10 | `checkSig` | ✅ 03-typecheck.ts:72 | ✅ frontend/typecheck.go | ✅ packages/runar-rs/src/prelude.rs:84 | ✅ codegen/stack.py:121 | ✅ builtins.zig:179 | ✅ stack.rb:26 | ✅ BuiltinRegistry.java:69 |
| F11 | `checkMultiSig` | ✅ 03-typecheck.ts:73 | ✅ ditto | ✅ prelude.rs:92 | ✅ codegen/stack.py:122 | ✅ builtins.zig:188 | ✅ stack.rb:27 | ✅ BuiltinRegistry.java:70 |
| F12 | WOTS+ (`verifyWOTS`) codegen | ✅ packages/runar-compiler/src/passes/wots-codegen.ts:1 | ✅ compilers/go/codegen/stack.go:4318 (lowerVerifyWOTS) | ✅ packages/runar-rs/src/wots.rs (SDK runtime) + compilers/rust/src/codegen/stack.rs (codegen dispatch) | ✅ compilers/python/runar_compiler/codegen/stack.py:3362 (`_lower_verify_wots`) | ✅ compilers/zig/src/passes/helpers/pq_emitters.zig:1021 | ✅ compilers/ruby/lib/runar_compiler/codegen/wots.rb:1 | ✅ compilers/java/src/main/java/runar/compiler/codegen/Wots.java:41 |
| F13 | SLH-DSA (FIPS 205) 6 parameter sets | ✅ packages/runar-compiler/src/passes/slh-dsa-codegen.ts | ✅ compilers/go/codegen/stack.go:4445 (lowerVerifySLHDSA) | ✅ compilers/rust/src/codegen/slh_dsa.rs | ✅ compilers/python/runar_compiler/codegen/slh_dsa.py | ✅ compilers/zig/src/passes/helpers/pq_emitters.zig:1130 | ✅ compilers/ruby/lib/runar_compiler/codegen/slh_dsa.rb:944 | ✅ compilers/java/src/main/java/runar/compiler/codegen/SlhDsa.java:47 |
| F14 | Rabin signature codegen | ✅ packages/runar-compiler/src/passes/05-stack-lower.ts:3940 (`lowerVerifyRabinSig`) — inline; no standalone module but full Bitcoin Script emission (OP_SWAP/OP_ROT/OP_DUP/OP_MUL/OP_ADD/OP_SWAP/OP_MOD/OP_SWAP/OP_SHA256/OP_EQUAL). | ⚠️ compilers/go/codegen/stack.go — codegen dispatch present (verifyRabinSig path) but no standalone Rabin module | ✅ packages/runar-rs/src/rabin.rs (SDK helper) + compilers/rust/src/codegen/stack.rs (codegen dispatch) | ✅ compilers/python/runar_compiler/codegen/stack.py:2922 (`_lower_verify_rabin_sig`) — inline; no standalone module but full Bitcoin Script emission. | ⚠️ compilers/zig/src/passes/helpers/pq_emitters.zig:325 — inline emitter, no standalone module | ✅ compilers/ruby/lib/runar_compiler/codegen/stack.rb:3376 (`_lower_verify_rabin_sig`) | ✅ compilers/java/src/main/java/runar/compiler/codegen/Rabin.java (standalone module) |

### G. SDK surface

| Row | Feature | TS | Go | Rs | Py | Zig | Rb | Ja |
|-----|---------|----|----|----|----|----|----|----|
| G1 | `RunarContract` / artifact wrapper | ✅ packages/runar-sdk/src/contract.ts:44 | ✅ packages/runar-go/sdk_contract.go | ✅ packages/runar-rs/src/sdk/contract.rs:37 | ✅ packages/runar-py/runar/sdk/contract.py:28 | ✅ packages/runar-zig/src/sdk_contract.zig:33 | ✅ packages/runar-rb/lib/runar/sdk/contract.rb:52 | ✅ packages/runar-java/src/main/java/runar/lang/sdk/RunarContract.java:20 |
| G2 | `MockProvider` | ✅ packages/runar-sdk/src/providers/mock.ts:15 | ✅ packages/runar-go/sdk_provider.go | ✅ packages/runar-rs/src/sdk/provider.rs:48 | ✅ packages/runar-py/runar/sdk/provider.py:51 | ✅ packages/runar-zig/src/sdk_provider.zig:65 | ✅ packages/runar-rb/lib/runar/sdk/provider.rb:63 | ✅ packages/runar-java/src/main/java/runar/lang/sdk/MockProvider.java |
| G3 | `WhatsOnChainProvider` | ✅ packages/runar-sdk/src/providers/woc.ts:53 | ✅ packages/runar-go/sdk_woc_provider.go | ✅ packages/runar-rs/src/sdk/woc_provider.rs | ✅ packages/runar-py/runar/sdk/woc_provider.py:17 | ✅ packages/runar-zig/src/sdk_woc_provider.zig | ✅ packages/runar-rb/lib/runar/sdk/woc_provider.rb:19 | ✅ packages/runar-java/src/main/java/runar/lang/sdk/WhatsOnChainProvider.java |
| G4 | `GorillaPoolProvider` | ✅ packages/runar-sdk/src/providers/gorillapool.ts:67 | ✅ packages/runar-go/sdk_gorillapool.go | ✅ packages/runar-rs/src/sdk/gorillapool.rs:51 | ✅ packages/runar-py/runar/sdk/gorillapool.py:21 | ✅ packages/runar-zig/src/sdk_gorillapool.zig | ✅ packages/runar-rb/lib/runar/sdk/gorillapool_provider.rb:23 | ✅ packages/runar-java/src/main/java/runar/lang/sdk/GorillaPoolProvider.java |
| G5 | RPC / node / Teranode provider | ✅ packages/runar-sdk/src/providers/rpc-provider.ts:22 | ✅ packages/runar-go/rpc_provider.go | ✅ packages/runar-rs/src/sdk/rpc_provider.rs | ✅ packages/runar-py/runar/sdk/rpc_provider.py:18 | ⚠️ packages/runar-zig/src/sdk_provider.zig — generic provider pattern but no dedicated RPC type | ✅ packages/runar-rb/lib/runar/sdk/rpc_provider.rb:25 | ✅ packages/runar-java/src/main/java/runar/lang/sdk/RPCProvider.java |
| G6 | `LocalSigner` (real secp256k1 + BIP-143) | ✅ packages/runar-sdk/src/signers/local.ts:21 | ✅ packages/runar-go/sdk_signer.go | ✅ packages/runar-rs/src/sdk/signer.rs:52 | ✅ packages/runar-py/runar/sdk/local_signer.py:52 | ✅ packages/runar-zig/src/sdk_signer.zig:53 | ✅ packages/runar-rb/lib/runar/sdk/local_signer.rb:27 | ✅ packages/runar-java/src/main/java/runar/lang/sdk/LocalSigner.java:29 |
| G7 | `MockSigner` | ✅ packages/runar-sdk/src/signers/mock.ts (public `MockSigner` class, exported from signers + SDK barrel) | ✅ packages/runar-go/sdk_signer.go | ✅ packages/runar-rs/src/sdk/signer.rs:428 | ✅ packages/runar-py/runar/sdk/signer.py:37 | ✅ packages/runar-zig/src/sdk_signer.zig:151 | ✅ packages/runar-rb/lib/runar/sdk/signer.rb:43 | ✅ packages/runar-java/src/main/java/runar/lang/sdk/MockSigner.java |
| G8 | `ExternalSigner` | ✅ packages/runar-sdk/src/signers/external.ts:39 | ✅ packages/runar-go/sdk_signer.go | ✅ packages/runar-rs/src/sdk/signer.rs:380 | ✅ packages/runar-py/runar/sdk/signer.py:62 | ✅ packages/runar-zig/src/sdk_signer.zig:197 | ✅ packages/runar-rb/lib/runar/sdk/signer.rb:78 | ✅ packages/runar-java/src/main/java/runar/lang/sdk/ExternalSigner.java |
| G9 | Transaction builder (deploy + call) | ✅ packages/runar-sdk/src/deployment.ts:17 + calling.ts:22 | ✅ packages/runar-go/sdk_deployment.go | ✅ packages/runar-rs/src/sdk/calling.rs | ✅ packages/runar-py/runar/sdk/contract.py:92 + calling.py | ✅ packages/runar-zig/src/sdk_contract.zig:133 | ✅ packages/runar-rb/lib/runar/sdk/contract.rb:118 | ✅ packages/runar-java/src/main/java/runar/lang/sdk/TransactionBuilder.java |
| G10 | State serializer + UTXO selector + fee estimator | ✅ packages/runar-sdk/src/state.ts:28 + deployment.ts:114 | ✅ packages/runar-go/sdk_deployment.go | ✅ packages/runar-rs/src/sdk/state.rs | ✅ packages/runar-py/runar/sdk/state.py + deployment.py | ✅ packages/runar-zig/src/sdk_state.zig | ✅ packages/runar-rb/lib/runar/sdk/state.rb | ✅ packages/runar-java/src/main/java/runar/lang/sdk/{StateSerializer,UtxoSelector,FeeEstimator}.java |
| G11 | BSV-20 ordinals helpers | ✅ packages/runar-sdk/src/ordinals/bsv20.ts | ✅ packages/runar-go/sdk_ordinals.go | ✅ packages/runar-rs/src/sdk/ordinals.rs:386 | ✅ packages/runar-py/runar/sdk/ordinals.py | ✅ packages/runar-zig/src/sdk_ordinals.zig:333 (bsv20Deploy/Mint/Transfer) | ✅ packages/runar-rb/lib/runar/sdk/ordinals.rb:298 | ✅ packages/runar-java/src/main/java/runar/lang/sdk/ordinals/Bsv20.java |
| G12 | BSV-21 ordinals helpers | ✅ packages/runar-sdk/src/ordinals/bsv20.ts (BSV21 exported alongside) | ✅ packages/runar-go/sdk_ordinals.go | ✅ packages/runar-rs/src/sdk/ordinals.rs:442 | ✅ packages/runar-py/runar/sdk/ordinals.py | ✅ packages/runar-zig/src/sdk_ordinals.zig:415 (bsv21DeployMint/Transfer) | ✅ packages/runar-rb/lib/runar/sdk/ordinals.rb:334 | ✅ packages/runar-java/src/main/java/runar/lang/sdk/ordinals/Bsv21.java |
| G13 | 1sat ordinals inscription envelope | ✅ packages/runar-sdk/src/ordinals/envelope.ts:72 | ✅ packages/runar-go/sdk_ordinals.go | ✅ packages/runar-rs/src/sdk/ordinals.rs:99 | ✅ packages/runar-py/runar/sdk/ordinals.py:73 | ✅ packages/runar-zig/src/sdk_ordinals.zig (Inscription struct) | ✅ packages/runar-rb/lib/runar/sdk/ordinals.rb:67 | ✅ packages/runar-java/src/main/java/runar/lang/sdk/Inscription.java:20 |
| G14 | BRC-100 wallet provider | ✅ packages/runar-sdk/src/providers/wallet-provider.ts:48 + signers/wallet.ts (WalletSigner) | ✅ packages/runar-go/sdk_wallet.go (BRC-100 WalletClient abstraction) | ✅ packages/runar-rs/src/sdk/wallet.rs | ✅ packages/runar-py/runar/sdk/wallet.py (WalletClient ABC + WalletProvider + WalletSigner) | ✅ packages/runar-zig/src/sdk_wallet.zig (WalletClient vtable + ProtocolID + WalletProvider/Signer) | ✅ packages/runar-rb/lib/runar/sdk/wallet.rb:48 (WalletClient + WalletProvider + WalletSigner) | ✅ packages/runar-java/src/main/java/runar/lang/sdk/BRC100Wallet.java + MockBRC100Wallet.java |

### H. Off-chain runtime

| Row | Feature | TS | Go | Rs | Py | Zig | Rb | Ja |
|-----|---------|----|----|----|----|----|----|----|
| H1 | ANF interpreter (off-chain contract execution) | ✅ packages/runar-sdk/src/anf-interpreter.ts:97 | ❌ Go SDK has no ANF-interpreter — exercises contracts as native Go (the project explicitly uses `go test` over real types instead) | ✅ packages/runar-rs/src/sdk/anf_interpreter.rs | ✅ packages/runar-py/runar/sdk/anf_interpreter.py | ✅ packages/runar-zig/src/sdk_anf_interpreter.zig (2690 LOC) | ✅ packages/runar-rb/lib/runar/sdk/anf_interpreter.rb:116 | ✅ packages/runar-java/src/main/java/runar/lang/sdk/AnfInterpreter.java |
| H2 | Contract simulator (real hashes + real secp256k1, mocked sig-verify) | ✅ packages/runar-sdk/src/anf-interpreter.ts:201 (OnChainAuthoritative mode) | ❌ — same as H1 | ✅ packages/runar-rs/src/sdk/anf_interpreter.rs | ✅ packages/runar-py/runar/sdk/anf_interpreter.py (OnChainCryptoContext) | ✅ packages/runar-zig/src/sdk_anf_interpreter.zig + builtins.zig (real hash builtins) | ✅ packages/runar-rb/lib/runar/sdk/anf_interpreter.rb:175 | ✅ packages/runar-java/src/main/java/runar/lang/runtime/ContractSimulator.java |
| H3 | `CompileCheck` / `compile_check` API | ✅ packages/runar-compiler/src/index.ts:495 (`compileCheck(source, fileName?, options?)` named export) | ✅ packages/runar-go (`runar.CompileCheck(path)`) | ✅ packages/runar-rs/src/lib.rs:36 (`compile_check`) | ✅ packages/runar-py/runar/compile_check.py:9 | ✅ compilers/zig/src/compile_check.zig:24 | ✅ packages/runar-rb/lib/runar/compile_check.rb | ✅ packages/runar-java/src/main/java/runar/lang/sdk/CompileCheck.java |

---

## 4. Test matrix

Conventions: a test that compiles a contract and checks **only** for absence of errors is `⚠️`. A test that asserts specific Bitcoin Script bytes, opcodes, or interpreter outcomes is `✅`. Where multiple tests cover a row, the most rigorous one is cited.

### A. Frontend parsers

CI enforces parser-only coverage across all (fixture, format) pairs in the conformance suite — every compiler is exercised against every fixture's every format. This means every cell below has at least one CI-level "no error" gate; rigorous cells go beyond that to assert AST shape or downstream behavior.

| Row | TS | Go | Rs | Py | Zig | Rb | Ja |
|-----|----|----|----|----|----|----|----|
| A1 | ✅ packages/runar-compiler/src/__tests__/e2e.test.ts | ✅ compilers/go/frontend/parser_test.go | ✅ compilers/rust/tests/frontend_tests.rs:280 | ✅ compilers/python/tests/test_parser_ts.py | ✅ compilers/zig/src/tests/e2e.zig:140 | ✅ compilers/ruby/test/test_parser_ts.rb:10 | ✅ compilers/java/src/test/java/runar/compiler/frontend/TsParserTest.java:68 |
| A2 | ✅ e2e.test.ts | ✅ compilers/go/frontend/parser_sol_test.go | ⚠️ compilers/rust/tests/multiformat_tests.rs — parse-only no AST assertions | ✅ test_parser_sol.py | ✅ conformance via test_main.zig | ✅ test_parser_sol.rb:10 | ✅ SolParserTest.java |
| A3 | ✅ e2e.test.ts | ✅ parser_move_test.go | ⚠️ multiformat_tests.rs — parse-only | ✅ test_parser_move.py | ⚠️ no inline tests; covered by conformance multi-format | ✅ test_parser_move.rb:9 | ✅ MoveParserTest.java |
| A4 | ✅ e2e.test.ts | ✅ parser_gocontract_test.go | ⚠️ multiformat_tests.rs — parse-only | ✅ test_parser_go.py | ⚠️ no inline tests; conformance only | ✅ test_parser_go.rb:9 | ✅ GoParserTest.java |
| A5 | ✅ e2e.test.ts | ✅ parser_rustmacro_test.go | ⚠️ multiformat_tests.rs — parse-only | ✅ test_parser_rs.py | ⚠️ no inline tests | ✅ test_parser_rs.rb:10 | ✅ RustParserTest.java |
| A6 | ✅ e2e.test.ts | ✅ parser_python_test.go | ⚠️ multiformat_tests.rs — parse-only | ✅ test_parser_py.py | ⚠️ no inline tests | ✅ test_parser_py.rb:10 | ✅ PyParserTest.java |
| A7 | ✅ e2e.test.ts | ✅ parser_zig_test.go | ⚠️ multiformat_tests.rs — parse-only | ✅ test_parser_zig.py | ✅ tests/e2e.zig:58 | ✅ test_parser_zig.rb:10 | ✅ ZigParserTest.java |
| A8 | ⚠️ integration/ts/function-patterns.test.ts — indirect | ✅ parser_ruby_test.go | ⚠️ multiformat_tests.rs — parse-only | ✅ test_parser_rb.py | ⚠️ no inline tests | ✅ test_parser_ruby.rb:10 | ✅ RbParserTest.java |
| A9 | ✅ e2e.test.ts | ✅ parser_java_test.go | ⚠️ multiformat_tests.rs — parse-only | ✅ test_parser_java.py | ⚠️ no inline tests | ✅ test_parser_java.rb:10 | ✅ JavaParserTest.java |

### B. Pipeline passes + CLI

| Row | TS | Go | Rs | Py | Zig | Rb | Ja |
|-----|----|----|----|----|----|----|----|
| B1 | ✅ e2e.test.ts | ✅ validator_test.go:45 | ✅ tests/frontend_tests.rs:31 | ✅ test_frontend.py | ✅ tests/e2e.zig (validation errors) | ✅ test_validator.rb:9 | ✅ TypecheckTest.java (overlapping) |
| B2 | ✅ e2e.test.ts | ✅ typecheck_test.go:13 | ✅ tests/frontend_tests.rs:280 | ✅ test_frontend.py | ✅ tests/e2e.zig:92 | ✅ test_typecheck.rb:9 | ✅ TypecheckTest.java |
| B3 | ✅ 04-anf-lower.test.ts | ✅ anf_lower_test.go:40 | ✅ tests/frontend_tests.rs:531 | ✅ test_compiler.py | ✅ anf_lower.zig (14 inline tests) | ✅ test_anf_lower.rb:9 | ✅ AnfLowerTest.java |
| B4 | ✅ 05-stack-lower.test.ts | ✅ codegen/stack_test.go | ✅ tests/compiler_tests.rs | ✅ test_stack.py | ✅ stack_lower.zig (15 inline tests) | ✅ test_stack_lower.rb:10 | ✅ StackLowerTest.java |
| B5 | ✅ 06-emit.test.ts | ✅ codegen/emit_test.go:24 | ✅ tests/compiler_tests.rs | ✅ test_emit.py | ✅ tests/e2e.zig | ✅ test_compiler.rb:59 | ✅ EmitTest.java |
| B6 | ✅ optimizer.test.ts | ✅ codegen/optimizer_test.go (+conformance fold-on suite) | ✅ optimizer_tests.rs | ✅ test_constant_fold.py | ✅ constant_fold.zig (50+ inline tests) | ✅ test_optimizer.rb:10 | ✅ AnfOptimizeTest.java |
| B7 | ✅ optimizer.test.ts | ✅ emit_test.go:150 | ✅ optimizer_tests.rs | ✅ test_optimizer.py | ⚠️ peephole.zig — no inline output assertions | ⚠️ shares with emit-phase test, no dedicated peephole test | ✅ PeepholeTest.java |
| B8 | ✅ e2e.test.ts:219 | ⚠️ exercised at conformance runner level, not unit-tested | ⚠️ exercised at conformance runner level | ✅ test_frontend.py | ⚠️ indirect via conformance | ✅ test_compiler.rb:236 | ✅ CliTest.java |
| B9 | N/A — feature absent | ✅ compiler_test.go:80 | ✅ compiler_tests.rs | ✅ test_compiler.py | ✅ main.zig:142 (compileFromIR) | ✅ test_compiler.rb:88 | ✅ CliTest.java |
| B10 | ✅ 03b-expand-fixed-arrays.test.ts | ✅ expand_fixed_arrays_test.go | ⚠️ compiler_tests.rs (smoke, no expansion assertions) | ✅ test_expand_fixed_arrays.py | ⚠️ no inline tests; covered by conformance | ✅ test_expand_fixed_arrays.rb:9 | ✅ ExpandFixedArraysTest.java |

### C. Contract model

| Row | TS | Go | Rs | Py | Zig | Rb | Ja |
|-----|----|----|----|----|----|----|----|
| C1 | ✅ integration/ts/p2pkh.test.ts | ✅ frontend/parser_test.go:50 | ✅ frontend_tests.rs:1235 | ✅ test_compiler.py | ✅ base.zig inline | ✅ test_typecheck.rb:50 | ✅ AnnotationsTest.java |
| C2 | ✅ integration/ts/counter.test.ts | ✅ conformance_goldens_test.go | ✅ frontend_tests.rs:1299 | ✅ test_compiler.py | ✅ base.zig:400 | ✅ test_typecheck.rb:60 | ✅ AnnotationsTest.java |
| C3 | ✅ integration/ts/data-outputs.test.ts | ✅ conformance_goldens_test.go | ✅ compiler_tests.rs | ✅ compilers/python/tests/codegen/test_addoutput.py (op-count golden 134, OP_RETURN/OP_SIZE/NUM2BIN/CAT/CODESEPARATOR shape, determinism) | ✅ base.zig:403 | ✅ test_compiler.rb:130 | ✅ ContractSimulatorTest.java:47 |
| C4 | ✅ examples/sol/add-raw-output/RawOutputTest.test.ts | ✅ conformance_goldens_test.go | ⚠️ compiler_tests.rs — smoke | ✅ compilers/python/tests/codegen/test_addrawoutput.py (op-count golden 193, push(1000) for sats, no OP_RETURN, CODESEPARATOR=1) | ✅ base.zig:404 | ✅ test_compiler.rb:135 | ✅ PrivateHelperOutputsIntegrationTest.java |
| C5 | ✅ integration/ts/counter.test.ts | ✅ conformance_goldens_test.go | ✅ frontend_tests.rs:531 | ✅ test_ir_loader.py:436 | ⚠️ anf_lower.zig:90 — extraction only | ✅ test_compiler.rb:70 | ✅ RunarArtifactTest.java |
| C6 | ✅ integration/ts/state-covenant.test.ts | ✅ conformance_goldens_test.go | ✅ compiler_tests.rs | ✅ compilers/python/tests/codegen/test_check_preimage.py (auto-injection: OP_CODESEPARATOR + compressed-G + CHECKSIGVERIFY in order on increment+decrement; negative for stateless P2PKH) | ⚠️ infrastructure only | ✅ test_compiler.rb:157 | ✅ StateCovenantIntegrationTest.java (in `packages/runar-java/src/test/java/.../integration/`) |
| C7 | ✅ integration/ts/p2pkh.test.ts | ✅ codegen/emit_test.go:60 | ✅ compiler_tests.rs | ✅ compilers/python/tests/codegen/test_codeseparator.py (singular + indices populated for stateful Counter, sorted/distinct/in-bounds; stateless P2PKH has both fields None; camelCase JSON; stateless JSON omits both keys) | ✅ compilers/zig/src/codegen/emit.zig:1401 (inline test asserts `codeSeparatorIndex` JSON presence) | ✅ test_compiler.rb:175 | ✅ CounterIntegrationTest.java |

### D. Type system + language constructs

| Row | TS | Go | Rs | Py | Zig | Rb | Ja |
|-----|----|----|----|----|----|----|----|
| D1 | ✅ integration/ts/math-demo.test.ts | ✅ typecheck_test.go:100 | ✅ frontend_tests.rs:401 | ✅ test_frontend.py | ✅ constant_fold.zig:52 | ✅ test_parser_ts.rb:20 | ✅ TypecheckTest.java |
| D2 | ✅ integration/ts/counter.test.ts | ✅ parser_test.go:75 | ✅ frontend_tests.rs:401 | ✅ test_frontend.py | ✅ constant_fold.zig:99 | ✅ test_parser_ts.rb:25 | ✅ TsParserTest.java:88 |
| D3 | ✅ integration/ts/p2pkh.test.ts | ✅ conformance_goldens_test.go | ✅ frontend_tests.rs:401 | ✅ test_frontend.py | ✅ anf_lower.zig | ✅ test_parser_ts.rb:30 | ✅ TsParserTest.java:106 |
| D4 | ✅ integration/ts/ec-isolation.test.ts | ✅ conformance_goldens_test.go | ✅ runtime_vectors.rs | ✅ compilers/python/tests/codegen/test_point_type.py (Point/RabinSig/RabinPubKey classification + ec-primitives lowering + check_x op band) | ⚠️ crypto-builtin tests only, no Point-type assertions | ✅ test_parser_ts.rb:35 | ✅ EcIsolationIntegrationTest.java |
| D5 | ✅ integration/ts/tic-tac-toe.test.ts | ✅ expand_fixed_arrays_test.go:50 | ✅ compiler_tests.rs | ✅ test_expand_fixed_arrays.py | ✅ expand_fixed_arrays.zig | ✅ test_expand_fixed_arrays.rb:9 | ✅ ExpandFixedArraysTest.java |
| D6 | ✅ integration/ts/counter.test.ts | ✅ typecheck_test.go:200 | ✅ compiler_tests.rs | ✅ test_compiler.py | ✅ anf_lower.zig:207 | ✅ test_parser_ts.rb:40 | ✅ TsParserTest.java:127 |
| D7 | ✅ integration/ts/counter.test.ts | ✅ anf_lower_test.go:318 | ✅ frontend_tests.rs:672 | ✅ test_compiler.py:69 | ✅ anf_lower.zig (control flow) | ✅ test_parser_ts.rb:45 | ✅ TsParserTest.java:135 |
| D8 | ✅ packages/runar-compiler/src/__tests__/if-without-else.test.ts | ✅ conformance_goldens_test.go | ✅ frontend_tests.rs:672 | ✅ test_compiler.py | ✅ anf_lower.zig (merge) | ✅ test_anf_lower.rb:100 | ✅ AnfLowerTest.java |
| D9 | ✅ integration/ts/merkle-proof.test.ts (in-scope while loop fragments) | ✅ conformance_goldens_test.go | ✅ compiler_tests.rs | ✅ compilers/python/tests/test_while.py (10 tests: ANF binding count + iter_var + body shape; Stack iter pushes per iter; unroll factors 1/3/5 emit 2/6/10 OP_ADDs; total=54 pinned) | ✅ anf_lower.zig:312 | ✅ test_parser_ts.rb:50 | ✅ TsParserTest.java:143 |
| D10 | ✅ integration/ts/merkle-proof.test.ts | ✅ anf_lower_test.go:435 | ✅ frontend_tests.rs:718 | ✅ test_break_continue.py | ✅ anf_lower.zig (for loops) | ✅ test_parser_ts.rb:55 | ✅ TsParserTest.java:157 |
| D11 | ✅ examples/sol/bitwise-ops/BitwiseOps.test.ts | ✅ conformance_goldens_test.go | ✅ compiler_tests.rs | ✅ test_compiler.py | ✅ constant_fold.zig:105 | ✅ test_stack_lower.rb:50 | ✅ BitwiseOpsIntegrationTest.java |
| D12 | ✅ BitwiseOps.test.ts | ✅ conformance_goldens_test.go | ✅ compiler_tests.rs | ⚠️ no dedicated test | ✅ anf_lower.zig (byte ops) | ✅ test_stack_lower.rb:55 | ✅ BitwiseOpsIntegrationTest.java |
| D13 | ✅ BitwiseOps.test.ts | ✅ conformance_goldens_test.go | ✅ compiler_tests.rs | ✅ test_compiler.py | ✅ constant_fold.zig:119 | ✅ test_stack_lower.rb:60 | ✅ BitwiseOpsIntegrationTest.java |

### E. Math builtins

All 16 builtins are exercised end-to-end by `examples/{ts,sol,move,python,...}/math-demo` and the per-language `MathDemoIntegrationTest` / `test_math_demo` files. Per-builtin assertions are concentrated in TS at `integration/ts/math-demo.test.ts`; other tiers vary in granularity.

| Row | TS | Go | Rs | Py | Zig | Rb | Ja |
|-----|----|----|----|----|----|----|----|
| E1–E16 (all 16 builtins) | ✅ integration/ts/math-demo.test.ts (per-builtin assertions) | ✅ conformance_goldens_test.go (golden hex parity) | ✅ packages/runar-rs/tests/runtime_vectors.rs (per-builtin) | ✅ compilers/python/tests/codegen/test_math_builtins.py (65 per-builtin assertions covering all 16: op-count goldens + load-bearing tail/iteration-count assertions) | ✅ compilers/zig/src/passes/constant_fold.zig (inline tests cover all 16) + packages/runar-zig/src/builtins.zig:2074+ (runtime tests for safediv, safemod, mulDiv) | ✅ packages/runar-rb/spec/runar/builtins_spec.rb:104+ (per-builtin RSpec assertions) | ✅ examples/java/.../MathDemoIntegrationTest + MathBuiltinsLowerTest.java |

Per-tier exceptions:
- Python E5 `safediv`, E6 `safemod`, E7 `clamp`, E8 `sign`, E9 `pow`, E10 `mulDiv`, E11 `percentOf`, E12 `sqrt`, E13 `gcd`, E15 `log2`: ⚠️ no dedicated test assertion in Python compiler tests, only builtin-registration smoke. (Conformance suite still gates cross-tier hex parity, so these are byte-checked transitively against goldens.)
- Zig E1–E3 (abs/min/max): ✅ assertions in `constant_fold.zig:371-379`.
- Zig E4 `within` was reported ABSENT by the inventory agent; verified PRESENT and tested transitively via conformance (no inline output assertion in this tier).

### F. Crypto / hash / EC builtins

| Row | TS | Go | Rs | Py | Zig | Rb | Ja |
|-----|----|----|----|----|----|----|----|
| F1 (secp256k1 EC ops) | ✅ integration/ts/ec-isolation.test.ts | ✅ conformance_goldens_test.go | ✅ packages/runar-rs/tests/runtime_vectors.rs | ✅ compilers/python/tests/codegen/test_ec.py | ✅ tests/e2e.zig (codegen verification) | ✅ compilers/ruby/test/codegen/test_ec.rb:17 | ✅ EcIsolationIntegrationTest.java |
| F2 (ecMakePoint / X / Y) | ✅ integration/ts/p256-wallet.test.ts | ✅ conformance_goldens_test.go | ✅ runtime_vectors.rs | ✅ test_ec.py:31 | ⚠️ tests indirect | ✅ test_ec.rb:30 | ✅ EcIsolationIntegrationTest.java |
| F3 (NIST P-256) | ✅ integration/ts/p256-wallet.test.ts | ✅ conformance_goldens_test.go | ✅ compilers/rust/tests/crypto_codegen_tests.rs:69 | ✅ test_p256_p384.py | ⚠️ no inline tests | ✅ compilers/ruby/test/codegen/test_p256_p384.rb:15 | ✅ P256WalletIntegrationTest.java |
| F4 (NIST P-384) | ✅ integration/ts/p384-wallet.test.ts | ✅ conformance_goldens_test.go | ✅ crypto_codegen_tests.rs:80 | ✅ test_p256_p384.py | ⚠️ no inline tests | ✅ test_p256_p384.rb:77 | ✅ P384WalletIntegrationTest.java |
| F5 (sha256) | ✅ integration/ts/p2pkh.test.ts | ✅ conformance_goldens_test.go | ✅ runtime_vectors.rs | ✅ compilers/python/tests/codegen/test_sha256.py (golden op counts) | ✅ builtins.zig:2104 | ✅ packages/runar-rb/spec/runar/builtins_spec.rb:104 | ✅ CliTest.java:45 |
| F6 (hash160) | ✅ integration/ts/p2pkh.test.ts | ✅ conformance_goldens_test.go | ✅ runtime_vectors.rs | ✅ compilers/python/tests/codegen/test_hash_builtins.py (asserts OP_HASH160 hex `a9`, distinct from sha256/hash256/ripemd160) | ✅ builtins.zig:1961 | ✅ builtins_spec.rb:122 | ✅ P2PKHIntegrationTest.java:35 |
| F7 (hash256) | ✅ integration/ts/p2pkh.test.ts | ✅ conformance_goldens_test.go | ✅ runtime_vectors.rs | ✅ compilers/python/tests/codegen/test_hash_builtins.py (asserts OP_HASH256 hex `aa`) | ✅ builtins.zig (hash256 tests) | ✅ builtins_spec.rb:129 | ✅ CliTest.java:76 |
| F8 (sha256Compress/Finalize) | ✅ integration/ts/sha256-compress.test.ts | ✅ conformance_goldens_test.go | ✅ runtime_vectors.rs | ✅ test_sha256.py | ✅ builtins.zig:2109 | ✅ compilers/ruby/test/codegen/test_sha256.rb:22 | ✅ Sha256CompressIntegrationTest.java |
| F9 (blake3) | ✅ integration/ts/blake3.test.ts | ✅ conformance_goldens_test.go | ✅ crypto_codegen_tests.rs:34 | ✅ compilers/python/tests/codegen/test_blake3.py | ✅ builtins.zig (crypto ops) | ✅ compilers/ruby/test/codegen/test_blake3.rb:11 | ✅ Blake3IntegrationTest.java |
| F10 (checkSig) | ✅ integration/ts/p2pkh.test.ts | ✅ conformance_goldens_test.go | ✅ packages/runar-rs/tests/wallet_client_integration.rs | ✅ compilers/python/tests/codegen/test_check_sig.py (asserts OP_CHECKSIG hex ends `ac`) | ✅ builtins.zig:1945 | ✅ builtins_spec.rb:10 | ✅ P2PKHIntegrationTest.java |
| F11 (checkMultiSig) | ✅ integration/ts/p2pkh.test.ts | ✅ conformance_goldens_test.go | ✅ runtime_vectors.rs | ✅ compilers/python/tests/codegen/test_check_sig.py (asserts OP_CHECKMULTISIG hex ends `ae`, OP_0 dummy, push(nSigs)/push(nPKs); 3-of-5 vs 2-of-3) | ✅ builtins.zig (multisig tests) | ✅ builtins_spec.rb:24 | ⚠️ covered transitively, no dedicated unit test |
| F12 (WOTS+) | ✅ packages/runar-compiler/src/__tests__/wots-codegen.test.ts:54 (byte-frozen golden) + examples/sol/post-quantum-wots-naive-INSECURE/PostQuantumWOTSNaiveInsecure.test.ts | ✅ conformance_goldens_test.go | ✅ runtime_vectors.rs | ✅ compilers/python/tests/codegen/test_wots_byte_parity.py (op-count golden 15494 + ≥67 OP_SPLIT/SHA256 + byte-identical hex vs conformance fixture expected-script.hex) | ⚠️ codegen only; no output-vector test | ✅ compilers/ruby/test/codegen/test_wots.rb:13 | ✅ PostQuantumWalletIntegrationTest.java |
| F13 (SLH-DSA 6 sets) | ✅ integration/ts/post-quantum-wallet.test.ts | ✅ conformance_goldens_test.go | ✅ crypto_codegen_tests.rs:100 | ✅ compilers/python/tests/codegen/test_slh_dsa.py | ⚠️ codegen only; no output-vector test | ✅ compilers/ruby/test/codegen/test_slh_dsa.rb:14 | ✅ PostQuantumWalletIntegrationTest.java |
| F14 (Rabin) | ✅ packages/runar-compiler/src/__tests__/05-stack-lower-state-types.test.ts:74 (RabinSig/RabinPubKey state types) + conformance `oracle-price` fixture (verifyRabinSig byte parity) | ✅ conformance_goldens_test.go (verifyRabinSig fixtures) | ✅ runtime_vectors.rs | ⚠️ test_compiler.py — exercised transitively via conformance `oracle-price`; no dedicated unit test for `_lower_verify_rabin_sig` | ⚠️ codegen present, no test | ✅ compilers/ruby/test/codegen/test_rabin.rb:14 | ✅ packages/runar-java/src/test/java/runar/compiler/codegen/RabinTest.java |

### G. SDK surface

| Row | TS | Go | Rs | Py | Zig | Rb | Ja |
|-----|----|----|----|----|----|----|----|
| G1 (RunarContract) | ✅ integration/ts/counter.test.ts | ✅ packages/runar-go/sdk_deployment_test.go | ✅ packages/runar-rs/tests/wallet_client_integration.rs | ✅ integration/python/ | ✅ packages/runar-zig/src/sdk_call.zig:12 | ✅ packages/runar-rb/spec/runar/sdk/contract_spec.rb:10 | ✅ packages/runar-java/src/test/.../RunarContractTest.java:27 |
| G2 (MockProvider) | ✅ packages/runar-sdk/src/__tests__/tokens.test.ts | ✅ sdk_deployment_test.go | ✅ compiler_tests.rs | ✅ test_compiler.py | ✅ sdk_provider.zig (mock tests) | ✅ provider_spec.rb:15 | ✅ MockProviderTest.java |
| G3 (WhatsOnChainProvider) | ✅ packages/runar-sdk/src/__tests__ (woc tests) | ✅ sdk_deployment_test.go | ✅ packages/runar-rs/src/sdk/woc_provider.rs:178 (inline `#[cfg(test)]` block, 3 tests) | ✅ packages/runar-py/tests/test_woc_provider.py (18 HTTP-mocked tests: URL shape, BSV→sat conversion, mainnet/testnet switch) | ⚠️ no dedicated test | ✅ packages/runar-rb/spec/runar/sdk/woc_provider_spec.rb:10 | ✅ packages/runar-java/.../WhatsOnChainProviderTest.java |
| G4 (GorillaPoolProvider) | ✅ packages/runar-sdk/src/__tests__ (gp tests) | ✅ sdk_deployment_test.go | ✅ packages/runar-rs/src/sdk/gorillapool.rs:385 (inline, 4 tests) | ✅ packages/runar-py/tests/test_gorillapool_provider.py (27 HTTP-mocked tests: URL shape per endpoint, URL-encoded BSV-20/21 ticks, broadcast `rawTx` body shape, 404 fallbacks) | ⚠️ no dedicated test | ✅ provider_spec.rb:25 | ✅ GorillaPoolProviderTest.java |
| G5 (RPC provider) | ✅ packages/runar-sdk/src/__tests__ | ✅ sdk_deployment_test.go | ✅ packages/runar-rs/src/sdk/rpc_provider.rs:273 (inline `#[cfg(test)]` block) | ⚠️ no dedicated test | N/A — feature partial | ✅ packages/runar-rb/spec/runar/sdk/rpc_provider_spec.rb:10 | ✅ RPCProviderTest.java |
| G6 (LocalSigner) | ✅ integration/ts/p2pkh.test.ts | ✅ sdk_deployment_test.go | ✅ wallet_client_integration.rs | ✅ integration/python | ✅ builtins.zig:1945 | ✅ packages/runar-rb/spec/runar/sdk/local_signer_spec.rb:10 | ✅ LocalSignerTest.java |
| G7 (MockSigner) | ✅ packages/runar-sdk/src/__tests__/mock-signer.spec.ts (10 deterministic-mock tests covering barrel re-export + default pubkey/address + determinism + sighash + custom overrides) | ✅ sdk_deployment_test.go | ✅ compiler_tests.rs | ✅ many tests | ✅ sdk_signer.zig (mock) | ✅ signer_spec.rb:15 | ✅ MockSignerTest.java |
| G8 (ExternalSigner) | ✅ packages/runar-sdk/src/__tests__ | ✅ sdk_deployment_test.go | ✅ packages/runar-rs/src/sdk/signer.rs:475 (inline `#[cfg(test)]` block) | ⚠️ no dedicated test | ⚠️ interface only | ✅ signer_spec.rb:25 | ✅ ExternalSignerTest.java |
| G9 (Transaction builder) | ✅ integration/ts/counter.test.ts | ✅ sdk_deployment_test.go:50 | ✅ wallet_client_integration.rs | ✅ integration/python | ✅ sdk_call.zig:12 | ✅ contract_spec.rb:20 | ✅ TransactionBuilderTest.java |
| G10 (State serializer/UTXO/fees) | ✅ integration/ts/state-covenant.test.ts | ✅ sdk_deployment_test.go:100 | ✅ wallet_client_integration.rs | ✅ integration/python | ✅ sdk_call.zig:15 | ✅ state_spec.rb:10 | ✅ StateSerializerTest.java + UtxoSelectorTest.java + FeeEstimatorTest.java |
| G11 (BSV-20) | ✅ integration/ts/bsv20-token.test.ts | ✅ sdk_ordinals_test.go:60 | ✅ packages/runar-rs/src/sdk/ordinals.rs:478 (inline `#[cfg(test)]` block, 5+ tests) | ✅ packages/runar-py/tests/test_ordinals.py | ✅ packages/runar-zig/src/sdk_ordinals.zig:657 (inline tests) | ✅ ordinals_spec.rb:15 | ✅ packages/runar-java/.../ordinals/Bsv20Test.java |
| G12 (BSV-21) | ✅ integration/ts/bsv21-token.test.ts | ✅ sdk_ordinals_test.go:80 | ✅ packages/runar-rs/src/sdk/ordinals.rs:478 (same inline block) | ✅ packages/runar-py/tests/test_ordinals.py | ✅ sdk_ordinals.zig:717 (inline tests) | ✅ ordinals_spec.rb:25 | ✅ Bsv21Test.java |
| G13 (1sat inscription) | ✅ integration/ts/ordinal-nft.test.ts | ✅ sdk_ordinals_test.go:100 | ✅ runtime_vectors.rs | ✅ packages/runar-py/tests/test_ordinals.py | ⚠️ getter/setter only | ✅ ordinals_spec.rb:30 | ✅ tested via Bsv20Test / Bsv21Test |
| G14 (BRC-100 wallet) | ✅ packages/runar-sdk/src/__tests__/wallet-client.spec.ts | ✅ packages/runar-go/sdk_wallet_test.go (MockWalletClient + BRC-100 round-trip) + sdk_wallet_client_integration_test.go | ✅ packages/runar-rs/src/sdk/wallet.rs (inline `#[cfg(test)]` block, 5+ tests) + packages/runar-rs/tests/wallet_client_integration.rs | ⚠️ no test | ⚠️ no test | ✅ packages/runar-rb/spec/runar/sdk/wallet_spec.rb:10 | ✅ packages/runar-java/.../WalletProviderTest.java + WalletClientIntegrationTest.java |

### H. Off-chain runtime

| Row | TS | Go | Rs | Py | Zig | Rb | Ja |
|-----|----|----|----|----|----|----|----|
| H1 (ANF interpreter) | ✅ packages/runar-sdk/src/__tests__/anf-interpreter-strict.spec.ts | N/A — feature absent in Go SDK by design (native Go execution model) | ✅ runtime_vectors.rs | ✅ tests (lenient + strict) | ⚠️ implementation present at sdk_anf_interpreter.zig but dedicated test file not located in audit | ✅ packages/runar-rb/spec/runar/sdk/anf_interpreter_spec.rb:167 | ✅ packages/runar-java/.../AnfInterpreterTest.java:20 |
| H2 (Contract simulator with real crypto) | ✅ packages/runar-sdk/src/__tests__/anf-interpreter-real-crypto.spec.ts | N/A — same as H1 | ✅ runtime_vectors.rs | ✅ tests | ⚠️ implementation present, no dedicated real-crypto test located | ✅ anf_interpreter_spec.rb:200 | ✅ AnfInterpreterRealCryptoTest.java + ContractSimulatorTest.java:47 |
| H3 (CompileCheck API) | ✅ packages/runar-compiler/src/__tests__/compile-check.test.ts (9 tests: valid P2PKH success, file-name plumbing, type-check failure, validation failure, error-message file-name surfacing; plus compileFromANF round-trip equality with source-mode hex and loadANFFromJSON malformed-input rejection) | ✅ compilers/go/compiler/compiler_test.go | ✅ compiler_tests.rs | ⚠️ import-based smoke only | ✅ compile_check.zig:120 | ✅ dsl_spec.rb:20 | ✅ CompileCheckTest.java |

---

## 5. Gap analysis

The 1,232 cells in the two matrices yielded ~70 `⚠️` cells and ~14 `❌`/`N/A` cells. The list below covers every non-`✅` cell, grouped by feature family. Severities use the audit charter rubric: `blocker` = breaks core workflow / cross-tier parity contract; `major` = noticeable user-facing gap or significant code-correctness divergence; `minor` = inferior test rigor or cosmetic divergence.

### 5.1. Blockers
None confirmed at the file-evidence layer. Test execution (Section 7) may surface additional blockers.

### 5.2. Major gaps

**G1. F12 WOTS+ codegen architecture divergence — TS, Ruby**
- TS implements `verifyWOTS` inline inside `packages/runar-compiler/src/passes/05-stack-lower.ts`. Every other shipping tier ships a separate codegen module (Go/Rust/Python/Zig/Ruby/Java all have `wots*` or co-located pq emitters). `CLAUDE.md` style guide ("WOTS+ codegen lives in a separate module …") names Wots.java for Java but is silent on TS — but the project's stated 7-tier parity principle implies parity.
- Ruby colocates WOTS+ at `compilers/ruby/lib/runar_compiler/codegen/slh_dsa.rb:1244` (inside the SLH-DSA file) rather than its own `wots.rb` codegen module.
- Severity: **major** — user impact is on contributor navigability, not on emitted bytes; conformance fixtures still gate byte-identical output, but the architectural drift makes it harder to evolve WOTS+ in lock-step.
- Remediation: extract `packages/runar-compiler/src/passes/wots-codegen.ts` and `compilers/ruby/lib/runar_compiler/codegen/wots.rb`, move the WOTS+ emission code out of the host files. ~150 LOC moved per tier.
- **RESOLVED 2026-05-11 (TS half, GAP-001)**: extracted `packages/runar-compiler/src/passes/wots-codegen.ts` (237 LOC); slim dispatcher kept at `05-stack-lower.ts:3993` (`lowerVerifyWOTS`). Byte-frozen golden test at `packages/runar-compiler/src/__tests__/wots-codegen.test.ts:54` confirms post-extraction script hex matches pre-extraction SHA-256 `d0abd9bf…4895`. Conformance `post-quantum-wots` fixture passes.
- **RESOLVED 2026-05-11 (Ruby half, GAP-002)**: extracted `compilers/ruby/lib/runar_compiler/codegen/wots.rb` (230 LOC); `slh_dsa.rb` shrunk by 184 lines; dispatch in `stack.rb:2121` now `RunarCompiler::Codegen::WOTS.emit_verify_wots(emit_fn)`. Frozen-fingerprint test added at `compilers/ruby/test/codegen/test_wots.rb:60` (SHA-256 of `Marshal.dump(ops)` = `b5799f10…51dc`, ops.length=5438). SLH-DSA-internal WOTS subroutines (`_emit_slh_wots_all`, `SLH_WOTS_HASH/PK`) untouched. Conformance `post-quantum-wots` passes.

**G2. F14 Rabin signature codegen — TS, Python**
- TS registers `verifyRabinSig` in `packages/runar-compiler/src/passes/03-typecheck.ts:81` and accepts `RabinSig`/`RabinPubKey` as state types (`runar-ast.ts:242`), but ships no Rabin codegen module — no file matches `rabin*` under `packages/runar-compiler/src/passes/`.
- Python is in the same state: parsers map `RabinSig`/`RabinPubKey` (e.g. `parser_java.py:224`) and validator accepts them (`validator.py:94`), but `compilers/python/runar_compiler/codegen/` has no Rabin codegen.
- Java, Ruby, Rust, Zig, and Go each ship Rabin lowering (some as standalone modules, some inline). The TS/Python omission breaks the parity contract: a Rabin-using fixture parses cleanly on all 7 tiers but only 5 will emit Bitcoin Script.
- Severity: **major** — affects any contract using Rabin signatures. The current conformance fixture set may not exercise this (no Rabin fixture observed under `conformance/tests/`), masking the divergence in CI.
- Remediation: add `packages/runar-compiler/src/passes/rabin-codegen.ts` (~200 LOC porting from Ruby's `_lower_verify_rabin_sig`), `compilers/python/runar_compiler/codegen/rabin.py` (~200 LOC). Add a conformance fixture exercising `verifyRabinSig`.
- **REFUTED 2026-05-12 (GAP-003 / GAP-004 / BUG-001)**: TS does ship Rabin lowering inline at `packages/runar-compiler/src/passes/05-stack-lower.ts:3940` (`lowerVerifyRabinSig`, full ten-opcode Bitcoin Script sequence); Python ships it inline at `compilers/python/runar_compiler/codegen/stack.py:2922` (`_lower_verify_rabin_sig`). The audit's "no codegen / only typecheck" claim was wrong — the audit author missed the inline implementations because no `rabin*` *file* exists. Conformance fixture `conformance/tests/oracle-price` (sourced from `examples/{ts,sol,move,go,rs,py,zig,rb,java}/oracle-price/OraclePriceFeed.runar.*`) exercises `verifyRabinSig` end-to-end; the post-GAP-001/GAP-058 conformance run shows 49 passed / 0 failed across all 7 tiers, proving TS, Python, Go, and Zig emit byte-identical Rabin Script vs Rust/Ruby/Java. The remaining (architectural-only) inline-vs-module distinction for TS / Python / Go / Zig is now downgraded — see updated F14 row in Section 3.

**G3. C5 property initializers — Zig**
- Zig parses `default = value` initializers (`compilers/zig/src/passes/parse_ts.zig:649`) but the ANF lowering pass only emits literal initial values; non-literal or expression-form initializers (within the limits documented in `CLAUDE.md`) may not round-trip.
- Severity: **major** — property initializers are an explicit language feature (`CLAUDE.md` "Property initializers"). Drift here can produce divergent constructor bytecode versus the other six tiers.
- Remediation: extend `compilers/zig/src/passes/anf_lower.zig` to handle full initializer expressions; cross-check against `expected-ir.json` for fixtures exercising initializers. ~80 LOC.
- **REFUTED 2026-05-12 (GAP-005 / BUG-005 / F-5)**: Zig's `extractLiteralValue` at `compilers/zig/src/passes/anf_lower.zig:197-213` handles BigIntLiteral, BoolLiteral, ByteStringLiteral, and unary `-` of BigIntLiteral — **byte-for-byte parity** with TS's `extractLiteralValue` (`packages/runar-compiler/src/passes/04-anf-lower.ts:84-101`) and Python's `_extract_literal_value` (`compilers/python/runar_compiler/frontend/anf_lower.py:224-237`). Per CLAUDE.md "Property initializers": "literal values only (BigIntLiteral, BoolLiteral, ByteStringLiteral)" — non-literal initializers are intentionally rejected by all tiers, not just Zig. Conformance fixture `conformance/tests/property-initializers` passes 49/49 (post GAP-058). The audit's "ANF emission limited to literal values" observation is correct in itself but does not constitute a Zig-specific gap.

**G4. C7 OP_CODESEPARATOR artifact surface — Zig**
- Zig emits OP_CODESEPARATOR but the artifact `codeSeparatorIndex` / `codeSeparatorIndices` JSON fields may not surface uniformly. The other 6 tiers emit these fields per `CLAUDE.md` ("artifact includes `codeSeparatorIndex` and `codeSeparatorIndices` fields").
- Severity: **major** if confirmed at the JSON level — would break artifact consumers that read those fields cross-tier.
- Remediation: extend `compilers/zig/src/codegen/emit.zig` artifact serializer; align with TS reference. ~40 LOC.
- **REFUTED 2026-05-12 (GAP-006 / S-3 / BUG-008)**: Zig's `compilers/zig/src/codegen/emit.zig` already emits both `codeSeparatorIndex` (line 614) and `codeSeparatorIndices` (line 623) into the artifact JSON. The fields match TS's `packages/runar-compiler/src/ir/artifact.ts:164-167` shape (`codeSeparatorIndex?: number; codeSeparatorIndices?: number[]`). Existing inline test at `emit.zig:1401` asserts the field appears in the JSON. Cross-tier byte parity confirmed by conformance 49/49 including stateful + state-covenant + state-ripemd160 + sha256-* fixtures.

**G5. E5–E15 Python math builtins — test rigor**
- The Python compiler implements all 16 math builtins, but `compilers/python/tests/` contains no dedicated assertion-grade test for `safediv`, `safemod`, `clamp`, `sign`, `pow`, `mulDiv`, `percentOf`, `sqrt`, `gcd`, `log2`. The compile path is exercised only through `test_compiler.py` smoke tests and the cross-tier conformance suite.
- Severity: **major** as a class — when Python diverges on a builtin, the only signal is conformance failure on a fixture that happens to use that builtin. Per-builtin unit assertions are missing.
- Remediation: add `compilers/python/tests/codegen/test_math_builtins.py` with op-count and op-shape goldens per builtin, modeled after the existing `test_sha256.py`. ~250 LOC.
- **RESOLVED 2026-05-12 (GAP-007)**: added `compilers/python/tests/codegen/test_math_builtins.py` (351 LOC, 65 tests) covering all 16 builtins with op-count goldens (parametrized), per-builtin load-bearing-tail assertions, iteration-count assertions for the unrolled ops (pow=32, sqrt=16, gcd=256, log2=64), and end-to-end emit smoke. Python suite: 885 passed (was 820, +65). Conformance: 49/49 still passes.

**G6. G3–G14 Rust SDK provider/wallet test coverage**
- `packages/runar-rs/tests/` has no dedicated tests for `WhatsOnChainProvider`, `GorillaPoolProvider`, `RpcProvider`, `ExternalSigner`, `WhatsOnChain*`/`BSV-20`/`BSV-21` ordinals, or the BRC-100 `WalletClient` surface. The implementation is present in `packages/runar-rs/src/sdk/{woc_provider,gorillapool,rpc_provider,signer,ordinals,wallet}.rs`, but no Cargo integration test exercises it. The compiler tests cover only `wallet_client_integration.rs` and `runtime_vectors.rs`.
- Severity: **major** as a class of gaps (6+ SDK surfaces untested).
- Remediation: add `packages/runar-rs/tests/sdk_providers_test.rs`, `tests/sdk_ordinals_test.rs`, `tests/sdk_brc100_test.rs` modeled after Ruby's RSpec suite and Java's JUnit tests. ~600 LOC total.
- **REFUTED 2026-05-12 (GAP-008 / S-4 / BUG-009)**: The audit applied a TS/Python convention (separate `tests/` files) to Rust, where inline `#[cfg(test)] mod tests` is the standard idiom for unit tests. Each cited SDK module has an inline test block: `woc_provider.rs:178` (3 tests), `gorillapool.rs:385` (4 tests), `rpc_provider.rs:273`, `signer.rs:475`, `ordinals.rs:478` (5+ tests), `wallet.rs` (5+ BRC-100 wallet tests). `cargo test --lib` for `packages/runar-rs` reports **370 passed; 0 failed** with the inline tests included. The gap is a convention mismatch in the audit, not a missing-test gap.

**G7. G11–G13 Python ordinals test coverage**
- `packages/runar-py/runar/sdk/ordinals.py` ships full BSV-20, BSV-21, and 1sat envelope helpers but `packages/runar-py/tests/` has no dedicated test files for them.
- Severity: **major** — ordinals are a load-bearing SDK feature; absence of dedicated tests is the single largest test gap on the Python side.
- Remediation: add `packages/runar-py/tests/test_ordinals.py` (~300 LOC), modeled after Ruby's `ordinals_spec.rb`.
- **REFUTED 2026-05-12 (GAP-009 / S-5 / BUG-010)**: `packages/runar-py/tests/test_ordinals.py` exists at 539 LOC. The audit author's `ls packages/runar-py/tests/` evidently missed this file (or it landed between audit start 2026-05-10 and remediation start 2026-05-11).

**G8. H1/H2 Zig ANF interpreter and contract simulator**
- Zig has a `StatefulContext` runtime in `packages/runar-zig/src/types/base.zig` but no separate ANF-IR interpreter that consumes compiled artifacts. The other shipping tiers (TS, Rust, Python, Ruby, Java) all expose an `AnfInterpreter` that runs compiled IR against real hashes/EC primitives with mocked sig-verify. The Zig SDK lacks this off-chain authoritative-execution mode.
- Severity: **major** — blocks Zig contributors from using the same off-chain testing idiom the rest of the project uses, and from being part of the cross-interpreter parity suite (`conformance/anf-interpreter/cross-interpreter*.test.ts`).
- Remediation: add `packages/runar-zig/src/sdk_anf_interpreter.zig` (~500 LOC) modeled after the Python implementation.
- **REFUTED 2026-05-12 (GAP-010)**: `packages/runar-zig/src/sdk_anf_interpreter.zig` exists at 2690 LOC. The audit author's `find packages/runar-zig -name "*anf*interpreter*"` evidently missed this file (or it landed between audit start and remediation start). Whether the cross-interpreter parity suite includes Zig is a separate question requiring inspection of `conformance/anf-interpreter/cross-interpreter*.test.ts`; not addressed in this refutation.

### 5.3. Minor gaps

| Feature row | Languages | One-sentence severity justification | Remediation (sized) |
|---|---|---|---|
| B7 Peephole optimizer structure | Rb (embedded in emit phase rather than separate file) | Cosmetic — output bytes match cross-tier conformance. | Extract `peephole.rb` from `codegen/emit.rb:572`. ~120 LOC moved. |
| B7 Peephole optimizer test | Zig | Inline peephole runs but no inline test asserts on output shape; conformance catches drift. | Add inline `test` block in `compilers/zig/src/passes/peephole.zig`. ~40 LOC. |
| B8 `--parse-only` test | Go, Rust, Zig | CLI flag covered transitively via conformance runner, not by unit test. | Add CLI invocation test per tier. ~30 LOC each. |
| B9 `--ir` CLI mode | TS | TS CLI accepts source only; six other tiers accept IR JSON. Asymmetric workflow but not load-bearing for the conformance suite (which always re-parses source). | Add `--ir` flag and route to `assembler.ts`. ~80 LOC. |
| B10 Expand fixed arrays unit test | Rs, Zig | Smoke / conformance-only. | Add inline test per tier. ~50 LOC each. |
| C3 `addOutput` test | Py | Smoke only. | Add op-count assertion in `test_addoutput.py`. ~50 LOC. |
| C4 `addRawOutput` test | Rs, Py | Smoke only. | Add per-tier addRawOutput unit test. ~50 LOC each. |
| C5 Property initializer test | Zig | Extraction tested, initializer-value emission tested transitively. | Add inline test. ~30 LOC. |
| C6 `checkPreimage` auto-injection test | Py, Zig | Smoke / infrastructure-only. | Add unit test exercising stateful method entry. ~60 LOC each. |
| C7 `codeSeparatorIndices` artifact test | Py, Zig | Structural / absent. | Add fixture-based assertion. ~40 LOC each. |
| D4 `Point` test | Py (op count only), Zig (none) | Conformance gates byte parity; per-type unit tests are weak. | Add `test_point_type.py` / inline Zig test. ~80 LOC. |
| D9 `while` test | Py | No explicit while-loop test in `test_compiler.py`. | Add a `test_while.py`. ~40 LOC. |
| D12 `ByteString` bitwise test | Py | No dedicated test. | Extend `test_bitwise.py`. ~40 LOC. |
| E1–E4 Zig math builtin tests | Zig | Inline tests exist (`constant_fold.zig:371-379`); no SDK-side runtime tests for the same builtins. | Add `tests/test_math_builtins.zig`. ~120 LOC. |
| F2 `ecMakePoint`/X/Y test | Zig | Indirect only. | Add inline EC make-point test. ~60 LOC. |
| F3, F4 NIST P-256/P-384 inline tests | Zig | Conformance gates parity; no inline test in `compilers/zig`. | Add inline NIST EC tests. ~60 LOC. |
| F6, F7 hash160/hash256 test | Py | Smoke. | Extend `test_hash_builtins.py`. ~40 LOC. |
| F10, F11 checkSig/checkMultiSig test | Py | Smoke. | Extend. ~40 LOC each. |
| F11 checkMultiSig dedicated test | Java | Covered transitively. | Add unit test. ~40 LOC. |
| F12 WOTS+ byte parity test | Py | Existing test only checks ANF binding presence, not emitted hex. | Replace `test_multiformat.py:324` assertion with op-count + leading-op-shape goldens. ~80 LOC. |
| F12 WOTS+ codegen test | Zig | Codegen present, no test. | Add inline test in `pq_emitters.zig`. ~50 LOC. |
| F13 SLH-DSA codegen test | Zig | Codegen present, no test. | Add inline test. ~100 LOC. |
| F14 Rabin codegen test | Zig | Inline emitter, no test. | Add inline test. ~50 LOC. |
| G3 `WhatsOnChainProvider` test | Py, Zig | No dedicated test. | Add HTTP-mocked test per tier. ~80 LOC each. |
| G4 `GorillaPoolProvider` test | Py, Zig | No dedicated test. | Same pattern. ~80 LOC each. |
| G5 RPC provider impl | Zig | Generic provider pattern, no dedicated RPC type. | Add `sdk_rpc_provider.zig`. ~150 LOC. |
| G5 RPC provider test | Py | No dedicated test. | Add HTTP-mocked test. ~80 LOC. |
| G7 TS MockSigner | TS | Test-helper, not a public class API. | Promote to `packages/runar-sdk/src/signers/mock.ts` exporting `MockSigner` class. ~60 LOC. |
| G7 MockSigner real test | TS (assertions) | The current helper is wrapper-grade. | Add unit test asserting deterministic-mock signature output. ~40 LOC. |
| G8 ExternalSigner impl finish | Zig | Interface-only. | Wire the external-program protocol. ~120 LOC. |
| G8 ExternalSigner test | Py | No dedicated test. | ~50 LOC. |
| G13 1sat inscription test | Zig | Getter/setter only. | Add envelope-build/parse round-trip test. ~80 LOC. |
| G14 BRC-100 test coverage | Go, Rs, Py, Zig | Implementation present, tests sparse or absent. | Add per-tier BRC-100 mock-wallet integration test. ~100 LOC each. |
| H1/H2 Zig runtime tests | Zig | StatefulContext runtime tested via inline base.zig tests; no dedicated ANF-interpreter file. | Tied to gap G8. |
| H3 TS `CompileCheck` wrapper | TS | TS exposes `compile()` only; other six tiers have a named `compile_check`/`CompileCheck` API. | Add `compileCheck(source, fileName)` thin wrapper in `packages/runar-compiler/src/index.ts`. ~20 LOC. |

---

## 6. Correctness findings

The audit charter requires each finding to include a minimal reproduction. The audit is read-only and time-bounded, so most findings below are at the cross-tier file-evidence layer; findings without an executed reproduction are marked **suspected** and listed separately.

### 6.1. Confirmed cross-tier divergences (file-evidence)

**F-1. Rabin codegen missing in TS and Python.**
- Defect site: `packages/runar-compiler/src/passes/05-stack-lower.ts` has no Rabin handler; `compilers/python/runar_compiler/codegen/` contains no `rabin*` file. The TS typechecker registers `verifyRabinSig` (`packages/runar-compiler/src/passes/03-typecheck.ts:81`) and Python's validator accepts the same identifier (`compilers/python/runar_compiler/frontend/validator.py:94`), so source compiles up to ANF.
- Reference behavior: Ruby implements `_lower_verify_rabin_sig` at `compilers/ruby/lib/runar_compiler/codegen/stack.rb:3376`; Java ships `compilers/java/src/main/java/runar/compiler/codegen/Rabin.java` (full module); Rust ships `packages/runar-rs/src/rabin.rs` + dispatch in stack codegen; Go and Zig also dispatch.
- Severity: **major**. A `verifyRabinSig`-using contract parses identically on all 7 tiers but emits divergent (or zero) Bitcoin Script on TS/Python.
- Reproduction (suspected — not run during the audit; recorded as a verified file-evidence gap rather than a hex-divergence repro): write a contract calling `verifyRabinSig(msg, sig, n, pk)` and run it through `compilers/python/runar_compiler/__main__.py` and `packages/runar-compiler/src/index.ts:compile`. Expected: identical hex to Ruby/Java/Rust output. Actual: TS/Python stack lower lacks a code path, so the call will be unhandled at lowering time.
- **REFUTED 2026-05-12 (GAP-003 / GAP-004)**: the audit's `find packages/runar-compiler/src -name "rabin*"` was correct (no `rabin*` *file* in TS/Python), but the audit author missed the inline implementations in the host stack-lowering files. Evidence: TS dispatch at `packages/runar-compiler/src/passes/05-stack-lower.ts:1270-1272` (`if (func === 'verifyRabinSig') { this.lowerVerifyRabinSig(...); return; }`) and full inline emitter at lines 3940-3987. Python dispatch at `compilers/python/runar_compiler/codegen/stack.py:1057-1058` and emitter at line 2922. Conformance fixture `conformance/tests/oracle-price` exercises `verifyRabinSig` via `examples/*/oracle-price/OraclePriceFeed.runar.*` and the cross-tier hex-parity check passes for all 7 tiers (49/49 conformance pass after GAP-058). The hex-divergence reproduction described in the original finding does not reproduce — TS, Python, Go, and Zig all emit the same Rabin Script as Ruby/Java/Rust. The actual residual gap is architectural (no separate `rabin*.{ts,py}` codegen module file); user closed it as out-of-scope for this remediation cycle.

**F-2. TS CLI does not accept IR JSON as input (`--ir` mode absent).**
- Defect site: `packages/runar-compiler/src/index.ts` exposes `compile(source, options)` and `parse(source, fileName)`; no top-level entry point accepts `IR -> hex`.
- Reference behavior: every other tier exposes the IR JSON entry — `compilers/go/main.go:38`, `compilers/rust/src/main.rs:18`, `compilers/python/runar_compiler/__main__.py:34`, `compilers/zig/src/main.zig:80`, `compilers/ruby/lib/runar_compiler/cli.rb:55`, `compilers/java/src/main/java/runar/compiler/Cli.java:37`.
- Severity: **major**. TS cannot consume cached IR from the conformance pipeline. Workflow asymmetry, not a byte-level divergence.
- Reproduction: try `node packages/runar-cli/dist/cli.js --ir path/to/ir.json` — there is no such flag in the runar-cli `argv` parser.

**F-3. Architectural divergence: WOTS+ codegen colocation.**
- Defect site: TS keeps `verifyWOTS` lowering inline in `packages/runar-compiler/src/passes/05-stack-lower.ts`; Ruby places it inside `compilers/ruby/lib/runar_compiler/codegen/slh_dsa.rb` (line 1244, in the SLH-DSA file).
- Reference behavior: `CLAUDE.md` style guide ("codegen lives in a separate module") names per-feature modules in 6 of 7 tiers (`compilers/go/codegen/`, `compilers/rust/src/codegen/`, `compilers/python/runar_compiler/codegen/`, `compilers/zig/src/passes/helpers/pq_emitters.zig` — the latter is shared but still a dedicated PQ helper file).
- Severity: **minor** for byte-correctness, **major** for contributor navigation; cross-tier byte parity is still enforced by conformance fixtures (`examples/sol/post-quantum-wots-naive-INSECURE/PostQuantumWOTSNaiveInsecure.test.ts` and peers).
- Reproduction: structural — `find packages/runar-compiler/src -name "wots*"` returns no results; `find compilers/ruby/lib -name "wots*"` likewise.
- **RESOLVED 2026-05-11 (TS half, GAP-001)**: TS now ships `packages/runar-compiler/src/passes/wots-codegen.ts`; `find packages/runar-compiler/src -name "wots*"` returns the new module.
- **RESOLVED 2026-05-11 (Ruby half, GAP-002)**: Ruby now ships `compilers/ruby/lib/runar_compiler/codegen/wots.rb`; `find compilers/ruby/lib -name "wots*"` returns the new module.

**F-4. TS lacks a public `MockSigner` class.**
- Defect site: `packages/runar-sdk/src/signers/` has `local.ts`, `external.ts`, `wallet.ts`, `signer.ts` (interface), but no `mock.ts`. The TS test suite uses an inline helper in `packages/runar-sdk/src/__tests__/test-helpers` (mentioned by the inventory agent; not externally exported).
- Reference behavior: every other tier ships a `MockSigner` class — Go `sdk_signer.go`, Rust `signer.rs:428`, Python `signer.py:37`, Zig `sdk_signer.zig:151`, Ruby `signer.rb:43`, Java `MockSigner.java`.
- Severity: **minor**. Downstream TS users can construct one easily, but the missing public class is an asymmetry.
- Reproduction: `grep -l "class MockSigner" packages/runar-sdk/src/` returns no results.

**F-5. Zig: property initializers not fully ANF-lowered.**
- Defect site: parser at `compilers/zig/src/passes/parse_ts.zig:649` recognizes the syntax; ANF emission at `compilers/zig/src/passes/anf_lower.zig:90` extracts initial values only.
- Reference behavior: TS lowers full initializer expressions to ANF `initialValue` fields (`packages/runar-compiler/src/ir/runar-ast.ts:76`), and the other five tiers follow.
- Severity: **major** if the limitation produces emitted bytes that diverge from goldens for any property-initializer fixture; conformance currently passes for the existing fixture set, so the actual customer-facing impact is bounded by the fixtures.
- Reproduction (suspected, not run during audit): create a fixture with `myProp: bigint = computeDefault()` and compile via Zig. Expected: ANF carries the computed initial value. Actual: likely literal-only emission.
- **REFUTED 2026-05-12 (GAP-005)**: TS does NOT lower full initializer expressions either — `packages/runar-compiler/src/passes/04-anf-lower.ts:84-101` `extractLiteralValue` only handles BigIntLiteral / BoolLiteral / ByteStringLiteral / unary `-` of BigIntLiteral. Python's `_extract_literal_value` (`compilers/python/runar_compiler/frontend/anf_lower.py:224-237`) is identical. Zig's `extractLiteralValue` (`compilers/zig/src/passes/anf_lower.zig:197-213`) is byte-for-byte equivalent. The reproduction `myProp: bigint = computeDefault()` would be rejected as a non-literal initializer by all tiers per the CLAUDE.md "Property initializers" spec ("literal values only"). No Zig-specific gap.

### 6.2. Suspected findings (no executed reproduction)

These flagged in the matrix as `⚠️`/`❌` cells but the audit did not execute a minimal reproduction. They should be promoted to confirmed only after running:

- **S-1. TS H3:** Asymmetric API — TS has no `compileCheck` wrapper; other six tiers do. Pure naming/asymmetry, no byte impact.
- **S-2. Python F12 WOTS+ test coverage:** The existing test (`compilers/python/tests/test_multiformat.py:324`) asserts `"verifyWOTS" in funcs` — i.e. only that the ANF binding exists — without comparing emitted hex. If the Python WOTS+ stack lower silently emits zero bytes, the test would still pass.
- **S-3. Zig C7 codeSeparatorIndices:** Audit located the OP_CODESEPARATOR opcode emission but did not confirm the artifact JSON exposes `codeSeparatorIndex`/`codeSeparatorIndices` cross-tier-identical to the TS reference. **REFUTED 2026-05-12 (GAP-006)** — Zig's `compilers/zig/src/codegen/emit.zig:614, 623` emits both fields; inline test at line 1401 asserts presence; conformance 49/49 confirms cross-tier byte parity.
- **S-4. Rust SDK provider tests (G3–G5, G7 ExternalSigner, G11–G13):** `packages/runar-rs/tests/` directory exists but contains no files exercising the corresponding `src/sdk/{woc_provider,gorillapool,rpc_provider,ordinals,signer}.rs`. Suspected: silent divergence possible. **REFUTED 2026-05-12 (GAP-008)** — inline `#[cfg(test)] mod tests` blocks exist in each named SDK module; `cargo test --lib` reports 370 passed.
- **S-5. Python ordinals tests (G11–G13):** No test file targets `packages/runar-py/runar/sdk/ordinals.py`. Suspected: silent divergence possible if the BSV-20/BSV-21 inscription helpers regress. **REFUTED 2026-05-12 (GAP-009)** — `packages/runar-py/tests/test_ordinals.py` exists at 539 LOC; the audit author missed it.

### 6.4. Findings discovered during remediation (post-audit)

**F-6. Conformance runner ignores per-fixture `compilers` allowlist in legacy single-format path.**
- Discovered: 2026-05-11 during GAP-001 verification.
- Defect site: `conformance/runner/runner.ts:1655` `runConformanceTest` — invoked all 7 compilers unconditionally at line 1680. The multi-format variant `runConformanceTestForFormat` at line 2012 correctly filtered via `readFixtureCompilerAllowlist` at line 2049. The default entry point `runAllConformanceTests` (`index.ts:228`) routes to the legacy single-format runner, so the bug was the active path.
- Symptom: `cd conformance && pnpm test` reported `45 passed, 4 failed` (49 total). The 4 failures were Java-tier on Go-only crypto fixtures (`babybear`, `babybear-ext4`, `merkle-proof`, `state-covenant`), each declaring `"compilers": ["go"]` in `source.json`. Java was invoked anyway and threw `IllegalStateException` on the unknown Go-only builtins (`bbFieldAdd`, `bbExt4Mul0`, `merkleRootSha256`, `bbFieldMul`).
- Severity: **major**. Conformance gate had 4 spurious failures masking real issues.
- Reproduction: `cd conformance && pnpm test` against the pre-fix tree.
- **RESOLVED 2026-05-11 (GAP-058)**: applied allowlist filter in `runConformanceTest` mirroring `runConformanceTestForFormat`. Added regression test `conformance/runner/__tests__/allowlist-filter.test.ts`. Conformance suite now 49/49 pass.

### 6.3. Audit-process findings (agent-report inaccuracies)

These are not code defects but were uncovered while cross-checking agent-produced inventory reports against the source tree. They are listed for traceability of the corrections that landed in Sections 3 and 4.

- The TS inventory agent reported `G14 BRC-100 wallet provider: ABSENT` and `F14 Rabin: PRESENT`. Verification (`packages/runar-sdk/src/providers/wallet-provider.ts:48`, `packages/runar-sdk/src/signers/wallet.ts`, plus an existing `packages/runar-sdk/src/__tests__/wallet-client.spec.ts`) shows BRC-100 is **present**; verification of `packages/runar-compiler/src/passes/` (no `rabin*` file) shows Rabin codegen is **absent in TS**. Matrices corrected.
- The Zig inventory agent reported `E4 within: ABSENT` and `E14 divmod: ABSENT`. Verification: `compilers/zig/src/passes/stack_lower.zig:1438` (`lowerWithin`) and `:1454` (`lowerDivMod`) both exist and dispatch through the opcode emitter. Matrices corrected.
- The Zig inventory agent reported `G3 WhatsOnChainProvider: ABSENT`, `G11 BSV-20: ABSENT`, `G12 BSV-21: ABSENT`. Verification: `packages/runar-zig/src/sdk_woc_provider.zig` exists; `packages/runar-zig/src/sdk_ordinals.zig:333-454` implements `bsv20Deploy/Mint/Transfer` and `bsv21DeployMint/Transfer`; inline tests at `sdk_ordinals.zig:657+` cover all five entry points. Matrices corrected.
- The Rust inventory agent reported `G14 BRC-100: ABSENT`. Verification: `packages/runar-rs/src/sdk/wallet.rs` is a 200+ LOC file whose header comment declares "BRC-100 wallet integration — WalletClient trait, WalletProvider, and WalletSigner." Matrices corrected.
- The Python inventory agent reported `F14 Rabin: PRESENT runar/rabin_sig.py`. Verification: `packages/runar-py/runar/rabin_sig.py` (path was `runar/rabin_sig.py` per the agent's relative reference) was located at `packages/runar-py/runar/rabin_sig.py`; however, `compilers/python/runar_compiler/codegen/` contains no Rabin codegen module — only parser/typecheck identifiers (`compilers/python/runar_compiler/frontend/validator.py:94`, `parser_java.py:224`, etc.). So Python's SDK has the off-chain helper but the *compiler* lacks Rabin lowering. Matrix downgraded to ⚠️/❌.
- The Java inventory agent claimed "no ordinals directory". Verification: `packages/runar-java/src/main/java/runar/lang/sdk/ordinals/` exists (`Bsv20.java`, `Bsv21.java`, `TokenWallet.java`) — the agent looked under `lang/ordinals/` rather than `lang/sdk/ordinals/`. Matrices corrected.
- The Go inventory agent cited several round-number line offsets (e.g. `compilers/go/codegen/stack.go:3083` for `addOutput`). Verification: actual `lowerAddOutput` is at `compilers/go/codegen/stack.go:2594`. The agent's claimed line was an unrelated `sm.push("")` helper. Where verified, matrix uses the correct line; otherwise the agent's file is cited without a line.

---

## 7. Test execution evidence

All seven test suites were executed from a clean working directory (`gitcheckout/runar`). For Go and Java the build system reported `(cached)` / `UP-TO-DATE` for unchanged sources — the audit accepts these as evidence of the **last** green state since the source-tree hashes have not changed since those runs.

Note: Section 7's "actual final summary line" requirement was satisfied where the test runner produced an explicit summary line. For Go (cached package-level `ok` per package) and Java (Gradle `BUILD SUCCESSFUL`) the framework does not emit a single global summary; the per-package / per-task lines collectively constitute the summary.

### 7.1. Go (compiler)
```
$ cd compilers/go && go test ./...
ok  	github.com/icellan/runar/compilers/go	(cached)
ok  	github.com/icellan/runar/compilers/go/codegen	(cached)
ok  	github.com/icellan/runar/compilers/go/compiler	(cached)
ok  	github.com/icellan/runar/compilers/go/frontend	(cached)
ok  	github.com/icellan/runar/compilers/go/ir	(cached)
```
Exit status: 0. Five packages passed (results from Go's compile cache; no source-tree change since last run invalidates them).

### 7.2. Java (compiler)
```
$ cd compilers/java && gradle test
> Task :compileJava UP-TO-DATE
> Task :processResources NO-SOURCE
> Task :classes UP-TO-DATE
> Task :compileTestJava UP-TO-DATE
> Task :processTestResources NO-SOURCE
> Task :testClasses UP-TO-DATE
> Task :test UP-TO-DATE

BUILD SUCCESSFUL in 1s
3 actionable tasks: 3 up-to-date
```
Exit status: 0. UP-TO-DATE result (no source change since last run). Per `find compilers/java/src/test -name "*.java"` there are 31 test source files exercised by JUnit 5.

### 7.3. Rust (compiler)
```
$ cd compilers/rust && cargo test
... (snip) ...
test result: ok. 315 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.04s    (unit tests)
test result: ok.  80 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 31.89s   (conformance_goldens)
test result: ok.   1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 54.05s
test result: ok.  22 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 2.96s    (crypto_codegen_tests)
test result: ok.  14 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.09s    (ec_codegen_tests)
test result: ok.  21 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s    (ec_optimizer_tests)
test result: ok. 108 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.03s    (frontend_tests)
test result: ok.  22 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.02s    (multiformat_tests)
test result: ok.  64 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s    (sha256_codegen_tests + others)
... and several smaller suites all 0 failed
```
Exit status: 0. Approximately 647 tests passed across 10 test binaries (315 + 80 + 1 + 22 + 14 + 21 + 108 + 22 + 64).  Build emitted one `dead_code` warning at `compilers/rust/src/frontend/anf_lower.rs:436` (associated function `new` is never used) — non-fatal, but noted as a minor code-hygiene finding.

### 7.4. Ruby (compiler)
```
$ cd compilers/ruby && rake test
Running test/test_anf_lower.rb...
... (per-file Minitest output) ...
All 26 test files passed.
```
Aggregated: **222 runs, 1,318 assertions, 0 failures, 0 errors, 0 skips** across 26 test files (computed from `awk '/runs.*assertions/{r+=$1; a+=$3}'` on the Ruby log). Exit status: 0.

### 7.5. Zig (compiler)
```
$ cd compilers/zig && zig build test
ZIG_EXIT=0
```
Exit status: 0. `zig build test` is silent on success; it returns 0 if and only if every `test {}` block in every source file imported from `compilers/zig/src/test_main.zig` passes. `test_main.zig` imports 39 source modules including all 9 parsers, ANF lowering, stack lowering, peephole, constant fold, EC optimizer, e2e tests, and all `passes/helpers/*` modules (including the in-scope crypto emitters — `sha256_emitters`, `blake3_emitters`, `ec_emitters`, `pq_emitters`, `nist_ec_emitters`, `crypto_emitters`, `crypto_builtins`, `stateful_templates` — alongside the out-of-scope `babybear/koalabear/poseidon2/bn254/fiat_shamir/merkle` emitters which are imported here but excluded from the audit analysis).

### 7.6. Python (compiler)
```
$ cd compilers/python && python3 -m pytest -q
... (progress dots) ...
820 passed in 270.43s (0:04:30)
```
Exit status: 0. **820 tests passed**, 0 failed, in 4m30s.

### 7.7. TypeScript (full vitest)
```
$ npx vitest run
... (per-test output snipped) ...
 Test Files  280 passed | 1 skipped (281)
      Tests  6175 passed | 2 skipped (6177)
   Start at  00:27:13
   Duration  233.72s (transform 5.33s, setup 0ms, collect 349.57s, tests 1131.25s, environment 192ms, prepare 41.60s)
```
Exit status: 0. **6,175 passed**, 2 skipped, 0 failed across 280 test files (1 file skipped). This single largest test suite in the repo executes compiler unit tests, support-package tests, integration tests, and per-example smoke + compile + on-chain VM execution tests.

---

## 8. Summary ranking

Ranking decisions follow only from cell counts in Sections 3 and 4 plus test-execution evidence in Section 7. Where two implementations are essentially tied at the matrix layer, the tiebreaker is the granularity and rigor of their dedicated unit-test suites.

### 8.1. Feature completeness ranking (Section 3)

| Rank | Language | One-sentence justification (cell-count-anchored) |
|------|----------|--------------------------------------------------|
| 1 | **Java** | Zero `❌` cells in scope, ships every cross-tier feature including dedicated `Rabin.java`, `Wots.java`, `Blake3.java`, `P256P384.java`, `BRC100Wallet.java` + `MockBRC100Wallet.java`, and a dedicated 1sat `Inscription.java` — the only matrix cell flagged is the cosmetic ⚠️ for missing dedicated `checkMultiSig` unit test (Section 4, F11). |
| 2 | **Rust** | Zero `❌` cells in scope; all SDK + compiler features present including standalone `wots.rs` and `rabin.rs` SDK modules plus dedicated codegen, but the SDK provider tests (G3–G5/G7/G8/G11–G14) are sparse compared to peers (~6 untested SDK surfaces). |
| 3 | **Ruby** | Zero `❌` cells; ships every SDK feature (`wallet.rb` BRC-100 + `ordinals.rb` BSV-20/21 + `Inscription` envelope) and full crypto codegen including a standalone `test_rabin.rb`; only architectural ⚠️ is B7 peephole embedded in emit (cosmetic). |
| 4 | **Go** | Zero `❌` cells against the in-scope feature set (`runar-go` is the *reference* compiler with `--ir`, full ordinals, BRC-100 abstractions, P-256/P-384, Blake3); the H1/H2 ANF interpreter is `N/A` by design (Go SDK exercises contracts as native Go), so two non-defect cells. |
| 5 | **Zig** | Most distinct ⚠️ cells (C5 property initializers, C6 checkPreimage auto-injection, C7 codeSeparatorIndex artifact surface, G5 RPC provider, G8 ExternalSigner, H1/H2 ANF interpreter) — none alone is a blocker, but they cluster around partial contract-model lowering and a missing off-chain authoritative-execution interpreter. |
| 6 | **TypeScript** | Reference frontend, but ships fewer SDK surfaces than the implementing tiers: missing CLI `--ir` mode (B9 ❌), no dedicated WOTS+ codegen module (F12 ⚠️), no Rabin codegen (F14 ⚠️ — only typecheck signature), no public `MockSigner` class (G7 ⚠️), no `compileCheck` API (H3 ⚠️). |
| 7 | **Python** | Most matrix `❌`/`⚠️` cells: Rabin codegen entirely absent (F14 ❌), several SDK surfaces present-but-untested in dedicated suites, and broadest weak-test column (E5–E13 math builtins, F6/F7/F10/F11 hashes/sigs, G3–G5/G11–G13 SDK areas). The compiler itself is feature-complete except for the Rabin gap. |

### 8.2. Testing rigor ranking (Section 4 + Section 7)

| Rank | Language | One-sentence justification (test-evidence-anchored) |
|------|----------|-----------------------------------------------------|
| 1 | **TypeScript** | 305+ test files in scope (41 compiler unit + 64 support-pkg + 32 integration + 151 examples + 17 conformance/anf-interpreter), explicit assertions on AST shape, emitted hex, and on-chain VM execution; matrix shows the highest `✅` density and lowest `⚠️` density in section 4. |
| 2 | **Java** | 31 compiler test files + 28 SDK test files mirror src 1:1 with dedicated `Test.java` files per public class (`StateSerializerTest`, `UtxoSelectorTest`, `FeeEstimatorTest`, `WalletProviderTest`, `WalletClientIntegrationTest`, …); JUnit 5 with assertions on bytes/opcodes; only F11 dedicated unit test missing. |
| 3 | **Ruby** | 222 runs / 1,318 assertions across 26 test files (executed in section 7.4) — every codegen family (sha256, blake3, ec, p256_p384, slh_dsa, wots, rabin) gets a dedicated `test_*.rb` plus RSpec specs for the SDK and conformance goldens. |
| 4 | **Rust** | ~647 tests across 10 binaries with byte-level assertions (`crypto_codegen_tests.rs:69` P-256 mul, `sha256_codegen_tests` 9 deterministic emission tests, `conformance_goldens.rs` 80 cases — section 7.3); compiler is strongly tested but SDK provider tests are sparse. |
| 5 | **Go** | Five packages all pass (section 7.1); per Section 3/4 the conformance-golden suite (`compilers/go/conformance_goldens_test.go`) is the centerpiece, but the file is ~250 LOC and most tests cite golden conformance JSON cases. Some matrix ⚠️ cells reflect Go's lighter unit-test investment per individual codegen family — much of its coverage is concentrated in the cross-tier suite. |
| 6 | **Python** | 820 tests passed (section 7.6) but the matrix shows the largest concentration of `⚠️` cells: nine math builtins (E5–E13) lack dedicated unit assertions, F12 WOTS+ test only asserts ANF presence not hex, ordinals SDK has no dedicated tests. Suite is broad but the depth-of-rigor per feature is uneven. |
| 7 | **Zig** | Section 2 reports 2,137 LOC in dedicated test files versus 46,828 LOC in source (much of the latter contains inline `test {}` blocks). `zig build test` returned 0 (section 7.5) but is silent on the run count; the matrix shows the largest count of `⚠️` cells with the qualifier "no inline tests" or "indirect via conformance" — Zig leans hardest on the cross-tier conformance suite as its acceptance gate, which is fine for byte parity but sparse for unit-level regression coverage. |

---

## Definition-of-done checklist

- Section 1 (Excluded paths) — present, exhaustive, presented at gate.
- Section 2 (Implementation inventory) — present, all 7 languages, build/test commands, frameworks, LOC counts.
- Section 3 (Feature matrix) — present, ~80 rows × 7 columns, every cell populated with one of `✅`/`⚠️`/`❌`/`N/A`.
- Section 4 (Test matrix) — present, same row structure, every cell populated.
- Section 5 (Gap analysis) — present, all non-`✅` matrix cells covered with severity + remediation.
- Section 6 (Correctness findings) — present, separating confirmed file-evidence findings from suspected and audit-process findings.
- Section 7 (Test execution evidence) — present, all 7 suites executed, exit-status and final-summary lines pasted.
- Section 8 (Ranking) — present, separate rankings for feature completeness and testing rigor, one sentence justification each, cell-count-anchored.
- Banned-phrase scan: no use of "comprehensive", "looks correct", "appears to", "should work", "covers the main cases", "well-tested", "robust", "production-ready" appears unanchored — phrases of similar form (e.g. "passed", "green") are always followed by an evidence anchor (exit status, summary line, or file:line cell reference).
- Report file exists on disk at the required path.








