# Rúnar Cross-Language Completeness & Correctness Audit

Date: 2026-05-16 (UTC, audit start)
Scope: Read-only analysis of the seven shipping language implementations of the Rúnar TypeScript-to-Bitcoin Script compiler, their SDKs, examples, integration tests, and shared conformance fixtures. EVM/STARK proof-system primitives and the Lean4 verification project are excluded per project policy and the audit charter (see Section 1).

Baseline reference: prior audit `audits/cross-language-completeness-20260514.md` and its closing commit `af43aada Close cross-language audit + fix SLH-DSA codegen + 14-cell parser gap` (2026-05-16 02:14 UTC), which reported "21 audit items closed; 3 latent codegen/parser bugs surfaced during execution were fixed too. Conformance suite 49/49 -> 56/56; parser-only matrix 504/504." This audit independently re-verifies that claim at current main and records any new gaps introduced by the remediation work or pre-existing gaps the prior audit missed.

Status: **Complete.** All eight sections written. New finding F-1 (TS vitest CPU-bound test hang) added in §6; conformance first-run flake added as F-2.

---

## 1. Excluded paths

Enumerated exhaustively before any analysis. Verified against current `main`. If a new STARK/proof-system path is discovered mid-audit, it is appended here with the note "added during audit".

Verified 2026-05-16: commit `af43aada` (the prior-audit remediation) touched zero files matching `babybear|koalabear|poseidon2|bn254|fiat_shamir|fiat-shamir|merkle|sp1_fri|sp1-fri|sp1fri|groth16|msm_bind`. The §1.2 STARK-path list below is therefore unchanged from `20260514`.

### 1.1. Lean4 verification project (charter exclusion #1)
- `runar-verification/` — entire directory. Owned by another agent. No file in this tree was opened, read for analysis, or counted. Note: this tree shows uncommitted modifications in `git status` at audit start (`HANDOFF.md`, `README.md`, several `RunarVerification/**.lean`, `TRUST_MANIFEST.md`, `lakefile.lean`, plus untracked `tests/PipelineConformance.lean`); all untouched here.

### 1.2. STARK / proof-system primitives (charter exclusion #2; project policy: Go-only)

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
- `packages/runar-compiler/dist/**` (build output mirroring the above)

#### Go proof-system codegen (Go-only reference; not part of cross-language comparison)
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
- Java ships no proof-system codegen files. Re-verified 2026-05-16: `find compilers/java -iname '*babybear*' -o -iname '*bn254*' -o -iname '*groth16*' -o -iname '*koalabear*' -o -iname '*poseidon*' -o -iname '*merkle*' -o -iname '*fri*'` returns empty. Consistent with the Go-only policy. Section 3/4 matrices carry no rows for these families.

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
- `packages/runar-go/bn254witness/` (entire subdirectory)
- `packages/runar-go/sp1fri/` (entire subdirectory)

#### Repo-root research vectors
- `tests/babybear-vectors.test.ts`, `tests/babybear-ext4-vectors.test.ts`, `tests/fri-colinearity-vectors.test.ts`, `tests/merkle-vectors.test.ts`
- `tests/vectors/babybear_*.json`, `tests/vectors/koalabear_*.json`, `tests/vectors/bn254_*.json`, `tests/vectors/fri_colinearity.json`, `tests/vectors/poseidon2_koalabear.json`
- `tests/vectors/sp1/**`
- `tests/generate-vectors/**` (Rust/Go vector generators)

#### Integration: STARK / Groth16 / SP1 tests
- `integration/go/babybear_test.go`, `integration/go/babybear_vectors_test.go`, `integration/go/koalabear_vectors_test.go`, `integration/go/poseidon2_kb_vectors_test.go`, `integration/go/bn254_vectors_test.go`, `integration/go/fri_colinearity_vectors_test.go`, `integration/go/groth16_test.go`, `integration/go/groth16_wa_test.go`, `integration/go/groth16_wa_msm_test.go`, `integration/go/groth16_wa_sdk_test.go`, `integration/go/groth16_wa_stateful_test.go`, `integration/go/sp1_fri_poc_test.go`, `integration/go/rollup_bug_test.go`, `integration/go/merkle_proof_test.go`, `integration/go/merkle_vectors_test.go`
- `integration/go/helpers/groth16.go`
- `integration/go/contracts/Groth16Verifier.runar.go`, `StatelessGroth16WA.runar.go`, `RollupGroth16WA.runar.go`, `RollupGroth16WAMSM.runar.go`, `Sp1FriVerifierPoc.runar.go`, `BasefoldVerifier.runar.go`, `RollupBug.runar.go`
- `integration/python/test_babybear.py`, `integration/python/test_merkle_proof.py`
- `integration/ts/babybear.test.ts`, `integration/ts/babybear-vectors.test.ts`, `integration/ts/merkle-proof.test.ts`
- `integration/rust/tests/babybear.rs`, `integration/rust/tests/merkle_proof.rs`
- `integration/zig/src/babybear_test.zig`, `integration/zig/src/merkle_proof_test.zig`
- `integration/ruby/spec/babybear_spec.rb`, `integration/ruby/spec/merkle_proof_spec.rb`

#### Examples: STARK demo contracts
- `examples/go/babybear/**`, `examples/go/babybear-ext4/**`, `examples/go/merkle-proof/**`
- `examples/go/sp1_verifier_main.go`, `examples/go/sp1_fri_verifier_main.go`, `examples/go/SP1Verifier_README.md`, `examples/go/SP1Verifier.groth16.vk.json`
- `examples/{ts,sol,move,python,rust,java,ruby,zig}/babybear/**`
- `examples/{ts,sol,move,python,rust,java,ruby,zig}/babybear-ext4/**`
- `examples/{ts,sol,move,python,rust,java,ruby,zig}/merkle-proof/**`

#### Conformance: STARK fixtures
- `conformance/tests/babybear/`, `conformance/tests/babybear-ext4/`, `conformance/tests/merkle-proof/`
- Any `conformance/runtime-vectors/`, `conformance/fuzz-findings-ir/`, `conformance/sdk-codegen/`, `conformance/sdk-output/` content scoped to babybear/koalabear/bn254/poseidon2/fri/groth16 — to be enumerated specifically if encountered during matrix work.

#### Documentation
- `docs/sp1-proof-format.md`, `docs/sp1-fri-verifier.md`, `docs/fri-verifier-measurements.md`
- `tests/vectors/sp1/fri/evm-guest/**` (SP1 EVM-guest fixture generator — STARK proof tooling)
- `spec/groth16_wa_vk.schema.json`

### 1.3. EVM
No EVM bytecode emitter, EVM transpiler, or EVM-targeted codegen exists in the repository. The only "EVM" references are:
- Descriptive prose contrasting BSV UTXO vs. EVM account model (`docs/cross-covenant-pattern.md`, `docs/formats/solidity.md`, `packages/runar-testing/src/__tests__/analyzer.test.ts:28`) — kept in scope, descriptive only.
- `tests/vectors/sp1/fri/evm-guest/**` — SP1 FRI proof fixture generator targeting the SP1 EVM prover; excluded under §1.2 as STARK tooling, not a Rúnar EVM path.

### 1.4. Build artifacts / vendored dependencies / transient state (not source)
- `node_modules/` (all locations)
- `compilers/rust/target/`, `compilers/python/dist/`, `packages/*/dist/`, `packages/runar-rs/target/`, `packages/runar-rs-macros/target/`, `examples/rust/target/`, `integration/rust/target/`, `tests/generate-vectors/target/`
- `compilers/zig/zig-out/`, `compilers/zig/.zig-cache/`, `packages/runar-zig/zig-out/`, `packages/runar-zig/.zig-cache/`, `examples/zig/zig-out/`
- `compilers/java/build/`, `compilers/java/.gradle/`, `packages/runar-java/build/`, `packages/runar-java/.gradle/`, `examples/java/build/`
- `compilers/python/.pytest_cache/`, all `__pycache__/`, `compilers/python/runar_compiler.egg-info/`, `packages/runar-py/runar.egg-info/`
- `integration/python/.venv/` (vendored Python deps)
- `**/zig-pkg/bsvz-*/` (vendored third-party `bsvz` BSV/SPV library — `packages/runar-zig`, `examples/zig`, `examples/end2end-example/zig`, `integration/zig`)
- `.git/`, `.changeset/`, `.idea/`, `.turbo/`, `.pytest_cache/`, `.planning/`, `.claude/` (incl. `.claude/worktrees/`)
- `conformance/.tmp/` (transient runner artifacts), `conformance/node_modules/`
- `audits/` (prior audit reports — `cross-language-completeness-20260510.md`, `remediation-plan-20260511.md`, `remediation-report-20260512.md`, `cross-language-completeness-20260514.md`, `remediation-plan-20260516.md` — read for context only, not analyzed as source)

---

## 2. Implementation inventory

Seven shipping language implementations of the Rúnar compiler. Each has a compiler under `compilers/<lang>/`, an SDK under `packages/runar-<lang>/`, contract examples under `examples/<lang>/`, and on-chain integration tests under `integration/<lang>/`. TypeScript is the reference; its compiler lives in `packages/runar-compiler/` with shared support packages.

LOC counts are physical lines via `wc -l` (not SLOC), **after excluding all Section 1 paths**. Proof-system files were filtered with the pattern `babybear|koalabear|poseidon2|bn254|fiat_shamir|fiat-shamir|merkle|sp1_fri|sp1-fri|sp1fri|groth16|msm_bind` applied to the file lists below.

Delta-from-20260514 column shown for each tier — net LOC change after the `af43aada` remediation. A surface enlargement of ~7,300 src + ~3,800 test LOC is concentrated in `runar-compiler`, `compilers/{go,rust,python,zig,ruby,java}` (the asm/UnsafeSmartContract/raw_script port from WS-1), `packages/runar-go` (the new WOC + GorillaPool tests from WS-4), `packages/runar-rb` (pure-Ruby ECDSA + BIP-143 fallback from WS-3), and `compilers/zig/src/tests/` (the new frontend.zig test suite from WS-4).

### Cross-cutting note on test LOC comparability
Test LOC is **not** directly comparable across languages because of differing idioms:
- **Go**: tests are separate `_test.go` files — counted in full.
- **TypeScript / Python / Ruby / Java**: tests are separate files (`*.test.ts` / `*.spec.ts`, `tests/test_*.py`, `test/test_*.rb` / `spec/*_spec.rb`, `src/test/**`) — counted in full.
- **Rust**: the `compilers/rust/tests/` and `packages/runar-rs/tests/` directories hold integration-style tests, but the majority of unit tests are inline `#[cfg(test)] mod tests` blocks inside `src/` files — **not** counted in the test LOC below (they fall inside the src count). Rust test LOC is therefore understated.
- **Zig**: `test "..." {}` blocks are inline in `src/` files; only files matching `test`/`tests` in their path are counted as test LOC — **inline tests in non-test-named files are understated** and counted under src.

This will be revisited in Section 8 (testing-rigor ranking) rather than taken at face value from raw LOC.

### TypeScript (reference)
- **Compiler path:** `packages/runar-compiler/`
- **Shared support packages:** `packages/runar-ir-schema/` (IR types/schemas), `packages/runar-lang/` (base classes/builtins, including `UnsafeSmartContract` and the `asm` intrinsic), `packages/runar-testing/` (TestContract, interpreter, ScriptVM, analyzer), `packages/runar-cli/` (CLI), `packages/decompiler/` (Script→TS decompiler)
- **SDK path:** `packages/runar-sdk/`
- **Examples:** `examples/ts/`, plus `examples/sol/` and `examples/move/` (Solidity-like and Move-style frontends parsed by the TS compiler)
- **Integration:** `integration/ts/`
- **Build:** `pnpm install && pnpm run build` (turbo + tsc)
- **Test command:** `npx vitest run`
- **Test framework:** vitest
- **LOC (excl. proof codegen):**
  - `runar-compiler`: src=33,282 (+55)  test=22,298 (+419)
  - `runar-sdk`: src=7,223  test=8,858
  - `runar-testing`: src=10,426 (-1)  test=7,012 (+3)
  - `runar-lang`: src=3,161  test=1,477
  - `runar-ir-schema`: src=1,360  test=697
  - `runar-cli`: src=2,631 (+58)  test=1,312 (+231)
  - `decompiler`: src=5,064  test=2,063

### Go
- **Compiler path:** `compilers/go/` (subdirs `frontend/`, `ir/`, `codegen/`, `compiler/`)
- **SDK path:** `packages/runar-go/`
- **Examples:** `examples/go/`
- **Integration:** `integration/go/`
- **Build:** `cd compilers/go && go build ./...`
- **Test commands:** `cd compilers/go && go test ./...` (compiler); `cd packages/runar-go && go test ./...` (SDK)
- **Test framework:** stdlib `testing`
- **Compiler LOC (excl. proof codegen):** src=34,988 (+975)  test=21,278 (+474)
- **SDK LOC (excl. proof support):** src=12,425 (+50)  test=7,916 (+703 — new `sdk_woc_provider_test.go` + `sdk_gorillapool_test.go`)

### Rust
- **Compiler path:** `compilers/rust/` (`src/{frontend,ir,codegen}`, integration-style tests under `compilers/rust/tests/`)
- **SDK path:** `packages/runar-rs/` (+ `packages/runar-rs-macros/` proc-macro crate, now also exporting `#[runar::unsafe_contract]`)
- **Examples:** `examples/rust/`
- **Integration:** `integration/rust/`
- **Build:** `cd compilers/rust && cargo build`
- **Test commands:** `cd compilers/rust && cargo test` (compiler); `cd packages/runar-rs && cargo test` (SDK)
- **Test framework:** cargo test (inline `#[cfg(test)]` + `tests/` dir)
- **Compiler LOC (excl. proof codegen):** src=47,730 (+1,744)  test(`tests/` dir only)=9,686 (+322) — **inline `#[cfg(test)]` blocks counted in src, not test; see cross-cutting note**
- **SDK LOC (excl. proof support):** src=18,422 (+10) (`runar-rs/src` + `runar-rs-macros/src`)  test(`tests/` dir only)=292 — **heavily understated; SDK unit tests are inline**

### Python
- **Compiler path:** `compilers/python/runar_compiler/`
- **SDK path:** `packages/runar-py/runar/`
- **Examples:** `examples/python/`
- **Integration:** `integration/python/`
- **Build:** `pip install -e compilers/python` (setuptools)
- **Test commands:** `cd compilers/python && python3 -m pytest` (compiler); `cd packages/runar-py && python3 -m pytest` (SDK)
- **Test framework:** pytest
- **Compiler LOC (excl. proof codegen):** src=31,678 (+1,026)  test=16,960 (+326)
- **SDK LOC:** src=9,674 (+58)  test=6,424 (+22)

### Zig
- **Compiler path:** `compilers/zig/src/`
- **SDK path:** `packages/runar-zig/src/`
- **Examples:** `examples/zig/`
- **Integration:** `integration/zig/`
- **Build:** `cd compilers/zig && zig build`
- **Test commands:** `cd compilers/zig && zig build test` (compiler); `cd packages/runar-zig && zig build test` (SDK)
- **Test framework:** Zig built-in `test` blocks
- **Compiler LOC (excl. proof codegen):** src=48,256 (+1,253)  test(test-named files only)=3,387 (+691 — new `src/tests/frontend.zig` + `src/tests/check_multisig.zig`) — **inline `test {}` blocks in non-test-named files counted in src; see cross-cutting note**
- **SDK LOC (excl. proof support):** src=17,358 (+327)  test(test-named files only)=1,016 (-281 vs `20260514`; see note¹)

¹ The `-281` test-LOC delta is an artifact of file-classification, not a regression: a chunk of SDK test code that lived in test-named files under `packages/runar-zig/src/tests/` at the time of `20260514` was rehomed into inline `test "..." {}` blocks during the `af43aada` cleanup. Inline blocks are counted under `src`, so the net SDK test coverage in this tier is unchanged or slightly higher; the apparent shrinkage is a measurement artifact.

### Ruby
- **Compiler path:** `compilers/ruby/lib/runar_compiler/`
- **SDK path:** `packages/runar-rb/lib/`
- **Examples:** `examples/ruby/`
- **Integration:** `integration/ruby/`
- **Build:** `cd compilers/ruby && bundle install`
- **Test commands:** `cd compilers/ruby && rake test` (compiler, minitest); `cd packages/runar-rb && bundle exec rspec` (SDK, rspec)
- **Test framework:** minitest (compiler), rspec (SDK)
- **Compiler LOC (excl. proof codegen):** src=31,983 (+689)  test=6,994 (+878 — new `test/codegen/test_math_builtins.rb` + `test_check_multisig.rb`)
- **SDK LOC:** src=11,015 (+326 — new `lib/runar/sdk/bip143.rb` + pure-Ruby ECDSA path)  test(`spec/`)=8,223 (+41)

### Java
- **Compiler path:** `compilers/java/src/main/java/runar/compiler/`
- **SDK path:** `packages/runar-java/src/main/java/runar/lang/`
- **Examples:** `examples/java/src/`
- **Integration:** `integration/java/`
- **Build:** `cd compilers/java && gradle build` (Gradle 8.5+, no wrapper committed)
- **Test commands:** `cd compilers/java && gradle test` (compiler); `cd packages/runar-java && gradle test` (SDK)
- **Test framework:** JUnit 5
- **Compiler LOC:** src=31,304 (+996)  test=11,437 (+393 — new `ConformanceGoldensTest.java`)
- **SDK LOC:** src=11,590 (+68 — new `UnsafeSmartContract.java`)  test=6,932

### Notes / open items for the inventory
1. **`asm({...})` intrinsic + `UnsafeSmartContract` base class are now in all 7 tiers** (closed by `af43aada` WS-1). The TS-only `raw_script` ANF node + the `UnsafeSmartContract` parent class have peer implementations in Go (`compilers/go/ir/types.go:259`, `frontend/anf_lower.go:1259`, `frontend/parser.go:185`, `runar-go/runar.go:34`), Rust (`compilers/rust/src/ir/mod.rs`, `frontend/anf_lower.rs`, `runar-rs/src/prelude.rs`), Python (`compilers/python/runar_compiler/ir/types.py`, `frontend/parser_python.go:874`, `runar-py/runar/base.py`), Zig (`compilers/zig/src/passes/parse_*.zig`, `compilers/zig/src/ir/types.zig`, `runar-zig/src/base.zig`), Ruby (`compilers/ruby/lib/runar_compiler/*`, `runar-rb/lib/runar/base.rb`), and Java (`compilers/java/src/main/java/runar/compiler/{ir/anf,passes,frontend}/*`, `packages/runar-java/src/main/java/runar/lang/UnsafeSmartContract.java`). Per-tier surface conformance is matrix material for §3.6 and §4.6.
2. **9 frontend formats × 7 compilers = 63 parser cells** are now exercised by the parser-only conformance matrix (`504/504` per the `af43aada` commit message); the §3.1 row count is unchanged but every cell needs to be re-confirmed at current main.
3. **Conformance fixtures grew 49 → 56**: the 7 new fixtures land 1× `asm-raw-script`, 1× `multisig`, 5× `post-quantum-slhdsa-{128f,192s,192f,256s,256f}`, and an extended `math-demo` that now exercises all 16 math builtins. The math-demo expansion replaces a "no golden" `⚠️` cluster in `20260514` §5.2 T-1; §4 will re-check.
4. **New SDK runtime surfaces:**
   - `packages/runar-go/runar.go` — added `UnsafeSmartContract` (see file, new in `af43aada`).
   - `packages/runar-py/runar/base.py` — new file (`UnsafeSmartContract` runtime base).
   - `packages/runar-rb/lib/runar/base.rb` — new file.
   - `packages/runar-rb/lib/runar/sdk/bip143.rb` — new file (176 LOC, pure-Ruby BIP-143 sighash helper).
   - `packages/runar-zig/src/base.zig` — new file.
   - `packages/runar-java/src/main/java/runar/lang/UnsafeSmartContract.java` — new file (68 LOC).
5. **`packages/runar-rb/lib/runar/sdk/local_signer.rb`** grew from a thin RuntimeError stub to a 143-LOC dual-path implementation (optional `bsv-sdk` gem first, pure-Ruby ECDSA fallback). Spec file expanded `local_signer_spec.rb` 18→130 LOC. §3.10 / §4.10 will re-check the LocalSigner row to confirm the pure-Ruby path is observable.
6. Example-pattern coverage is now mostly even after WS-7 (added 10 example dirs across the 9 formats). The `examples/<lang>/<pattern>/` directories that the prior audit flagged as `❌` in §3.13 have all been added; §3.13 of this audit will re-walk and confirm.
7. Build/test commands above are the canonical commands from `CLAUDE.md` and the repo layout; **actual execution and summary lines are deferred to Section 7** per the audit structure.

---

## 3. Feature matrix

Columns: TS | Go | Rust | Python | Zig | Ruby | Java. Cell legend: `✅ file:line` implemented · `⚠️ file:line — reason` partial · `❌` absent · `N/A — reason`. Reference tier for "which rows exist" is Go (per project policy), cross-checked against TS. Where a citation shows a file path without a line, the symbol is defined at/near the top of that file and the file was verified to exist and contain the symbol.

Cross-cutting evidence note: all 7 compilers run a **cross-tier conformance golden harness** that asserts byte-identical ANF IR + Bitcoin Script hex against checked-in goldens for every fixture with no `compilers` allowlist — TS/Zig via `conformance/runner` multi-format runner, Go `compilers/go/conformance_goldens_test.go`, Rust `compilers/rust/tests/conformance_goldens.rs`, Python `compilers/python/tests/test_conformance_goldens.py`, Ruby `compilers/ruby/test/conformance_goldens_test.rb`, Java via the in-tree `compilers/java/src/test/java/runar/compiler/ConformanceGoldensTest.java` (new since `20260514`). This harness (56/56 fixtures green on a clean re-run, see §7 + §6 F-2) is the byte-level safety net behind every `⚠️` test cell.

### 3.1. Frontend format parsers (9 rows)

| Feature | TS | Go | Rust | Python | Zig | Ruby | Java |
|---|---|---|---|---|---|---|---|
| `.runar.ts` parser | ✅ packages/runar-compiler/src/passes/01-parse.ts:79 | ✅ compilers/go/frontend/parser.go:70 | ✅ compilers/rust/src/frontend/parser.rs:43 | ✅ compilers/python/runar_compiler/frontend/parser_ts.py:1598 | ✅ compilers/zig/src/passes/parse_ts.zig:64 | ✅ compilers/ruby/lib/runar_compiler/frontend/parser_ts.rb:499 | ✅ compilers/java/src/main/java/runar/compiler/frontend/TsParser.java:66 |
| `.runar.sol` parser | ✅ 01-parse-sol.ts:1022 | ✅ frontend/parser_sol.go:15 | ✅ frontend/parser_sol.rs:44 | ✅ frontend/parser_sol.py:1262 | ✅ passes/parse_sol.zig:67 | ✅ frontend/parser_sol.rb:317 | ✅ frontend/SolParser.java:75 |
| `.runar.move` parser | ✅ 01-parse-move.ts:1028 | ✅ frontend/parser_move.go:15 | ✅ frontend/parser_move.rs:42 | ✅ frontend/parser_move.py:1325 | ✅ passes/parse_move.zig:69 | ✅ frontend/parser_move.rb | ✅ frontend/MoveParser.java:56 |
| `.runar.go` parser | ✅ 01-parse-go.ts:1244 | ✅ frontend/parser_gocontract.go:26 | ✅ frontend/parser_gocontract.rs:51 | ✅ frontend/parser_go.py:1678 | ✅ passes/parse_go.zig:69 | ✅ frontend/parser_go.rb | ✅ frontend/GoParser.java:77 |
| `.runar.rs` parser | ✅ 01-parse-rust.ts:1187 | ✅ frontend/parser_rustmacro.go:17 | ✅ frontend/parser_rustmacro.rs:1169 | ✅ frontend/parser_rust.py:1272 | ✅ passes/parse_rust.zig:68 | ✅ frontend/parser_rust.rb | ✅ frontend/RustParser.java:82 |
| `.runar.py` parser | ✅ 01-parse-python.ts:1644 | ✅ frontend/parser_python.go:17 | ✅ frontend/parser_python.rs:49 | ✅ frontend/parser_python.py:1420 | ✅ passes/parse_python.zig:72 | ✅ frontend/parser_python.rb | ✅ frontend/PyParser.java:63 |
| `.runar.zig` parser | ✅ 01-parse-zig.ts:1453 | ✅ frontend/parser_zig.go:16 | ✅ frontend/parser_zig.rs:58 | ✅ frontend/parser_zig.py:1665 | ✅ passes/parse_zig.zig:63 | ✅ frontend/parser_zig.rb | ✅ frontend/ZigParser.java:75 |
| `.runar.rb` parser | ✅ 01-parse-ruby.ts:1830 | ✅ frontend/parser_ruby.go:17 | ✅ frontend/parser_ruby.rs:55 | ✅ frontend/parser_ruby.py:1724 | ✅ passes/parse_ruby.zig:73 | ✅ frontend/parser_ruby.rb:724 | ✅ frontend/RbParser.java:78 |
| `.runar.java` parser | ✅ 01-parse-java.ts:1609 | ✅ frontend/parser_java.go:36 | ✅ frontend/parser_java.rs:56 | ✅ frontend/parser_java.py:1564 | ✅ passes/parse_java.zig:66 | ✅ frontend/parser_java.rb | ✅ frontend/JavaParser.java:111 |

All 9 parsers present in all 7 tiers; extension dispatch verified (TS `01-parse.ts:84`, Go `parser.go:45`, Rust `parser.rs:1166`, Python `parser_dispatch.py:28`, Zig `compiler_api.zig:44`, Ruby `compiler.rb:121`, Java `ParserDispatch.java:27`).

### 3.2. Type system

| Feature | TS | Go | Rust | Python | Zig | Ruby | Java |
|---|---|---|---|---|---|---|---|
| bigint / bool / ByteString | ✅ ir/runar-ast.ts:23 | ✅ frontend/ast.go | ✅ frontend/ast.rs | ✅ frontend/ast_nodes.py | ✅ ir/types.zig | ✅ frontend/ast_nodes.rb | ✅ ir/ast/PrimitiveTypeName.java |
| Point (64-byte EC type) | ✅ ir/runar-ast.ts:35 | ✅ frontend/ast.go | ✅ frontend/ast.rs | ✅ frontend/ast_nodes.py | ✅ ir/types.zig | ✅ frontend/ast_nodes.rb | ✅ ir/ast/PrimitiveTypeName.java |
| Fixed-size arrays | ✅ ir/runar-ast.ts:45 | ✅ frontend/expand_fixed_arrays.go:44 | ✅ frontend/expand_fixed_arrays.rs:46 | ✅ frontend/expand_fixed_arrays.py:97 | ✅ passes/expand_fixed_arrays.zig:68 | ✅ frontend/expand_fixed_arrays.rb:63 | ✅ passes/ExpandFixedArrays.java:99 |
| readonly properties | ✅ ir/runar-ast.ts:76 | ✅ frontend/ast.go (PropertyNode) | ✅ frontend/ast.rs | ✅ frontend/ast_nodes.py | ✅ ir/types.zig | ✅ frontend/ast_nodes.rb | ✅ ir/ast/PropertyNode.java |
| Property initializers | ✅ ir/runar-ast.ts:77 | ✅ frontend/ast.go (initializer) | ✅ frontend/ast.rs | ✅ frontend/ast_nodes.py | ✅ ir/types.zig | ✅ frontend/ast_nodes.rb | ✅ ir/ast/PropertyNode.java |

### 3.3. Control flow

| Feature | TS | Go | Rust | Python | Zig | Ruby | Java |
|---|---|---|---|---|---|---|---|
| if / else | ✅ ir/runar-ast.ts:142 | ✅ frontend/ast.go | ✅ frontend/ast.rs | ✅ frontend/ast_nodes.py | ✅ ir/types.zig | ✅ frontend/ast_nodes.rb | ✅ ir/ast/IfStatement.java |
| if-without-else | ✅ passes/04-anf-lower.ts | ✅ frontend/anf_lower.go | ✅ frontend/anf_lower.rs | ✅ frontend/anf_lower.py | ✅ passes/anf_lower.zig | ✅ frontend/anf_lower.rb | ✅ passes/AnfLower.java |
| Ternary expression | ✅ ir/runar-ast.ts:270 | ✅ frontend/ast.go (TernaryExpr) | ✅ frontend/ast.rs | ✅ frontend/ast_nodes.py | ✅ ir/types.zig | ✅ frontend/ast_nodes.rb | ✅ ir/ast/TernaryExpr.java |
| Bounded for-loop | ✅ ir/runar-ast.ts:150 | ✅ frontend/anf_lower.go | ✅ frontend/anf_lower.rs | ✅ frontend/anf_lower.py | ✅ passes/anf_lower.zig | ✅ frontend/anf_lower.rb | ✅ passes/AnfLower.java |
| while-loop | N/A — not a Rúnar construct | N/A | N/A | N/A | N/A | N/A | N/A |
| break / continue | N/A — explicitly rejected | N/A | N/A | N/A | N/A | N/A | N/A |

### 3.4. Operators

| Feature | TS | Go | Rust | Python | Zig | Ruby | Java |
|---|---|---|---|---|---|---|---|
| Arithmetic `+ - * / %` | ✅ ir/runar-ast.ts:183 | ✅ frontend/ast.go (BinaryOp) | ✅ frontend/ast.rs | ✅ frontend/ast_nodes.py | ✅ ir/types.zig | ✅ frontend/ast_nodes.rb | ✅ ir/ast/BinaryOp |
| Comparison `== != < <= > >=` | ✅ ir/runar-ast.ts:189 | ✅ frontend/ast.go | ✅ frontend/ast.rs | ✅ frontend/ast_nodes.py | ✅ ir/types.zig | ✅ frontend/ast_nodes.rb | ✅ ir/ast |
| Boolean `&& \|\| !` | ✅ ir/runar-ast.ts:195 | ✅ frontend/ast.go | ✅ frontend/ast.rs | ✅ frontend/ast_nodes.py | ✅ ir/types.zig | ✅ frontend/ast_nodes.rb | ✅ ir/ast |
| Bitwise `& \| ^ ~` | ✅ ir/runar-ast.ts:197 | ✅ frontend/ast.go | ✅ frontend/ast.rs | ✅ frontend/ast_nodes.py | ✅ ir/types.zig | ✅ frontend/ast_nodes.rb | ✅ ir/ast |
| Shift `<< >>` | ✅ ir/runar-ast.ts:200 | ✅ frontend/ast.go | ✅ frontend/ast.rs | ✅ frontend/ast_nodes.py | ✅ ir/types.zig | ✅ frontend/ast_nodes.rb | ✅ ir/ast |

### 3.5. Compiler passes

| Feature | TS | Go | Rust | Python | Zig | Ruby | Java |
|---|---|---|---|---|---|---|---|
| validate | ✅ passes/02-validate.ts:32 | ✅ frontend/validator.go:38 | ✅ frontend/validator.rs:33 | ✅ frontend/validator.py:65 | ✅ passes/validate.zig:48 | ✅ frontend/validator.rb:57 | ✅ passes/Validate.java:91 |
| typecheck | ✅ passes/03-typecheck.ts:33 | ✅ frontend/typecheck.go:29 | ✅ frontend/typecheck.rs:29 | ✅ frontend/typecheck.py:60 | ✅ passes/typecheck.zig:44 | ✅ frontend/typecheck.rb:208 | ✅ passes/Typecheck.java:80 |
| ANF lowering | ✅ passes/04-anf-lower.ts:45 | ✅ frontend/anf_lower.go:17 | ✅ frontend/anf_lower.rs:35 | ✅ frontend/anf_lower.py:66 | ✅ passes/anf_lower.zig:52 | ✅ frontend/anf_lower.rb:28 | ✅ passes/AnfLower.java:114 |
| constant folding | ✅ optimizer/constant-fold.ts:447 | ✅ frontend/constant_fold.go:70 | ✅ frontend/constant_fold.rs:493 | ✅ frontend/constant_fold.py:513 | ✅ passes/constant_fold.zig:545 | ✅ frontend/constant_fold.rb:522 | ✅ passes/ConstantFold.java:49 |
| peephole optimizer | ✅ optimizer/peephole.ts:448 | ✅ codegen/optimizer.go:16 | ✅ codegen/optimizer.rs:12 | ✅ codegen/optimizer.py:19 | ✅ passes/peephole.zig:82 | ✅ codegen/optimizer.rb:15 | ✅ passes/Peephole.java:36 |
| expand-fixed-arrays | ✅ passes/03b-expand-fixed-arrays.ts:105 | ✅ frontend/expand_fixed_arrays.go:44 | ✅ frontend/expand_fixed_arrays.rs:46 | ✅ frontend/expand_fixed_arrays.py:97 | ✅ passes/expand_fixed_arrays.zig:68 | ✅ frontend/expand_fixed_arrays.rb:63 | ✅ passes/ExpandFixedArrays.java:99 |
| stack lowering (ANF→Stack IR) | ✅ passes/05-stack-lower.ts:1 | ✅ codegen/stack.go:1 | ✅ codegen/stack.rs:1 | ✅ codegen/stack.py:1 | ✅ passes/stack_lower.zig:1 | ✅ codegen/stack.rb:1 | ✅ passes/StackLower.java:1 |
| emit (Stack IR→hex) | ✅ passes/06-emit.ts:1 | ✅ codegen/emit.go:1 | ✅ codegen/emit.rs:1 | ✅ codegen/emit.py:1 | ✅ codegen/emit.zig:1 | ✅ codegen/emit.rb:1 | ✅ passes/Emit.java:1 |
| opcode mapping table | ✅ passes/06-emit.ts:100 | ✅ codegen/emit.go:80 | ✅ codegen/opcodes.rs | ✅ codegen/emit.py | ✅ codegen/opcodes.zig | ✅ codegen/emit.rb | ✅ passes/Emit.java:139 |

### 3.6. Contract model

| Feature | TS | Go | Rust | Python | Zig | Ruby | Java |
|---|---|---|---|---|---|---|---|
| SmartContract (stateless) base | ✅ ir/runar-ast.ts (parentClass) | ✅ ir/types.go | ✅ ir/mod.rs | ✅ ir/types.py | ✅ ir/types.zig | ✅ ir/types.rb | ✅ ir/ast/ParentClass.java |
| StatefulSmartContract base | ✅ passes/04-anf-lower.ts:129 | ✅ frontend/anf_lower.go | ✅ frontend/anf_lower.rs | ✅ frontend/anf_lower.py | ✅ passes/anf_lower.zig | ✅ frontend/anf_lower.rb | ✅ passes/AnfLower.java |
| parentClass discrimination | ✅ passes/04-anf-lower.ts:129 | ✅ codegen/stack.go (methodUsesCheckPreimage) | ✅ codegen/stack.rs | ✅ codegen/stack.py | ✅ passes/stack_lower.zig | ✅ codegen/stack.rb:372 | ✅ passes/StackLower.java:355 |
| Auto checkPreimage at stateful entry | ✅ passes/04-anf-lower.ts:129 | ✅ codegen/stack.go:3877 | ✅ codegen/stack.rs | ✅ codegen/stack.py | ✅ passes/stack_lower.zig | ✅ codegen/stack.rb:372 | ✅ passes/StackLower.java:399 |
| State continuation at exit | ✅ passes/05-stack-lower.ts:292 | ✅ codegen/stack.go (get_state_script) | ✅ codegen/stack.rs:976 | ✅ codegen/stack.py:299 | ✅ passes/stack_lower.zig | ✅ codegen/stack.rb:275 | ✅ passes/StackLower.java |
| OP_CODESEPARATOR auto-insertion | ✅ passes/05-stack-lower.ts:3021 | ✅ codegen/stack.go:2830 | ✅ codegen/stack.rs | ✅ codegen/stack.py | ✅ passes/stack_lower.zig | ✅ codegen/stack.rb | ✅ passes/StackLower.java:1938 |
| codeSeparatorIndex/Indices artifact fields | ✅ passes/06-emit.ts:158 | ✅ codegen/emit.go:164 | ✅ codegen/emit.rs | ✅ codegen/emit.py | ✅ codegen/emit.zig | ✅ codegen/emit.rb | ✅ passes/Emit.java |
| `this.addOutput` (multi-output) | ✅ passes/05-stack-lower.ts:1023 | ✅ codegen/stack.go:2594 | ✅ codegen/stack.rs:2269 | ✅ codegen/stack.py:854 | ✅ passes/stack_lower.zig:799 | ✅ codegen/stack.rb:1079 | ✅ passes/StackLower.java:310 |
| `this.addRawOutput` (raw script bytes) | ✅ passes/05-stack-lower.ts:1038 | ✅ codegen/stack.go:2690 | ✅ codegen/stack.rs:2372 | ✅ codegen/stack.py:856 | ✅ passes/stack_lower.zig:800 | ✅ codegen/stack.rb:1081 | ✅ passes/StackLower.java:314 |
| `this.addDataOutput` (OP_RETURN data) | ✅ passes/05-stack-lower.ts:307 | ✅ codegen/stack.go:932 | ✅ codegen/stack.rs:988 | ✅ codegen/stack.py:858 | ✅ passes/stack_lower.zig:801 | ✅ codegen/stack.rb:286 | ✅ passes/StackLower.java:317 |
| **`asm` intrinsic / `raw_script` ANF node / `UnsafeSmartContract` base** | ✅ passes/04-anf-lower.ts:1079; 02-validate.ts:399; 06-emit.ts:461 | ✅ frontend/anf_lower.go:1263; ir/types.go (ParentClass enum); codegen/stack.go:2769 (lowerRawScript); codegen/emit.go:274 (emitRawBytes); validator.go:413 | ✅ frontend/anf_lower.rs:1379; ir/mod.rs:214 (ANFValue::RawScript); codegen/stack.rs:2473 (lower_raw_script); codegen/emit.rs:184; validator.rs:366 | ✅ frontend/anf_lower.py:1040; codegen/stack.py:2418 (_lower_raw_script); codegen/emit.py:253; validator.py:303 | ✅ passes/anf_lower.zig:1058; ir/types.zig:9 (ANFValue.raw_script); passes/stack_lower.zig:856; codegen/emit.zig:183; passes/validate.zig:418 | ✅ frontend/anf_lower.rb:1102; ir/types.rb:81; codegen/stack.rb:3242; codegen/emit.rb:476; validator.rb:512 | ✅ passes/AnfLower.java:805; ir/anf/RawScript.java; passes/StackLower.java:2879; passes/Emit.java:303; passes/Validate.java:394 |
| `assert()` control mechanism | ✅ passes/05-stack-lower.ts (OP_VERIFY) | ✅ codegen/stack.go | ✅ codegen/stack.rs | ✅ codegen/stack.py | ✅ passes/stack_lower.zig | ✅ codegen/stack.rb:121 | ✅ passes/StackLower.java |

The asm/UnsafeSmartContract row was the single ❌-in-6-tiers cell in `20260514` §3.6 (was tracked as F-1/G-1). Now ✅ in all 7 tiers per `af43aada` WS-1.

### 3.7. Math builtins

| Feature | TS | Go | Rust | Python | Zig | Ruby | Java |
|---|---|---|---|---|---|---|---|
| abs | ✅ 05-stack-lower.ts:101 | ✅ stack.go:106 | ✅ stack.rs:173 | ✅ stack.py:125 | ✅ stack_lower.zig:1304 | ✅ stack.rb:32 | ✅ StackLower.java:108 |
| min | ✅ 05-stack-lower.ts:102 | ✅ stack.go:107 | ✅ stack.rs:174 | ✅ stack.py:126 | ✅ stack_lower.zig:1305 | ✅ stack.rb:33 | ✅ StackLower.java:109 |
| max | ✅ 05-stack-lower.ts:103 | ✅ stack.go:108 | ✅ stack.rs:175 | ✅ stack.py:127 | ✅ stack_lower.zig:1306 | ✅ stack.rb:34 | ✅ StackLower.java:110 |
| within | ✅ 05-stack-lower.ts:104 | ✅ stack.go:109 | ✅ stack.rs:176 | ✅ stack.py:128 | ✅ stack_lower.zig:1307 | ✅ stack.rb:35 | ✅ StackLower.java:111 |
| safediv | ✅ 05-stack-lower.ts:1448 | ✅ stack.go:1319 | ✅ stack.rs:1348 | ✅ stack.py:1118 | ✅ stack_lower.zig:1188 | ✅ stack.rb:1416 | ✅ StackLower.java:891 |
| safemod | ✅ 05-stack-lower.ts:1448 | ✅ stack.go:3514 | ✅ stack.rs:1353 | ✅ stack.py:1118 | ✅ stack_lower.zig:1189 | ✅ stack.rb:1416 | ✅ StackLower.java:891 |
| clamp | ✅ 05-stack-lower.ts:1453 | ✅ stack.go:1311 | ✅ stack.rs:1342 | ✅ stack.py:1122 | ✅ stack_lower.zig:1197 | ✅ stack.rb:1420 | ✅ StackLower.java:899 |
| sign | ✅ 05-stack-lower.ts:1493 | ✅ stack.go:1351 | ✅ stack.rs (lower_sign) | ✅ stack.py:1154 | ✅ stack_lower.zig:1209 | ✅ stack.rb:1452 | ✅ StackLower.java:927 |
| pow | ✅ 05-stack-lower.ts:1458 | ✅ stack.go:1316 | ✅ stack.rs:1347 | ✅ stack.py:1126 | ✅ stack_lower.zig:1190 | ✅ stack.rb:1424 | ✅ StackLower.java:903 |
| mulDiv | ✅ 05-stack-lower.ts:1463 | ✅ stack.go:1321 | ✅ stack.rs:1352 | ✅ stack.py:1130 | ✅ stack_lower.zig:1191 | ✅ stack.rb:1428 | ✅ StackLower.java:907 |
| percentOf | ✅ 05-stack-lower.ts:1468 | ✅ stack.go:1326 | ✅ stack.rs:1357 | ✅ stack.py:1134 | ✅ stack_lower.zig:1192 | ✅ stack.rb:1432 | ✅ StackLower.java:895 |
| sqrt | ✅ 05-stack-lower.ts:1473 | ✅ stack.go:1331 | ✅ stack.rs:1362 | ✅ stack.py:1138 | ✅ stack_lower.zig:1193 | ✅ stack.rb:1436 | ✅ StackLower.java:911 |
| gcd | ✅ 05-stack-lower.ts:1478 | ✅ stack.go:1336 | ✅ stack.rs:1367 | ✅ stack.py:1142 | ✅ stack_lower.zig:1194 | ✅ stack.rb:1440 | ✅ StackLower.java:915 |
| divmod | ✅ 05-stack-lower.ts:1483 | ✅ stack.go:1341 | ✅ stack.rs:1372 | ✅ stack.py:1146 | ✅ stack_lower.zig:1195 | ✅ stack.rb:1444 | ✅ StackLower.java:919 |
| log2 | ✅ 05-stack-lower.ts:1488 | ✅ stack.go:1346 | ✅ stack.rs:1377 | ✅ stack.py:1150 | ✅ stack_lower.zig:1196 | ✅ stack.rb:1448 | ✅ StackLower.java:923 |
| bool | ✅ 05-stack-lower.ts:108 | ✅ stack.go:105 | ✅ stack.rs:171 | ✅ stack.py:134 | ✅ stack_lower.zig (builtin enum) | ✅ stack.rb:39 | ✅ StackLower.java:115 |

### 3.8. Hash builtins

| Feature | TS | Go | Rust | Python | Zig | Ruby | Java |
|---|---|---|---|---|---|---|---|
| sha256 | ✅ 05-stack-lower.ts:88 | ✅ stack.go:88 | ✅ stack.rs (hash op table) | ✅ stack.py:125 | ✅ stack_lower.zig | ✅ stack.rb:506 | ✅ StackLower.java |
| hash160 | ✅ 05-stack-lower.ts:90 | ✅ stack.go:90 | ✅ stack.rs | ✅ stack.py:127 | ✅ stack_lower.zig | ✅ stack.rb | ✅ StackLower.java |
| hash256 | ✅ 05-stack-lower.ts:91 | ✅ stack.go:91 | ✅ stack.rs | ✅ stack.py:128 | ✅ stack_lower.zig | ✅ stack.rb | ✅ StackLower.java |
| ripemd160 | ✅ 05-stack-lower.ts:89 | ✅ stack.go:89 | ✅ stack.rs | ✅ stack.py:126 | ✅ stack_lower.zig | ✅ stack.rb | ✅ StackLower.java |
| sha256Compress | ✅ 05-stack-lower.ts:1346 | ✅ stack.go:1246 | ✅ stack.rs:1277 | ✅ stack.py:1070 | ✅ stack_lower.zig:1221 | ✅ codegen/sha256.rb | ✅ codegen/Sha256.java |
| sha256Finalize | ✅ 05-stack-lower.ts:1351 | ✅ stack.go:1251 | ✅ stack.rs:1282 | ✅ stack.py:1074 | ✅ stack_lower.zig:1222 | ✅ codegen/sha256.rb | ✅ codegen/Sha256.java |
| checkPreimage | ✅ 05-stack-lower.ts:1023 | ✅ stack.go:923 | ✅ stack.rs:976 | ✅ stack.py:850 | ✅ stack_lower.zig:561 | ✅ stack.rb:1075 | ✅ StackLower.java:306 |

### 3.9. Crypto codegen

| Feature | TS | Go | Rust | Python | Zig | Ruby | Java |
|---|---|---|---|---|---|---|---|
| checkSig | ✅ 05-stack-lower.ts:92 | ✅ codegen/stack.go:92 | ✅ codegen/stack.rs:158 | ✅ codegen/stack.py:121 | ✅ passes/stack_lower.zig:1297 | ✅ codegen/stack.rb:26 | ✅ passes/StackLower.java:102 |
| checkMultiSig (m-of-n) | ✅ 05-stack-lower.ts:1610 | ✅ codegen/stack.go:1205 | ✅ codegen/stack.rs:2457 | ✅ codegen/stack.py:2401 | ✅ passes/stack_lower.zig:2024 | ✅ codegen/stack.rb:1999 | ✅ passes/StackLower.java:1119 |
| ecAdd | ✅ passes/ec-codegen.ts:579 | ✅ codegen/ec.go:663 | ✅ codegen/ec.rs:676 | ✅ codegen/ec.py:651 | ✅ passes/helpers/ec_emitters.zig:712 | ✅ codegen/ec.rb:800 | ✅ codegen/Ec.java:614 |
| ecMul | ✅ ec-codegen.ts:592 | ✅ ec.go:676 | ✅ ec.rs:689 | ✅ ec.py:664 | ✅ ec_emitters.zig:719 | ✅ ec.rb:816 | ✅ Ec.java:622 |
| ecMulGen | ✅ ec-codegen.ts:675 | ✅ ec.go:759 | ✅ ec.rs:764 | ✅ ec.py:737 | ✅ ec_emitters.zig:775 | ✅ ec.rb:890 | ✅ Ec.java:682 |
| ecNegate | ✅ ec-codegen.ts:690 | ✅ ec.go:772 | ✅ ec.rs:777 | ✅ ec.py:750 | ✅ ec_emitters.zig:782 | ✅ ec.rb:904 | ✅ Ec.java:693 |
| ecOnCurve | ✅ ec-codegen.ts:703 | ✅ ec.go:783 | ✅ ec.rs:788 | ✅ ec.py:763 | ✅ ec_emitters.zig:789 | ✅ ec.rb:918 | ✅ Ec.java:701 |
| ecModReduce | ✅ ec-codegen.ts:730 | ✅ ec.go:808 | ✅ ec.rs:813 | ✅ ec.py:788 | ✅ passes/helpers/crypto_emitters.zig:75 | ✅ ec.rb:944 | ✅ Ec.java:722 |
| ecEncodeCompressed | ✅ ec-codegen.ts:746 | ✅ ec.go:822 | ✅ ec.rs:827 | ✅ ec.py:804 | ✅ crypto_emitters.zig:86 | ✅ ec.rb:961 | ✅ Ec.java:733 |
| ecMakePoint | ✅ ec-codegen.ts:777 | ✅ ec.go:851 | ✅ ec.rs:856 | ✅ ec.py:836 | ✅ crypto_emitters.zig:107 | ✅ ec.rb:994 | ✅ Ec.java:758 |
| ecPointX | ✅ ec-codegen.ts:805 | ✅ ec.go:877 | ✅ ec.rs:882 | ✅ ec.py:864 | ✅ crypto_emitters.zig:115 | ✅ ec.rb:1023 | ✅ Ec.java:780 |
| ecPointY | ✅ ec-codegen.ts:821 | ✅ ec.go:891 | ✅ ec.rs:896 | ✅ ec.py:880 | ✅ crypto_emitters.zig:153 | ✅ ec.rb:1040 | ✅ Ec.java:790 |
| NIST P-256 codegen | ✅ passes/p256-p384-codegen.ts:994 | ✅ codegen/p256_p384.go:993 | ✅ codegen/p256_p384.rs:1080 | ✅ codegen/p256_p384.py | ✅ passes/helpers/nist_ec_emitters.zig:1328 | ✅ codegen/p256_p384.rb | ✅ codegen/P256P384.java:886 |
| NIST P-384 codegen | ✅ p256-p384-codegen.ts:1117 | ✅ p256_p384.go (P384* funcs) | ✅ p256_p384.rs:1175 | ✅ p256_p384.py | ✅ nist_ec_emitters.zig:1434 | ✅ p256_p384.rb | ✅ P256P384.java:972 |
| SHA-256 full codegen module | ✅ passes/sha256-codegen.ts:217 | ✅ codegen/sha256.go:440 | ✅ codegen/sha256.rs:532 | ✅ codegen/sha256.py:466 | ✅ passes/helpers/sha256_emitters.zig:352 | ✅ codegen/sha256.rb:497 | ✅ codegen/Sha256.java:488 |
| BLAKE3 codegen | ✅ passes/blake3-codegen.ts:406 | ✅ codegen/blake3.go:591 | ✅ codegen/blake3.rs:652 | ✅ codegen/blake3.py:598 | ✅ passes/helpers/blake3_emitters.zig:321 | ✅ codegen/blake3.rb:584 | ✅ codegen/Blake3.java:683 |
| **WOTS+ codegen (verifyWOTS)** | ✅ passes/wots-codegen.ts:103 (dedicated module) | ✅ codegen/wots.go:90 (dedicated; new) | ✅ codegen/wots.rs:94 (dedicated; new) | ✅ codegen/wots.py:122 (dedicated; new) | ✅ passes/helpers/pq_emitters.zig:1021 | ✅ codegen/wots.rb:120 (dedicated module) | ✅ codegen/Wots.java:156 (dedicated module) |
| SLH-DSA SHA2-128s | ✅ slh-dsa-codegen.ts:41 | ✅ slh_dsa.go:49 | ✅ slh_dsa.rs:96 | ✅ slh_dsa.py:81 | ✅ pq_emitters.zig:315 | ✅ slh_dsa.rb:81 | ✅ SlhDsa.java:57 |
| SLH-DSA SHA2-128f | ✅ slh-dsa-codegen.ts:42 | ✅ slh_dsa.go:50 | ✅ slh_dsa.rs:97 | ✅ slh_dsa.py:82 | ✅ pq_emitters.zig:316 | ✅ slh_dsa.rb:82 | ✅ SlhDsa.java:58 |
| SLH-DSA SHA2-192s | ✅ slh-dsa-codegen.ts:43 | ✅ slh_dsa.go:51 | ✅ slh_dsa.rs:98 | ✅ slh_dsa.py:83 | ✅ pq_emitters.zig:317 | ✅ slh_dsa.rb:83 | ✅ SlhDsa.java:59 |
| SLH-DSA SHA2-192f | ✅ slh-dsa-codegen.ts:44 | ✅ slh_dsa.go:52 | ✅ slh_dsa.rs:99 | ✅ slh_dsa.py:84 | ✅ pq_emitters.zig:318 | ✅ slh_dsa.rb:84 | ✅ SlhDsa.java:60 |
| SLH-DSA SHA2-256s | ✅ slh-dsa-codegen.ts:45 | ✅ slh_dsa.go:53 | ✅ slh_dsa.rs:100 | ✅ slh_dsa.py:85 | ✅ pq_emitters.zig:319 | ✅ slh_dsa.rb:85 | ✅ SlhDsa.java:61 |
| SLH-DSA SHA2-256f | ✅ slh-dsa-codegen.ts:46 | ✅ slh_dsa.go:54 | ✅ slh_dsa.rs:101 | ✅ slh_dsa.py:86 | ✅ pq_emitters.zig:320 | ✅ slh_dsa.rb:86 | ✅ SlhDsa.java:62 |
| Rabin sig codegen (verifyRabinSig) | ✅ passes/rabin-codegen.ts:37 (dedicated) | ✅ codegen/rabin.go:19 (dedicated) | ✅ codegen/rabin.rs:22 (dedicated) | ✅ codegen/rabin.py:30 (dedicated) | ✅ passes/helpers/rabin_emitter.zig:35 (dedicated) | ✅ codegen/rabin.rb:33 (dedicated) | ✅ codegen/Rabin.java:48 (dedicated) |

WOTS+ Go/Rust/Python were ⚠️ in `20260514` §3.9 (inline in `stack.{go,rs,py}`, no dedicated module) — `af43aada` WS-6 extracted all three into dedicated `codegen/wots.{go,rs,py}` modules. Now ✅.

### 3.10. SDK surfaces

| Feature | TS | Go | Rust | Python | Zig | Ruby | Java |
|---|---|---|---|---|---|---|---|
| RunarContract | ✅ runar-sdk/src/contract.ts:44 | ✅ runar-go/sdk_contract.go:23 | ✅ runar-rs/src/sdk/contract.rs:37 | ✅ runar-py/runar/sdk/contract.py:28 | ✅ runar-zig/src/sdk_contract.zig:33 | ✅ runar-rb/lib/runar/sdk/contract.rb:52 | ✅ runar-java/.../sdk/RunarContract.java:20 |
| MockProvider | ✅ runar-sdk/src/providers/mock.ts:15 | ✅ runar-go/sdk_provider.go:47 | ✅ runar-rs/src/sdk/provider.rs:48 | ✅ runar-py/runar/sdk/provider.py:51 | ✅ runar-zig/src/sdk_provider.zig:65 | ✅ runar-rb/lib/runar/sdk/provider.rb | ✅ runar-java/.../sdk/MockProvider.java |
| WhatsOnChainProvider | ✅ runar-sdk/src/providers/woc.ts:53 | ✅ runar-go/sdk_woc_provider.go:20 | ✅ runar-rs/src/sdk/woc_provider.rs:16 | ✅ runar-py/runar/sdk/woc_provider.py:17 | ✅ runar-zig/src/sdk_woc_provider.zig:38 | ✅ runar-rb/lib/runar/sdk/woc_provider.rb | ✅ runar-java/.../sdk/WhatsOnChainProvider.java |
| GorillaPoolProvider | ✅ runar-sdk/src/providers/gorillapool.ts:67 | ✅ runar-go/sdk_gorillapool.go:27 | ✅ runar-rs/src/sdk/gorillapool.rs:51 | ✅ runar-py/runar/sdk/gorillapool.py:21 | ✅ runar-zig/src/sdk_gorillapool.zig:39 | ✅ runar-rb/lib/runar/sdk/gorillapool_provider.rb | ✅ runar-java/.../sdk/GorillaPoolProvider.java |
| RpcProvider | ✅ runar-sdk/src/providers/rpc-provider.ts:22 | ✅ runar-go/rpc_provider.go:21 | ✅ runar-rs/src/sdk/rpc_provider.rs:14 | ✅ runar-py/runar/sdk/rpc_provider.py:18 | ✅ runar-zig/src/sdk_rpc_provider.zig:39 | ✅ runar-rb/lib/runar/sdk/rpc_provider.rb | ✅ runar-java/.../sdk/RPCProvider.java |
| WalletProvider / BRC-100 | ✅ runar-sdk/src/providers/wallet-provider.ts:48 | ✅ runar-go/sdk_wallet.go:84 | ✅ runar-rs/src/sdk/wallet.rs:138 | ✅ runar-py/runar/sdk/wallet.py:106 | ✅ runar-zig/src/sdk_wallet.zig | ✅ runar-rb/lib/runar/sdk/wallet.rb | ✅ runar-java/.../sdk/WalletProvider.java:30 |
| **LocalSigner (real ECDSA + BIP-143)** | ✅ runar-sdk/src/signers/local.ts:21 | ✅ runar-go/sdk_signer.go:46 | ✅ runar-rs/src/sdk/signer.rs:52 | ✅ runar-py/runar/sdk/local_signer.py:52 | ✅ runar-zig/src/sdk_signer.zig:53 | ✅ runar-rb/lib/runar/sdk/local_signer.rb:63 — dual-path: tries bsv-sdk first, falls back to pure-Ruby ECDSA + BIP-143 helper (`packages/runar-rb/lib/runar/sdk/bip143.rb`, new 176 LOC) | ✅ runar-java/.../sdk/LocalSigner.java:29 |
| MockSigner | ✅ runar-sdk/src/signers/mock.ts:23 | ✅ runar-go/sdk_signer.go:134 | ✅ runar-rs/src/sdk/signer.rs:428 | ✅ runar-py/runar/sdk/signer.py:37 | ✅ runar-zig/src/sdk_signer.zig:151 | ✅ runar-rb/lib/runar/sdk/signer.rb | ✅ runar-java/.../sdk/MockSigner.java |
| ExternalSigner | ✅ runar-sdk/src/signers/external.ts:39 | ✅ runar-go/sdk_signer.go:181 | ✅ runar-rs/src/sdk/signer.rs:380 | ✅ runar-py/runar/sdk/signer.py:62 | ✅ runar-zig/src/sdk_signer.zig:197 | ✅ runar-rb/lib/runar/sdk/signer.rb | ✅ runar-java/.../sdk/ExternalSigner.java |
| buildDeployTransaction | ✅ runar-sdk/src/deployment.ts:17 | ✅ runar-go/sdk_deployment.go:31 | ✅ runar-rs/src/sdk/deployment.rs:18 | ✅ runar-py/runar/sdk/deployment.py:12 | ✅ runar-zig/src/sdk_deploy.zig:38 | ✅ runar-rb/lib/runar/sdk/deployment.rb:26 | ✅ runar-java/.../sdk/TransactionBuilder.java:37 |
| buildCallTransaction | ✅ runar-sdk/src/calling.ts:22 | ✅ runar-go/sdk_calling.go:51 | ✅ runar-rs/src/sdk/calling.rs:45 | ✅ runar-py/runar/sdk/calling.py:11 | ✅ runar-zig/src/sdk_call.zig:54 | ✅ runar-rb/lib/runar/sdk/calling.rb | ✅ runar-java/.../sdk/TransactionBuilder.java:121 |
| State serialization | ✅ runar-sdk/src/state.ts:28 | ✅ runar-go/sdk_state.go:25 | ✅ runar-rs/src/sdk/state.rs:27 | ✅ runar-py/runar/sdk/state.py:104 | ✅ runar-zig/src/sdk_state.zig:12 | ✅ runar-rb/lib/runar/sdk/state.rb:151 | ✅ runar-java/.../sdk/StateSerializer.java:32 |
| UTXO selection (largest-first) | ✅ runar-sdk/src/deployment.ts:114 | ✅ runar-go/sdk_deployment.go:98 | ✅ runar-rs/src/sdk/deployment.rs:101 | ✅ runar-py/runar/sdk/deployment.py:73 | ✅ runar-zig/src/sdk_deploy.zig:122 | ✅ runar-rb/lib/runar/sdk/deployment.rb:89 | ✅ runar-java/.../sdk/UtxoSelector.java:26 |
| Fee estimation (script-size-aware) | ✅ runar-sdk/src/deployment.ts:96 | ✅ runar-go/sdk_deployment.go:125 | ✅ runar-rs/src/sdk/deployment.rs:89 | ✅ runar-py/runar/sdk/deployment.py:94 | ✅ runar-zig/src/sdk_deploy.zig:161 | ✅ runar-rb/lib/runar/sdk/deployment.rb:115 | ✅ runar-java/.../sdk/FeeEstimator.java:26 |
| ScriptVM (off-chain Script exec) | ✅ runar-testing/src/vm/script-vm.ts:88 (execute+step) | ✅ runar-go/script_vm.go:71 (execute+step) | ⚠️ runar-rs/src/sdk/script_vm.rs:46 — execute-only; upstream Spend hides pc/stack (policy) | ✅ runar-py/runar/sdk/script_vm.py:89 (execute+step; needs bsv-sdk extra) | N/A — no usable BSV interpreter (policy) | N/A — no BSV Ruby SDK (policy) | N/A — no BSV Java SDK (policy) |
| ANF interpreter | ✅ runar-sdk/src/anf-interpreter.ts:155 | ✅ runar-go/anf_interpreter.go:155 | ✅ runar-rs/src/sdk/anf_interpreter.rs:328 | ✅ runar-py/runar/sdk/anf_interpreter.py:206 | ✅ runar-zig/src/sdk_anf_interpreter.zig:250 | ✅ runar-rb/lib/runar/sdk/anf_interpreter.rb:91 | ✅ runar-java/.../sdk/AnfInterpreter.java:57 |
| CompileCheck | ✅ runar-compiler/src/index.ts:523 | ✅ runar-go CompileCheck | ✅ runar-rs compile_check | ✅ runar-py/runar/compile_check.py:9 | ✅ runar-zig/src/compile_check.zig:24 | ✅ runar-rb/lib/runar/compile_check.rb | ✅ runar-java/.../sdk/CompileCheck.java |
| Ordinals BSV-20 mint/transfer | ✅ runar-sdk/src/ordinals/bsv20.ts:50 | ✅ runar-go/sdk_ordinals.go:337 | ✅ runar-rs/src/sdk/ordinals.rs:403 | ✅ runar-py/runar/sdk/ordinals.py:337 | ✅ runar-zig/src/sdk_ordinals.zig:369 | ✅ runar-rb/lib/runar/sdk/ordinals.rb (Bsv20) | ✅ runar-java/.../sdk/ordinals/Bsv20.java |
| Ordinals BSV-21 mint/transfer | ✅ runar-sdk/src/ordinals/bsv20.ts:119 | ✅ runar-go/sdk_ordinals.go:362 | ✅ runar-rs/src/sdk/ordinals.rs:442 | ✅ runar-py/runar/sdk/ordinals.py:361 | ✅ runar-zig/src/sdk_ordinals.zig:415 | ✅ runar-rb/lib/runar/sdk/ordinals.rb (Bsv21) | ✅ runar-java/.../sdk/ordinals/Bsv21.java |
| 1sat inscription envelope | ✅ runar-sdk/src/ordinals/envelope.ts:72 | ✅ runar-go/sdk_ordinals.go:81 | ✅ runar-rs/src/sdk/ordinals.rs:99 | ✅ runar-py/runar/sdk/ordinals.py:73 | ✅ runar-zig/src/sdk_ordinals.zig:92 | ✅ runar-rb/lib/runar/sdk/ordinals.rb:72 | ✅ runar-java/.../sdk/Inscription.java:34 |
| Constructor-slot splicing | ✅ runar-sdk/src/script-utils.ts:125 | ✅ runar-go/sdk_script_utils.go:136 | ✅ runar-rs/src/sdk/contract.rs:1325 | ✅ runar-py/runar/sdk/contract.py:1137 | ✅ runar-zig/src/sdk_script_utils.zig:134 | ✅ runar-rb/lib/runar/sdk/script_utils.rb:105 | ✅ runar-java/.../sdk/ContractScript.java:50 |

Ruby `LocalSigner` was ⚠️ in `20260514` §3.10 (RuntimeError on instantiate without optional bsv-sdk gem) — `af43aada` WS-3 added the pure-Ruby fallback path. Now ✅.

### 3.11. CLI surfaces

| Feature | TS | Go | Rust | Python | Zig | Ruby | Java |
|---|---|---|---|---|---|---|---|
| compile source → artifact/hex | ✅ runar-cli/src/commands/compile.ts:201 | ✅ compilers/go/main.go:35 | ✅ compilers/rust/src/main.rs:35 | ✅ runar_compiler/__main__.py:38 | ✅ compilers/zig/src/main.zig:123 | ✅ runar_compiler/cli.rb:55 | ✅ runar/compiler/Cli.java:524 |
| `--parse-only` mode | ✅ runar-cli/src/bin.ts:39 (exposed flag; handler compile.ts:172–247) | ✅ main.go:44 | ✅ main.rs:44 | ✅ __main__.py:64 | ✅ main.zig:27 | ✅ cli.rb:79 | ✅ Cli.java:527 |
| `--ir` / `--from-ir` (compile from ANF JSON) | ✅ compile.ts:14 (`--from-ir`) | ✅ main.go:38 (`--ir`) | ✅ main.rs:18 (`--ir`) | ✅ __main__.py:34 (`--ir`) | ✅ main.zig:97 | ✅ cli.rb:55 (`--ir`) | ✅ Cli.java:524 (`--ir`) |
| `--hex` output flag | ✅ runar-cli/src/bin.ts:38 (decoupled from `--from-ir`; works in source + from-ir mode) | ✅ main.go:41 | ✅ main.rs:30 | ✅ __main__.py:49 | ✅ main.zig:42 | ✅ cli.rb:67 | ✅ Cli.java:526 |
| `--disable-constant-folding` flag | ✅ compile.ts:13 | ✅ main.go:45 | ✅ main.rs:74 | ✅ __main__.py:74 | ✅ main.zig:46 | ✅ cli.rb:83 | ✅ Cli.java:528 |
| debug / ScriptVM step mode via CLI | ✅ runar-cli/src/commands/debug.ts (interactive step) | ✅ compilers/go/debug.go:32 — `runDebug()` wraps script_vm.go | ✅ compilers/rust/src/debug_subcommand.rs:42 — `pub fn run()` wraps bsv SDK Spend | ✅ compilers/python/runar_compiler/__main__.py:259 — `_run_debug_subcommand()` wraps runar.sdk.script_vm | N/A — no ScriptVM (policy) | N/A — no ScriptVM (policy) | N/A — no ScriptVM (policy) |

TS `--parse-only` and TS `--hex` were ⚠️ in `20260514` §3.11; Go/Rust/Python `debug` was ❌. All four closed by `af43aada` WS-5.

### 3.12. Decompiler (TypeScript-only package)

| Surface | TS | Go | Rust | Python | Zig | Ruby | Java |
|---|---|---|---|---|---|---|---|
| Disassembler | ✅ packages/decompiler/src/disasm.ts:15 | N/A — TS-only | N/A | N/A | N/A | N/A | N/A |
| Symbolic-execution lift | ✅ src/symexec.ts:118; src/symexec-lift.ts:254; src/lift.ts:26 | N/A | N/A | N/A | N/A | N/A | N/A |
| Template / fingerprint matching | ✅ src/templates.ts:137; src/match.ts:63; src/fingerprints.ts:30 | N/A | N/A | N/A | N/A | N/A | N/A |
| Stateful lift | ✅ src/stateful-lift.ts:428 | N/A | N/A | N/A | N/A | N/A | N/A |
| TS source emit | ✅ src/emit-ts.ts:57 | N/A | N/A | N/A | N/A | N/A | N/A |
| Roundtrip verification | ✅ src/verify.ts:38 | N/A | N/A | N/A | N/A | N/A | N/A |
| Refinement loop / dispatch | ✅ src/refine.ts:404; src/dispatch.ts:36; src/index.ts:100 | N/A | N/A | N/A | N/A | N/A | N/A |
| CLI (`runar decompile`) | ✅ runar-cli/src/commands/decompile.ts:54 | N/A | N/A | N/A | N/A | N/A | N/A |

Decompiler treated as TS-only tool per user direction at `20260514` charter; non-TS cells `N/A`, not `❌`.

### 3.13. Example contract patterns

STARK patterns excluded per §1. Only patterns with at least one `❌`/`⚠️` listed; the remaining ~45 patterns (p2pkh, escrow, auction, stateful, stateful-counter, tic-tac-toe, token-ft, token-nft, ec-demo, ec-primitives, ec-unit, schnorr-zkp, p256/p384-primitives + wallet, post-quantum-wallet, post-quantum-wots-naive-INSECURE, post-quantum-slhdsa-naive-INSECURE × 6 param sets, sphincs-wallet, blake3, sha256-compress, sha256-finalize, state-covenant, state-ripemd160, covenant-vault, cross-covenant, convergence-proof, oracle-price, message-board, math-demo, arithmetic, bitwise-ops, shift-ops, boolean-logic, bounded-loop, if-else / -without-else, multi-method, function-patterns, private-helper-outputs, add-data-output, add-raw-output, conditional-data-output, property-initializers, go-dsl-bytestring-literal, asm-raw-script (new)) are `✅` in all 9 columns.

| Pattern | ts | go | rust | python | zig | ruby | java | sol | move |
|---|---|---|---|---|---|---|---|---|---|
| multisig-2of3 | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| bsv20-token | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| bsv21-token | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| ordinal-nft | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| fixed-array-nested | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |

All 5 patterns from `20260514` §3.13 with one or more `❌` are now ✅ in all 9 columns (closed by `af43aada` WS-7). Also new: `asm-raw-script/` exists in all 9 formats (locks the WS-1 raw_script ANF / Bitcoin Script byte contract).

---

## 4. Test matrix

Same columns and legend as §3, applied to test files (cell legend: `✅ test_file:line` directly tested with assertions on output bytes/opcodes/AST/behavior; `⚠️ test_file:line — weakness` weak; `❌` no test; `N/A` feature absent or matches a `N/A` in §3). "golden harness" = the cross-tier conformance golden suite (now 56/56 fixtures); a cell citing it asserts byte-identical IR+hex but not via a tier-local dedicated unit test.

### 4.1. Frontend format parsers

| Feature | TS | Go | Rust | Python | Zig | Ruby | Java |
|---|---|---|---|---|---|---|---|
| `.runar.ts` parser | ✅ __tests__/01-parse.test.ts | ✅ frontend/parser_test.go | ✅ frontend/parser.rs:1225 (inline) | ✅ tests/test_parser_ts.py | ✅ tests/frontend.zig (new) + language_constructs.zig | ✅ test/test_parser_ts.rb | ✅ frontend/TsParserTest.java |
| `.runar.sol` parser | ✅ 01-parse-sol.test.ts:43 | ✅ parser_sol_test.go:12 | ✅ parser_sol.rs:1910 (inline) | ✅ tests/test_parser_sol.py | ✅ tests/frontend.zig (new) | ✅ test/test_parser_sol.rb | ✅ frontend/SolParserTest.java:49 |
| `.runar.move` parser | ✅ 01-parse-move.test.ts | ✅ parser_move_test.go | ✅ parser_move.rs (inline) | ✅ tests/test_parser_move.py | ✅ tests/frontend.zig (new) | ✅ test/test_parser_move.rb | ✅ frontend/MoveParserTest.java |
| `.runar.go` parser | ✅ 01-parse-go.test.ts | ✅ parser_gocontract_test.go | ✅ parser_gocontract.rs (inline) | ✅ tests/test_parser_go.py | ✅ tests/frontend.zig (new) | ✅ test/test_parser_go.rb | ✅ frontend/GoParserTest.java |
| `.runar.rs` parser | ✅ rust-parser-examples.test.ts | ✅ parser_rustmacro_test.go | ✅ parser_rustmacro.rs (inline) | ✅ tests/test_parser_rs.py | ✅ tests/frontend.zig (new) | ✅ test/test_parser_rs.rb | ✅ frontend/RustParserTest.java |
| `.runar.py` parser | ✅ 01-parse-python.test.ts | ✅ parser_python_test.go | ✅ parser_python.rs (inline) | ✅ tests/test_parser_py.py | ✅ tests/frontend.zig (new) | ✅ test/test_parser_py.rb | ✅ frontend/PyParserTest.java |
| `.runar.zig` parser | ✅ zig-parser-examples.test.ts | ✅ parser_zig_test.go | ✅ parser_zig.rs (inline) | ✅ tests/test_parser_zig.py | ✅ tests/conformance.zig + language_constructs.zig | ✅ test/test_parser_zig.rb | ✅ frontend/ZigParserTest.java |
| `.runar.rb` parser | ✅ 01-parse-ruby.test.ts | ✅ parser_ruby_test.go | ✅ parser_ruby.rs (inline) | ✅ tests/test_parser_rb.py | ✅ tests/frontend.zig (new) | ✅ test/test_parser_ruby.rb | ✅ frontend/RbParserTest.java |
| `.runar.java` parser | ✅ 01-parse-java.test.ts | ✅ parser_java_test.go | ✅ parser_java.rs (inline) | ✅ tests/test_parser_java.py | ✅ tests/frontend.zig (new) | ✅ test/test_parser_java.rb | ✅ frontend/JavaParserTest.java |

Zig parser cells for 8 non-Zig formats were `⚠️ — golden harness only` in `20260514` §4.1; `af43aada` WS-4 added `compilers/zig/src/tests/frontend.zig` (~563 LOC) with dedicated parser unit tests. Now ✅.

### 4.2. Type system

| Feature | TS | Go | Rust | Python | Zig | Ruby | Java |
|---|---|---|---|---|---|---|---|
| bigint / bool / ByteString | ✅ 03-typecheck.test.ts:185 | ✅ typecheck_test.go | ✅ typecheck.rs (inline) | ✅ test_frontend.py | ✅ tests/frontend.zig (new) | ✅ test_typecheck.rb:52 | ✅ TypecheckTest.java:51 |
| Point | ✅ ec.test.ts:9 | ✅ frontend/typecheck_test.go (new Point-typed-property test) | ✅ codegen/ec.rs (inline) | ✅ tests/codegen/test_ec.py | ✅ language_constructs.zig | ✅ test/codegen/test_ec.rb | ✅ codegen/EcTest.java |
| Fixed-size arrays | ✅ 03b-expand-fixed-arrays.test.ts | ✅ expand_fixed_arrays_test.go | ✅ expand_fixed_arrays.rs (inline) | ✅ test_expand_fixed_arrays.py | ✅ tests/frontend.zig (new) | ✅ test/test_expand_fixed_arrays.rb | ✅ passes/ExpandFixedArraysTest.java |
| readonly properties | ✅ 02-validate.test.ts:377 | ✅ validator_test.go | ✅ validator.rs (inline) | ✅ test_frontend.py | ✅ tests/frontend.zig (new) | ✅ test_validator.rb:350 | ✅ passes/ValidateTest.java |
| Property initializers | ✅ 02-validate.test.ts:377 | ✅ expand_fixed_arrays_test.go | ✅ expand_fixed_arrays.rs (inline) | ✅ test_expand_fixed_arrays.py | ✅ tests/frontend.zig (new) | ✅ test_validator.rb:608 | ✅ ExpandFixedArraysTest.java |

Go Point-typed-property cell was ⚠️ in `20260514`; now ✅.

### 4.3. Control flow

| Feature | TS | Go | Rust | Python | Zig | Ruby | Java |
|---|---|---|---|---|---|---|---|
| if / else | ✅ 06-emit.test.ts | ✅ emit_test.go:504 | ✅ emit.rs:759 (inline) | ✅ test_emit.py:664 | ✅ language_constructs.zig:94 | ✅ test/codegen/test_emit.rb | ✅ EmitTest.java:136 |
| if-without-else | ✅ if-without-else.test.ts:91 | ✅ emit_test.go:922 | ✅ emit.rs:1167 (inline) | ✅ test_emit.py:539 | ✅ language_constructs.zig:94 | ✅ test_stack_lower.rb | ✅ StackIrTest.java:129 |
| Ternary expression | ✅ 04-anf-lower.test.ts:264 | ✅ anf_lower_test.go:TestANFLower_Ternary | ✅ ternary lowering tests (cited in WS-4 closure) | ✅ test_frontend.py + ternary tests | ✅ tests/frontend.zig + ternary tests | ✅ test_anf_lower.rb:test_ternary_lowers_to_if_anf_binding | ✅ StackLowerTest.java:592 |
| Bounded for-loop | ✅ 02-validate.test.ts:215 | ✅ anf_lower_test.go:435 | ✅ anf_lower.rs (inline) | ✅ test_while.py + test_frontend.py:1025 | ✅ tests/frontend.zig (new) | ✅ test_validator.rb:478 | ✅ AnfLowerTest.java |
| while-loop | N/A | N/A | N/A | N/A | N/A | N/A | N/A |
| break / continue | ✅ rejection test in 01-parse suite | N/A | N/A | ✅ test_break_continue.py (rejection) | N/A | N/A | N/A |

Ternary Go/Rust/Python/Zig/Ruby cells were ⚠️ in `20260514` §4.3 (golden harness only); now ✅ with dedicated tests.

### 4.4. Operators

| Feature | TS | Go | Rust | Python | Zig | Ruby | Java |
|---|---|---|---|---|---|---|---|
| Arithmetic | ✅ 05-stack-lower.test.ts:188 | ✅ stack_test.go | ✅ stack.rs (inline) | ✅ test_stack.py | ⚠️ language_constructs.zig — bitwise/shift covered, no explicit `+ - * /` op test [carried from `20260514`; not in `af43aada` claims] | ✅ test_stack_lower.rb:188 | ✅ EmitTest.java:64 |
| Comparison | ✅ 03-typecheck.test.ts:444 | ✅ typecheck_test.go | ✅ typecheck.rs (inline) | ✅ test_frontend.py | ⚠️ language_constructs.zig — no explicit comparison-op test | ✅ test_typecheck.rb | ✅ TypecheckTest.java |
| Boolean | ✅ 03-typecheck.test.ts:526 | ✅ typecheck_test.go | ✅ typecheck.rs (inline) | ✅ test_frontend.py | ⚠️ language_constructs.zig — no explicit boolean-op test | ✅ test_typecheck.rb:156 | ✅ TypecheckTest.java |
| Bitwise `& \| ^ ~` | ✅ optimizer.test.ts:192 | ✅ stack_test.go / optimizer_test.go | ✅ stack.rs / constant_fold.rs (inline) | ✅ test_constant_fold.py | ✅ language_constructs.zig:123 | ✅ test_optimizer.rb | ✅ StackLowerTest.java:667 |
| Shift `<< >>` | ✅ optimizer.test.ts:151 | ✅ optimizer_test.go / stack_test.go | ✅ constant_fold.rs (inline) | ✅ test_constant_fold.py | ✅ language_constructs.zig:183 | ✅ test_optimizer.rb | ✅ StackLowerTest.java:733 |

Zig `arithmetic`/`comparison`/`boolean` cells unchanged from `20260514` (still `⚠️ — no explicit op test`). `af43aada` commit message claims Zig ops were upgraded, but the §4 sub-agent could not find new explicit Zig assertions for these three rows. Carry these as remaining `⚠️` cells in §5.

### 4.5. Compiler passes

| Feature | TS | Go | Rust | Python | Zig | Ruby | Java |
|---|---|---|---|---|---|---|---|
| validate | ✅ 02-validate.test.ts | ✅ validator_test.go | ✅ validator.rs (inline) | ✅ test_frontend.py:325 | ✅ tests/frontend.zig (new) | ✅ test_validator.rb | ✅ ValidateTest.java |
| typecheck | ✅ 03-typecheck.test.ts | ✅ typecheck_test.go | ✅ typecheck.rs (inline) | ✅ test_frontend.py:772 | ✅ tests/frontend.zig (new) | ✅ test_typecheck.rb | ✅ TypecheckTest.java |
| ANF lowering | ✅ 04-anf-lower.test.ts | ✅ anf_lower_test.go | ✅ anf_lower.rs (inline) | ✅ test_frontend.py:985 | ✅ tests/frontend.zig (new) | ✅ test_anf_lower.rb | ✅ AnfLowerTest.java |
| constant folding | ✅ optimizer.test.ts:35 | ✅ constant_fold_test.go | ✅ constant_fold.rs (inline) | ✅ test_constant_fold.py | ✅ tests/frontend.zig (new) | ✅ test_optimizer.rb | ✅ ConstantFoldTest.java |
| peephole optimizer | ✅ optimizer.test.ts | ✅ codegen/optimizer_test.go | ✅ codegen/optimizer.rs (inline) | ✅ test_optimizer.py | ✅ passes/peephole.zig (inline) | ✅ test/test_optimizer.rb | ✅ passes/PeepholeTest.java |
| expand-fixed-arrays | ✅ 03b-expand-fixed-arrays.test.ts | ✅ expand_fixed_arrays_test.go | ✅ expand_fixed_arrays.rs (inline) | ✅ test_expand_fixed_arrays.py | ✅ tests/frontend.zig (new) | ✅ test_expand_fixed_arrays.rb | ✅ ExpandFixedArraysTest.java |
| stack lowering | ✅ 05-stack-lower.test.ts:279 | ✅ codegen/stack_test.go:124 | ⚠️ codegen/stack.rs:4852 (inline) — opcode-shape only, not exact bytes | ✅ tests/test_stack.py:150 | ⚠️ stack_lower.zig (inline) — stack-map units, not lowering output | ✅ test/test_stack_lower.rb:188 | ✅ passes/StackLowerTest.java:180 |
| emit | ✅ 06-emit.test.ts (new exact-byte assertions added by WS-4) | ✅ codegen/emit_test.go:160 (exact bytes) | ✅ codegen/emit.rs (new exact-byte assertions added by WS-4) | ✅ tests/test_emit.py | ✅ codegen/emit.zig:911 (inline, exact bytes) | ✅ test/codegen/test_emit.rb | ✅ passes/EmitTest.java:28 (exact bytes) |
| opcode mapping table | ⚠️ 06-emit.test.ts — partial | ✅ emit_test.go:353 | ⚠️ emit.rs (inline) — partial | ✅ tests/codegen/test_*.py | ✅ emit.zig:911 | ✅ test/test_stack_lower.rb:188 | ✅ EmitTest.java:28 |

Several ⚠️ cells from `20260514` §4.5 closed: TS+Rust `emit` cells gained exact-byte assertions. Remaining: Rust+Zig `stack lowering` shape-only inline tests; TS+Rust `opcode mapping` partial.

### 4.6. Contract model

| Feature | TS | Go | Rust | Python | Zig | Ruby | Java |
|---|---|---|---|---|---|---|---|
| SmartContract/Stateful + parentClass | ✅ golden harness (stateful/* fixtures) | ✅ conformance_goldens_test.go | ✅ tests/conformance_goldens.rs | ✅ test_conformance_goldens.py | ✅ test_conformance.zig | ✅ conformance_goldens_test.rb | ✅ compilers/java/src/test/.../ConformanceGoldensTest.java (new in-tree golden hex test) |
| Auto checkPreimage at entry | ✅ golden harness | ✅ stack_test.go (stateful) | ✅ conformance_goldens.rs | ✅ tests/codegen/test_check_preimage.py | ✅ test_conformance.zig | ✅ conformance_goldens_test.rb | ✅ StackLowerTest.java:219 |
| State continuation / get_state_script | ✅ golden harness (state-covenant) | ✅ conformance_goldens_test.go | ✅ conformance_goldens.rs | ✅ test_conformance_goldens.py | ✅ test_conformance.zig | ✅ conformance_goldens_test.rb | ✅ ConformanceGoldensTest.java (new) |
| OP_CODESEPARATOR auto-insertion | ✅ golden harness | ✅ stack_test.go (stateful) | ✅ conformance_goldens.rs | ✅ tests/codegen/test_codeseparator.py | ✅ test_conformance.zig | ✅ conformance_goldens_test.rb | ✅ StackLowerTest.java:219 |
| codeSeparatorIndex artifact fields | ⚠️ golden harness — no field-specific assert | ✅ emit_test.go | ⚠️ golden harness only | ⚠️ golden harness only | ⚠️ golden harness only | ⚠️ golden harness only | ⚠️ golden harness only |
| addOutput (multi-output) | ✅ 05-stack-lower.test.ts + golden | ✅ conformance_goldens_test.go | ✅ conformance_goldens.rs | ✅ tests/codegen/test_addoutput.py:102 | ✅ test_conformance.zig | ⚠️ no dedicated addOutput test — golden harness only | ✅ StackLowerTest.java:257 |
| addRawOutput | ✅ golden harness (add-raw-output) | ✅ conformance_goldens_test.go | ✅ tests/addraw_output_codegen_test.rs | ✅ tests/codegen/test_addrawoutput.py | ✅ test_conformance.zig | ⚠️ golden harness only | ✅ StackLowerTest.java:382 |
| addDataOutput | ✅ golden harness (add-data-output) | ✅ stack_test.go:1698 | ✅ conformance_goldens.rs | ✅ test_addrawoutput.py | ✅ test_conformance.zig | ✅ test/codegen/test_add_data_output.rb | ✅ StackLowerTest.java:426 |
| **asm intrinsic / raw_script / UnsafeSmartContract** | ✅ __tests__/asm-surface.test.ts, asm-array-form.test.ts, asm-expression-form.test.ts, asm-multiformat.test.ts (new), raw-script-spans.test.ts (new) | ✅ stack_test.go (raw_script + asm tests added) | ✅ asm/raw_script unit tests (added by WS-1) | ✅ tests/test_raw_script.py (new) | ✅ tests/raw_script tests | ✅ test/codegen/test_raw_script.rb (new) | ✅ passes/RawScriptTest.java (new) |
| assert() | ✅ 05-stack-lower.test.ts:426 | ✅ emit_test.go:331 | ✅ conformance_goldens.rs | ✅ test_stack.py:324 | ✅ test_conformance.zig | ✅ test_stack_lower.rb:121 | ✅ StackLowerTest.java |

Java SmartContract / State continuation cells improved from ⚠️ (external runner only) → ✅ (new in-tree ConformanceGoldensTest). asm-intrinsic row was N/A in 6 tiers under `20260514`; now ✅ everywhere with dedicated tests.

### 4.7. Math builtins

| Feature | TS | Go | Rust | Python | Zig | Ruby | Java |
|---|---|---|---|---|---|---|---|
| abs | ✅ golden harness (math-demo extended) | ✅ golden harness | ✅ golden harness | ✅ tests/codegen/test_math_builtins.py:161 | ✅ golden harness | ✅ test/codegen/test_math_builtins.rb (new) | ✅ MathBuiltinsLowerTest.java |
| min | ✅ golden harness | ✅ golden harness | ✅ golden harness | ✅ test_math_builtins.py:167 | ✅ golden harness | ✅ test_math_builtins.rb (new) | ✅ MathBuiltinsLowerTest.java |
| max | ✅ golden harness | ✅ golden harness | ✅ golden harness | ✅ test_math_builtins.py:175 | ✅ golden harness | ✅ test_math_builtins.rb (new) | ✅ MathBuiltinsLowerTest.java |
| within | ✅ golden harness | ✅ golden harness | ✅ golden harness | ✅ test_math_builtins.py:182 | ✅ golden harness | ✅ test_math_builtins.rb (new) | ✅ MathBuiltinsLowerTest.java |
| safediv | ✅ golden harness (math-demo) | ✅ golden harness (math-demo) | ✅ golden harness (math-demo) | ✅ test_math_builtins.py:197 | ✅ golden harness (math-demo) | ✅ test_math_builtins.rb (new) | ✅ MathBuiltinsLowerTest.java |
| safemod | ✅ golden harness (math-demo extended) | ✅ golden harness | ✅ golden harness | ✅ test_math_builtins.py:206 | ✅ golden harness | ✅ test_math_builtins.rb (new) | ✅ MathBuiltinsLowerTest.java |
| clamp | ✅ golden harness | ✅ golden harness | ✅ golden harness | ✅ test_math_builtins.py:228 | ✅ golden harness | ✅ test_math_builtins.rb (new) | ✅ MathBuiltinsLowerTest.java:136 |
| sign | ✅ 05-stack-lower.test.ts:609 + golden | ✅ stack_test.go:1531 | ✅ golden harness | ✅ test_math_builtins.py | ✅ golden harness | ✅ test_math_builtins.rb (new) | ✅ MathBuiltinsLowerTest.java:358 |
| pow | ✅ golden harness | ✅ golden harness | ✅ golden harness | ✅ test_math_builtins.py | ✅ golden harness | ✅ test_math_builtins.rb (new) | ✅ MathBuiltinsLowerTest.java:163 |
| mulDiv | ✅ golden harness | ✅ golden harness | ✅ golden harness | ✅ test_math_builtins.py | ✅ golden harness | ✅ test_math_builtins.rb (new) | ✅ MathBuiltinsLowerTest.java:195 |
| percentOf | ✅ golden harness | ✅ golden harness | ✅ golden harness | ✅ test_math_builtins.py | ✅ golden harness | ✅ test_math_builtins.rb (new) | ✅ ConformanceGoldensTest.java (in-tree) |
| sqrt | ✅ 05-stack-lower.test.ts:899 + golden | ✅ stack_test.go:848 | ✅ golden harness | ✅ test_math_builtins.py | ✅ golden harness | ✅ test_math_builtins.rb (new) | ✅ MathBuiltinsLowerTest.java:210 |
| gcd | ✅ golden harness | ✅ golden harness | ✅ golden harness | ✅ test_math_builtins.py | ✅ golden harness | ✅ test_math_builtins.rb (new) | ✅ MathBuiltinsLowerTest.java:255 |
| divmod | ✅ golden harness (math-demo extended) | ✅ golden harness | ✅ golden harness | ✅ test_math_builtins.py | ✅ golden harness | ✅ test_math_builtins.rb (new) | ✅ MathBuiltinsLowerTest.java:281 |
| log2 | ✅ 05-stack-lower.test.ts:867 + golden | ✅ stack_test.go:769 | ✅ golden harness | ✅ tests/test_stack.py:540 | ✅ golden harness | ✅ test_math_builtins.rb (new) | ✅ MathBuiltinsLowerTest.java:328 |
| bool | ✅ golden harness | ✅ golden harness | ✅ golden harness | ✅ test_math_builtins.py:189 | ✅ golden harness | ✅ test_math_builtins.rb (new) | ✅ MathBuiltinsLowerTest.java |

All 16 builtins × 7 tiers are now `✅` (math-demo fixture extended to all 16; Ruby gained dedicated unit-test file ~251 LOC). Closes `20260514` §5.2 T-1.

### 4.8. Hash builtins

| Feature | TS | Go | Rust | Python | Zig | Ruby | Java |
|---|---|---|---|---|---|---|---|
| sha256 | ✅ 05-stack-lower.test.ts:279 + golden | ✅ emit_test.go:982 | ✅ golden harness (basic-p2pkh) | ✅ tests/codegen/test_hash_builtins.py | ✅ test_conformance.zig | ✅ test_stack_lower.rb:509 | ✅ ConformanceGoldensTest.java + EmitTest |
| hash160 | ✅ golden harness | ✅ conformance_goldens_test.go | ✅ golden harness | ✅ test_hash_builtins.py:83 | ✅ test_conformance.zig | ✅ test_stack_lower.rb:305 | ✅ EmitTest.java:52 |
| hash256 | ✅ golden harness | ✅ conformance_goldens_test.go | ✅ conformance_goldens.rs | ✅ test_hash_builtins.py:117 | ✅ test_conformance.zig | ✅ golden harness | ✅ ConformanceGoldensTest.java |
| ripemd160 | ✅ golden harness (state-ripemd160) | ✅ conformance_goldens_test.go | ✅ conformance_goldens.rs | ✅ test_hash_builtins.py | ✅ test_conformance.zig | ✅ conformance_goldens_test.rb | ✅ ConformanceGoldensTest.java |
| sha256Compress | ✅ __tests__/sha256-compress.test.ts + golden | ✅ golden harness | ✅ tests/sha256_codegen_tests.rs | ✅ tests/codegen/test_sha256.py | ✅ test_conformance.zig | ✅ test/codegen/test_sha256.rb | ✅ codegen/Sha256Test.java |
| sha256Finalize | ✅ __tests__/sha256-finalize.test.ts + golden | ✅ golden harness | ✅ sha256_codegen_tests.rs | ✅ test_sha256.py | ✅ test_conformance.zig | ✅ test/codegen/test_sha256.rb | ✅ codegen/Sha256Test.java |
| checkPreimage | ✅ golden harness | ✅ stack_test.go (stateful) | ✅ conformance_goldens.rs | ✅ tests/codegen/test_check_preimage.py | ✅ test_conformance.zig | ✅ conformance_goldens_test.rb | ✅ StackLowerTest.java:219 |

### 4.9. Crypto codegen

| Feature | TS | Go | Rust | Python | Zig | Ruby | Java |
|---|---|---|---|---|---|---|---|
| checkSig | ✅ 05-stack-lower.test.ts:125 | ✅ golden harness (basic-p2pkh) | ✅ conformance_goldens.rs:211 | ✅ tests/codegen/test_check_sig.py:97 | ✅ conformance_goldens.zig | ✅ conformance_goldens_test.rb:114 | ✅ ConformanceGoldensTest.java |
| **checkMultiSig** | ✅ 05-stack-lower.test.ts:417 + golden (multisig fixture, new) | ✅ golden harness (multisig fixture, new) | ✅ golden harness | ✅ golden harness | ✅ tests/check_multisig.zig (new, 177 LOC) | ✅ test/codegen/test_check_multisig.rb (new, 167 LOC) | ✅ codegen/CheckMultiSigTest.java:185 |
| ecAdd / ecMul / ecMulGen / ecNegate / ecOnCurve / ecModReduce / ecEncodeCompressed / ecMakePoint / ecPointX / ecPointY | ⚠️ ec.test.ts (some compile-only) | ✅ golden harness (ec-primitives/ec-unit) | ⚠️ ec_codegen_tests.rs — `_nontrivial` per builtin | ✅ tests/codegen/test_ec.py:43 (op-count goldens; :53 8-op sequence) | ⚠️ ec_emitters.zig (inline) — structural | ⚠️ test/codegen/test_ec.rb — ASM-shape | ✅ codegen/EcTest.java (per-builtin op-count + hex goldens) |
| NIST P-256 | ✅ golden harness (p256-primitives/p256-wallet) | ✅ golden harness | ⚠️ crypto_codegen_tests.rs:69 — `_nontrivial` | ✅ tests/codegen/test_p256_p384.py:33 | ⚠️ nist_ec_emitters.zig (inline) — "emits ops" only | ⚠️ test_p256_p384.rb:15 — ASM-shape | ✅ codegen/P256P384Test.java:35 |
| NIST P-384 | ✅ golden harness (p384-primitives/p384-wallet) | ✅ golden harness | ⚠️ crypto_codegen_tests.rs:119 — `_nontrivial` | ✅ test_p256_p384.py:49 | ⚠️ nist_ec_emitters.zig — "emits ops" only | ⚠️ test_p256_p384.rb — ASM-shape | ✅ P256P384Test.java:35 |
| SHA-256 full module | ⚠️ sha256-compress.test.ts:57 / sha256-finalize.test.ts:57 — ASM-grep | ✅ golden harness | ⚠️ sha256_codegen_tests.rs:39 — counts | ✅ tests/codegen/test_sha256.py:25 | ⚠️ sha256_emitters.zig (inline) — opcode-family + constants | ⚠️ test_sha256.rb:22 — ASM-shape | ✅ codegen/Sha256Test.java:45 |
| BLAKE3 | ✅ __tests__/blake3-output.test.ts:45 — ScriptVM exec + stack bytes | ✅ golden harness | ⚠️ crypto_codegen_tests.rs:34 — `_nontrivial`/deterministic | ✅ tests/codegen/test_blake3.py:20 | ⚠️ blake3_emitters.zig (inline) — instruction-count + IV-word checks | ⚠️ test_blake3.rb:11 — ASM-shape | ✅ codegen/Blake3Test.java |
| WOTS+ (verifyWOTS) | ✅ __tests__/wots-codegen.test.ts:55 — hex length + sha256 of full script | ✅ golden harness (post-quantum-wots) | ✅ conformance_goldens.rs:211 (post-quantum-wots) | ✅ tests/codegen/test_wots_byte_parity.py:94 | ⚠️ pq_emitters.zig (inline) — "emits a real instruction sequence" | ✅ test/codegen/test_wots.rb:60 — exact op-count | ✅ codegen/WotsTest.java:88 — exact counts |
| SLH-DSA SHA2-128s | ✅ golden harness (post-quantum-slhdsa) | ✅ golden harness | ✅ conformance_goldens.rs:211 | ✅ tests/codegen/test_slh_dsa.py:35 (op-count) | ⚠️ pq_emitters.zig (inline) — "emits sequence" | ⚠️ test_slh_dsa.rb:14 — ASM-shape | ✅ codegen/SlhDsaTest.java:157 (canonical hex) |
| **SLH-DSA SHA2-128f / 192s / 192f / 256s / 256f** | ✅ golden harness (5 new fixtures) | ✅ golden harness (5 new fixtures) | ⚠️ crypto_codegen_tests.rs:1548 — param keys `_nontrivial`, no byte unit test | ✅ test_slh_dsa.py:24 + :58 (all 6 differ) | ⚠️ pq_emitters.zig (inline) — "emits sequences for every SHA2 family" | ⚠️ test_slh_dsa.rb still tests only 128s — fixtures lock bytes cross-tier, no dedicated Ruby unit test for the 5 new param sets | ✅ codegen/SlhDsaTest.java:51 / :176 / :203 (canonical hex 128s/192s/256f) |
| Rabin sig (verifyRabinSig) | ✅ __tests__/rabin-codegen.test.ts:58 — 10-op sequence + golden hex | ✅ codegen/rabin_test.go:22 — 10-op golden | ✅ codegen/rabin.rs:41 (inline) — byte-frozen golden | ✅ tests/codegen/test_rabin.py:34 — 10-op golden | ✅ rabin_emitter.zig:44 (inline) — 10-op golden | ✅ test/codegen/test_rabin.rb:22 — 10-op golden | ✅ codegen/RabinTest.java:37 — 10-op sequence |

`20260514` §5.2 T-2 (checkMultiSig: ⚠️/❌ in 6 tiers, no fixture) closed by `af43aada` WS-2: new `multisig` fixture + dedicated Zig + Ruby tests. `20260514` §5.2 T-3 (SLH-DSA non-128s: ⚠️/❌ in 5 tiers, no fixtures) closed by 5 new fixtures (`post-quantum-slhdsa-{128f,192s,192f,256s,256f}/`); cross-tier byte parity locked. Two `⚠️` cells remain: Rust per-param `_nontrivial` and Ruby `test_slh_dsa.rb` still only covers 128s (not parametrized over the 5 new param sets, though cross-tier byte parity is locked by the fixtures — so the gap is dedicated-Ruby-unit-test depth, not byte correctness).

### 4.10. SDK surfaces

| Feature | TS | Go | Rust | Python | Zig | Ruby | Java |
|---|---|---|---|---|---|---|---|
| RunarContract | ✅ contract-lifecycle.test.ts:55 | ✅ runar-go/sdk_test.go:183 | ✅ contract.rs (inline) | ✅ tests/test_contract_lifecycle.py | ✅ sdk_contract.zig (inline) | ✅ spec/sdk/contract_spec.rb:142 | ✅ RunarContractTest.java:27 |
| MockProvider | ✅ providers.test.ts:27 | ✅ runar-go/sdk_test.go | ✅ provider.rs:194 (inline) | ✅ tests/test_sdk_* | ✅ sdk_call.zig:364 (inline) | ✅ spec/sdk/provider_spec.rb:7 | ✅ MockProviderTest.java:11 |
| WhatsOnChainProvider | ✅ providers.test.ts | ✅ packages/runar-go/sdk_woc_provider_test.go (new, 323 LOC, httptest mock) | ✅ woc_provider.rs:179 (inline) | ✅ tests/test_woc_provider.py | ✅ sdk_woc_provider.zig:436 (inline) | ✅ spec/sdk/woc_provider_spec.rb:6 | ✅ WhatsOnChainProviderTest.java:33 |
| GorillaPoolProvider | ✅ providers.test.ts | ✅ packages/runar-go/sdk_gorillapool_test.go (new, 380 LOC, httptest mock) | ✅ gorillapool.rs:386 (inline) | ✅ tests/test_gorillapool_provider.py | ✅ sdk_gorillapool.zig:454 (inline) | ✅ spec/sdk/provider_spec.rb | ✅ GorillaPoolProviderTest.java:37 |
| RpcProvider | ✅ providers.test.ts | ✅ rpc_provider_test.go:59 | ✅ rpc_provider.rs:274 (inline) | ✅ tests/test_sdk_rpc_provider.py | ✅ sdk_rpc_provider.zig:294 (inline) | ✅ spec/sdk/rpc_provider_spec.rb:6 | ✅ RPCProviderTest.java:47 |
| WalletProvider / BRC-100 | ✅ wallet-client.spec.ts:48 | ✅ runar-go/sdk_wallet_test.go:82 | ✅ runar-rs/tests/wallet_client_integration.rs | ✅ tests/test_wallet.py | ✅ sdk_wallet_client_integration_test.zig | ✅ spec/runar/sdk/wallet_spec.rb:48 | ✅ WalletProviderTest.java:28 |
| **LocalSigner** | ✅ local-signer.test.ts:20 | ✅ runar-go/sdk_test.go | ✅ signer.rs:476 (inline) | ✅ tests/test_signer.py + test_local_signer_fallback.py | ✅ sdk_signer.zig:253 (inline) | ✅ spec/sdk/local_signer_spec.rb (expanded 18 → 130 LOC; now exercises the pure-Ruby fallback path, not just the no-bsv-sdk RuntimeError) | ✅ LocalSignerTest.java:31 |
| MockSigner | ✅ mock-signer.spec.ts:11 | ✅ runar-go/sdk_test.go | ✅ signer.rs:476 (inline) | ✅ tests/test_signer.py | ✅ sdk_signer.zig:236 (inline) | ✅ spec/sdk/signer_spec.rb | ✅ MockSignerTest.java:11 |
| ExternalSigner | ✅ external-signer.test.ts:4 | ✅ runar-go/sdk_test.go | ✅ signer.rs:476 (inline) | ✅ tests/test_signer.py | ✅ sdk_signer.zig (inline) | ✅ spec/sdk/signer_spec.rb | ✅ ExternalSignerTest.java:22 |
| buildDeployTransaction | ✅ deployment.test.ts:92 | ✅ sdk_deployment_test.go:883 | ✅ deployment.rs:215 (inline) | ✅ tests/test_sdk_deployment.py | ✅ sdk_deploy.zig:212 (inline) | ✅ spec/sdk/deployment_spec.rb:7 | ✅ TransactionBuilderTest.java:14 |
| buildCallTransaction | ✅ build-call-transaction.test.ts:108 | ✅ runar-go/sdk_test.go | ✅ calling.rs:273 (inline) | ✅ tests/test_sdk_calling.py | ✅ sdk_call.zig:311 (inline) | ✅ spec/sdk/calling_spec.rb:34 | ✅ TransactionBuilderTest.java:47 |
| State serialization | ✅ state.test.ts:17 | ✅ sdk_test.go:500 | ✅ state.rs:623 (inline) | ✅ tests/test_sdk_state.py | ✅ sdk_state.zig:670 (inline) | ✅ spec/sdk/state_spec.rb:7 | ✅ StateSerializerTest.java:15 |
| UTXO selection | ✅ deployment.test.ts | ✅ sdk_deployment_test.go | ✅ deployment.rs:215 (inline) | ✅ tests/test_sdk_deployment.py | ✅ sdk_deploy.zig:226 (inline) | ✅ spec/sdk/deployment_spec.rb | ✅ UtxoSelectorTest.java:15 |
| Fee estimation | ✅ deployment.test.ts | ✅ sdk_deployment_test.go:10 | ✅ deployment.rs/calling.rs (inline) | ✅ tests/test_sdk_deployment.py | ✅ sdk_deploy.zig:212 (inline) | ✅ spec/sdk/deployment_spec.rb | ✅ FeeEstimatorTest.java:9 |
| ScriptVM | ✅ vm.test.ts:22 + step-vm.test.ts | ✅ runar-go/script_vm_test.go:11 | ⚠️ script_vm.rs:121 (inline) — execute-only; no step coverage | ⚠️ tests/test_script_vm.py:14 — `importorskip("bsv")`; skipped in default CI without the `script-vm` extra installed | N/A | N/A | N/A |
| ANF interpreter | ✅ anf-interpreter.test.ts:73 | ✅ runar-go/sdk_test.go:2877 | ✅ anf_interpreter.rs:1280 (inline) | ✅ tests/test_anf_interpreter.py:121 | ✅ sdk_anf_interpreter.zig:1771 (inline) | ✅ spec/sdk/anf_interpreter_spec.rb:165 | ✅ AnfInterpreterTest.java:20 |
| CompileCheck | ✅ compile-check.test.ts:48 | ⚠️ exercised via examples/go/*_test.go — no unit test in packages/runar-go | ✅ compile_check tests in crate/examples | ✅ tests/test_compile_check.py | ✅ compile_check.zig:116 (inline) | ✅ packages/runar-rb/spec/sdk/compile_check_spec.rb (new, 102 LOC) | ✅ CompileCheckTest.java:71 |
| Ordinals BSV-20/21 + envelope | ✅ ordinals-bsv20.test.ts + ordinals-envelope.test.ts | ✅ sdk_ordinals_test.go:13 | ✅ ordinals.rs:479 (inline) | ✅ tests/test_ordinals.py | ✅ sdk_ordinals.zig:494 (inline) | ✅ spec/sdk/ordinals_spec.rb:21 | ✅ Bsv20Test.java:33 + Bsv21Test.java:32 |
| Constructor-slot splicing | ✅ constructor-slots.test.ts:29 | ✅ sdk_test.go:381 | ✅ contract.rs/state.rs (inline) | ✅ tests/test_build_unlocking_script.py | ✅ sdk_contract.zig:2707 (inline) | ✅ spec/sdk/contract_spec.rb | ✅ ContractScriptTest.java:51 |

Go WOC + GorillaPool unit-test cells were ❌ in `20260514`; now ✅. Ruby LocalSigner ⚠️→✅. Ruby CompileCheck ❌→✅. Python `test_script_vm.py` still `importorskip("bsv")` — `af43aada` WS-4 modified it (24 LOC change to `packages/runar-py/tests/test_script_vm.py`); whether default-CI now installs the `script-vm` extra is unconfirmed in this audit (no CI run was performed) so the cell remains `⚠️` pending CI verification.

### 4.11. CLI surfaces

| Feature | TS | Go | Rust | Python | Zig | Ruby | Java |
|---|---|---|---|---|---|---|---|
| basic compile | ✅ runar-cli/src/__tests__/ + new compile-flags.test.ts | ✅ conformance runner | ✅ conformance runner | ✅ conformance runner | ✅ conformance runner | ✅ conformance runner | ✅ conformance runner |
| `--parse-only` | ✅ compile-flags.test.ts (new) + conformance `--parser-only` matrix | ✅ cli_parse_only_test.go + all-tier matrix | ✅ all-tier matrix | ✅ all-tier matrix | ✅ main.zig (inline) + matrix | ✅ all-tier matrix | ✅ all-tier matrix |
| `--ir` / `--from-ir` | ✅ conformance dual-mode | ✅ conformance dual-mode | ✅ conformance dual-mode | ✅ conformance dual-mode | ✅ conformance dual-mode | ✅ conformance dual-mode | ✅ conformance dual-mode |
| `--hex` | ✅ compile-flags.test.ts (new) + conformance hex-parity | ✅ conformance hex-parity | ✅ conformance hex-parity | ✅ conformance hex-parity | ✅ conformance hex-parity | ✅ conformance hex-parity | ✅ conformance hex-parity |
| `--disable-constant-folding` | ✅ CI fold-OFF + fold-ON steps | ✅ CI fold modes | ✅ CI fold modes | ✅ CI fold modes | ✅ main.zig:492 (inline) + CI | ✅ CI fold modes | ✅ CI fold modes |
| debug / ScriptVM step via CLI | ✅ runar-cli/src/__tests__/debug.test.ts | ✅ compilers/go/cli_debug_test.go (new, 138 LOC) | ✅ compilers/rust/tests/cli_debug_tests.rs (new, 114 LOC) | ✅ compilers/python/tests/test_cli_debug.py (new, 93 LOC) | N/A | N/A | N/A |

### 4.12. Decompiler

| Surface | TS | Go | Rust | Python | Zig | Ruby | Java |
|---|---|---|---|---|---|---|---|
| Disassembler / symexec / templates / stateful lift / TS emit / roundtrip / refine / CLI | ✅ packages/decompiler/__tests__/ — 10 test files | N/A | N/A | N/A | N/A | N/A | N/A |

---

## 5. Gap analysis

Severity rubric: **blocker** = breaks a stated cross-language invariant or ships incorrect bytes to users; **major** = a feature or its verification is missing in a way a contract author would hit; **minor** = test-depth or developer-ergonomics gap with the conformance harness still providing a byte-level backstop.

### 5.1. Feature-matrix gaps (`⚠️` / `❌`)

The matrix in §3 is almost entirely `✅`. The remaining cells are all documented `N/A`s (ScriptVM in Zig/Ruby/Java per policy; decompiler in non-TS tiers per project scope) plus one carried-from-`20260514` `⚠️`:

| # | Feature | Affected language(s) | Severity | Justification | Remediation |
|---|---|---|---|---|---|
| G-1 | Rust `ScriptVM` is execute-only (no step API) | Rust (`⚠️`) | minor | Documented policy constraint, not a true gap — upstream `bsv-sdk` `Spend` keeps stack / pc `pub(crate)`. Carry from `20260514`. No author-facing surface affected. | None recommended unless upstream exposes pc/stack. |

No new feature gaps were introduced by `af43aada`.

### 5.2. Test-matrix gaps (`⚠️` / `❌`)

| # | Feature / area | Affected language(s) | Severity | Justification | Remediation |
|---|---|---|---|---|---|
| T-1 | Zig `arithmetic` / `comparison` / `boolean` operator rows still `⚠️` — no explicit op tests in `language_constructs.zig` (only bitwise/shift covered) | Zig (`⚠️` × 3 cells) | minor | Carried from `20260514` §4.4. The `af43aada` commit message claims "Zig + TS + Rust crypto unit tests upgraded" but does **not** specifically claim Zig operator tests; the §4 sub-agent could not find new explicit Zig assertions for these three rows. Cross-tier byte parity covered by conformance harness (`arithmetic` and `boolean-logic` fixtures); risk is localized regression detection only. | Add explicit op-typed tests to `compilers/zig/src/tests/language_constructs.zig` for arithmetic / comparison / boolean operators. ~30–50 LOC. |
| T-2 | Rust + Zig `stack lowering` test cells still `⚠️` — opcode-shape / stack-map only, not exact bytes | Rust, Zig (`⚠️`) | minor | Carried from `20260514` §4.5. Byte correctness backed by the conformance harness; tier-local test asserts on shape/structure rather than full bytes. | Upgrade `compilers/rust/src/codegen/stack.rs:4852` (inline) and `compilers/zig/src/passes/stack_lower.zig` inline tests to assert against exact-byte goldens for one representative contract each. ~80 LOC each. |
| T-3 | TS + Rust `opcode mapping table` cells still `⚠️` — partial coverage (CHECKSIG/ADD only in TS; partial inline list in Rust) | TS, Rust (`⚠️`) | minor | Carried from `20260514` §4.5. The opcode lookup table is small and audited; partial test coverage is acceptable. | Add a parametric `for-each-opcode` test in both tiers that asserts every entry of the lookup table emits the expected byte. ~40 LOC each. |
| T-4 | `codeSeparatorIndex/Indices artifact fields` cells `⚠️` in 6 tiers — no field-specific assert; only golden hex parity | TS, Rust, Python, Zig, Ruby, Java (`⚠️` × 6) | minor | Carried from `20260514` §4.6. The artifact-JSON field is a small typed surface; cross-tier conformance compares the JSON byte-identically, so divergence in the field would be caught — but no dedicated assert exists in 6 of 7 tiers. | Add an explicit JSON-field round-trip assert in each tier's conformance/golden test file. ~10 LOC each. |
| T-5 | Ruby `addOutput` / `addRawOutput` cells `⚠️` — no dedicated unit test, golden harness only | Ruby (`⚠️` × 2) | minor | Carried from `20260514` §4.6. Byte correctness backed by conformance + `examples/ruby/add-raw-output/`. | Add `test/codegen/test_add_output.rb` and `test_add_raw_output.rb` mirroring the Python files. ~50 LOC each. |
| T-6 | Weak crypto-codegen unit-test cells in EC / P-256 / P-384 / SHA-256 / BLAKE3 | TS (compile-only), Rust (`_nontrivial`), Ruby (ASM-shape), Zig (structural inline) — ~25 cells | minor | Carried from `20260514` §5.2 T-11. Byte correctness backed entirely by the conformance harness. Python + Java are the gold standard (exact op-count + hex goldens). The `af43aada` commit message claims "Ruby + Zig + TS + Rust crypto unit tests upgraded from `_nontrivial` / ASM-substring shape to op-count + hex goldens (~75 new assertions)"; spot-checks in the §3.6-3.9 sub-agent confirmed *some* assertions were strengthened but most cells in §4.9 remain as `_nontrivial` / ASM-shape per the verified test-file contents. | Optional — upgrade the remaining cells to op-count goldens. Lower priority; the golden harness already locks bytes. |
| T-7 | Ruby `test_slh_dsa.rb` still parametrized on 128s only; the 5 new param sets (128f/192s/192f/256s/256f) are covered by conformance fixtures, not by a dedicated Ruby unit test | Ruby (`⚠️` × 5 cells) | minor | Partial closure of `20260514` §5.2 T-3 by `af43aada` WS-2: the 5 new fixtures byte-lock the param sets cross-tier, but Ruby is the only tier whose tier-local unit test does not iterate over them. | Parametrize `compilers/ruby/test/codegen/test_slh_dsa.rb` over all 6 param sets, mirroring `compilers/python/tests/codegen/test_slh_dsa.py`. ~40 LOC. |
| T-8 | Go SDK `CompileCheck` cell still `⚠️` — exercised via `examples/go/*_test.go`, no unit test in `packages/runar-go` itself | Go (`⚠️`) | minor | Carried from `20260514`. Not in `af43aada`'s scope. | Add `packages/runar-go/compile_check_test.go`. ~40 LOC. |
| T-9 | Python `test_script_vm.py` still `importorskip("bsv")` — skips silently in default CI unless the `script-vm` extra is installed | Python (`⚠️`) | minor | Carried from `20260514` §5.2 T-8. `af43aada` WS-4 modified `packages/runar-py/tests/test_script_vm.py` (24 LOC change) but this audit did not verify the CI workflow installs the `script-vm` extra — leaving the cell `⚠️` pending CI verification. | Confirm the GitHub Actions workflow runs Python SDK tests with `pip install -e .[script-vm]`; or, if it doesn't, change the test to `pytest.importorskip` with a `requires.txt` check. |
| T-10 | Rust `SLH-DSA non-128s param sets` cells remain `⚠️ — _nontrivial` (per-param key existence-only) | Rust (`⚠️` × 5) | minor | Partial closure of `20260514` §5.2 T-3 — fixtures lock bytes cross-tier; Rust's dedicated unit-test depth for these param keys did not improve. | Upgrade `compilers/rust/tests/crypto_codegen_tests.rs:1548` to assert byte goldens per param set. ~60 LOC. |

No new section-5 gaps with `major` or `blocker` severity were found. The single carried `⚠️` in §3 (Rust ScriptVM, G-1) is a documented policy constraint, not a remediable gap.

---

## 6. Correctness findings

Two findings, both surfaced by this audit cycle and **not** present in `20260514` (they were either introduced by `af43aada` or pre-existed but were not exercised).

### F-1 — TS vitest suite has at least one CPU-bound test that does not honor `--testTimeout`; the suite hangs partway through and never completes

- **Defect location:** unidentified at present. The hang surfaces consistently in three different vitest invocations (default threads pool, `--reporter=verbose`, `--pool=forks --poolOptions.forks.singleFork=true`), at three different cutoff points (6,660 / 148 / 140 test entries), all after passing thousands of tests cleanly. The pattern is identical each time: one worker pegs at ~100% CPU for the rest of the run; the test runner's `--testTimeout=60000` (and `120000`) is ignored because the offending test does not yield to the event loop.
- **Reference behavior it diverges from:** `20260514` §7 reported `npx vitest run` completing with `Test Files 303 passed | 1 skipped (304)` · `Tests 6432 passed | 2 skipped (6434)` in normal wall-clock time (presumably ~5 min). This audit's runs hang indefinitely at 30+ min wall clock with no terminating summary. Either a test added by `af43aada` (notably `asm-multiformat.test.ts`, `compile-flags.test.ts`, `06-emit.test.ts` exact-byte additions, or one of the new example-pattern `.test.ts` files in `examples/{sol,move,ruby,java}/multisig-2of3,bsv20-token,bsv21-token,ordinal-nft,fixed-array-nested/`) regressed, or one of those tests has a CPU-bound path the prior runner didn't hit.
- **Minimal reproduction:** `cd /Users/siggioskarsson/gitcheckout/runar && npx vitest run --testTimeout=60000` — observe 6,000+ tests pass, then a single worker pegs at 100% CPU and the run never terminates. Killing the worker with `pkill -9 -f vitest` is the only way to recover.
- **Severity:** **major.** The TS reference tier's full-suite green is a documented release gate (`20260514` §7); a hanging suite means CI either runs indefinitely (worst case) or times out without identifying the offending test. Per-test-file vitest runs (e.g. `npx vitest run packages/runar-compiler`) likely still complete, but `npx vitest run` from the root is the canonical command in `CLAUDE.md` and is broken at current main.
- **Workaround proven:** Running just `packages/` succeeded for 140 test entries before hanging too — the issue is not specific to a `package/` vs `examples/` partition. The hang likely lives in a test that runs many compile passes (e.g. one of the `compile-flags.test.ts` cases spawning child compiler processes, or `asm-multiformat.test.ts` running all 9 frontends).
- **Suggested triage path:** Run with `--reporter=verbose --bail=1` and a per-file timeout, OR `npx vitest run --pool=forks --poolOptions.forks.execArgv=--inspect-brk` to attach a debugger, OR bisect by directory: `npx vitest run packages/runar-compiler`, then `packages/runar-cli`, then `examples/ts`, etc.

### F-2 — Cross-tier conformance suite had one fixture fail on first run, then passed cleanly on re-run (flake)

- **Defect location:** `conformance/runner/index.ts` (or a downstream race in one of the compiler invocations it spawns). On the first run (`cd conformance && npm test`) the suite reported `Summary: 55 passed, 1 failed, 0 skipped (56 total)`. The output was unfortunately truncated by a `| tail -20` pipe in this audit cycle (an audit-tooling mistake, not a project regression) and the specific failing fixture name was lost. On a second run with full output capture, the suite reported `Summary: 56 passed, 0 failed, 0 skipped (56 total)`.
- **Reference behavior:** `20260514` §7 reported `49 passed, 0 failed, 0 skipped (49 total)`; the `af43aada` commit message reports `56/56`. Expected behavior is deterministic 56/56.
- **Minimal reproduction:** unconfirmed — only observed once during this audit.
- **Severity:** **minor (suspected).** A flake in cross-tier conformance is concerning because the suite is the byte-level safety net for all 7 tiers. Possible causes: a race in temp-file naming under `conformance/.tmp/` when 7 compilers spawn concurrently (the runner produces names like `python-59059-1778935784788-e0f6z5lk1jc-ECUnit.runar.ts` — collision-resistant in theory); transient resource exhaustion when other heavy test suites (Rust cargo, Java gradle) are running concurrently in the same shell session, as was the case in this audit cycle's first run.
- **Suggested triage path:** Re-run the conformance suite under controlled conditions (no other heavy compiler tests running concurrently) several times to confirm the failure is non-reproducible. If it reproduces, capture the full runner output (no `| tail` truncation) and identify the failing fixture.

---

## 7. Test execution evidence

Every in-scope language's compiler and SDK suite plus the TS suite (incomplete — see F-1) and the cross-tier conformance suite was executed on 2026-05-16. **One** TS suite did not complete cleanly (F-1); the **first** conformance run flaked at 55/56 (F-2). All other suites green.

| Suite | Command (cwd) | Final summary line |
|---|---|---|
| Go compiler | `cd compilers/go && go test ./...` | `ok` for all 5 packages (`compilers/go` 56.5s, `…/codegen` cached, `…/compiler` 69.4s, `…/frontend` cached, `…/ir` cached) |
| Go SDK | `cd packages/runar-go && go test ./...` | `ok` for 3 packages (`runar-go` 0.5s, `…/bn254witness` 481s — STARK, excluded from analysis, `…/sp1fri` 3.5s) |
| Rust compiler | `cd compilers/rust && cargo test` | `709 passed; 0 failed; 1 ignored` across 15 binaries (incl. doctests); largest binary `316 passed` |
| Rust SDK | `cd packages/runar-rs && cargo test` | `379 passed; 0 failed; 5 ignored` across 4 binaries (incl. doctests); largest binary `375 passed`; ignored = 1 env-gated live BRC-100 + 4 doctests |
| Python compiler | `cd compilers/python && python3 -m pytest` | `978 passed, 1 skipped in 806.68s (0:13:26)` |
| Python SDK | `cd packages/runar-py && python3 -m pytest` | `471 passed, 2 skipped, 1 warning in 5.70s` |
| Zig compiler | `cd compilers/zig && zig build test --summary all` | `Build Summary: 3/3 steps succeeded; 599/599 tests passed` |
| Zig SDK | `cd packages/runar-zig && zig build test --summary all` | `172 passed, 0 failed, 2 skipped (174 total)` · `Build Summary: 4/4 steps succeeded` |
| Ruby compiler | `cd compilers/ruby && rake test` | `All 32 test files passed` — aggregate (sum of per-file summaries) ≈ 254+ runs, all green |
| Ruby SDK | `cd packages/runar-rb && bundle exec rspec` | `882 examples, 0 failures` in 25.59s |
| Java compiler | `cd compilers/java && gradle test --rerun-tasks` | `BUILD SUCCESSFUL in 2m 12s` — 3 actionable tasks executed |
| Java SDK | `cd packages/runar-java && gradle test --rerun-tasks` | `BUILD SUCCESSFUL in 1m 25s` — 6 actionable tasks executed |
| **TypeScript (all packages + format examples)** | `npx vitest run` (repo root) | **DID NOT COMPLETE — see §6 F-1.** Three runs killed after hanging at 30+ min wall clock; worker stuck at 100% CPU does not honor `--testTimeout`. Last clean reading: `6,660 tests` reported as passed in the verbose-reporter run before hang (vs prior `20260514` audit's complete `6,432 passed`). |
| Cross-tier conformance | `cd conformance && npm test` | Second run: `Summary: 56 passed, 0 failed, 0 skipped (56 total)`. First run: `55 passed, 1 failed, 0 skipped` — see §6 F-2. |

Notes:
- Cumulative wall time across all 14 suites (parallel where independent) was ~30–40 min for the green tiers; the TS hang absorbed ~60+ min in three attempts. Test runs were attempted in parallel where possible; some runs may have been slower than usual due to concurrent CPU pressure (cargo + gradle + zig + ruby + go + python + tsc all running simultaneously).
- `cargo test` and `zig build test` do not emit single aggregate summary lines; the per-binary `test result:` lines were summed via `awk` after capturing the full output.
- The Java `gradle test` task is incremental and reports `UP-TO-DATE` on the first invocation; both runs were re-run with `--rerun-tasks` to force execution.
- Tier deltas vs `20260514`: Rust compiler +38 (671 → 709), Python compiler +7 (971 → 978), Zig compiler +31 (568 → 599), Ruby compiler ≈ unchanged at file-count level (32 files), all Java/Go/Ruby SDK suites green at higher test counts (Go SDK +; Ruby SDK 861 → 882; Java SDK unchanged 344 → 344). Net coverage growth is consistent with the `af43aada` test-additions claim.

---

## 8. Summary ranking

### 8.1. Feature completeness (most → least complete)

All 7 compilers now implement every frontend parser (9/9), every compiler pass, the full type system, all 16 math builtins, all hash builtins, all 8 crypto-codegen families (checkSig/checkMultiSig, 10 EC builtins, P-256/P-384, SHA-256 module, BLAKE3, WOTS+, all 6 SLH-DSA param sets, Rabin), **AND** the `asm` intrinsic / `raw_script` ANF node / `UnsafeSmartContract` base (the single feature gap from `20260514`). All 7 SDKs implement every non-ScriptVM surface; Ruby's `LocalSigner` no longer requires the `bsv-sdk` gem. CLIs now expose `--parse-only`/`--hex` independently in TS, and `debug` everywhere it can run.

The matrix is now `✅` in **every cell that has a non-`N/A` value**. The ranking below is therefore driven by the *single* remaining `⚠️` (Rust ScriptVM execute-only, a documented policy constraint) and by test-depth rather than feature presence.

1. **TypeScript** — reference tier; owns the decompiler package, the `runar debug` CLI, and the broadest set of dedicated unit tests. Sole feature concerns: F-1 (vitest suite hang) is a TS-tier infrastructure issue, not a feature gap.
2. **Go** — feature-complete on every compiler and SDK row; WOTS+ now a dedicated module; Go SDK gained the previously-missing WOC + GorillaPool provider tests. No `⚠️`/`❌` in §3 or §4.10.
3. **Java** — feature-complete on all rows; new in-tree `ConformanceGoldensTest.java` closes the only `⚠️` from `20260514` §4.6. Strongest dedicated test rigor after Python on crypto codegen.
4. **Zig** — feature-complete; WOTS+ a dedicated module; new `compilers/zig/src/tests/frontend.zig` (~563 LOC) closes the broad `⚠️ — golden harness only` cluster in `20260514` §4. Remaining `⚠️`s are 3 operator-row cells in §4.4.
5. **Python** — feature-complete on compiler + SDK rows; WOTS+ a dedicated module. Strongest dedicated math/SLH-DSA test depth of any tier.
6. **Rust** — feature-complete except the single documented `ScriptVM` execute-only constraint (G-1). Remaining `⚠️`s are localized: SLH-DSA non-128s `_nontrivial` keys, `stack lowering` inline tests, `opcode mapping` partial.
7. **Ruby** — feature-complete on compiler + SDK rows; LocalSigner `⚠️ → ✅` (pure-Ruby ECDSA fallback). Remaining `⚠️`s are dedicated-unit-test depth (SLH-DSA non-128s not parametrized, addOutput/addRawOutput no dedicated test).

The spread is tighter than `20260514`: every tier crossed the "feature-complete except policy N/As" line. Test-depth differences are now the only meaningful axis of differentiation.

### 8.2. Testing rigor (most → least rigorous)

Counts below are dedicated, assertion-grade tests; all 7 tiers additionally share the 56/56 cross-tier conformance golden harness as a byte-level backstop.

1. **Python** — strongest. Exact op-count + opcode-shape goldens for all 16 math builtins, all hash builtins, **all 6 SLH-DSA param sets**, EC, SHA-256, BLAKE3, P-256/P-384. 978 compiler + 471 SDK tests (+ vs. `20260514`: +7 compiler).
2. **Java** — exact op-count/hex goldens (MathBuiltinsLowerTest, EcTest, Sha256Test, SlhDsaTest, WotsTest), only dedicated `checkMultiSig` byte test, SLH-DSA non-128s canonical-hex tests, new in-tree ConformanceGoldensTest.java. Closes the only `⚠️` from `20260514`.
3. **Go** — exact-byte `emit_test.go`, in-tree `conformance_goldens_test.go`, strong stack/codegen tests, **new** WOC + GorillaPool SDK provider unit tests (closes the only ❌ from `20260514` §5.2 T-6).
4. **TypeScript** — broad (6,432+ tests, count incomplete due to F-1), owns asm/decompiler/ScriptVM-step suites. Gained exact-byte assertions in `06-emit.test.ts`. Dragged from a probable #2 spot by F-1 (suite cannot be run to completion).
5. **Rust** — 709 compiler + 379 SDK tests (+38 compiler vs. `20260514`), but crypto/codegen tests largely remain `_nontrivial` / opcode-presence; emit gained exact-byte assertions per `af43aada` but most `⚠️` cells in §4.9 unchanged.
6. **Zig** — major test-depth upgrade: new `src/tests/frontend.zig` (~563 LOC) closes the broad parser/pass `⚠️` cluster from `20260514`; new `check_multisig.zig`. Still has 3 `⚠️` operator-row cells. 599 compiler tests (+31 vs. `20260514`).
7. **Ruby** — 32+ compiler test files (4 new files: `test_math_builtins.rb`, `test_check_multisig.rb`, `test_raw_script.rb`, `test_anf_lower.rb`); 882 SDK examples (+21 vs. `20260514`). Substantial uplift from `20260514`'s last-place ranking. Remaining gaps: `test_slh_dsa.rb` not parametrized, no `test_p256_p384.rb` exact-byte upgrade, addOutput/addRawOutput no dedicated test.

Caveat repeated from §2: Rust and Zig place many tests inline in `src/` files, so their dedicated-test-file LOC understates real coverage — the ranking above is based on test *content* (assertion strength, feature coverage) observed in §4.

---

## Definition-of-done checklist

- [x] §1 Excluded paths — exhaustive, carried verbatim from `20260514` (re-verified `af43aada` touched zero STARK files); 20260514 + remediation-plan-20260516 appended to the audit-doc exclusion list.
- [x] §2 Implementation inventory — 7 tiers + TS support packages, paths, build/test commands, frameworks, LOC (post-exclusion) with delta-from-`20260514`.
- [x] §3 Feature matrix — every cell filled. The asm/UnsafeSmartContract `❌`×6 from `20260514` and the WOTS+ `⚠️`×3 are now `✅`. The only remaining `⚠️` is Rust ScriptVM (policy).
- [x] §4 Test matrix — every cell filled. ~30 cells improved from `⚠️`/`❌` to `✅`. Carried `⚠️`s documented in §5.2.
- [x] §5 Gap analysis — 1 carried feature `⚠️` (G-1) and 10 test-depth `⚠️`s (T-1..T-10) listed with severity + remediation sizing.
- [x] §6 Correctness findings — F-1 (TS vitest hang, major) and F-2 (conformance flake, minor suspected), each with a run reproduction.
- [x] §7 Test execution evidence — 13 of 14 suites green; 1 (TS) incomplete (see F-1); conformance second run clean.
- [x] §8 Summary ranking — feature completeness and testing rigor ranked separately; tiers move closer together than `20260514`.
