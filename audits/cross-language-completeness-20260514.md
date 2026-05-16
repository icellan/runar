# Rúnar Cross-Language Completeness & Correctness Audit

Date: 2026-05-14 (UTC, audit start)
Scope: Read-only analysis of the seven shipping language implementations of the Rúnar TypeScript-to-Bitcoin Script compiler, their SDKs, examples, integration tests, and shared conformance fixtures. EVM/STARK proof-system primitives and the Lean4 verification project are excluded per project policy and the audit charter (see Section 1).

Status: **Sections 1–2 complete, awaiting user confirmation before matrix work (charter approval gate).**

---

## 1. Excluded paths

Enumerated exhaustively before any analysis. If a new STARK/proof-system path is discovered mid-audit, it is appended here with the note "added during audit".

### 1.1. Lean4 verification project (charter exclusion #1)
- `runar-verification/` — entire directory. Owned by another agent. No file in this tree was opened, read for analysis, or counted. Note: this tree shows uncommitted modifications in `git status` at audit start; untouched here.

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
- Java ships no proof-system codegen files. Verified: `find compilers/java -iname '*babybear*' -o -iname '*bn254*' -o -iname '*groth16*' -o -iname '*koalabear*' -o -iname '*poseidon*' -o -iname '*merkle*' -o -iname '*fri*'` returns empty. Consistent with the Go-only policy. Section 3/4 matrices carry no rows for these families.

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
- `integration/go/babybear_test.go`, `integration/go/babybear_vectors_test.go`, `integration/go/koalabear_vectors_test.go`, `integration/go/poseidon2_kb_vectors_test.go`, `integration/go/bn254_vectors_test.go`, `integration/go/fri_colinearity_vectors_test.go`, `integration/go/groth16_test.go`, `integration/go/groth16_wa_test.go`, `integration/go/groth16_wa_msm_test.go`, `integration/go/groth16_wa_sdk_test.go`, `integration/go/groth16_wa_stateful_test.go`, `integration/go/sp1_fri_poc_test.go`, `integration/go/rollup_bug_test.go`
- `integration/go/helpers/groth16.go`
- `integration/go/contracts/Groth16Verifier.runar.go`, `StatelessGroth16WA.runar.go`, `RollupGroth16WA.runar.go`, `RollupGroth16WAMSM.runar.go`, `Sp1FriVerifierPoc.runar.go`, `BasefoldVerifier.runar.go`, `RollupBug.runar.go`
- `integration/python/test_babybear.py`
- `integration/ts/babybear.test.ts`, `integration/ts/babybear-vectors.test.ts`
- `integration/rust/tests/babybear.rs`
- `integration/zig/src/babybear_test.zig`
- `integration/ruby/spec/babybear_spec.rb`

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
- `.git/`, `.changeset/`, `.idea/`, `.turbo/`, `.pytest_cache/`, `.planning/`, `.claude/`
- `conformance/.tmp/` (transient runner artifacts), `conformance/node_modules/`
- `audits/` (prior audit reports — `cross-language-completeness-20260510.md`, `remediation-plan-20260511.md`, `remediation-report-20260512.md` — read for context only, not analyzed as source)

---

## 2. Implementation inventory

Seven shipping language implementations of the Rúnar compiler. Each has a compiler under `compilers/<lang>/`, an SDK under `packages/runar-<lang>/`, contract examples under `examples/<lang>/`, and on-chain integration tests under `integration/<lang>/`. TypeScript is the reference; its compiler lives in `packages/runar-compiler/` with shared support packages.

LOC counts are physical lines via `wc -l` (not SLOC), **after excluding all Section 1 paths**. Proof-system files were filtered with the pattern `babybear|koalabear|poseidon2|bn254|fiat_shamir|fiat-shamir|merkle|sp1_fri|sp1-fri|sp1fri|groth16|msm_bind` applied to the file lists below.

### Cross-cutting note on test LOC comparability
Test LOC is **not** directly comparable across languages because of differing idioms:
- **Go**: tests are separate `_test.go` files — counted in full.
- **TypeScript / Python / Ruby / Java**: tests are separate files (`*.test.ts` / `*.spec.ts`, `tests/test_*.py`, `test/test_*.rb` / `spec/*_spec.rb`, `src/test/**`) — counted in full.
- **Rust**: the `compilers/rust/tests/` and `packages/runar-rs/tests/` directories hold integration-style tests, but the majority of unit tests are inline `#[cfg(test)] mod tests` blocks inside `src/` files — **not** counted in the test LOC below (they fall inside the src count). Rust test LOC is therefore understated.
- **Zig**: `test "..." {}` blocks are inline in `src/` files; only files matching `test`/`tests` in their path are counted as test LOC — **inline tests in non-test-named files are understated** and counted under src.

This will be revisited in Section 8 (testing-rigor ranking) rather than taken at face value from raw LOC.

### TypeScript (reference)
- **Compiler path:** `packages/runar-compiler/`
- **Shared support packages:** `packages/runar-ir-schema/` (IR types/schemas), `packages/runar-lang/` (base classes/builtins), `packages/runar-testing/` (TestContract, interpreter, ScriptVM, analyzer), `packages/runar-cli/` (CLI), `packages/decompiler/` (Script→TS decompiler — **new since the 2026-05-10 audit**, in scope)
- **SDK path:** `packages/runar-sdk/`
- **Examples:** `examples/ts/`, plus `examples/sol/` and `examples/move/` (Solidity-like and Move-style frontends parsed by the TS compiler)
- **Integration:** `integration/ts/`
- **Build:** `pnpm install && pnpm run build` (turbo + tsc)
- **Test command:** `npx vitest run`
- **Test framework:** vitest
- **LOC (excl. proof codegen):**
  - `runar-compiler`: src=33,227  test=21,879
  - `runar-sdk`: src=7,223  test=8,858
  - `runar-testing`: src=10,427  test=7,009
  - `runar-lang`: src=3,161  test=1,477
  - `runar-ir-schema`: src=1,360  test=697
  - `runar-cli`: src=2,573  test=1,081
  - `decompiler`: src=5,064  test=2,063

### Go
- **Compiler path:** `compilers/go/` (subdirs `frontend/`, `ir/`, `codegen/`, `compiler/`)
- **SDK path:** `packages/runar-go/`
- **Examples:** `examples/go/`
- **Integration:** `integration/go/`
- **Build:** `cd compilers/go && go build ./...`
- **Test commands:** `cd compilers/go && go test ./...` (compiler); `cd packages/runar-go && go test ./...` (SDK)
- **Test framework:** stdlib `testing`
- **Compiler LOC (excl. proof codegen):** src=34,013  test=20,804
- **SDK LOC (excl. proof support):** src=12,375  test=7,213

### Rust
- **Compiler path:** `compilers/rust/` (`src/{frontend,ir,codegen}`, integration-style tests under `compilers/rust/tests/`)
- **SDK path:** `packages/runar-rs/` (+ `packages/runar-rs-macros/` proc-macro crate)
- **Examples:** `examples/rust/`
- **Integration:** `integration/rust/`
- **Build:** `cd compilers/rust && cargo build`
- **Test commands:** `cd compilers/rust && cargo test` (compiler); `cd packages/runar-rs && cargo test` (SDK)
- **Test framework:** cargo test (inline `#[cfg(test)]` + `tests/` dir)
- **Compiler LOC (excl. proof codegen):** src=45,986  test(`tests/` dir only)=9,364 — **inline `#[cfg(test)]` blocks counted in src, not test; see cross-cutting note**
- **SDK LOC (excl. proof support):** src=18,412 (`runar-rs/src` + `runar-rs-macros/src`)  test(`tests/` dir only)=292 — **heavily understated; SDK unit tests are inline**

### Python
- **Compiler path:** `compilers/python/runar_compiler/`
- **SDK path:** `packages/runar-py/runar/`
- **Examples:** `examples/python/`
- **Integration:** `integration/python/`
- **Build:** `pip install -e compilers/python` (setuptools)
- **Test commands:** `cd compilers/python && python3 -m pytest` (compiler); `cd packages/runar-py && python3 -m pytest` (SDK)
- **Test framework:** pytest
- **Compiler LOC (excl. proof codegen):** src=30,652  test=16,634
- **SDK LOC:** src=9,616  test=6,402

### Zig
- **Compiler path:** `compilers/zig/src/`
- **SDK path:** `packages/runar-zig/src/`
- **Examples:** `examples/zig/`
- **Integration:** `integration/zig/`
- **Build:** `cd compilers/zig && zig build`
- **Test commands:** `cd compilers/zig && zig build test` (compiler); `cd packages/runar-zig && zig build test` (SDK)
- **Test framework:** Zig built-in `test` blocks
- **Compiler LOC (excl. proof codegen):** src=47,003  test(test-named files only)=2,696 — **inline `test {}` blocks in non-test-named files counted in src; see cross-cutting note**
- **SDK LOC (excl. proof support):** src=17,031  test(test-named files only)=1,297

### Ruby
- **Compiler path:** `compilers/ruby/lib/runar_compiler/`
- **SDK path:** `packages/runar-rb/lib/`
- **Examples:** `examples/ruby/`
- **Integration:** `integration/ruby/`
- **Build:** `cd compilers/ruby && bundle install`
- **Test commands:** `cd compilers/ruby && rake test` (compiler, minitest); `cd packages/runar-rb && bundle exec rspec` (SDK, rspec)
- **Test framework:** minitest (compiler), rspec (SDK)
- **Compiler LOC (excl. proof codegen):** src=31,294  test=6,116
- **SDK LOC:** src=10,689  test(`spec/`)=8,182

### Java
- **Compiler path:** `compilers/java/src/main/java/runar/compiler/`
- **SDK path:** `packages/runar-java/src/main/java/runar/lang/`
- **Examples:** `examples/java/src/`
- **Integration:** `integration/java/`
- **Build:** `cd compilers/java && gradle build` (Gradle 8.5+, no wrapper committed)
- **Test commands:** `cd compilers/java && gradle test` (compiler); `cd packages/runar-java && gradle test` (SDK)
- **Test framework:** JUnit 5
- **Compiler LOC:** src=30,308  test=11,044
- **SDK LOC:** src=11,522  test=6,932

### Notes / open items for the inventory
1. **`packages/decompiler/`** is a new in-scope TypeScript package (Bitcoin Script → Rúnar-TS decompiler) added after the 2026-05-10 audit (`git log`: commit `48368528 "Add asm intrinsic + decompiler package"`). It is TypeScript-only; the matrices will carry a row for it with `N/A` for the six non-TS tiers unless a peer port is found.
2. **`asm` intrinsic** is a new language feature (same commit `48368528`) — present in the TS compiler passes (`01-parse.ts`, `02-validate.ts`, `03-typecheck.ts`, `04-anf-lower.ts`, `06-emit.ts`, `push-encoding.ts`) and referenced in `compilers/go/main.go`, `compilers/go/compiler/compiler.go`, `compilers/python/runar_compiler/compiler.py`, `compilers/ruby/lib/runar_compiler/compiler.rb`. Rust/Zig/Java coverage to be confirmed during matrix work — this is a candidate completeness gap.
3. Build/test commands above are the canonical commands from `CLAUDE.md` and the repo layout; **actual execution and summary lines are deferred to Section 7** per the audit structure. If the user wants test execution confirmed before matrix work, that can be done at this gate.
4. The `examples/java/` tree only contains `build.gradle.kts`, `settings.gradle.kts`, `src/`, `README.md` — example contracts live under `src/`. The non-Java example trees (`examples/ts`, `examples/go`, etc.) hold one directory per contract pattern.
5. Example-pattern coverage is uneven across languages (e.g. `bsv20-token`/`bsv21-token`/`ordinal-nft` exist for ts/go/zig/python but not ruby/rust/sol/move; `multisig-2of3` exists for ts/zig/sol but not all). This is matrix material for Section 3, flagged here so it is not lost.

---

## 3. Feature matrix

Columns: TS | Go | Rust | Python | Zig | Ruby | Java. Cell legend: `✅ file:line` implemented · `⚠️ file:line — reason` partial · `❌` absent · `N/A — reason`. Where a citation shows a file path without a line, the symbol is defined at/near the top of that file and the file was verified to exist and contain the symbol. Reference tier for "which rows exist" is Go (per project policy), cross-checked against TS.

Cross-cutting evidence note: all 7 compilers run a **cross-tier conformance golden harness** that asserts byte-identical ANF IR + Bitcoin Script hex against checked-in goldens for every fixture with no `compilers` allowlist — TS/Zig via `conformance/runner` multi-format runner, Go `compilers/go/conformance_goldens_test.go`, Rust `compilers/rust/tests/conformance_goldens.rs`, Python `compilers/python/tests/test_conformance_goldens.py`, Ruby `compilers/ruby/test/conformance_goldens_test.rb`, Java via the external `conformance/runner` Java daemon. This harness (49/49 passing, see §7) is the byte-level safety net behind every `⚠️` test cell below.

### 3.1. Frontend format parsers (9 rows)

| Feature | TS | Go | Rust | Python | Zig | Ruby | Java |
|---|---|---|---|---|---|---|---|
| `.runar.ts` parser | ✅ packages/runar-compiler/src/passes/01-parse.ts:79 | ✅ compilers/go/frontend/parser.go:68 | ✅ compilers/rust/src/frontend/parser.rs:43 | ✅ compilers/python/runar_compiler/frontend/parser_ts.py:1333 | ✅ compilers/zig/src/passes/parse_ts.zig:63 | ✅ compilers/ruby/lib/runar_compiler/frontend/parser_ts.rb:1507 | ✅ compilers/java/src/main/java/runar/compiler/frontend/TsParser.java:66 |
| `.runar.sol` parser | ✅ 01-parse-sol.ts:1021 | ✅ frontend/parser_sol.go:15 | ✅ frontend/parser_sol.rs:44 | ✅ frontend/parser_sol.py:1262 | ✅ passes/parse_sol.zig:67 | ✅ frontend/parser_sol.rb:317 | ✅ frontend/SolParser.java:75 |
| `.runar.move` parser | ✅ 01-parse-move.ts:1015 | ✅ frontend/parser_move.go:15 | ✅ frontend/parser_move.rs:42 | ✅ frontend/parser_move.py:1325 | ✅ passes/parse_move.zig:69 | ✅ frontend/parser_move.rb | ✅ frontend/MoveParser.java:56 |
| `.runar.go` parser | ✅ 01-parse-go.ts:1241 | ✅ frontend/parser_gocontract.go:26 | ✅ frontend/parser_gocontract.rs:51 | ✅ frontend/parser_go.py:1678 | ✅ passes/parse_go.zig:69 | ✅ frontend/parser_go.rb | ✅ frontend/GoParser.java:77 |
| `.runar.rs` parser | ✅ 01-parse-rust.ts:1165 | ✅ frontend/parser_rustmacro.go:17 | ✅ frontend/parser_rustmacro.rs:1169 | ✅ frontend/parser_rust.py:1272 | ✅ passes/parse_rust.zig:68 | ✅ frontend/parser_rust.rb | ✅ frontend/RustParser.java:82 |
| `.runar.py` parser | ✅ 01-parse-python.ts:1639 | ✅ frontend/parser_python.go:17 | ✅ frontend/parser_python.rs:49 | ✅ frontend/parser_python.py:1420 | ✅ passes/parse_python.zig:72 | ✅ frontend/parser_python.rb | ✅ frontend/PyParser.java:63 |
| `.runar.zig` parser | ✅ 01-parse-zig.ts:1449 | ✅ frontend/parser_zig.go:16 | ✅ frontend/parser_zig.rs:58 | ✅ frontend/parser_zig.py:1665 | ✅ passes/parse_zig.zig:63 | ✅ frontend/parser_zig.rb | ✅ frontend/ZigParser.java:75 |
| `.runar.rb` parser | ✅ 01-parse-ruby.ts:1825 | ✅ frontend/parser_ruby.go:17 | ✅ frontend/parser_ruby.rs:55 | ✅ frontend/parser_ruby.py:1724 | ✅ passes/parse_ruby.zig:73 | ✅ frontend/parser_ruby.rb:724 | ✅ frontend/RbParser.java:78 |
| `.runar.java` parser | ✅ 01-parse-java.ts:1607 | ✅ frontend/parser_java.go:36 | ✅ frontend/parser_java.rs:56 | ✅ frontend/parser_java.py:1564 | ✅ passes/parse_java.zig:66 | ✅ frontend/parser_java.rb | ✅ frontend/JavaParser.java:111 |

All 9 parsers present in all 7 compilers; extension dispatch verified (TS `01-parse.ts:84`, Go `parser.go:46`, Rust `parser.rs:1166`, Python `parser_dispatch.py:28`, Zig `compiler_api.zig:44`, Ruby `compiler.rb:121`, Java `ParserDispatch.java:27`).

### 3.2. Type system

| Feature | TS | Go | Rust | Python | Zig | Ruby | Java |
|---|---|---|---|---|---|---|---|
| bigint / bool / ByteString | ✅ ir/runar-ast.ts:24 | ✅ frontend/ast.go | ✅ frontend/ast.rs | ✅ frontend/ast_nodes.py | ✅ ir/types.zig | ✅ frontend/ast_nodes.rb | ✅ ir/ast/PrimitiveTypeName.java |
| Point (64-byte EC type) | ✅ ir/runar-ast.ts:35 | ✅ frontend/ast.go | ✅ frontend/ast.rs | ✅ frontend/ast_nodes.py | ✅ ir/types.zig | ✅ frontend/ast_nodes.rb | ✅ ir/ast/PrimitiveTypeName.java |
| Fixed-size arrays | ✅ ir/runar-ast.ts:45 | ✅ frontend/expand_fixed_arrays.go:44 | ✅ frontend/expand_fixed_arrays.rs:46 | ✅ frontend/expand_fixed_arrays.py:97 | ✅ passes/expand_fixed_arrays.zig:68 | ✅ frontend/expand_fixed_arrays.rb:63 | ✅ passes/ExpandFixedArrays.java:99 |
| readonly properties | ✅ ir/runar-ast.ts:76 | ✅ frontend/ast.go (PropertyNode) | ✅ frontend/ast.rs | ✅ frontend/ast_nodes.py | ✅ ir/types.zig | ✅ frontend/ast_nodes.rb | ✅ ir/ast/PropertyNode.java |
| Property initializers (literal defaults) | ✅ ir/runar-ast.ts:77 | ✅ frontend/ast.go (initializer) | ✅ frontend/ast.rs | ✅ frontend/ast_nodes.py | ✅ ir/types.zig | ✅ frontend/ast_nodes.rb | ✅ ir/ast/PropertyNode.java |

### 3.3. Control flow

| Feature | TS | Go | Rust | Python | Zig | Ruby | Java |
|---|---|---|---|---|---|---|---|
| if / else | ✅ ir/runar-ast.ts:142 | ✅ frontend/ast.go | ✅ frontend/ast.rs | ✅ frontend/ast_nodes.py | ✅ ir/types.zig | ✅ frontend/ast_nodes.rb | ✅ ir/ast/IfStatement.java |
| if-without-else | ✅ passes/04-anf-lower.ts | ✅ frontend/anf_lower.go | ✅ frontend/anf_lower.rs | ✅ frontend/anf_lower.py | ✅ passes/anf_lower.zig | ✅ frontend/anf_lower.rb | ✅ passes/AnfLower.java |
| Ternary expression | ✅ ir/runar-ast.ts:270 | ✅ frontend/ast.go (TernaryExpr) | ✅ frontend/ast.rs | ✅ frontend/ast_nodes.py | ✅ ir/types.zig | ✅ frontend/ast_nodes.rb | ✅ ir/ast/TernaryExpr.java |
| Bounded for-loop | ✅ ir/runar-ast.ts:150 (bound checked 02-validate.ts:599) | ✅ frontend/anf_lower.go | ✅ frontend/anf_lower.rs | ✅ frontend/anf_lower.py | ✅ passes/anf_lower.zig | ✅ frontend/anf_lower.rb | ✅ passes/AnfLower.java |
| while-loop | N/A — not a Rúnar construct; Python `for…in range` lowers to bounded loop | N/A | N/A | N/A | N/A | N/A | N/A |
| break / continue | N/A — explicitly rejected by parsers (regression-pinned, e.g. Python `test_break_continue.py`) | N/A | N/A | N/A | N/A | N/A | N/A |

### 3.4. Operators

| Feature | TS | Go | Rust | Python | Zig | Ruby | Java |
|---|---|---|---|---|---|---|---|
| Arithmetic `+ - * / %` | ✅ ir/runar-ast.ts:184 | ✅ frontend/ast.go (BinaryOp) | ✅ frontend/ast.rs | ✅ frontend/ast_nodes.py | ✅ ir/types.zig | ✅ frontend/ast_nodes.rb | ✅ ir/ast/BinaryOp |
| Comparison `== != < <= > >=` | ✅ ir/runar-ast.ts:189 | ✅ frontend/ast.go | ✅ frontend/ast.rs | ✅ frontend/ast_nodes.py | ✅ ir/types.zig | ✅ frontend/ast_nodes.rb | ✅ ir/ast |
| Boolean `&& \|\| !` | ✅ ir/runar-ast.ts:195 | ✅ frontend/ast.go | ✅ frontend/ast.rs | ✅ frontend/ast_nodes.py | ✅ ir/types.zig | ✅ frontend/ast_nodes.rb | ✅ ir/ast |
| Bitwise `& \| ^ ~` | ✅ ir/runar-ast.ts:197 | ✅ frontend/ast.go | ✅ frontend/ast.rs | ✅ frontend/ast_nodes.py | ✅ ir/types.zig | ✅ frontend/ast_nodes.rb | ✅ ir/ast |
| Shift `<< >>` | ✅ ir/runar-ast.ts:200 | ✅ frontend/ast.go | ✅ frontend/ast.rs | ✅ frontend/ast_nodes.py | ✅ ir/types.zig | ✅ frontend/ast_nodes.rb | ✅ ir/ast |

### 3.5. Compiler passes

| Feature | TS | Go | Rust | Python | Zig | Ruby | Java |
|---|---|---|---|---|---|---|---|
| validate | ✅ passes/02-validate.ts:32 | ✅ frontend/validator.go:35 | ✅ frontend/validator.rs:33 | ✅ frontend/validator.py:65 | ✅ passes/validate.zig:48 | ✅ frontend/validator.rb:57 | ✅ passes/Validate.java:91 |
| typecheck | ✅ passes/03-typecheck.ts:33 | ✅ frontend/typecheck.go:28 | ✅ frontend/typecheck.rs:29 | ✅ frontend/typecheck.py:60 | ✅ passes/typecheck.zig:44 | ✅ frontend/typecheck.rb:208 | ✅ passes/Typecheck.java:80 |
| ANF lowering | ✅ passes/04-anf-lower.ts:45 | ✅ frontend/anf_lower.go:17 | ✅ frontend/anf_lower.rs:35 | ✅ frontend/anf_lower.py:66 | ✅ passes/anf_lower.zig:52 | ✅ frontend/anf_lower.rb:28 | ✅ passes/AnfLower.java:114 |
| constant folding | ✅ optimizer/constant-fold.ts:447 | ✅ frontend/constant_fold.go:557 | ✅ frontend/constant_fold.rs:493 | ✅ frontend/constant_fold.py:508 | ✅ passes/constant_fold.zig:545 | ✅ frontend/constant_fold.rb:516 | ✅ passes/ConstantFold.java:49 |
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
| `asm` intrinsic / `raw_script` ANF node / `UnsafeSmartContract` base | ✅ passes/04-anf-lower.ts:1079 (lowerAsmCall); 02-validate.ts:399; 06-emit.ts:461 | ❌ — port expected by CLAUDE.md "Adding a New ANF Value Kind" policy; see §6 F-1 | ❌ — see §6 F-1 | ❌ — see §6 F-1 | ❌ — see §6 F-1 | ❌ — see §6 F-1 | ❌ — see §6 F-1 |
| `assert()` control mechanism | ✅ passes/05-stack-lower.ts (OP_VERIFY) | ✅ codegen/stack.go | ✅ codegen/stack.rs | ✅ codegen/stack.py | ✅ passes/stack_lower.zig | ✅ codegen/stack.rb:121 | ✅ passes/StackLower.java |

### 3.7. Math builtins (16 rows)

| Feature | TS | Go | Rust | Python | Zig | Ruby | Java |
|---|---|---|---|---|---|---|---|
| abs | ✅ 05-stack-lower.ts:101 | ✅ stack.go:98 | ✅ stack.rs:164 | ✅ stack.py:127 | ✅ stack_lower.zig:1304 | ✅ stack.rb:32 | ✅ StackLower.java:108 |
| min | ✅ 05-stack-lower.ts:102 | ✅ stack.go:99 | ✅ stack.rs:165 | ✅ stack.py:128 | ✅ stack_lower.zig:1305 | ✅ stack.rb:33 | ✅ StackLower.java:109 |
| max | ✅ 05-stack-lower.ts:103 | ✅ stack.go:100 | ✅ stack.rs:166 | ✅ stack.py:129 | ✅ stack_lower.zig:1306 | ✅ stack.rb:34 | ✅ StackLower.java:110 |
| within | ✅ 05-stack-lower.ts:104 | ✅ stack.go:101 | ✅ stack.rs:167 | ✅ stack.py:130 | ✅ stack_lower.zig:1307 | ✅ stack.rb:35 | ✅ StackLower.java:111 |
| safediv | ✅ 05-stack-lower.ts:1448 | ✅ stack.go:1306 | ✅ stack.rs:1332 | ✅ stack.py:1118 | ✅ stack_lower.zig:1188 | ✅ stack.rb:1416 | ✅ StackLower.java:891 |
| safemod | ✅ 05-stack-lower.ts:1448 | ✅ stack.go:3469 | ✅ stack.rs:1337 | ✅ stack.py:1118 | ✅ stack_lower.zig:1189 | ✅ stack.rb:1416 | ✅ StackLower.java:891 |
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
| sha256 | ✅ 05-stack-lower.ts:88 | ✅ stack.go:88 | ✅ stack.rs (hash op table) | ✅ stack.py | ✅ stack_lower.zig | ✅ stack.rb:506 | ✅ StackLower.java |
| hash160 | ✅ 05-stack-lower.ts:90 | ✅ stack.go:90 | ✅ stack.rs | ✅ stack.py | ✅ stack_lower.zig | ✅ stack.rb | ✅ StackLower.java |
| hash256 | ✅ 05-stack-lower.ts:91 | ✅ stack.go:91 | ✅ stack.rs | ✅ stack.py | ✅ stack_lower.zig | ✅ stack.rb | ✅ StackLower.java |
| ripemd160 | ✅ 05-stack-lower.ts:89 | ✅ stack.go:89 | ✅ stack.rs | ✅ stack.py | ✅ stack_lower.zig | ✅ stack.rb | ✅ StackLower.java |
| sha256Compress | ✅ 05-stack-lower.ts:1346 | ✅ stack.go:1246 | ✅ stack.rs:1277 | ✅ stack.py:1070 | ✅ stack_lower.zig:1221 | ✅ codegen/sha256.rb | ✅ codegen/Sha256.java |
| sha256Finalize | ✅ 05-stack-lower.ts:1351 | ✅ stack.go:1251 | ✅ stack.rs:1282 | ✅ stack.py:1074 | ✅ stack_lower.zig:1222 | ✅ codegen/sha256.rb | ✅ codegen/Sha256.java |
| checkPreimage | ✅ 05-stack-lower.ts:1023 | ✅ stack.go:923 | ✅ stack.rs:976 | ✅ stack.py:850 | ✅ stack_lower.zig:561 | ✅ stack.rb:1075 | ✅ StackLower.java:306 |

(`sha1` is not a Rúnar builtin — absent from `runar-lang/src/builtins.ts` and every compiler's builtin dispatch table; `OP_SHA1` exists only in raw opcode→byte lookup tables. No row.)

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
| WOTS+ codegen (verifyWOTS) | ✅ passes/wots-codegen.ts:103 (dedicated module) | ⚠️ codegen/stack.go:4300 — inline in stack.go, no dedicated module | ⚠️ codegen/stack.rs:3589 — inline in stack.rs | ⚠️ codegen/stack.py:3348 — inline in stack.py | ✅ passes/helpers/pq_emitters.zig:1021 | ✅ codegen/wots.rb:120 (dedicated module) | ✅ codegen/Wots.java:156 (dedicated module) |
| SLH-DSA SHA2-128s | ✅ slh-dsa-codegen.ts:41 | ✅ slh_dsa.go:49 | ✅ slh_dsa.rs:96 | ✅ slh_dsa.py:81 | ✅ pq_emitters.zig:315 | ✅ slh_dsa.rb:81 | ✅ SlhDsa.java:57 |
| SLH-DSA SHA2-128f | ✅ slh-dsa-codegen.ts:42 | ✅ slh_dsa.go:50 | ✅ slh_dsa.rs:97 | ✅ slh_dsa.py:82 | ✅ pq_emitters.zig:316 | ✅ slh_dsa.rb:82 | ✅ SlhDsa.java:58 |
| SLH-DSA SHA2-192s | ✅ slh-dsa-codegen.ts:43 | ✅ slh_dsa.go:51 | ✅ slh_dsa.rs:98 | ✅ slh_dsa.py:83 | ✅ pq_emitters.zig:317 | ✅ slh_dsa.rb:83 | ✅ SlhDsa.java:59 |
| SLH-DSA SHA2-192f | ✅ slh-dsa-codegen.ts:44 | ✅ slh_dsa.go:52 | ✅ slh_dsa.rs:99 | ✅ slh_dsa.py:84 | ✅ pq_emitters.zig:318 | ✅ slh_dsa.rb:84 | ✅ SlhDsa.java:60 |
| SLH-DSA SHA2-256s | ✅ slh-dsa-codegen.ts:45 | ✅ slh_dsa.go:53 | ✅ slh_dsa.rs:100 | ✅ slh_dsa.py:85 | ✅ pq_emitters.zig:319 | ✅ slh_dsa.rb:85 | ✅ SlhDsa.java:61 |
| SLH-DSA SHA2-256f | ✅ slh-dsa-codegen.ts:46 | ✅ slh_dsa.go:54 | ✅ slh_dsa.rs:101 | ✅ slh_dsa.py:86 | ✅ pq_emitters.zig:320 | ✅ slh_dsa.rb:86 | ✅ SlhDsa.java:62 |
| Rabin sig codegen (verifyRabinSig) | ✅ passes/rabin-codegen.ts:37 (dedicated) | ✅ codegen/rabin.go:19 (dedicated) | ✅ codegen/rabin.rs:22 (dedicated) | ✅ codegen/rabin.py:30 (dedicated) | ✅ passes/helpers/rabin_emitter.zig:35 (dedicated) | ✅ codegen/rabin.rb:33 (dedicated) | ✅ codegen/Rabin.java:48 (dedicated) |

### 3.10. SDK surfaces

| Feature | TS | Go | Rust | Python | Zig | Ruby | Java |
|---|---|---|---|---|---|---|---|
| RunarContract | ✅ runar-sdk/src/contract.ts:44 | ✅ runar-go/sdk_contract.go:23 | ✅ runar-rs/src/sdk/contract.rs:37 | ✅ runar-py/runar/sdk/contract.py:28 | ✅ runar-zig/src/sdk_contract.zig:33 | ✅ runar-rb/lib/runar/sdk/contract.rb:52 | ✅ runar-java/.../sdk/RunarContract.java:20 |
| MockProvider | ✅ runar-sdk/src/providers/mock.ts:15 | ✅ runar-go/sdk_provider.go:47 | ✅ runar-rs/src/sdk/provider.rs:48 | ✅ runar-py/runar/sdk/provider.py:51 | ✅ runar-zig/src/sdk_provider.zig:65 | ✅ runar-rb/lib/runar/sdk/provider.rb | ✅ runar-java/.../sdk/MockProvider.java |
| WhatsOnChainProvider | ✅ runar-sdk/src/providers/woc.ts:53 | ✅ runar-go/sdk_woc_provider.go:20 | ✅ runar-rs/src/sdk/woc_provider.rs:16 | ✅ runar-py/runar/sdk/woc_provider.py:17 | ✅ runar-zig/src/sdk_woc_provider.zig:38 | ✅ runar-rb/lib/runar/sdk/woc_provider.rb | ✅ runar-java/.../sdk/WhatsOnChainProvider.java |
| GorillaPoolProvider | ✅ runar-sdk/src/providers/gorillapool.ts:67 | ✅ runar-go/sdk_gorillapool.go:27 | ✅ runar-rs/src/sdk/gorillapool.rs:51 | ✅ runar-py/runar/sdk/gorillapool.py:21 | ✅ runar-zig/src/sdk_gorillapool.zig:39 | ✅ runar-rb/lib/runar/sdk/gorillapool_provider.rb | ✅ runar-java/.../sdk/GorillaPoolProvider.java |
| RpcProvider | ✅ runar-sdk/src/providers/rpc-provider.ts:22 | ✅ runar-go/rpc_provider.go:21 | ✅ runar-rs/src/sdk/rpc_provider.rs:14 | ✅ runar-py/runar/sdk/rpc_provider.py:18 | ✅ runar-zig/src/sdk_rpc_provider.zig:39 | ✅ runar-rb/lib/runar/sdk/rpc_provider.rb | ✅ runar-java/.../sdk/RPCProvider.java |
| WalletProvider / BRC-100 | ✅ runar-sdk/src/providers/wallet-provider.ts:48 | ✅ runar-go/sdk_wallet.go:84 | ✅ runar-rs/src/sdk/wallet.rs:138 | ✅ runar-py/runar/sdk/wallet.py:106 | ✅ runar-zig/src/sdk_wallet.zig | ✅ runar-rb/lib/runar/sdk/wallet.rb | ✅ runar-java/.../sdk/WalletProvider.java:30 |
| LocalSigner (real ECDSA + BIP-143) | ✅ runar-sdk/src/signers/local.ts:21 | ✅ runar-go/sdk_signer.go:46 | ✅ runar-rs/src/sdk/signer.rs:52 | ✅ runar-py/runar/sdk/local_signer.py:52 | ✅ runar-zig/src/sdk_signer.zig:53 | ⚠️ runar-rb/lib/runar/sdk/local_signer.rb:27 — raises RuntimeError on instantiate unless optional `bsv-sdk` gem installed; no pure-Ruby fallback (Python has one) | ✅ runar-java/.../sdk/LocalSigner.java:29 |
| MockSigner | ✅ runar-sdk/src/signers/mock.ts:23 | ✅ runar-go/sdk_signer.go:134 | ✅ runar-rs/src/sdk/signer.rs:428 | ✅ runar-py/runar/sdk/signer.py:37 | ✅ runar-zig/src/sdk_signer.zig:151 | ✅ runar-rb/lib/runar/sdk/signer.rb | ✅ runar-java/.../sdk/MockSigner.java |
| ExternalSigner | ✅ runar-sdk/src/signers/external.ts:39 | ✅ runar-go/sdk_signer.go:181 | ✅ runar-rs/src/sdk/signer.rs:380 | ✅ runar-py/runar/sdk/signer.py:62 | ✅ runar-zig/src/sdk_signer.zig:197 | ✅ runar-rb/lib/runar/sdk/signer.rb | ✅ runar-java/.../sdk/ExternalSigner.java |
| buildDeployTransaction | ✅ runar-sdk/src/deployment.ts:17 | ✅ runar-go/sdk_deployment.go:31 | ✅ runar-rs/src/sdk/deployment.rs:18 | ✅ runar-py/runar/sdk/deployment.py:12 | ✅ runar-zig/src/sdk_deploy.zig:38 | ✅ runar-rb/lib/runar/sdk/deployment.rb:26 | ✅ runar-java/.../sdk/TransactionBuilder.java:37 |
| buildCallTransaction | ✅ runar-sdk/src/calling.ts:22 | ✅ runar-go/sdk_calling.go:51 | ✅ runar-rs/src/sdk/calling.rs:45 | ✅ runar-py/runar/sdk/calling.py:11 | ✅ runar-zig/src/sdk_call.zig:54 | ✅ runar-rb/lib/runar/sdk/calling.rb | ✅ runar-java/.../sdk/TransactionBuilder.java:121 |
| State serialization | ✅ runar-sdk/src/state.ts:28 | ✅ runar-go/sdk_state.go:25 | ✅ runar-rs/src/sdk/state.rs:27 | ✅ runar-py/runar/sdk/state.py:104 | ✅ runar-zig/src/sdk_state.zig:12 | ✅ runar-rb/lib/runar/sdk/state.rb:151 | ✅ runar-java/.../sdk/StateSerializer.java:32 |
| UTXO selection (largest-first) | ✅ runar-sdk/src/deployment.ts:114 | ✅ runar-go/sdk_deployment.go:98 | ✅ runar-rs/src/sdk/deployment.rs:101 | ✅ runar-py/runar/sdk/deployment.py:73 | ✅ runar-zig/src/sdk_deploy.zig:122 | ✅ runar-rb/lib/runar/sdk/deployment.rb:89 | ✅ runar-java/.../sdk/UtxoSelector.java:26 |
| Fee estimation (script-size-aware) | ✅ runar-sdk/src/deployment.ts:96 | ✅ runar-go/sdk_deployment.go:125 | ✅ runar-rs/src/sdk/deployment.rs:89 | ✅ runar-py/runar/sdk/deployment.py:94 | ✅ runar-zig/src/sdk_deploy.zig:161 | ✅ runar-rb/lib/runar/sdk/deployment.rb:115 | ✅ runar-java/.../sdk/FeeEstimator.java:26 |
| ScriptVM (off-chain Script exec) | ✅ runar-testing/src/vm/script-vm.ts:88 (execute+step) | ✅ runar-go/script_vm.go:71 (execute+step) | ⚠️ runar-rs/src/sdk/script_vm.rs:46 — execute-only; upstream `Spend` hides pc/stack (documented in CLAUDE.md) | ✅ runar-py/runar/sdk/script_vm.py:89 (execute+step; needs `bsv-sdk` extra) | N/A — project policy: no usable upstream BSV Script interpreter for Zig | N/A — project policy: no BSV Ruby SDK | N/A — project policy: no BSV Java SDK |
| ANF interpreter | ✅ runar-sdk/src/anf-interpreter.ts:155 | ✅ runar-go/anf_interpreter.go:155 | ✅ runar-rs/src/sdk/anf_interpreter.rs:328 | ✅ runar-py/runar/sdk/anf_interpreter.py:206 | ✅ runar-zig/src/sdk_anf_interpreter.zig:250 | ✅ runar-rb/lib/runar/sdk/anf_interpreter.rb:91 | ✅ runar-java/.../sdk/AnfInterpreter.java:57 |
| CompileCheck | ✅ runar-compiler/src/index.ts:523 | ✅ runar-go CompileCheck | ✅ runar-rs compile_check | ✅ runar-py/runar/compile_check.py:9 | ✅ runar-zig/src/compile_check.zig:24 | ✅ runar-rb/lib/runar/compile_check.rb | ✅ runar-java/.../sdk/CompileCheck.java |
| Ordinals BSV-20 mint/transfer | ✅ runar-sdk/src/ordinals/bsv20.ts:50 | ✅ runar-go/sdk_ordinals.go:337 | ✅ runar-rs/src/sdk/ordinals.rs:403 | ✅ runar-py/runar/sdk/ordinals.py:337 | ✅ runar-zig/src/sdk_ordinals.zig:369 | ✅ runar-rb/lib/runar/sdk/ordinals.rb (Bsv20) | ✅ runar-java/.../sdk/ordinals/Bsv20.java |
| Ordinals BSV-21 mint/transfer | ✅ runar-sdk/src/ordinals/bsv20.ts:119 | ✅ runar-go/sdk_ordinals.go:362 | ✅ runar-rs/src/sdk/ordinals.rs:442 | ✅ runar-py/runar/sdk/ordinals.py:361 | ✅ runar-zig/src/sdk_ordinals.zig:415 | ✅ runar-rb/lib/runar/sdk/ordinals.rb (Bsv21) | ✅ runar-java/.../sdk/ordinals/Bsv21.java |
| 1sat inscription envelope | ✅ runar-sdk/src/ordinals/envelope.ts:72 | ✅ runar-go/sdk_ordinals.go:81 | ✅ runar-rs/src/sdk/ordinals.rs:99 | ✅ runar-py/runar/sdk/ordinals.py:73 | ✅ runar-zig/src/sdk_ordinals.zig:92 | ✅ runar-rb/lib/runar/sdk/ordinals.rb:72 | ✅ runar-java/.../sdk/Inscription.java:34 |
| Constructor-slot splicing | ✅ runar-sdk/src/script-utils.ts:125 | ✅ runar-go/sdk_script_utils.go:136 | ✅ runar-rs/src/sdk/contract.rs:1325 | ✅ runar-py/runar/sdk/contract.py:1137 | ✅ runar-zig/src/sdk_script_utils.zig:134 | ✅ runar-rb/lib/runar/sdk/script_utils.rb:105 | ✅ runar-java/.../sdk/ContractScript.java:50 |

### 3.11. CLI surfaces

| Feature | TS | Go | Rust | Python | Zig | Ruby | Java |
|---|---|---|---|---|---|---|---|
| compile source → artifact/hex | ✅ runar-cli/src/commands/compile.ts:201 | ✅ compilers/go/main.go:35 | ✅ compilers/rust/src/main.rs:35 | ✅ runar_compiler/__main__.py:38 | ✅ compilers/zig/src/main.zig:123 | ✅ runar_compiler/cli.rb:55 | ✅ runar/compiler/Cli.java:524 |
| `--parse-only` mode | ⚠️ runar-compiler/src/index.ts:69 — library option only; not exposed as a `runar-cli` flag | ✅ main.go:44 | ✅ main.rs:44 | ✅ __main__.py:64 | ✅ main.zig:27 | ✅ cli.rb:79 | ✅ Cli.java:527 |
| `--ir` / `--from-ir` (compile from ANF JSON) | ✅ compile.ts:14 (`--from-ir`) | ✅ main.go:38 (`--ir`) | ✅ main.rs:18 (`--ir`) | ✅ __main__.py:34 (`--ir`) | ✅ main.zig:97 | ✅ cli.rb:55 (`--ir`) | ✅ Cli.java:524 (`--ir`) |
| `--hex` output flag | ⚠️ compile.ts:145 — only emits hex when `--from-ir` is also set (coupled, unlike other tiers) | ✅ main.go:41 | ✅ main.rs:30 | ✅ __main__.py:49 | ✅ main.zig:42 | ✅ cli.rb:67 | ✅ Cli.java:526 |
| `--disable-constant-folding` flag | ✅ compile.ts:13 | ✅ main.go:45 | ✅ main.rs:74 | ✅ __main__.py:74 | ✅ main.zig:46 (source-mode only; rejected for IR-mode by design) | ✅ cli.rb:83 | ✅ Cli.java:528 |
| debug / ScriptVM step mode via CLI | ✅ runar-cli/src/commands/debug.ts (interactive step debugger) | ❌ — no `debug` subcommand (Go ships a ScriptVM library but no CLI) | ❌ — Rust ships a ScriptVM library (execute-only) but no CLI | ❌ — Python ships a ScriptVM library but no CLI | N/A — no ScriptVM in Zig (policy) | N/A — no ScriptVM in Ruby (policy) | N/A — no ScriptVM in Java (policy) |

### 3.12. Decompiler (`packages/decompiler/`, TypeScript-only package)

| Surface | TS | Go | Rust | Python | Zig | Ruby | Java |
|---|---|---|---|---|---|---|---|
| Disassembler | ✅ packages/decompiler/src/disasm.ts:15 | N/A — TS-only package, no peer port | N/A | N/A | N/A | N/A | N/A |
| Symbolic-execution lift | ✅ src/symexec.ts:118; src/symexec-lift.ts:254; src/lift.ts:26 | N/A | N/A | N/A | N/A | N/A | N/A |
| Template / fingerprint matching | ✅ src/templates.ts:137; src/match.ts:63; src/fingerprints.ts:30 | N/A | N/A | N/A | N/A | N/A | N/A |
| Stateful lift | ✅ src/stateful-lift.ts:428 | N/A | N/A | N/A | N/A | N/A | N/A |
| TS source emit | ✅ src/emit-ts.ts:57 | N/A | N/A | N/A | N/A | N/A | N/A |
| Roundtrip verification | ✅ src/verify.ts:38 | N/A | N/A | N/A | N/A | N/A | N/A |
| Refinement loop / dispatch | ✅ src/refine.ts:404; src/dispatch.ts:36; src/index.ts:100 | N/A | N/A | N/A | N/A | N/A | N/A |
| CLI (`runar decompile`) | ✅ runar-cli/src/commands/decompile.ts:54 | N/A | N/A | N/A | N/A | N/A | N/A |

Per user direction at the §1–2 approval gate, the decompiler is treated as a TypeScript-only tool (not a language feature subject to the 7-tier ANF-node policy); non-TS cells are `N/A`, not `❌`.

### 3.13. Example contract patterns (per language; `✅` = pattern exists, `❌` = absent)

STARK patterns (`babybear`, `babybear-ext4`, `merkle-proof`) excluded per §1. `sol`/`move` are TS-frontend formats. 49 non-STARK patterns enumerated; only patterns with at least one `❌` are listed individually — the remaining 45 patterns (p2pkh, p2blake3pkh, escrow, auction, stateful, stateful-counter, tic-tac-toe, token-ft, token-nft, ec-demo, ec-primitives, ec-unit, schnorr-zkp, p256/p384-primitives, p256/p384-wallet, post-quantum-wallet, post-quantum-wots-naive-INSECURE, post-quantum-slhdsa-naive-INSECURE, sphincs-wallet, blake3, sha256-compress, sha256-finalize, state-covenant, state-ripemd160, covenant-vault, cross-covenant, convergence-proof, oracle-price, message-board, math-demo, arithmetic, bitwise-ops, shift-ops, boolean-logic, bounded-loop, if-else, if-without-else, if-without-else-multi-temp, multi-method, function-patterns, private-helper-outputs, add-data-output, add-raw-output, conditional-data-output, property-initializers, go-dsl-bytestring-literal) are `✅` in all 9 columns.

| Pattern | ts | go | rust | python | zig | ruby | java | sol | move |
|---|---|---|---|---|---|---|---|---|---|
| multisig-2of3 | ✅ | ❌ | ❌ | ❌ | ✅ | ❌ | ❌ | ✅ | ❌ |
| bsv20-token | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ❌ | ❌ |
| bsv21-token | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ❌ | ❌ |
| ordinal-nft | ✅ | ✅ | ❌ | ✅ | ✅ | ❌ | ✅ | ❌ | ❌ |
| fixed-array-nested | ✅ | ✅ | ✅ | ✅ | ✅ | ❌ | ❌ | ✅ | ✅ |

(These are developer-facing example gaps, not conformance gaps — conformance fixtures live under `conformance/tests/`, independent of `examples/`.)

---

## 4. Test matrix

Same columns. Cell legend: `✅ test_file:line` directly tested with assertions on output bytes/opcodes/AST/behavior · `⚠️ test_file:line — weakness` tested but weak · `❌` no test · `N/A` feature absent (matches a `❌`/`N/A` in §3). "golden harness" = the cross-tier conformance golden suite described in §3 (run evidence in §7); a cell citing it asserts byte-identical IR+hex but not via a tier-local dedicated unit test.

### 4.1. Frontend format parsers

| Feature | TS | Go | Rust | Python | Zig | Ruby | Java |
|---|---|---|---|---|---|---|---|
| `.runar.ts` parser | ✅ __tests__/01-parse.test.ts | ✅ frontend/parser_test.go | ✅ frontend/parser.rs:1225 (inline) | ✅ tests/test_parser_ts.py | ✅ tests/language_constructs.zig | ✅ test/test_parser_ts.rb | ✅ frontend/TsParserTest.java |
| `.runar.sol` parser | ✅ 01-parse-sol.test.ts:43 | ✅ parser_sol_test.go:12 | ✅ parser_sol.rs:1910 (inline) | ✅ tests/test_parser_sol.py | ⚠️ tests/conformance.zig — golden harness only, no dedicated sol AST unit test | ✅ test/test_parser_sol.rb | ✅ frontend/SolParserTest.java:49 |
| `.runar.move` parser | ✅ 01-parse-move.test.ts | ✅ parser_move_test.go | ✅ parser_move.rs (inline) | ✅ tests/test_parser_move.py | ⚠️ conformance.zig — golden harness only | ✅ test/test_parser_move.rb | ✅ frontend/MoveParserTest.java |
| `.runar.go` parser | ✅ 01-parse-go.test.ts | ✅ parser_gocontract_test.go | ✅ parser_gocontract.rs (inline) | ✅ tests/test_parser_go.py | ⚠️ conformance.zig — golden harness only | ✅ test/test_parser_go.rb | ✅ frontend/GoParserTest.java |
| `.runar.rs` parser | ✅ rust-parser-examples.test.ts | ✅ parser_rustmacro_test.go | ✅ parser_rustmacro.rs (inline) | ✅ tests/test_parser_rs.py | ⚠️ conformance.zig — golden harness only | ✅ test/test_parser_rs.rb | ✅ frontend/RustParserTest.java |
| `.runar.py` parser | ✅ 01-parse-python.test.ts | ✅ parser_python_test.go | ✅ parser_python.rs (inline) | ✅ tests/test_parser_py.py | ⚠️ conformance.zig — golden harness only | ✅ test/test_parser_py.rb | ✅ frontend/PyParserTest.java |
| `.runar.zig` parser | ✅ zig-parser-examples.test.ts | ✅ parser_zig_test.go | ✅ parser_zig.rs (inline) | ✅ tests/test_parser_zig.py | ✅ tests/conformance.zig + language_constructs.zig | ✅ test/test_parser_zig.rb | ✅ frontend/ZigParserTest.java |
| `.runar.rb` parser | ✅ 01-parse-ruby.test.ts | ✅ parser_ruby_test.go | ✅ parser_ruby.rs (inline) | ✅ tests/test_parser_rb.py | ⚠️ conformance.zig — golden harness only | ✅ test/test_parser_ruby.rb | ✅ frontend/RbParserTest.java |
| `.runar.java` parser | ✅ 01-parse-java.test.ts | ✅ parser_java_test.go | ✅ parser_java.rs (inline) | ✅ tests/test_parser_java.py | ⚠️ conformance.zig — golden harness only | ✅ test/test_parser_java.rb | ✅ frontend/JavaParserTest.java |

### 4.2. Type system

| Feature | TS | Go | Rust | Python | Zig | Ruby | Java |
|---|---|---|---|---|---|---|---|
| bigint / bool / ByteString | ✅ 03-typecheck.test.ts:185 | ✅ typecheck_test.go | ✅ typecheck.rs (inline) | ✅ test_frontend.py | ⚠️ language_constructs.zig — exercised only via op tests | ✅ test_typecheck.rb:52 | ✅ TypecheckTest.java:51 |
| Point | ✅ ec.test.ts:9 | ⚠️ codegen/stack_state_types_test.go — state-type serialization only, no Point-typed-property frontend probe | ✅ codegen/ec.rs (inline) | ✅ tests/codegen/test_ec.py | ✅ language_constructs.zig | ✅ test/codegen/test_ec.rb | ✅ codegen/EcTest.java |
| Fixed-size arrays | ✅ 03b-expand-fixed-arrays.test.ts | ✅ expand_fixed_arrays_test.go | ✅ expand_fixed_arrays.rs (inline) | ✅ test_expand_fixed_arrays.py | ⚠️ conformance.zig — golden harness only, no dedicated expand-arrays unit test | ✅ test/test_expand_fixed_arrays.rb | ✅ passes/ExpandFixedArraysTest.java |
| readonly properties | ✅ 02-validate.test.ts:377 | ✅ validator_test.go | ✅ validator.rs (inline) | ✅ test_frontend.py | ⚠️ conformance.zig — golden harness only | ✅ test_validator.rb:350 | ✅ passes/ValidateTest.java |
| Property initializers | ✅ 02-validate.test.ts:377 | ✅ expand_fixed_arrays_test.go | ✅ expand_fixed_arrays.rs (inline) | ✅ test_expand_fixed_arrays.py | ⚠️ conformance.zig — golden harness only | ✅ test_validator.rb:608 | ✅ ExpandFixedArraysTest.java |

### 4.3. Control flow

| Feature | TS | Go | Rust | Python | Zig | Ruby | Java |
|---|---|---|---|---|---|---|---|
| if / else | ✅ 06-emit.test.ts | ✅ emit_test.go:504 | ✅ emit.rs:759 (inline) | ✅ test_emit.py:664 | ✅ language_constructs.zig:94 | ✅ test/codegen/test_emit.rb | ✅ EmitTest.java:136 |
| if-without-else | ✅ if-without-else.test.ts:91 | ✅ emit_test.go:922 | ✅ emit.rs:1167 (inline) | ✅ test_emit.py:539 | ✅ language_constructs.zig:94 | ✅ test_stack_lower.rb | ✅ StackIrTest.java:129 |
| Ternary expression | ✅ 04-anf-lower.test.ts:264 | ⚠️ no dedicated ternary lowering/emit test — covered only via golden harness | ⚠️ no dedicated ternary test — golden harness only | ⚠️ no dedicated ternary test — golden harness only | ⚠️ no dedicated ternary test — golden harness only | ⚠️ no dedicated ternary test — golden harness only | ✅ StackLowerTest.java:592 |
| Bounded for-loop | ✅ 02-validate.test.ts:215 | ✅ anf_lower_test.go:435 | ✅ anf_lower.rs (inline) | ✅ test_while.py + test_frontend.py:1025 | ⚠️ conformance.zig — golden harness only | ✅ test_validator.rb:478 | ✅ AnfLowerTest.java |
| while-loop | N/A | N/A | N/A | N/A | N/A | N/A | N/A |
| break / continue | ✅ rejection test in 01-parse suite | N/A | N/A | ✅ test_break_continue.py (rejection) | N/A | N/A | N/A |

### 4.4. Operators

| Feature | TS | Go | Rust | Python | Zig | Ruby | Java |
|---|---|---|---|---|---|---|---|
| Arithmetic | ✅ 05-stack-lower.test.ts:188 | ✅ stack_test.go | ✅ stack.rs (inline) | ✅ test_stack.py | ⚠️ language_constructs.zig — only bitwise/shift covered, no explicit `+ - * /` op test | ✅ test_stack_lower.rb:188 | ✅ EmitTest.java:64 |
| Comparison | ✅ 03-typecheck.test.ts:444 | ✅ typecheck_test.go | ✅ typecheck.rs (inline) | ✅ test_frontend.py | ⚠️ language_constructs.zig — no explicit comparison-op test | ✅ test_typecheck.rb | ✅ TypecheckTest.java |
| Boolean | ✅ 03-typecheck.test.ts:526 | ✅ typecheck_test.go | ✅ typecheck.rs (inline) | ✅ test_frontend.py | ⚠️ language_constructs.zig — no explicit boolean-op test | ✅ test_typecheck.rb:156 | ✅ TypecheckTest.java |
| Bitwise `& \| ^ ~` | ✅ optimizer.test.ts:192 | ✅ stack_test.go / optimizer_test.go | ✅ stack.rs / constant_fold.rs (inline) | ✅ test_constant_fold.py | ✅ language_constructs.zig:123 | ✅ test_optimizer.rb | ✅ StackLowerTest.java:667 |
| Shift `<< >>` | ✅ optimizer.test.ts:151 | ✅ optimizer_test.go / stack_test.go | ✅ constant_fold.rs (inline) | ✅ test_constant_fold.py | ✅ language_constructs.zig:183 | ✅ test_optimizer.rb | ✅ StackLowerTest.java:733 |

### 4.5. Compiler passes

| Feature | TS | Go | Rust | Python | Zig | Ruby | Java |
|---|---|---|---|---|---|---|---|
| validate | ✅ 02-validate.test.ts | ✅ validator_test.go | ✅ validator.rs (inline) | ✅ test_frontend.py:325 | ⚠️ conformance.zig — golden harness only, no dedicated validate unit test | ✅ test_validator.rb | ✅ ValidateTest.java |
| typecheck | ✅ 03-typecheck.test.ts | ✅ typecheck_test.go | ✅ typecheck.rs (inline) | ✅ test_frontend.py:772 | ⚠️ conformance.zig — golden harness only | ✅ test_typecheck.rb | ✅ TypecheckTest.java |
| ANF lowering | ✅ 04-anf-lower.test.ts | ✅ anf_lower_test.go | ✅ anf_lower.rs (inline) | ✅ test_frontend.py:985 | ⚠️ conformance.zig — golden harness only | ✅ test_anf_lower.rb | ✅ AnfLowerTest.java |
| constant folding | ✅ optimizer.test.ts:35 | ✅ constant_fold_test.go | ✅ constant_fold.rs (inline) | ✅ test_constant_fold.py | ⚠️ conformance.zig — golden harness only | ✅ test_optimizer.rb | ✅ ConstantFoldTest.java |
| peephole optimizer | ✅ optimizer.test.ts | ✅ codegen/optimizer_test.go | ✅ codegen/optimizer.rs (inline) | ✅ test_optimizer.py | ✅ passes/peephole.zig (inline test blocks) | ✅ test/test_optimizer.rb | ✅ passes/PeepholeTest.java |
| expand-fixed-arrays | ✅ 03b-expand-fixed-arrays.test.ts | ✅ expand_fixed_arrays_test.go | ✅ expand_fixed_arrays.rs (inline) | ✅ test_expand_fixed_arrays.py | ⚠️ conformance.zig — golden harness only | ✅ test_expand_fixed_arrays.rb | ✅ ExpandFixedArraysTest.java |
| stack lowering | ✅ 05-stack-lower.test.ts:279 | ✅ codegen/stack_test.go:124 | ⚠️ codegen/stack.rs:4852 (inline) — opcode-presence/shape only, not exact bytes | ✅ tests/test_stack.py:150 | ⚠️ stack_lower.zig:4333 (inline) — stack-map units, not lowering output | ✅ test/test_stack_lower.rb:188 | ✅ passes/StackLowerTest.java:180 |
| emit | ⚠️ 06-emit.test.ts:78 — mostly "valid hex"/length checks, few exact-byte asserts | ✅ codegen/emit_test.go:160 (exact bytes) | ⚠️ codegen/emit.rs:580 (inline) — hex non-empty / slot checks | ✅ tests/test_emit.py | ✅ codegen/emit.zig:911 (inline, exact bytes) | ✅ test/codegen/test_emit.rb | ✅ passes/EmitTest.java:28 (exact bytes) |
| opcode mapping table | ⚠️ 06-emit.test.ts — partial (CHECKSIG/ADD only) | ✅ emit_test.go:353 | ⚠️ emit.rs (inline) — partial | ✅ tests/codegen/test_*.py | ✅ emit.zig:911 | ✅ test/test_stack_lower.rb:188 | ✅ EmitTest.java:28 |

### 4.6. Contract model

| Feature | TS | Go | Rust | Python | Zig | Ruby | Java |
|---|---|---|---|---|---|---|---|
| SmartContract/Stateful + parentClass | ✅ golden harness (stateful/* fixtures) | ✅ conformance_goldens_test.go | ✅ tests/conformance_goldens.rs | ✅ test_conformance_goldens.py | ✅ test_conformance.zig | ✅ conformance_goldens_test.rb | ⚠️ golden parity enforced only via external `conformance/runner` (no in-tree Java golden-hex test) |
| Auto checkPreimage at entry | ✅ golden harness | ✅ stack_test.go (stateful) | ✅ conformance_goldens.rs | ✅ tests/codegen/test_check_preimage.py | ✅ test_conformance.zig | ✅ conformance_goldens_test.rb | ✅ StackLowerTest.java:219 |
| State continuation / get_state_script | ✅ golden harness (state-covenant) | ✅ conformance_goldens_test.go | ✅ conformance_goldens.rs | ✅ test_conformance_goldens.py | ✅ test_conformance.zig | ✅ conformance_goldens_test.rb | ⚠️ external runner only |
| OP_CODESEPARATOR auto-insertion | ✅ golden harness (stateful fixtures) | ✅ stack_test.go (stateful) | ✅ conformance_goldens.rs | ✅ tests/codegen/test_codeseparator.py | ✅ test_conformance.zig | ✅ conformance_goldens_test.rb | ✅ StackLowerTest.java:219 |
| codeSeparatorIndex artifact fields | ⚠️ golden harness — no field-specific assert | ✅ emit_test.go | ⚠️ golden harness only | ⚠️ golden harness only | ⚠️ golden harness only | ⚠️ golden harness only | ⚠️ golden harness only |
| addOutput (multi-output) | ✅ 05-stack-lower.test.ts + golden | ✅ conformance_goldens_test.go | ✅ conformance_goldens.rs | ✅ tests/codegen/test_addoutput.py:102 | ✅ test_conformance.zig | ⚠️ no dedicated addOutput test — golden harness only | ✅ StackLowerTest.java:257 |
| addRawOutput | ✅ golden harness (add-raw-output) | ✅ conformance_goldens_test.go | ✅ tests/addraw_output_codegen_test.rs | ✅ tests/codegen/test_addrawoutput.py | ✅ test_conformance.zig | ⚠️ golden harness only | ✅ StackLowerTest.java:382 |
| addDataOutput | ✅ golden harness (add-data-output) | ✅ stack_test.go:1698 | ✅ conformance_goldens.rs | ✅ test_addrawoutput.py | ✅ test_conformance.zig | ✅ test/codegen/test_add_data_output.rb | ✅ StackLowerTest.java:426 |
| asm intrinsic / raw_script / UnsafeSmartContract | ✅ __tests__/asm-surface.test.ts, asm-array-form.test.ts, asm-expression-form.test.ts | N/A — feature absent (§3.6, §6 F-1) | N/A | N/A | N/A | N/A | N/A |
| assert() | ✅ 05-stack-lower.test.ts:426 | ✅ emit_test.go:331 | ✅ conformance_goldens.rs | ✅ test_stack.py:324 | ✅ test_conformance.zig | ✅ test_stack_lower.rb:121 | ✅ StackLowerTest.java |

### 4.7. Math builtins

| Feature | TS | Go | Rust | Python | Zig | Ruby | Java |
|---|---|---|---|---|---|---|---|
| abs | ⚠️ no conformance golden, no dedicated unit test | ⚠️ no conformance golden, no dedicated unit test | ⚠️ no conformance golden, no dedicated unit test | ✅ tests/codegen/test_math_builtins.py:161 | ⚠️ no conformance golden, no dedicated unit test | ❌ no test | ⚠️ MathBuiltinsLowerTest.java — abs imported but no abs-specific assertion |
| min | ⚠️ no golden / no unit test | ⚠️ no golden / no unit test | ⚠️ no golden / no unit test | ✅ test_math_builtins.py:167 | ⚠️ no golden / no unit test | ❌ | ❌ |
| max | ⚠️ no golden / no unit test | ⚠️ no golden / no unit test | ⚠️ no golden / no unit test | ✅ test_math_builtins.py:175 | ⚠️ no golden / no unit test | ❌ | ❌ |
| within | ⚠️ no golden / no unit test | ⚠️ no golden / no unit test | ⚠️ no golden / no unit test | ✅ test_math_builtins.py:182 | ⚠️ no golden / no unit test | ❌ | ❌ |
| safediv | ✅ golden harness (math-demo) | ✅ golden harness (math-demo) | ✅ golden harness (math-demo) | ✅ test_math_builtins.py:197 | ✅ golden harness (math-demo) | ✅ golden harness (math-demo) | ⚠️ external runner golden only |
| safemod | ⚠️ no golden (not in math-demo) / no unit test | ⚠️ no golden / no unit test | ⚠️ no golden / no unit test | ✅ test_math_builtins.py:206 | ⚠️ no golden / no unit test | ❌ | ❌ |
| clamp | ✅ golden harness (math-demo) | ✅ golden harness | ✅ golden harness | ✅ test_math_builtins.py:228 | ✅ golden harness | ✅ golden harness | ✅ MathBuiltinsLowerTest.java:136 |
| sign | ✅ 05-stack-lower.test.ts:609 + golden | ✅ stack_test.go:1531 | ✅ golden harness | ✅ test_math_builtins.py | ✅ golden harness | ✅ golden harness | ✅ MathBuiltinsLowerTest.java:358 |
| pow | ✅ golden harness | ✅ golden harness | ✅ golden harness | ✅ test_math_builtins.py | ✅ golden harness | ✅ golden harness | ✅ MathBuiltinsLowerTest.java:163 |
| mulDiv | ✅ golden harness | ✅ golden harness | ✅ golden harness | ✅ test_math_builtins.py | ✅ golden harness | ✅ golden harness | ✅ MathBuiltinsLowerTest.java:195 |
| percentOf | ✅ golden harness | ✅ golden harness | ✅ golden harness | ✅ test_math_builtins.py | ✅ golden harness | ✅ golden harness | ⚠️ external runner golden only |
| sqrt | ✅ 05-stack-lower.test.ts:899 + golden | ✅ stack_test.go:848 | ✅ golden harness | ✅ test_math_builtins.py | ✅ golden harness | ✅ golden harness | ✅ MathBuiltinsLowerTest.java:210 |
| gcd | ✅ golden harness | ✅ golden harness | ✅ golden harness | ✅ test_math_builtins.py | ✅ golden harness | ✅ golden harness | ✅ MathBuiltinsLowerTest.java:255 |
| divmod | ⚠️ no golden (not in math-demo) / no unit test | ⚠️ no golden / no unit test | ⚠️ no golden / no unit test | ✅ test_math_builtins.py | ⚠️ no golden / no unit test | ❌ | ✅ MathBuiltinsLowerTest.java:281 |
| log2 | ✅ 05-stack-lower.test.ts:867 + golden | ✅ stack_test.go:769 | ✅ golden harness | ✅ tests/test_stack.py:540 | ✅ golden harness | ✅ golden harness | ✅ MathBuiltinsLowerTest.java:328 |
| bool | ⚠️ no golden / no unit test | ⚠️ no golden / no unit test | ⚠️ no golden / no unit test | ✅ test_math_builtins.py:189 | ⚠️ no golden / no unit test | ❌ | ❌ |

### 4.8. Hash builtins

| Feature | TS | Go | Rust | Python | Zig | Ruby | Java |
|---|---|---|---|---|---|---|---|
| sha256 | ✅ 05-stack-lower.test.ts:279 + golden | ✅ emit_test.go:982 | ✅ golden harness (basic-p2pkh) | ✅ tests/codegen/test_hash_builtins.py | ✅ test_conformance.zig | ✅ test_stack_lower.rb:509 | ⚠️ EmitTest opcode-only; full hex via external runner |
| hash160 | ✅ golden harness (basic-p2pkh) | ✅ conformance_goldens_test.go | ✅ golden harness | ✅ test_hash_builtins.py:83 | ✅ test_conformance.zig | ✅ test_stack_lower.rb:305 | ✅ EmitTest.java:52 |
| hash256 | ✅ golden harness | ✅ conformance_goldens_test.go | ✅ conformance_goldens.rs | ✅ test_hash_builtins.py:117 | ✅ test_conformance.zig | ⚠️ golden harness only | ⚠️ external runner only |
| ripemd160 | ✅ golden harness (state-ripemd160) | ✅ conformance_goldens_test.go | ✅ conformance_goldens.rs | ✅ test_hash_builtins.py | ✅ test_conformance.zig | ✅ conformance_goldens_test.rb | ⚠️ external runner only |
| sha256Compress | ✅ __tests__/sha256-compress.test.ts + golden | ✅ golden harness (sha256-compress) | ✅ tests/sha256_codegen_tests.rs | ✅ tests/codegen/test_sha256.py | ✅ test_conformance.zig | ✅ test/codegen/test_sha256.rb | ✅ codegen/Sha256Test.java |
| sha256Finalize | ✅ __tests__/sha256-finalize.test.ts + golden | ✅ golden harness (sha256-finalize) | ✅ sha256_codegen_tests.rs | ✅ test_sha256.py | ✅ test_conformance.zig | ✅ test/codegen/test_sha256.rb | ✅ codegen/Sha256Test.java |
| checkPreimage | ✅ golden harness (stateful fixtures) | ✅ stack_test.go (stateful) | ✅ conformance_goldens.rs | ✅ tests/codegen/test_check_preimage.py | ✅ test_conformance.zig | ✅ conformance_goldens_test.rb | ✅ StackLowerTest.java:219 |

### 4.9. Crypto codegen

| Feature | TS | Go | Rust | Python | Zig | Ruby | Java |
|---|---|---|---|---|---|---|---|
| checkSig | ✅ 05-stack-lower.test.ts:125 | ✅ golden harness (basic-p2pkh) | ✅ conformance_goldens.rs:211 | ✅ tests/codegen/test_check_sig.py:97 | ✅ conformance_goldens.zig | ✅ conformance_goldens_test.rb:114 | ✅ golden harness via gradle (basic-p2pkh) |
| checkMultiSig | ⚠️ 05-stack-lower.test.ts:417 — `toContain('OP_CHECKMULTISIG')` only, no sequence/hex; no conformance fixture | ⚠️ optimizer_test.go references it but no byte golden; no conformance fixture | ⚠️ no dedicated test; no conformance fixture | ⚠️ test_check_sig.py — multisig not byte-asserted | ❌ no checkMultiSig test | ❌ no checkMultiSig test | ✅ codegen/CheckMultiSigTest.java:185 (7 tests, OP_0 dummy + counts + sequence) |
| ecAdd | ⚠️ ec.test.ts:144 — compile-only, no output assertion | ✅ golden harness (ec-primitives/ec-unit) | ⚠️ ec_codegen_tests.rs:37 — `_nontrivial` (ops.len()>0) only | ✅ tests/codegen/test_ec.py:43 (exact op-count golden) | ⚠️ ec_emitters.zig:833 (inline) — structural, not byte-exact | ⚠️ test/codegen/test_ec.rb:17 — ASM-substring + size>500 | ✅ codegen/EcTest.java:42 (exact op count + hex byte count) |
| ecMul | ⚠️ ec.test.ts — compile-only | ✅ golden harness | ⚠️ ec_codegen_tests.rs:43 — `_nontrivial` | ✅ test_ec.py:43 | ⚠️ ec_emitters.zig:843 — structural | ⚠️ test_ec.rb:45 — ASM-shape | ✅ EcTest.java:52 |
| ecMulGen / ecNegate / ecOnCurve / ecModReduce / ecEncodeCompressed / ecMakePoint / ecPointX / ecPointY | ⚠️ ec.test.ts:128 — compile-only for tested subset; rest golden harness only | ✅ golden harness (ec-primitives/ec-unit) | ⚠️ ec_codegen_tests.rs:49 — `_nontrivial` per builtin | ✅ test_ec.py:43 op-count goldens; :53 ecModReduce exact 8-op sequence | ⚠️ ec_emitters.zig:856 / crypto_emitters.zig:220 (inline) — structural | ⚠️ test_ec.rb — ASM-shape | ✅ EcTest.java:60 (per-builtin exact op-count + hex-byte goldens) |
| NIST P-256 | ✅ golden harness (p256-primitives/p256-wallet) | ✅ golden harness | ⚠️ crypto_codegen_tests.rs:69 — `_nontrivial` | ✅ tests/codegen/test_p256_p384.py:33 (op-count goldens) | ⚠️ nist_ec_emitters.zig:1541 (inline) — "emits ops" only | ⚠️ test_p256_p384.rb:15 — ASM-shape | ✅ codegen/P256P384Test.java:35 (op-count/hex goldens) |
| NIST P-384 | ✅ golden harness (p384-primitives/p384-wallet) | ✅ golden harness | ⚠️ crypto_codegen_tests.rs:119 — `_nontrivial` | ✅ test_p256_p384.py:49 | ⚠️ nist_ec_emitters.zig:1559 — "emits ops" only | ⚠️ test_p256_p384.rb — ASM-shape | ✅ P256P384Test.java:35 |
| SHA-256 full module | ⚠️ sha256-compress.test.ts:57 / sha256-finalize.test.ts:57 — ASM-grep; byte golden via harness | ✅ golden harness (sha256-compress/finalize) | ⚠️ sha256_codegen_tests.rs:39 — counts OP_ADD/OP_NUM2BIN>0 | ✅ tests/codegen/test_sha256.py:25 (exact op-count 21292/63941) | ⚠️ sha256_emitters.zig:570 (inline) — opcode-family + round-constant checks | ⚠️ test_sha256.rb:22 — ASM-shape | ✅ codegen/Sha256Test.java:45 (exact op count + push-value + hex-prefix goldens) |
| BLAKE3 | ✅ __tests__/blake3-output.test.ts:45 — executes in ScriptVM, asserts stack output bytes | ✅ golden harness | ⚠️ crypto_codegen_tests.rs:34 — `_nontrivial`/deterministic | ✅ tests/codegen/test_blake3.py:20 (exact op count 10819/10829) | ⚠️ blake3_emitters.zig:586 (inline) — instruction-count + IV-word checks | ⚠️ test_blake3.rb:11 — ASM-shape | ✅ codegen/Blake3Test.java (op-count goldens) |
| WOTS+ (verifyWOTS) | ✅ __tests__/wots-codegen.test.ts:55 — hex length + sha256 digest of full script | ✅ golden harness (post-quantum-wots) | ✅ conformance_goldens.rs:211 (post-quantum-wots) | ✅ tests/codegen/test_wots_byte_parity.py:94 — hex == conformance golden | ⚠️ pq_emitters.zig:1343 (inline) — "emits a real instruction sequence" | ✅ test/codegen/test_wots.rb:60 — exact op-count | ✅ codegen/WotsTest.java:88 — exact counts |
| SLH-DSA SHA2-128s | ✅ golden harness (post-quantum-slhdsa) | ✅ golden harness | ✅ conformance_goldens.rs:211 | ✅ tests/codegen/test_slh_dsa.py:35 (exact op-count golden) | ⚠️ pq_emitters.zig:1393 (inline) — "emits a real instruction sequence" | ⚠️ test_slh_dsa.rb:14 — ASM-shape | ✅ codegen/SlhDsaTest.java:157 (canonical hex) |
| SLH-DSA SHA2-128f/192s/192f/256s/256f | ❌ no conformance fixture or unit test for non-128s param sets | ❌ no fixture/test for non-128s | ⚠️ crypto_codegen_tests.rs:1548 — param keys `_nontrivial` per set, no byte golden | ✅ tests/codegen/test_slh_dsa.py:24 (exact op-count goldens for all 6; :58 128s≠128f) | ⚠️ pq_emitters.zig:1417 (inline) — "emits sequences for every SHA2 family" (existence only) | ❌ only 128s tested in test_slh_dsa.rb | ✅ codegen/SlhDsaTest.java:51 (op counts all 6 differ); :176/:203 192s/256f canonical hex |
| Rabin sig (verifyRabinSig) | ✅ __tests__/rabin-codegen.test.ts:58 — exact 10-op sequence + golden hex | ✅ codegen/rabin_test.go:22 — byte-frozen 10-op golden | ✅ codegen/rabin.rs:41 (inline) — byte-frozen golden | ✅ tests/codegen/test_rabin.py:34 — byte-frozen 10-op golden | ✅ rabin_emitter.zig:44 (inline) — byte-frozen 10-op golden | ✅ test/codegen/test_rabin.rb:22 — byte-frozen 10-op golden | ✅ codegen/RabinTest.java:37 — exact 10-op sequence |

### 4.10. SDK surfaces

Note: Rust SDK and Zig SDK use inline test blocks (`#[cfg(test)] mod tests`, `test "..." {}`) inside `src/` files — counted as real tests.

| Feature | TS | Go | Rust | Python | Zig | Ruby | Java |
|---|---|---|---|---|---|---|---|
| RunarContract | ✅ contract-lifecycle.test.ts:55 | ✅ runar-go/sdk_test.go:183 | ✅ contract.rs (inline mod tests) | ✅ tests/test_contract_lifecycle.py | ✅ sdk_contract.zig:2707 (inline) | ✅ spec/sdk/contract_spec.rb:142 | ✅ RunarContractTest.java:27 |
| MockProvider | ✅ providers.test.ts:27 | ✅ runar-go/sdk_test.go | ✅ provider.rs:194 (inline) | ✅ tests/test_sdk_* | ✅ sdk_call.zig:364 (inline) | ✅ spec/sdk/provider_spec.rb:7 | ✅ MockProviderTest.java:11 |
| WhatsOnChainProvider | ✅ providers.test.ts | ❌ no Go WOC provider test file | ✅ woc_provider.rs:179 (inline) | ✅ tests/test_woc_provider.py | ✅ sdk_woc_provider.zig:436 (inline) | ✅ spec/sdk/woc_provider_spec.rb:6 | ✅ WhatsOnChainProviderTest.java:33 |
| GorillaPoolProvider | ✅ providers.test.ts | ❌ no Go GorillaPool provider test file | ✅ gorillapool.rs:386 (inline) | ✅ tests/test_gorillapool_provider.py | ✅ sdk_gorillapool.zig:454 (inline) | ✅ spec/sdk/provider_spec.rb | ✅ GorillaPoolProviderTest.java:37 |
| RpcProvider | ✅ providers.test.ts | ✅ rpc_provider_test.go:59 | ✅ rpc_provider.rs:274 (inline) | ✅ tests/test_sdk_rpc_provider.py | ✅ sdk_rpc_provider.zig:294 (inline) | ✅ spec/sdk/rpc_provider_spec.rb:6 | ✅ RPCProviderTest.java:47 |
| WalletProvider / BRC-100 | ✅ wallet-client.spec.ts:48 | ✅ runar-go/sdk_wallet_test.go:82 | ✅ runar-rs/tests/wallet_client_integration.rs | ✅ tests/test_wallet.py | ✅ sdk_wallet_client_integration_test.zig | ✅ spec/runar/sdk/wallet_spec.rb:48 | ✅ WalletProviderTest.java:28 |
| LocalSigner | ✅ local-signer.test.ts:20 | ✅ runar-go/sdk_test.go | ✅ signer.rs:476 (inline) | ✅ tests/test_signer.py + test_local_signer_fallback.py | ✅ sdk_signer.zig:253 (inline) | ⚠️ spec/sdk/local_signer_spec.rb:18 — only asserts the no-bsv-sdk RuntimeError path; no real signing test | ✅ LocalSignerTest.java:31 |
| MockSigner | ✅ mock-signer.spec.ts:11 | ✅ runar-go/sdk_test.go | ✅ signer.rs:476 (inline) | ✅ tests/test_signer.py | ✅ sdk_signer.zig:236 (inline) | ✅ spec/sdk/signer_spec.rb | ✅ MockSignerTest.java:11 |
| ExternalSigner | ✅ external-signer.test.ts:4 | ✅ runar-go/sdk_test.go | ✅ signer.rs:476 (inline) | ✅ tests/test_signer.py | ✅ sdk_signer.zig (inline) | ✅ spec/sdk/signer_spec.rb | ✅ ExternalSignerTest.java:22 |
| buildDeployTransaction | ✅ deployment.test.ts:92 | ✅ sdk_deployment_test.go:883 | ✅ deployment.rs:215 (inline) | ✅ tests/test_sdk_deployment.py | ✅ sdk_deploy.zig:212 (inline) | ✅ spec/sdk/deployment_spec.rb:7 | ✅ TransactionBuilderTest.java:14 |
| buildCallTransaction | ✅ build-call-transaction.test.ts:108 | ✅ runar-go/sdk_test.go | ✅ calling.rs:273 (inline) | ✅ tests/test_sdk_calling.py | ✅ sdk_call.zig:311 (inline) | ✅ spec/sdk/calling_spec.rb:34 | ✅ TransactionBuilderTest.java:47 |
| State serialization | ✅ state.test.ts:17 | ✅ sdk_test.go:500 | ✅ state.rs:623 (inline) | ✅ tests/test_sdk_state.py | ✅ sdk_state.zig:670 (inline) | ✅ spec/sdk/state_spec.rb:7 | ✅ StateSerializerTest.java:15 |
| UTXO selection | ✅ deployment.test.ts | ✅ sdk_deployment_test.go | ✅ deployment.rs:215 (inline) | ✅ tests/test_sdk_deployment.py | ✅ sdk_deploy.zig:226 (inline) | ✅ spec/sdk/deployment_spec.rb | ✅ UtxoSelectorTest.java:15 |
| Fee estimation | ✅ deployment.test.ts | ✅ sdk_deployment_test.go:10 | ✅ deployment.rs/calling.rs (inline) | ✅ tests/test_sdk_deployment.py | ✅ sdk_deploy.zig:212 (inline) | ✅ spec/sdk/deployment_spec.rb | ✅ FeeEstimatorTest.java:9 |
| ScriptVM | ✅ runar-testing/src/__tests__/vm.test.ts:22 + step-vm.test.ts | ✅ runar-go/script_vm_test.go:11 | ⚠️ script_vm.rs:121 (inline) — execute-only; no step coverage | ⚠️ tests/test_script_vm.py:14 — `importorskip("bsv")`; skipped in default CI without the `script-vm` extra | N/A | N/A | N/A |
| ANF interpreter | ✅ anf-interpreter.test.ts:73 | ✅ runar-go/sdk_test.go:2877 | ✅ anf_interpreter.rs:1280 (inline) | ✅ tests/test_anf_interpreter.py:121 | ✅ sdk_anf_interpreter.zig:1771 (inline) | ✅ spec/sdk/anf_interpreter_spec.rb:165 | ✅ AnfInterpreterTest.java:20 |
| CompileCheck | ✅ compile-check.test.ts:48 | ⚠️ exercised via examples/go/*_test.go — no unit test in packages/runar-go | ✅ compile_check tests in crate/examples | ✅ tests/test_compile_check.py | ✅ compile_check.zig:116 (inline) | ❌ no compile_check spec in runar-rb/spec | ✅ CompileCheckTest.java:71 |
| Ordinals BSV-20/21 + envelope | ✅ ordinals-bsv20.test.ts:13 + ordinals-envelope.test.ts:16 | ✅ sdk_ordinals_test.go:13 | ✅ ordinals.rs:479 (inline) | ✅ tests/test_ordinals.py | ✅ sdk_ordinals.zig:494 (inline) | ✅ spec/sdk/ordinals_spec.rb:21 | ✅ Bsv20Test.java:33 + Bsv21Test.java:32 |
| Constructor-slot splicing | ✅ constructor-slots.test.ts:29 | ✅ sdk_test.go:381 | ✅ contract.rs/state.rs (inline) | ✅ tests/test_build_unlocking_script.py | ✅ sdk_contract.zig:2707 (inline) | ✅ spec/sdk/contract_spec.rb | ✅ ContractScriptTest.java:51 |

### 4.11. CLI surfaces

| Feature | TS | Go | Rust | Python | Zig | Ruby | Java |
|---|---|---|---|---|---|---|---|
| basic compile | ✅ runar-cli/src/__tests__/ | ✅ conformance runner | ✅ conformance runner | ✅ conformance runner | ✅ conformance runner | ✅ conformance runner | ✅ conformance runner |
| `--parse-only` | ✅ conformance `--parser-only` matrix (lib-level) | ✅ cli_parse_only_test.go + all-tier matrix | ✅ all-tier parser-only matrix | ✅ all-tier matrix | ✅ main.zig:449 (inline) + matrix | ✅ all-tier matrix | ✅ all-tier matrix |
| `--ir` / `--from-ir` | ✅ conformance dual-mode | ✅ conformance dual-mode | ✅ conformance dual-mode | ✅ conformance dual-mode | ✅ conformance dual-mode | ✅ conformance dual-mode | ✅ conformance dual-mode |
| `--hex` | ✅ conformance hex-parity | ✅ conformance hex-parity | ✅ conformance hex-parity | ✅ conformance hex-parity | ✅ conformance hex-parity | ✅ conformance hex-parity | ✅ conformance hex-parity |
| `--disable-constant-folding` | ✅ CI fold-OFF + fold-ON steps | ✅ CI fold modes | ✅ CI fold modes | ✅ CI fold modes | ✅ main.zig:492 (inline) + CI | ✅ CI fold modes | ✅ CI fold modes |
| debug / ScriptVM step via CLI | ⚠️ ScriptVM step API tested in runar-testing; no dedicated `runar debug` command test | N/A | N/A | N/A | N/A | N/A | N/A |

### 4.12. Decompiler

| Surface | TS | Go | Rust | Python | Zig | Ruby | Java |
|---|---|---|---|---|---|---|---|
| Disassembler / symexec / templates / stateful lift / TS emit / roundtrip / refine / CLI | ✅ packages/decompiler/__tests__/ — roundtrip.test.ts, symexec.test.ts, symexec-extra.test.ts, symexec-multimethod.test.ts, symexec-v04.test.ts, stateful.test.ts, refine.test.ts, fingerprints.test.ts, hand-rolled.test.ts, constructor-placeholders.test.ts (10 test files) | N/A | N/A | N/A | N/A | N/A | N/A |

---

## 5. Gap analysis

Severity rubric: **blocker** = breaks a stated cross-language invariant or ships incorrect bytes to users; **major** = a feature or its verification is missing in a way a contract author would hit; **minor** = test-depth or developer-ergonomics gap with the conformance harness still providing a byte-level backstop.

### 5.1. Feature-matrix gaps (`⚠️` / `❌`)

| # | Feature | Affected language(s) | Severity | Justification (user impact) | Remediation |
|---|---|---|---|---|---|
| G-1 | `asm` intrinsic / `raw_script` ANF node / `UnsafeSmartContract` base class | Go, Rust, Python, Zig, Ruby, Java (`❌`) | major | A `.runar.ts` contract using `asm({...})` compiles only under the TS tier; the other 6 reject or silently mis-compile it (see §6 F-1). Violates the CLAUDE.md "Adding a New ANF Value Kind" policy and frontend-parity invariant #1. Not a *blocker* only because no shipped conformance fixture or example uses it yet, so no current user contract is broken. | Port `raw_script` ANF node + `asm` parse/validate/typecheck/anf/emit + `UnsafeSmartContract` base to all 6 tiers per the CLAUDE.md ANF-node checklist. ~150–250 LOC per tier (parser hook in `01-parse*`/`parser*`, validator gate, ANF node, stack-lower passthrough, emit). Add a `conformance/tests/asm-raw-script` fixture (no allowlist) to lock parity. |
| G-2 | WOTS+ codegen not factored into a dedicated module | Go, Rust, Python (`⚠️`) | minor | Functionally complete and byte-correct (post-quantum-wots golden passes in all 7); only an organizational divergence from the TS/Ruby/Java/Zig layout. No author-visible impact. | Optional: extract `verifyWOTS` lowering from `stack.go:4300` / `stack.rs:3589` / `stack.py:3348` into `codegen/wots.{go,rs,py}`. ~200 LOC each, pure move. Low priority. |
| G-3 | Ruby `LocalSigner` has no pure-Ruby fallback | Ruby (`⚠️`) | major | `runar-rb` cannot do real ECDSA/BIP-143 signing out of the box — instantiating `LocalSigner` raises `RuntimeError` unless the optional `bsv-sdk` gem is present. Python solved the same constraint with a bundled pure-Python ECDSA fallback; Ruby did not. A Ruby user following the SDK docs to deploy a contract hits a hard failure. | Either bundle a pure-Ruby secp256k1+BIP-143 fallback (mirror `runar-py/runar/sdk/_pure_ecdsa.py`, ~400–600 LOC) or make `bsv-sdk` a hard gem dependency in `runar.gemspec` and document it. |
| G-4 | `--parse-only` not exposed as a `runar-cli` flag | TS (`⚠️`) | minor | The TS library honors `parseOnly`, and the conformance `--parser-only` matrix drives TS through the library API, so frontend-parity CI is unaffected. A CLI user cannot invoke parse-only the way the other 6 binaries allow. | Add a `--parse-only` flag to `runar-cli/src/commands/compile.ts` wired to the existing `parseOnly` option. ~15 LOC. |
| G-5 | `--hex` coupled to `--from-ir` | TS (`⚠️`) | minor | `runar-cli` only prints hex when `--from-ir` is also set; the other 6 CLIs treat `--hex` as orthogonal. Surface inconsistency, mildly confusing, not incorrect. | Decouple `--hex` in `compile.ts:145` so it prints `scriptHex` for source input too. ~10 LOC. |
| G-6 | No `debug` / ScriptVM-step CLI subcommand | Go, Rust, Python (`❌`); Zig, Ruby, Java (`N/A`) | minor | Go/Rust/Python ship a ScriptVM *library* but no interactive `debug` command (TS has `runar debug`). Zig/Ruby/Java have no ScriptVM at all (documented policy → `N/A`). Author-facing convenience gap only. | Optional: add a `debug` subcommand to the Go/Rust/Python CLIs wrapping their existing ScriptVM. Medium effort (~150 LOC each); low priority. |
| G-7 | Example contract patterns missing per language | `multisig-2of3` (go, rust, python, ruby, java, move); `bsv20-token`/`bsv21-token` (sol, move); `ordinal-nft` (rust, ruby, sol, move); `fixed-array-nested` (ruby, java) | minor | Developer-facing example coverage is uneven. No conformance impact (conformance fixtures are independent of `examples/`); a developer looking for a reference contract in their language may not find one. | Add the missing `examples/<lang>/<pattern>/` directories with a contract + test each. ~30–80 LOC per cell; ~13 cells. Bulk-portable from the existing TS/Go versions. |

### 5.2. Test-matrix gaps (`⚠️` / `❌`)

| # | Feature / area | Affected language(s) | Severity | Justification (user impact) | Remediation |
|---|---|---|---|---|---|
| T-1 | 7 math builtins (`abs`, `min`, `max`, `within`, `safemod`, `divmod`, `bool`) have **no conformance golden** | TS, Go, Rust, Zig (`⚠️` — no golden, no unit test); Ruby (`❌` — no golden, no unit test, no math test file at all) | major | `conformance/tests/math-demo` exercises only 9 of the 16 math builtins. Cross-tier byte parity for these 7 is **unverified** for Go/Rust/Zig/Ruby; a codegen divergence in one tier would not be caught. Ruby has zero coverage for them. | Extend the `math-demo` fixture (or add a `math-demo-2` fixture) to call all 16 builtins — one fixture change locks all 7 tiers. ~40 LOC in the fixture contract + regenerate goldens. Separately, add `compilers/ruby/test/codegen/test_math_builtins.rb` mirroring the Python file (~250 LOC). |
| T-2 | `checkMultiSig` has **no conformance fixture** and no byte-level test in most tiers | TS, Go, Rust, Python (`⚠️` — weak/no byte assert); Zig, Ruby (`❌` — no test at all) | major | `checkMultiSig` codegen exists in all 7 (§3.9) but gets **zero cross-tier byte coverage**. Only Java has a real unit test. A divergence in the OP_0-dummy / count encoding would ship silently. | Add a `conformance/tests/multisig` fixture (no allowlist) exercising a 2-of-3 — locks all 7. ~30 LOC fixture + goldens. Optionally add Zig/Ruby unit tests. |
| T-3 | SLH-DSA non-128s param sets (128f, 192s, 192f, 256s, 256f) have **no conformance fixture** | TS, Go, Ruby (`❌` — no test); Rust, Zig (`⚠️` — existence-only) | major | Only `SHA2-128s` is exercised by a fixture. The other 5 param sets have codegen in all 7 tiers but byte-level coverage only in Python and Java. A param-set-specific divergence in TS/Go/Ruby would go undetected. | Add 1–2 `conformance/tests/post-quantum-slhdsa-<set>` fixtures (e.g. one `f` set, one 256-bit set). ~30 LOC each + goldens. |
| T-4 | Zig frontend (parsers for non-Zig formats, validate/typecheck/anf/expand-arrays passes) has **no dedicated unit tests** — covered only via the golden harness | Zig (`⚠️`, ~15 cells) | minor | The golden conformance harness *does* exercise every Zig parser and pass and asserts byte parity, so regressions are caught — but a parser/pass bug surfaces as an opaque cross-tier hex mismatch rather than a localized failing test. Test-depth gap, not a correctness gap. | Add `compilers/zig/src/tests/frontend.zig` with dedicated parse/validate/typecheck assertions (the project's other tiers all have these). ~400–600 LOC. |
| T-5 | Ternary expression has **no dedicated lowering/emit test** | Go, Rust, Python, Zig, Ruby (`⚠️`) | minor | Implemented in all 7 (§3.3) and covered indirectly by the golden harness; Java has an explicit test. Localized regression detection is missing in 5 tiers. | Add a ternary lowering assertion to each tier's stack-lower test file. ~15 LOC each. |
| T-6 | Go SDK has **no provider unit test** for WhatsOnChain or GorillaPool | Go (`❌`) | major | `sdk_woc_provider.go` and `sdk_gorillapool.go` ship with zero test coverage — the strings only appear in `sdk_ordinals_test.go`. Every other tier (TS, Rust, Python, Zig, Ruby, Java) has explicit WOC + GorillaPool provider tests with mock transports. A regression in Go's WOC/GorillaPool HTTP parsing ships uncaught. | Add `packages/runar-go/sdk_woc_provider_test.go` and `sdk_gorillapool_test.go` with `httptest.Server` mock-transport tests, mirroring `rpc_provider_test.go`. ~120 LOC each. |
| T-7 | Ruby SDK has **no `CompileCheck` spec** | Ruby (`❌`) | minor | `runar-rb/lib/runar/compile_check.rb` exists but is untested; all other tiers test it. A regression in Ruby's frontend wrapper ships uncaught (though the Ruby *compiler* suite covers the underlying frontend). | Add `packages/runar-rb/spec/sdk/compile_check_spec.rb`. ~40 LOC. |
| T-8 | Python ScriptVM tests are skip-gated behind the optional `bsv-sdk` extra | Python (`⚠️`) | minor | `test_script_vm.py` uses `importorskip("bsv")`; in a default CI without the `runar[script-vm]` extra the ScriptVM tests silently skip — a regression in `script_vm.py` would not be caught by default. | Install the `script-vm` extra in the Python SDK CI job, or add a CI assertion that the extra is present so the skip is visible. ~5 LOC CI change. |
| T-9 | Java has **no in-tree conformance-golden hex test** | Java (`⚠️`, contract-model + several hash/crypto cells) | minor | Java's golden + cross-tier byte parity is enforced *only* via the external `conformance/runner` Java daemon. If that CI step is skipped or broken, Java codegen regressions in non-`MathBuiltinsLower` features (state continuation, ripemd160, hash256, percentOf) would not be caught by `gradle test`. | Add `compilers/java/src/test/java/runar/compiler/ConformanceGoldensTest.java` that reads `conformance/tests/*/expected-script.hex` and asserts byte equality, mirroring the other 6 tiers' in-tree golden tests. ~150 LOC. |
| T-10 | `emit` pass test asserts mostly "valid hex"/length, not exact bytes | TS, Rust (`⚠️`) | minor | TS `06-emit.test.ts` and Rust `emit.rs` inline tests check hex non-emptiness/length and opcode presence rather than exact byte sequences. The golden harness provides the real byte backstop, so this is a localized-test-depth gap. | Strengthen the existing emit tests with exact-byte assertions for a few representative contracts. ~50 LOC each. |
| T-11 | Weak crypto unit tests (compile-only / `_nontrivial` / ASM-substring / structural) | TS (`ec.test.ts` compile-only), Rust (`_nontrivial`), Ruby (ASM-shape), Zig (structural inline) — EC, P256/P384, SHA-256, BLAKE3 cells | minor | These tests catch a crash or gross regression but not byte-level codegen drift; byte correctness rests entirely on the golden harness. Python and Java are the gold standard here (exact op-count + hex goldens). | Optional: upgrade the weak tiers' crypto tests to op-count goldens like Python's. Higher effort, lower priority — the golden harness already locks bytes. |
| T-12 | Go has no frontend test compiling a `Point`-typed *property* | Go (`⚠️`) | minor | Go's EC codegen is well-tested; only the frontend path for a contract with a `Point`-typed property lacks a dedicated test (TS has `ec.test.ts:9`). Golden harness covers it indirectly. | Add a Point-typed-property case to `compilers/go/frontend/typecheck_test.go`. ~20 LOC. |

---

## 6. Correctness findings

One confirmed finding with a run reproduction, plus one minor secondary finding sharing the same root cause. No additional suspected findings — the cross-tier conformance harness (49/49, §7) and all 14 test suites (green, §7) did not surface byte-level divergences in any in-scope feature outside F-1.

### F-1 — `asm` intrinsic / `UnsafeSmartContract` base class implemented only in the TypeScript compiler (divergence from CLAUDE.md ANF-node policy)

- **Defect location:** the `raw_script` ANF node + `asm` intrinsic + `UnsafeSmartContract` base class exist only in TS: `packages/runar-compiler/src/passes/04-anf-lower.ts:1079` (`lowerAsmCall`), `packages/runar-compiler/src/passes/02-validate.ts:399` (gating), `packages/runar-compiler/src/passes/06-emit.ts:461` (emit). No `raw_script`/`RawScript` IR node, `asm`-call dispatch, or `UnsafeSmartContract` parent-class handling exists in `compilers/go/`, `compilers/rust/`, `compilers/python/`, `compilers/zig/`, `compilers/ruby/`, or `compilers/java/` (verified by grep; the `asm` hits in those tiers are all the unrelated `script_asm`/`--asm` disassembly-output field).
- **Reference behavior it diverges from:** `CLAUDE.md` → "Adding a New ANF Value Kind": *"When adding a new ANF IR node (like `add_output`), update ALL of these"* and lists all 7 compilers' ANF node + anf-lower + stack-lower + loader files. The `raw_script` node was added to TS only. Also diverges from frontend-parity invariant #1 ("All seven compilers parse all nine `.runar.{…}` extensions for every fixture").
- **Minimal reproduction** — input file `/tmp/asm-repro/AsmRepro.runar.ts`:
  ```ts
  import { UnsafeSmartContract, asm } from 'runar-lang';
  class Anyone extends UnsafeSmartContract {
    constructor() { super(); }
    public unlock() {
      asm({ body: '51', in_arity: 0, out_arity: 1 });
    }
  }
  ```
  - **Expected output** (per the TS reference and `asm-surface.test.ts`): `scriptHex = "51"` in all 7 tiers.
  - **Actual output** (each compiler run against the *same* `.runar.ts` file — all 7 have a `.runar.ts` parser, so this is a clean frontend-parity probe):
    - **TS** (`compile()` reference): `success: true  scriptHex: 51` ✅
    - **Go** (`go run . --source AsmRepro.runar.ts --hex`): `Compilation error: validation errors: AsmRepro.runar.ts:8:2: public method 'unlock' must end with an assert() call` — the `asm()` statement is silently dropped, leaving `unlock` effectively empty.
    - **Python** (`python3 -m runar_compiler --source AsmRepro.runar.ts --hex`): `Compilation error: parse errors: no class extending SmartContract or StatefulSmartContract found` — `UnsafeSmartContract` is not a recognized base class.
    - **Rust** (`cargo run -- --source AsmRepro.runar.ts --hex`): `Compilation error: Parse errors: No class extending SmartContract or StatefulSmartContract found`.
    - **Zig** (`runar-zig --source AsmRepro.runar.ts --hex`): `parse error: AsmRepro.runar.ts:3:42: unknown parent class: 'UnsafeSmartContract', expected SmartContract or StatefulSmartContract`.
    - **Java** (`java … runar.compiler.Cli --source AsmRepro.runar.ts --hex`): `runar-java: parse error: no class extending SmartContract or StatefulSmartContract found`.
    - **Ruby** (`ruby -Ilib lib/runar_compiler/cli.rb --source AsmRepro.runar.ts`): no output, exit code 0 (see F-2).
- **Severity:** **major.** It is a real violation of two documented invariants and a contract that compiles under one tier fails under the other six. It is not a *blocker* because no shipped conformance fixture or `examples/` contract uses `asm`/`UnsafeSmartContract` yet, so no currently-shipping user contract is broken and CI is (correctly) green — the gap is latent until someone writes an `asm` contract or a fixture is added.

### F-2 — Ruby compiler CLI exits 0 with no output when given a source it cannot compile

- **Defect location:** `compilers/ruby/lib/runar_compiler/cli.rb` — the CLI's error path for a source file that produces no contract. Reproduction (same file as F-1): `ruby -Ilib lib/runar_compiler/cli.rb --source /tmp/asm-repro/AsmRepro.runar.ts` → **no stdout, no stderr, exit code 0**.
- **Reference behavior it diverges from:** every other compiler CLI fails loudly on the same input — Go exits 1 with a validation error, Rust/Zig/Java/Python print a parse error. A compiler CLI that cannot produce an artifact must not report success.
- **Minimal reproduction:** input = the F-1 `.runar.ts` file (a `.runar.ts` Ruby cannot parse because `UnsafeSmartContract` is unknown). Expected: non-zero exit + a diagnostic on stderr. Actual: silent, exit 0.
- **Severity:** **minor.** Shares F-1's root cause (unknown base class) and is only reachable today via inputs the Ruby frontend rejects; but the silent exit-0 is independently a CLI-robustness bug — a build script shelling out to the Ruby compiler would treat a failed compile as success. Fix: in `cli.rb`, when the frontend returns no contract / a parse error, print the diagnostic to stderr and `exit 1`. ~10 LOC.

---

## 7. Test execution evidence

Every in-scope language's compiler and SDK suite plus the TypeScript suite and the cross-tier conformance suite was executed on 2026-05-14. All passed.

| Suite | Command (cwd) | Final summary line |
|---|---|---|
| Go compiler | `cd compilers/go && go test ./...` | `ok` for all 5 packages (`compilers/go`, `…/codegen`, `…/compiler`, `…/frontend`, `…/ir`) |
| Go SDK | `cd packages/runar-go && go test ./...` | `ok` for all 3 packages (`runar-go`, `…/bn254witness`, `…/sp1fri` — last two STARK, excluded from analysis) |
| Rust compiler | `cd compilers/rust && cargo test` | aggregate across 13 test binaries + doctests: `671 passed; 0 failed; 1 ignored` (largest line: `test result: ok. 316 passed; 0 failed`) |
| Rust SDK | `cd packages/runar-rs && cargo test` | aggregate: `379 passed; 0 failed; 5 ignored` (largest line: `test result: ok. 375 passed; 0 failed; 0 ignored`); ignored = 1 env-gated live BRC-100 test + 4 doctests |
| Python compiler | `cd compilers/python && python3 -m pytest` | `971 passed in 217.63s (0:03:37)` |
| Python SDK | `cd packages/runar-py && python3 -m pytest` | `471 passed, 2 skipped, 1 warning in 1.46s` |
| Zig compiler | `cd compilers/zig && zig build test --summary all` | `Build Summary: 3/3 steps succeeded; 568/568 tests passed` |
| Zig SDK | `cd packages/runar-zig && zig build test --summary all` | `172 passed, 0 failed, 2 skipped (174 total)` |
| Ruby compiler | `cd compilers/ruby && rake test` | `All 29 test files passed` — aggregated: `233 runs, 1254 assertions, 0 failures, 0 errors` |
| Ruby SDK | `cd packages/runar-rb && bundle exec rspec` | `861 examples, 0 failures` |
| Java compiler | `cd compilers/java && gradle test --rerun-tasks` | `BUILD SUCCESSFUL` — from `build/test-results/**/*.xml`: `tests=488 failures=0 errors=0 skipped=0` |
| Java SDK | `cd packages/runar-java && gradle test --rerun-tasks` | `BUILD SUCCESSFUL` — from `build/test-results/**/*.xml`: `tests=344 failures=0 errors=0 skipped=1` |
| TypeScript (all packages + format examples) | `npx vitest run` (repo root) | `Test Files 303 passed | 1 skipped (304)` · `Tests 6432 passed | 2 skipped (6434)` |
| Cross-tier conformance | `cd conformance && npm test` (`tsx runner/index.ts`) | `Summary: 49 passed, 0 failed, 0 skipped (49 total)` — every no-allowlist fixture byte-identical across all 7 tiers |

Notes:
- `cargo test` and `zig build test` do not emit a single aggregate summary line; the per-binary `test result:` lines were summed and the largest reproduced above. Full per-binary output was captured during the run.
- The Java `gradle test` task is incremental and reported `UP-TO-DATE` on the first invocation; it was re-run with `--rerun-tasks` to force execution, and the counts were read from the JUnit XML reports under `build/test-results/`.
- No suite failed to build or run. There is therefore no §6 finding arising from a broken suite.

---

## 8. Summary ranking

### 8.1. Feature completeness (most → least complete)

All 7 compilers implement every frontend parser (9/9), every compiler pass, the full type system, all 16 math builtins, all hash builtins, and all 8 crypto-codegen families (checkSig/checkMultiSig, 10 EC builtins, P-256/P-384, SHA-256 module, BLAKE3, WOTS+, all 6 SLH-DSA param sets, Rabin). All 7 SDKs implement every non-ScriptVM surface. The matrix is almost entirely `✅`; ranking is therefore driven by the handful of gaps.

1. **TypeScript** — the only tier with the `asm`/`UnsafeSmartContract` feature (§3.6), the decompiler package, and the `runar debug` CLI. Reference tier; most complete by definition. Sole `⚠️` cells are two CLI ergonomics quirks (G-4, G-5).
2. **Go** — feature-complete on every compiler and SDK row; only `⚠️` is the cosmetic WOTS+-not-a-module (G-2). Reference tier for the matrix per project policy.
3. **Java** — feature-complete on all compiler + SDK rows; WOTS+ is a dedicated module; no feature `⚠️`/`❌` other than the shared `asm` gap and `N/A` ScriptVM (policy).
4. **Zig** — feature-complete; WOTS+ is a dedicated module; only the shared `asm` gap and `N/A` ScriptVM (policy).
5. **Python** — feature-complete on compiler rows; SDK complete; `⚠️` only on WOTS+-not-a-module (G-2). Tied closely with Zig/Java on feature count.
6. **Rust** — feature-complete; `⚠️` on WOTS+-not-a-module (G-2) and ScriptVM execute-only (G-… documented policy constraint, not a true gap).
7. **Ruby** — feature-complete on compiler rows, but the SDK `LocalSigner` is a soft stub with no pure-Ruby fallback (G-3, major) — the only tier whose SDK cannot do real signing out of the box. Ranked last on completeness solely because of G-3.

The spread is narrow: items 2–6 differ only by cosmetic module organization. The single substantive feature divergence is `asm` (TS-only, F-1), which sits *above* the pack rather than dragging anyone below it.

### 8.2. Testing rigor (most → least rigorous)

Counts below are dedicated, assertion-grade tests; all 7 tiers additionally share the 49/49 cross-tier conformance golden harness as a byte-level backstop.

1. **Python** — strongest. Exact op-count + opcode-shape goldens for all 16 math builtins (`test_math_builtins.py`), all hash builtins, all 6 SLH-DSA param sets, EC, SHA-256, BLAKE3, P-256/P-384; the only tier with dedicated tests for the 7 builtins that lack a conformance fixture (T-1, T-3). 971 compiler + 471 SDK tests.
2. **Java** — exact op-count/hex goldens (`MathBuiltinsLowerTest`, `EcTest`, `Sha256Test`, `SlhDsaTest`, `WotsTest`), the only dedicated `checkMultiSig` byte test (`CheckMultiSigTest`, T-2), SLH-DSA non-128s canonical-hex tests. Loses the top spot only for having no in-tree conformance-golden hex test (T-9). 488 compiler + 344 SDK tests.
3. **Go** — exact-byte `emit_test.go`, in-tree `conformance_goldens_test.go`, strong stack/codegen tests; dragged down by zero WOC/GorillaPool SDK provider tests (T-6, major) and the shared math-builtin golden gap (T-1).
4. **TypeScript** — broad (6432 tests) and owns the asm/decompiler/ScriptVM-step test suites, but `06-emit.test.ts` leans on "valid hex"/length asserts (T-10) and `ec.test.ts` is compile-only (T-11); relies more on the golden harness for byte correctness than Python/Java do.
5. **Rust** — 671 compiler + 379 SDK tests, but crypto/codegen tests are largely `_nontrivial` (ops.len()>0) existence checks (T-11) and `stack.rs`/`emit.rs` inline tests assert opcode-presence not exact bytes (T-10); byte correctness rests on the golden harness.
6. **Ruby** — 233 compiler + 861 SDK tests, but **no math-builtin and no hash-builtin codegen test file at all** (T-1 → `❌`), no `checkMultiSig` test (T-2), no `CompileCheck` spec (T-7), and `LocalSigner` spec only tests the failure path (G-3); crypto tests are ASM-substring shape checks (T-11).
7. **Zig** — least rigorous *for dedicated tests*: the entire frontend (parsers for 8 non-Zig formats + validate/typecheck/anf/expand-arrays passes) has no dedicated unit tests and is exercised only through the golden harness (T-4, ~15 `⚠️` cells), crypto helper tests are structural ("emits ops"), and dedicated test LOC is the lowest of any tier (2,696 in test-named files). The 568 passing tests are real, but skew toward codegen-helper internals over end-to-end frontend/pass assertions.

Caveat repeated from §2: Rust and Zig place many tests inline in `src/` files, so their *dedicated-test-file* LOC understates real coverage — the ranking above is based on test *content* (assertion strength, feature coverage) observed in §4, not raw LOC.

---

## Definition-of-done checklist

- [x] §1 Excluded paths — exhaustive, produced before analysis; no STARK/EVM path found mid-audit needed appending.
- [x] §2 Implementation inventory — 7 tiers, paths, build/test commands, frameworks, LOC (post-exclusion).
- [x] §3 Feature matrix — every cell filled with `✅ file:line` / `⚠️ … — reason` / `❌` / `N/A — reason`.
- [x] §4 Test matrix — every cell filled; `N/A` cells match a `❌`/`N/A` in §3 (asm row).
- [x] §5 Gap analysis — every `⚠️`/`❌` covered with affected languages, severity + justification, and sized remediation.
- [x] §6 Correctness findings — 1 confirmed finding (F-1) + 1 minor secondary (F-2), each with a run reproduction; **no suspected-only findings** to list separately.
- [x] §7 Test execution evidence — all 14 suites executed, real summary lines pasted; no suite failed to build/run.
- [x] §8 Summary ranking — feature completeness and testing rigor ranked separately with matrix-count justification.

