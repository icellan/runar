# Test Skip Inventory

This file is the audit of every explicit test-skip in the Rúnar test corpus, classified
by category. It exists so a reviewer can tell at a glance which skips are intentional
preconditions ("Environmental"), which are placeholders for unimplemented work
("Gap"), and which are leftover obsolete guards ("Stale"). The expectation is that
the **Stale** column stays empty: any new stale skip should be removed in the same PR
as the change that made it obsolete, and any new Gap skip must reference the tracker
issue that owns the missing piece.

## How to add a skip

A skip not in this file is a bug. If you must skip a test:

1. Add a row to the inventory below with `file:line`, the skip mechanism, and a
   precise reason. If the precondition is reproducible (regtest node, env var,
   build artifact), say exactly what to flip to make the test execute. The
   `file:line` is machine-checked: a row whose location cannot be parsed is a
   hard failure, because such a row documents nothing and is invisible to the
   orphan/stale reconciliation.
2. Pick a category (Environmental / Gap / Stale) — the set is closed and
   checked. Stale skips should be deleted in the same PR that made them
   obsolete — the only valid `Stale` row is one that's about to be removed. A
   `Gap` row must name the tracker issue (`#<number>`) that owns the missing
   piece, and the `### Gap skips` / `### Stale skips` sections must state a
   count that matches the table. A footer that says "None" while a `Gap` row
   exists is a hard failure: that exact contradiction once let a reader
   conclude there were zero deferred defects while an S0 was open.
3. Never add a silent skip. The Zig integration suite previously contained 162
   `catch |err| { std.log.warn("skipping"); return; }` blocks that the test
   runner reported as PASSED. They were all converted to `try` (real failures
   surface) or to negative-test patterns that return `error.TestUnexpectedResult`
   on unexpected success. CI lints for the surface markers — see
   `.github/workflows/ci.yml` job `lint-no-silent-skips`.

## Anchor accuracy

The `file:line` in each row is the **only sound anchor**. `scripts/audit-test-skips.py`
matches a live skip to its row by exact `file:line` first; only if that fails does it
fall back to pairing leftovers within the same file by whole-token overlap between the
skip snippet and the row's cells.

That fallback is a churn-tolerance heuristic, not a check. It exists so a skip whose
line merely drifted is not reported as an orphan skip and a stale row at the same time.
It cannot tell "the same skip, moved" from "a different skip, added in the same file",
so a row whose line number is stale is a real defect even while the audit is green:
it means the audit is pairing on prose instead of on the anchor. Keep the line numbers
current in the same PR that moves them.

The predicate this fallback uses previously compared tokens as **substrings** of the
row's concatenated prose, which made it near-vacuous — a two-character token such as
`it` matches inside the word "with". It now compares whole tokens of length >= 3, and
`scripts/audit-test-skips.py --self-test` pins both floors: an unrelated snippet must
not pair, and a drifted skip must still pair with its own row.

## Categories

- **Environmental** — the test depends on a precondition that the local machine may
  not satisfy (live regtest node, BRC-100 wallet endpoint, optional toolchain, large
  fixture file regenerated out of band, `-short` flag for >10 s tests, missing
  optional examples directory). The skip is correct; running the test under the
  documented precondition makes it execute.
- **Gap** — functionality is not yet implemented. The skip masks a real gap and
  must reference the tracker issue that owns the missing piece. Open issue first;
  link to it in the inventory row.
- **Stale** — the skip is obsolete; the test should run unconditionally. The audit
  removes these and replaces them with the actual assertion.

## Inventory

| Test | File:line | Category | Rationale |
|---|---|---|---|
| `TestWOTS_ScriptExecution` (+ `_TamperedSig`, `_WrongMessage`) | `conformance/script_execution_test.go:1093,1123,1154` | Environmental | WOTS+ script execution is several seconds per test. Run with `go test -count=1 ./...` (no `-short`) to enable. |
| `TestStatefulWOTSGate_ScriptExecution` (+ `_TamperedSig`) | `conformance/script_execution_test.go:1218,1326` | Environmental | Composes the stateful preimage/continuation covenant with a WOTS+ verify in one script (`examples/ts/stateful-wots-gate/StatefulWOTSGate.runar.ts`); same WOTS+ cost as the plain `TestWOTS_ScriptExecution` rows. Drop `-short` to enable. |
| `TestSLHDSA_ScriptExecution` (+ `_TamperedSig`, `_WrongMessage`) | `conformance/script_execution_test.go:1432,1483,1521` | Environmental | SLH-DSA-SHA2-128s generates a ~248 KB script; running it through the BSV interpreter takes minutes. Drop `-short` to enable. |
| `TestSLHDSA128f_ScriptExecution` (+ `_TamperedSig`, `_WrongMessage`) | `conformance/script_execution_test.go:2249,2263,2281` | Environmental | SLH-DSA-SHA2-128f generates a ~534 KB script. Drop `-short` to enable. Accept test: the compiled script must accept a valid signature (the pre-existing `emitSLHHmsg` multi-block CAT-order codegen bug is now fixed, audit #2). |
| `TestSLHDSA192s_ScriptExecution` (+ `_TamperedSig`, `_WrongMessage`) | `conformance/script_execution_test.go:2313,2327,2345` | Environmental | SLH-DSA-SHA2-192s generates a ~277 KB script. Drop `-short` to enable. Accept test: script must accept a valid signature (the `emitSLHHmsg` + `emitSLHFors` a=14 codegen bugs are now fixed, audit #2). |
| `TestSLHDSA192f_ScriptExecution` (+ `_TamperedSig`, `_WrongMessage`) | `conformance/script_execution_test.go:2363,2377,2395` | Environmental | SLH-DSA-SHA2-192f generates a ~788 KB script; the largest of the six parameter sets. Drop `-short` to enable. Accept test: script must accept a valid signature (the `emitSLHHmsg` codegen bug is now fixed, audit #2). |
| `TestSLHDSA256s_ScriptExecution` (+ `_TamperedSig`, `_WrongMessage`) | `conformance/script_execution_test.go:2413,2427,2445` | Environmental | SLH-DSA-SHA2-256s generates a ~369 KB script. Drop `-short` to enable. Accept test: script must accept a valid signature (the `emitSLHHmsg` + `emitSLHFors` a=14 codegen bugs are now fixed, audit #2). |
| `TestSLHDSA256f_ScriptExecution` (+ `_TamperedSig`, `_WrongMessage`) | `conformance/script_execution_test.go:2463,2477,2495` | Environmental | SLH-DSA-SHA2-256f generates a ~729 KB script; minutes on the go-sdk interpreter. Drop `-short` to enable. Accept test: script must accept a valid signature (the `emitSLHHmsg` codegen bug is now fixed, audit #2). |
| `TestWOTS_ValidSpend` (+ `_TamperedSig`, `_WrongMessage`) | `integration/go/wots_test.go:168,219,268` | Environmental | Same WOTS+ slowness; integration suite already requires `-tags=integration` + regtest, dropping `-short` enables. |
| `TestSLHDSA_*` regtest tests | `integration/go/slhdsa_test.go:173,219,263` | Environmental | Same SLH-DSA cost note as conformance row. |
| `TestGroth16WA_Regtest_Deploy_SP1` (+ `_Spend`, `_Tamper`, `_Tamper2`) | `integration/go/groth16_wa_test.go:418,437,459,506` | Environmental | Witness-assisted Groth16 verifier produces a ~470 KB locking script; full deploy + spend round-trip is multi-second. |
| `TestGroth16WA_SDK_*` | `integration/go/groth16_wa_sdk_test.go:113,178` | Environmental | Same Groth16 WA cost. |
| `TestSchnorr_ValidProof` / `TestSchnorr_TamperedProof` | `integration/go/schnorr_zkp_test.go:289,343` | Environmental | Schnorr verifier exercises full secp256k1 EC scalar-mul on the interpreter; multi-second. |
| `TestCLI_Groth16WA_SP1` | `compilers/go/groth16_wa_cli_test.go:22` | Environmental | Builds the compiler binary and runs an end-to-end CLI invocation against the SP1 v6.0.0 fixture (~10 s). |
| `TestGroth16WA_EndToEnd_SP1Proof_Script` | `packages/runar-go/bn254witness/sp1_script_test.go:207` | Environmental | Script execution of the Groth16-WA verifier against the SP1 fixture is minutes-long on the go-sdk interpreter. |
| `TestVerifyEvmGuest` / `TestSp1FriEvmGuest_*` | `packages/runar-go/sp1fri/verify_test.go:71`, `compilers/go/codegen/sp1_fri_test.go:2114,2118` | Environmental | The `tests/vectors/sp1/fri/evm-guest/proof.postcard` fixture lives outside git LFS — regenerate via `tests/vectors/sp1/fri/evm-guest/regen/` to enable. |
| `TestSp1Fri_FoldRow` arity-skip branches | `compilers/go/codegen/sp1_fri_test.go:1274,1600` | Environmental | Test only handles arity = 2; SP1 fixtures use arity = 2, so the skip is a future-proof guard for higher-arity SP1 builds. |
| `TestSourceCompile_*` (P2PKH / Arithmetic / BooleanLogic / IfElse / BoundedLoop / MultiMethod / Stateful / IRvsSourceMatch / AllConformanceFromSource / TestCompilerParity_AllConformance) | `compilers/go/compiler/compiler_test.go:899,926,947,964,978,992,1006,1051,1117,1186` | Environmental | Defensive guard for `conformance/tests/<dir>/source.json` missing — only fires if the conformance fixtures are not checked out (e.g. compiler is consumed as an extracted module). When the repo is checked out normally, every fixture exists and these tests run. |
| `TestSource_LoadsRunarSource` (multiformat) | `compilers/go/compiler/compiler_multiformat_test.go:47,57,263,374` | Environmental | Same conformance-fixture-missing guard for `.runar.{ts,sol,move,go,rs,py,zig,rb,java}` cross-format tests. The two guards `TestGoContract_CompileConformance` / `TestRubyContract_CompileConformance` used to carry were NOT environmental and are gone: they looked for the pre-migration `<dir>/<dir>.runar.{go,rb}` path, which no fixture has had since the sources moved to `examples/<format>/`, so all 12 subtests skipped on every run. Both now resolve through `source.json` via `conformanceSourcePathExt`, run, and match their goldens. |
| `TestIntegrationCompiler` (per-fixture loader) | `compilers/go/compiler/integration_test.go:48,95` | Environmental | `expected-ir.json` missing — same conformance-fixture-missing guard. Build-tag `//go:build integration`. |
| `TestWalletClient_LiveEndpoint_RoundTrip` | `packages/runar-go/sdk_wallet_client_integration_test.go:130` | Environmental | Set `RUNAR_WALLET_ENDPOINT` to a BRC-100 wallet URL to enable. Optional `RUNAR_WALLET_AUTH`, `RUNAR_WALLET_BASKET`. |
| `BRC-100 WalletClient live endpoint` | `packages/runar-sdk/src/__tests__/wallet-client.spec.ts:47` | Environmental | Same `RUNAR_WALLET_ENDPOINT` precondition as Go. |
| `BRC-100 WalletClient live endpoint round-trip` | `packages/runar-zig/src/sdk_wallet_client_integration_test.zig:96,97` | Environmental | `return error.SkipZigTest` when `RUNAR_WALLET_ENDPOINT` is unset; same precondition as Go. |
| `walletClientLiveRoundTrip` | `packages/runar-java/src/test/java/runar/lang/sdk/WalletClientIntegrationTest.java:44` | Environmental | `@EnabledIfEnvironmentVariable("RUNAR_WALLET_ENDPOINT")` — same precondition as Go. |
| `test_wallet_client_live_round_trip` | `packages/runar-py/tests/test_wallet_client_integration.py:61` | Environmental | Same `RUNAR_WALLET_ENDPOINT` precondition as Go. |
| `wallet_client_live_round_trip` | `packages/runar-rs/tests/wallet_client_integration.rs:46` | Environmental | `#[ignore]` annotation; run with `cargo test -- --ignored` and `RUNAR_WALLET_ENDPOINT` set. Same precondition as Go. |
| `BRC-100 WalletClient live endpoint round-trip` | `integration/ruby/spec/wallet_client_spec.rb:107,142` | Environmental | Two RSpec `skip 'reason'` calls (the `before do` gate at :107 and the auth-required spec body at :142); same `RUNAR_WALLET_ENDPOINT` precondition as Go. |
| `Cross-compiler: TS IR -> Go Script` (+ Rust / Python / Zig / Ruby / Java suites, 11 `describe.skipIf(...)` blocks) | `packages/runar-compiler/src/__tests__/cross-compiler.test.ts:610,687,821,940,994,1038,1088,1133,1176,1217,1259` | Environmental | CI-strict: the `ts-compiler` CI job sets `RUNAR_REQUIRE_ALL_COMPILERS=1` and installs every toolchain the matrix references, so a missing compiler hard-fails the suite via `cross-compiler.test.ts:283-304`. Local devs without a given toolchain see a one-line WARNING and the suite skips. Set `RUNAR_REQUIRE_ALL_COMPILERS=1` locally to upgrade to hard-fail. |
| `assembleMultiContractCall — regtest integration` | `packages/runar-sdk/src/__tests__/multi-contract-call.regtest.test.ts:237` | Environmental | `describe.skipIf(!nodeUp)` — the accept/reject on-chain paths need a live BSV regtest node (probed by `isNodeAvailable()`). Skipped when no node is up; the 11 in-process `Spend`-validated unit tests in `multi-contract-call.test.ts` are the always-on gate. CI's `integration` job runs a regtest node. |
| `BRC-100 WalletClient live endpoint (skipped)` sentinel | `packages/runar-sdk/src/__tests__/wallet-client.spec.ts:76,77` | Environmental | `describe.skipIf(ENDPOINT)` wrapper at :76 plus the inner `it.skip(...)` placeholder at :77 — the pair makes vitest report "discovered-but-skipped" when `RUNAR_WALLET_ENDPOINT` is unset. Mirrors the Ruby spec sibling. |
| `CurlHttpTransport live GET hits httpbin` / `StdHttpTransport live GET hits httpbin` | `packages/runar-zig/src/sdk_http_client.zig:331,341` | Environmental | Set `RUNAR_HTTP_LIVE=1` to exercise the real HTTPS GET path. |
| `e2e FixedArray: TicTacToe v2 ...` / `e2e MultiSig2of3 ...` | `compilers/zig/src/tests/e2e.zig:657,663,765` | Environmental | Skips if the example source can't be opened — only fires when the Zig test binary runs from outside `compilers/zig/` (e.g. an extracted module without `examples/`). |
| Zig `script_integration_test` (compileRunarScriptHex) | `packages/runar-zig/src/script_integration_test.zig:79,145` | Environmental | Skips if the TypeScript compiler dist bundle isn't built — run `pnpm -r build` first to enable. |
| `TestRubyCompilerParity::test_ruby_compiler_parity_all` | `compilers/python/tests/test_source_compile.py:169` | Environmental | Defensive guard for `.runar.rb` source missing — fires only if a conformance fixture's `source.json` doesn't list `.runar.rb`. Today every fixture has Ruby coverage, so the skip never fires. |
| `test_compile_check_accepts_valid_p2pkh` | `packages/runar-py/tests/test_compile_check.py:16` | Environmental | Defensive guard for `examples/python/p2pkh/P2PKH.runar.py` missing — fires only when the package is consumed without the examples tree. |
| `IntegrationBase.ensureNode` (Java) | `integration/java/src/test/java/runar/integration/helpers/IntegrationBase.java:43` | Environmental | `Assumptions.assumeTrue(System.getProperty("runar.integration") == "true")`. Run with `gradle test -Drunar.integration=true` and a regtest node up. |
| `@RequiresIntegration` meta-annotation (Java) | `integration/java/src/test/java/runar/integration/helpers/RequiresIntegration.java:27` | Environmental | `@EnabledIfSystemProperty(named = "runar.integration", matches = "true")` composed annotation applied to `IntegrationBase`. Same precondition as the row above; this is the JUnit-5 declarative gate that complements the imperative `Assumptions.assumeTrue` check inside `@BeforeAll`. |
| `ANF interpreter parity (<sdk> SDK)` (per-SDK suite) | `conformance/anf-interpreter/cross-interpreter.test.ts:259` | Environmental | `describe.skipIf(!isDriverAvailable(cfg))` gates each non-TS SDK driver on its built binary/script. CI strict-mode (`RUNAR_ANF_DRIVERS_STRICT=1` in the `conformance-anf-parity` job) hard-fails on a missing driver. Local devs without all toolchains see a one-line WARNING per missing driver and only the available drivers run. Set `RUNAR_ANF_DRIVERS_STRICT=1` locally to mirror CI. |
| Java integration suite (run-all.sh) | `integration/run-all.sh:129` | Environmental | When Gradle ≥ 8 is not on `PATH`, `pnpm run integration:all` prints `--- Java: SKIPPED ---` and exits green so local devs without Gradle can still run the rest of the suite. `pnpm run test:ci` sets `RUNAR_INTEGRATION_STRICT=1` so the skip path is upgraded to a hard failure in the CI driver. CI also bypasses run-all.sh and invokes `gradle test -Drunar.integration=true` directly. Set `RUNAR_INTEGRATION_STRICT=1` to upgrade the local skip into a hard failure. |
| `test_spend` / `test_tampered_slhdsa_sig` / `test_slhdsa_signed_wrong_message` / `test_spend_multiple_messages` (SPHINCSWallet) | `examples/python/sphincs-wallet/test_sphincs_wallet.py:22` | Environmental | `pytest.mark.skipif(not _HAS_SLHDSA)` — the optional `slh-dsa` PyPI package is not installed. CI's `python-sdk` and `integration` jobs both install `slh-dsa` so these tests run their real-crypto path under the standard invocation. Tests are also marked `@_slow` (~10 s each) for the keygen + sign cost. **Note:** `runar.slhdsa_impl.slh_verify` is now fail-closed (raises `RuntimeError` when `slh-dsa` is missing), so any code that reaches the verify path without the package fails loudly rather than silently mock-true-ing. |
| `test_arbitrary_message_passes_anyone_can_spend` | `examples/python/post-quantum-slhdsa-naive-INSECURE/test_post_quantum_slhdsa_naive_insecure.py:20` | Environmental | Same `pytest.mark.skipif(not _HAS_SLHDSA)` precondition as the SPHINCSWallet rows; pedagogy fixture demonstrating an "anyone-can-spend" flaw under naive SLH-DSA usage. CI installs `slh-dsa` so the test runs its real-crypto path. |
| `TestSLHDSA_SelfConsistency` (-short) | `packages/runar-go/crypto_kat_test.go:313` | Environmental | `t.Skip` under `go test -short` — the SLH-DSA keygen+sign+verify round-trip costs ~seconds. Runs by default (no `-short`); it is the proof that the SLH-DSA ACVP xfail (`TestOfficialKAT_SLHDSA_ACVP`, an always-running enforcing assertion — NOT a skip, so it is intentionally absent from this inventory) is an impl bug, not a harness bug (identical API/format round-trips fine). |
| ANF strict-mode parity (per-SDK suite) | `conformance/anf-interpreter/cross-interpreter-strict.test.ts:263` | Environmental | Same `describe.skipIf(!isDriverAvailable(cfg))` gate as lenient parity. Drivers run in `--mode=strict` against the strict-fixtures inputs; CI strict-mode (`RUNAR_ANF_DRIVERS_STRICT=1` in the `conformance-anf-parity` job) hard-fails on a missing driver. |
| ANF real-crypto parity (per-SDK suite) | `conformance/anf-interpreter/cross-interpreter-real-crypto.test.ts:280` | Environmental | Same `describe.skipIf(!isDriverAvailable(cfg))` gate. Drivers run in `--mode=on-chain` against the real-crypto fixtures; CI strict-mode (`RUNAR_ANF_DRIVERS_STRICT=1` in the `conformance-anf-parity` job) hard-fails on a missing driver. |
| `TestCLI_ParseOnly_ValidSource` / `_InvalidSource` / `_RequiresSourceFlag` | `compilers/go/cli_parse_only_test.go:27,75,112` | Environmental | `if testing.Short()` guard — these tests build the Go compiler binary and invoke it as a subprocess to exercise `--parse-only` (success, failure, missing-flag paths), so they're skipped under `go test -short`. Drop `-short` (default `go test ./...`) to enable. |
| `Tier 2: conformance fixtures` directory-missing guard | `packages/decompiler/__tests__/roundtrip.test.ts:131` | Environmental | `if (!existsSync(FIXTURES_DIR))` guard — `it.skip(...)` fires only when `conformance/sdk-codegen/fixtures/` is absent (e.g. the decompiler is consumed as an extracted module without the conformance tree). When the repo is checked out normally the directory exists and every fixture is exercised. |
| `Tier 1: examples coverage matrix` — pathological-decompile skip set | `packages/decompiler/__tests__/roundtrip.test.ts:115` | Environmental | `it.skip` (via `testFn`) for the 6 SLH-DSA `naive INSECURE` param-set examples (128s/128f/192f/192s/256f/256s) plus `SPHINCSWallet` — **7 entries** in `PATHOLOGICAL_DECOMPILE` — whose compiled scripts drive the symbolic-execution lifter into super-linear runtime (minutes-to-hours each) and would blow past CI's job timeout. The trigger is the unrolled SLH-DSA hash-chain *structure*, not raw size (p384-wallet ~1.95 MB decompiles in <1s). These 7 are excluded from decompiler byte-match coverage; `coverage-baseline.json` must not list them as byte-match targets (regenerate it after changing the skip set). Remove from `PATHOLOGICAL_DECOMPILE` if the lifter's blowup is fixed. |
| `analyzerMatchesGolden` (Java analyzer ↔ golden) | `packages/runar-java/src/test/java/runar/lang/analyzer/FixtureConformanceTest.java:62` | Environmental | `@EnabledIf("repoLayoutAvailable")` — the parameterized analyzer-vs-golden conformance test is disabled when the surrounding repo layout (`conformance/tests/`, `conformance/analyzer/` goldens) isn't resolvable, e.g. when the Java package is consumed as an extracted artifact. Runs in a normal checkout / CI. The generic JUnit `@EnabledIf` form is now part of the audit's `SKIP_PATTERNS`, so this site is discovered like every other and its `file:line` is machine-checked rather than tracked by hand. |
| `TestCLI_Debug_TrivialScript` / `_RequiresInput` / `_FailingScript` / `_Artifact` | `compilers/go/cli_debug_test.go:21,56,77,110` | Environmental | `if testing.Short()` guard — each `debug`-subcommand smoke test builds the Go compiler binary and invokes it as a subprocess, so they're skipped under `go test -short`. Drop `-short` (default `go test ./...`) to enable. |
| `PostQuantumSLHDSANaiveInsecure (Move)` | `examples/move/post-quantum-slhdsa-naive-INSECURE/PostQuantumSLHDSANaiveInsecure.test.ts:16` | Environmental | `describe.skipIf(!runSlowTests)` — runs full SLH-DSA-SHA2-128s verification inside the off-chain interpreter (~100 s per file). `runSlowTests = IS_CI \|\| RUN_SLOW_TESTS === '1'`, so it runs automatically in CI; locally set `RUN_SLOW_TESTS=1` to enable. |
| `SPHINCSWallet (Move)` | `examples/move/sphincs-wallet/SPHINCSWallet.test.ts:41` | Environmental | `describe.skipIf(!runSlowTests)` — same slow SLH-DSA cost. `runSlowTests = IS_CI \|\| RUN_SLOW_TESTS === '1'`; runs in CI, locally set `RUN_SLOW_TESTS=1`. |
| `PostQuantumSLHDSANaiveInsecure (Solidity)` | `examples/sol/post-quantum-slhdsa-naive-INSECURE/PostQuantumSLHDSANaiveInsecure.test.ts:16` | Environmental | `describe.skipIf(!runSlowTests)` — same slow SLH-DSA cost. `runSlowTests = IS_CI \|\| RUN_SLOW_TESTS === '1'`; runs in CI, locally set `RUN_SLOW_TESTS=1`. |
| `SPHINCSWallet (Solidity, Hybrid ECDSA + SLH-DSA-SHA2-128s)` | `examples/sol/sphincs-wallet/SPHINCSWallet.test.ts:41` | Environmental | `describe.skipIf(!runSlowTests)` — same slow SLH-DSA cost. `runSlowTests = IS_CI \|\| RUN_SLOW_TESTS === '1'`; runs in CI, locally set `RUN_SLOW_TESTS=1`. |
| `PostQuantumSLHDSANaiveInsecure` | `examples/ts/post-quantum-slhdsa-naive-INSECURE/PostQuantumSLHDSANaiveInsecure.test.ts:19` | Environmental | `describe.skipIf(!runSlowTests)` — same slow SLH-DSA cost. `runSlowTests = IS_CI \|\| RUN_SLOW_TESTS === '1'`; runs in CI, locally set `RUN_SLOW_TESTS=1`. |
| `SPHINCSWallet (Hybrid ECDSA + SLH-DSA-SHA2-128s)` | `examples/ts/sphincs-wallet/SPHINCSWallet.test.ts:40` | Environmental | `describe.skipIf(!runSlowTests)` — same slow SLH-DSA cost. `runSlowTests = IS_CI \|\| RUN_SLOW_TESTS === '1'`; runs in CI, locally set `RUN_SLOW_TESTS=1`. |
| `SLH-DSA-SHA2-128s dual-oracle` | `packages/runar-testing/src/__tests__/post-quantum-slh-dual-oracle.test.ts:36` | Environmental | `describe.skipIf(!runSlowTests)` — cross-checks the SLH-DSA reference impl against the script oracle, genuinely expensive. `runSlowTests = IS_CI \|\| RUN_SLOW_TESTS === '1'` (see `packages/runar-testing/src/test-env.ts`); runs in CI, locally set `RUN_SLOW_TESTS=1`. |
| `SLH-DSA-SHA2-128s NIST ACVP vector (on-chain)` — the two `compiled script …` cases | `packages/runar-testing/src/__tests__/post-quantum-slh-acvp-onchain.test.ts:93,106` | Environmental | `it.skipIf(!runSlowTests)` — compiling and executing the ~184 KB SLH-DSA-128s script on `@bsv/sdk`'s `Spend` takes tens of seconds per case. `runSlowTests = IS_CI \|\| RUN_SLOW_TESTS === '1'` (see `packages/runar-testing/src/test-env.ts`), so both run in CI; locally set `RUN_SLOW_TESTS=1`. The two **interpreter** cases in the same file are NOT skipped and always replay the NIST ACVP vector (tgId 31 / tcId 422) against the reference impl, so #137 conformance is gated unconditionally even in a default local run. |
| `SLH-DSA reference implementation` | `packages/runar-testing/src/crypto/__tests__/slh-dsa.test.ts:9` | Environmental | `describe.skipIf(!runSlowTests)` — exercises the SLH-DSA reference keygen/sign/verify (slow). `runSlowTests = IS_CI \|\| RUN_SLOW_TESTS === '1'` (see `packages/runar-testing/src/test-env.ts`); runs in CI, locally set `RUN_SLOW_TESTS=1`. |
| `Runar.compile_check accepts a path to a valid .runar.rb contract` | `packages/runar-rb/spec/sdk/compile_check_spec.rb:22` | Environmental | RSpec `skip "...not found"` guard — fires only when `examples/ruby/p2pkh/P2PKH.runar.rb` is absent (e.g. the gem is consumed without the examples tree). When the repo is checked out normally the fixture exists and the spec runs the real frontend. |
| `TestEmitVerifyRabinSig_RejectsMalleatedSignature/FlipHighBitOfSig` | `compilers/go/codegen/rabin_adversarial_test.go:381` | Environmental | `t.Skip` defensive guard for `sig.BitLen() - 2 < 1` — only fires if the generated Rabin signature is pathologically tiny (< 3 bits), in which case there is no high bit to flip. Real Rabin signatures under the test key are hundreds of bits, so the skip never fires in practice; the other three mutation subtests still run unconditionally. |
| `test_fixture_byte_identical` (Python analyzer conformance) | `packages/runar-py/tests/analyzer/test_conformance.py:42,44` | Environmental | `pytest.skip` guards for a missing `conformance/tests/<fixture>/expected-script.hex` or `conformance/analyzer/<fixture>/expected-analyzer-report.json` — same conformance-fixture-missing pattern as the Go compiler guards. When the repo is checked out normally every fixture exists and all parameterized cases run. |
| `produces byte-identical JSON for <fixture>` (Ruby analyzer conformance) | `packages/runar-rb/spec/analyzer/conformance_spec.rb:25,26` | Environmental | RSpec `skip` guards for the same missing `expected-script.hex` / `expected-analyzer-report.json` preconditions as the Python analyzer row above. When the repo is checked out normally every fixture exists and all specs run. |
| `SLH-DSA adversarial bound-violation tests (all 6 parameter sets)` | `packages/runar-testing/src/__tests__/post-quantum-bounds.test.ts:193` | Environmental | `describe.skipIf(!runSlowTests)` — full SLH-DSA keygen + sign across all 6 FIPS 205 parameter sets is genuinely slow. `runSlowTests = IS_CI \|\| RUN_SLOW_TESTS === '1'` (see `packages/runar-testing/src/test-env.ts`); runs in CI, locally set `RUN_SLOW_TESTS=1`. |
| `Issue #100 — terminal var-len state read gets _codePart` | `packages/runar-rb/spec/sdk/issue100_spec.rb:59` | Environmental | RSpec `skip 'Ruby compiler CLI unavailable'` guard — fires only when `compilers/ruby/bin/runar-compiler-ruby` is absent (e.g. the gem is consumed without the monorepo compiler tree). When the repo is checked out normally the CLI exists and the spec compiles `StateRead` and asserts the codePart-prefixed unlock. |
| `Issue #106 — EMPTY_SIG marker for OR-CHECKSIG branched auth` | `packages/runar-rb/spec/sdk/issue106_empty_sig_spec.rb:120,131,144` | Environmental | RSpec `skip 'Ruby compiler CLI unavailable'` guards — fire only when `compilers/ruby/bin/runar-compiler-ruby` is absent (e.g. the gem is consumed without the monorepo compiler tree). When the repo is checked out normally the CLI exists and the specs compile the OR-CHECKSIG contract and assert `EMPTY_SIG` encodes as an empty (OP_0) push that satisfies NULLFAIL in the failing branch. |
| `Issue #123 — per-method SIGHASH mode threaded through preimage/signing` | `packages/runar-rb/spec/sdk/issue123_sighash_spec.rb:124` | Environmental | RSpec `skip 'Ruby compiler CLI unavailable'` guard — fires only when `compilers/ruby/bin/runar-compiler-ruby` is absent (e.g. the gem is consumed without the monorepo compiler tree). When the repo is checked out normally the CLI exists and the spec compiles the SINGLE\|FORKID (0x43) contract and asserts the SDK builds the matching preimage. |
| `needs_script_vm` marker (MockProvider script-execution layer) | `packages/runar-py/tests/test_mock_broadcast_validation.py:49` | Environmental | `MockProvider`'s SCRIPT-EXECUTION validation layer needs the optional `bsv-sdk`. Install with `pip install bsv-sdk` (or `pip install 'runar[dev]'`) to enable. CI never skips it silently: the provider raises `BroadcastValidationUnavailable` when `$CI` is set, so the script layer cannot vanish unnoticed. The structural / non-vacuity / value-conservation layers are still exercised by the unmarked tests in the same module. Same precedent as `packages/runar-py/tests/test_script_vm.py`. |
| `SP1 FRI on-chain negative tests — PoC contract absent` | `compilers/go/compiler/sp1_fri_negative_test.go:76` | Environmental | `t.Skipf` fires only when `integration/go/contracts/Sp1FriVerifierPoc.runar.go` is missing from the checkout (e.g. a consumer vendoring `compilers/go` alone). When the contract IS present — which it is in this repo and in CI — the test compiles it and runs the corruption fixtures through the go-sdk interpreter, so the skip does not hide the on-chain soundness finding it exists to pin. That finding (the deployable verifier accepts forged Merkle openings; see `docs/sp1-fri-verifier.md`) is asserted, not skipped, and is additionally surfaced as a compile-time warning by `compilers/go/frontend/sp1_fri_soundness_warning.go`. |
| `TestCodePartHijack_VarLenState_SplitPointCollision` / `TestCodePartHijack_SplitPointCollision` | `conformance/codepart_authenticity_test.go:713,811` | Environmental | `t.Skip` fires only if the compiled fixture happens to carry NO interior `0x6a` byte, in which case there is no offset to forge a split-point collision at and the test has nothing to assert. Both fixtures do carry such bytes today (message-board: 512, 724; stateful-counter: 506, 597, 1185, 1280), so both tests execute and drive a full BIP-143 spend at every collision offset. The skip exists so a future codegen change that removes the collisions reports "nothing to forge" instead of silently passing a vacuous loop. |
| `TestCLI_SP1FriIRGuard` (+ `_Compile`) | `compilers/go/cli_sp1_fri_ir_guard_test.go:45,132` | Environmental | `if testing.Short()` guard — each builds the Go compiler binary and invokes it as a subprocess. Drop `-short` (default `go test ./...`) to enable. Same pattern as the `cli_debug_test.go` row above. |
| `TestMainDoS` reference-source case | `examples/end2end-example/webapp/main_dos_test.go:159` | Environmental | `t.Skipf` fires only when the reference TypeScript source for the webapp contract cannot be read (e.g. the Go module is consumed without the surrounding examples tree). In a normal checkout the source resolves and the case runs. |
| `ec-mulgen-linear: TS/Go hex parity` | `packages/runar-compiler/src/__tests__/ec-mulgen-linear-parity.test.ts:96` | Environmental | `describe.skipIf(!hasGo)` — the cross-tier parity block shells out to the Go compiler. Install a Go toolchain (CI always has one) to enable. |
| `TestCLI_PrintsValidatorWarnings` / `_WarningDoesNotChangeExitCodeOrBytes` / `_ParseOnlyPrintsValidatorWarnings` | `compilers/go/cli_warnings_test.go:89,125,154` | Environmental | `if testing.Short()` guard — each builds the Go compiler binary and runs it as a subprocess to assert validator warnings reach stderr without changing the exit code or the emitted bytes. Drop `-short` (default `go test ./...`) to enable. Same pattern as the `cli_debug_test.go` / `cli_parse_only_test.go` rows above. |
| `TestR161_TheIssue99ReferenceSurvives` | `compilers/go/codegen/r161_branch_balance_guard_test.go:76` | Environmental | `t.Skip` fires only when the guard string `to balance a NON-EMPTY else arm` is absent from `compilers/go/codegen/stack.go` — in which case `TestR161_PaddingItselfIsGuarded`, directly above, has already failed on that same string, and this test has no window to search for the `#99` citation in. The guard is present today, so the skip does not fire and the citation is asserted. |
| `test_go_compiles_our_anf_to_the_same_script` (Python N-094) | `compilers/python/tests/test_n094_sighash_ir_wire_format.py:213` | Environmental | `pytest.skip` when `compilers/go/runar-go` is not built — this case feeds Python's `--emit-ir` output to the Go CLI and compares the script both tiers emit. Build with `cd compilers/go && go build -o runar-go .` to enable. The Python-side wire-format assertions in the same module run unconditionally. |
| `test_no_method_is_defined_twice_in_the_same_body` | `compilers/ruby/test/codegen/test_n078_single_method_definition.rb:36` | Environmental | Minitest `skip` when `RubyVM::AbstractSyntaxTree` is unavailable — it is a CRuby-only API, so the duplicate-`def` sweep over `compilers/ruby/lib/**` cannot run on JRuby / TruffleRuby. CRuby (what CI and `RunarCompiler::MINIMUM_RUBY_VERSION` require) always has it, so the sweep runs. |
| `test_go_compiles_our_anf_to_the_same_script` (Ruby N-094) | `compilers/ruby/test/test_n094_sighash_ir_wire_format.rb:199` | Environmental | Same missing-`compilers/go/runar-go` precondition as the Python N-094 row above; same build command enables it. |
| N-086 cross-tier: a non-default `@sighash` on a FixedArray contract | `compilers/zig/src/tests/n086_cross_tier_sighash_fixed_array.zig:372` | Environmental | `return error.SkipZigTest`, and it fires on exactly one condition: `peers_found == 0`. A tier counts as a peer when its probe path exists and, for the interpreted tiers, its interpreter answers `--version` (`unavailableReason`). Go, Rust and Java need a built artifact; Python and Ruby need only an interpreter, because their probes (`runar_compiler/__main__.py`, `bin/runar-compiler-ruby`) are checked-in sources. So the skip path is the clean local checkout with no tier built — not CI, where the runner image supplies python3 and ruby and the comparison runs. Only the cross-tier agreement claim is dropped when it does fire; the zig-tier sighash-byte assertions earlier in the test always run, and the diagnostic names every unreachable tier with the exact command that would build it. A peer that IS reachable and then disagrees, refuses, or prints no hex fails hard — availability is never an excuse. `RUNAR_CROSS_TIER_MIN=<n>` (default 0) converts the skip into a failure; the count excludes Zig itself, so a job building all six peers sets 6 (verified: with 5 peers built, `RUNAR_CROSS_TIER_MIN=5` passes and `=7` fails with "demands 7 peer tier(s), only 5 available"). **The caveat worth stating:** a job that sets no floor compares against whatever peers its runner image happens to provide, so the comparison can narrow — losing exactly the compiled tiers most likely to diverge — while the job stays green. |
| `R-095` / `R-010` codepart-pin per-tier cases | `conformance/codepart-pin/codepart-pin-parity.test.ts:217,368` | Environmental | `const run = tier.cmd === null ? it.skip : it` — a tier's case is skipped when its compiler binary is not built. Not silent: `codepart-pin-parity.test.ts:203-209` runs unconditionally and asserts at least two tiers are available locally, and under `CI=true` asserts that NO tier is missing, so CI hard-fails instead of skipping. |
| `PostQuantumSLHDSANaiveInsecure{128f,192f,192s,256f,256s} (real signatures)` | `examples/ts/post-quantum-slhdsa-naive-INSECURE-128f/PostQuantumSLHDSANaiveInsecure128f.test.ts:55`, `examples/ts/post-quantum-slhdsa-naive-INSECURE-192f/PostQuantumSLHDSANaiveInsecure192f.test.ts:55`, `examples/ts/post-quantum-slhdsa-naive-INSECURE-192s/PostQuantumSLHDSANaiveInsecure192s.test.ts:55`, `examples/ts/post-quantum-slhdsa-naive-INSECURE-256f/PostQuantumSLHDSANaiveInsecure256f.test.ts:55`, `examples/ts/post-quantum-slhdsa-naive-INSECURE-256s/PostQuantumSLHDSANaiveInsecure256s.test.ts:55` | Environmental | `describe.skipIf(!runSlowTests)` — the real-signature blocks run SLH-DSA keygen + sign for their parameter set and then verify off-chain, which is minutes per file. `runSlowTests = IS_CI \|\| RUN_SLOW_TESTS === '1'` (see `packages/runar-testing/src/test-env.ts`), so all five run in CI; locally set `RUN_SLOW_TESTS=1`. The source-shape cases in each file (the contract calls its own parameter set and no other) run unconditionally. |
| `ec-add-negate-cancel{,-reversed}: cross-tier parity via --ir` (per-tier suite) | `packages/runar-compiler/src/__tests__/r034-ec-negate-cancel-parity.test.ts:324` | Environmental | `describe.skipIf(tier.binary === null)` — the per-tier `--ir` hex-parity block is skipped when that tier's compiler binary is not built. Build the tier (`compilers/<tier>/`) to enable. The TS-side lowering and reachability assertions in the same file run unconditionally. |
| `TestMockAgreesWithEmitter` slow rows | `packages/runar-go/mock_script_agreement_test.go:565` | Environmental | `t.Skip` on `c.slow && testing.Short()` — the rows of the mock-vs-emitter differential sweep whose scripts take seconds on the go-sdk interpreter. Drop `-short` (default `go test ./...`) to enable. The case table is asserted non-empty first, so the sweep cannot pass vacuously. |
| `R-166: no tier ships an empty source map` (per-tier cases) | `tests/r166-source-map-not-empty.test.ts:130` | Environmental | `const maybe = available.includes(tier) ? it : it.skip` — a tier's cases are skipped when its compiler binary is not built. The suite asserts `available.length >= 2` unconditionally, so a one-tier run fails rather than quietly proving nothing. |
| `R-212: SOURCE_DATE_EPOCH is honoured by every tier that stamps a time` (per-tier cases) | `tests/r212-source-date-epoch-parity.test.ts:212` | Environmental | `const run = tier.cmd === null ? it.skip : it` — same not-built precondition. `TIERS` is the built subset and the suite asserts `TIERS.length >= 2` unconditionally, so a one-tier run fails. |
| `R-277: the webapp contract copy still means what the reference means` (compile cases) | `tests/r277-webapp-contract-copy-in-sync.test.ts:81` | Environmental | `const maybe = javaAvailable ? it : it.skip` — the compile-and-compare case shells out to the Java tier, so it is skipped when no Java compiler jar is found. Build with `cd compilers/java && ./gradlew jar` to enable. The both-files-present and not-a-symlink cases run unconditionally, so the copy cannot silently disappear. |
| `R-289: a malformed synthetic-array run is refused` (per-tier cases + the Java case) | `tests/r289-partial-synthetic-array-run.test.ts:176,246` | Environmental | `it.skip` for a tier whose compiler binary is not built (`:176`) and for the Java-specific case when no Java jar is found (`:246`). The suite asserts `available.length >= 2` unconditionally, so a one-tier run fails rather than proving nothing. Build the missing tier (`compilers/<tier>/`; Java via `./gradlew jar`) to enable. |
| `artifact ABI params agree across tiers` (per-tier cases) | `tests/abi-cross-tier-parity.test.ts:130` | Environmental | `it.skip` for a tier whose compiler binary is not built. The suite asserts `available.length >= 2` unconditionally, so a one-tier run fails rather than proving nothing, and every tier — skipped or not — is graded against the checked-in seven-tier ANF golden rather than against its peers, so a run with tiers missing still cannot pass by agreement. Build the missing tier (`compilers/<tier>/`; Java via `./gradlew jar`) to enable. |

### Stale skips

None — the audit found no stale skips. Every skip in the corpus either guards an
environmental precondition or marks a known gap.

### Gap skips

None — the audit found no gap skips. The Java tier has explicit allowlists in
conformance fixtures (`source.json` with `"compilers"` field) for crypto codegen
modules that are intentionally Go-only (BabyBear, KoalaBear, Poseidon2, BN254,
FiatShamirKb, Merkle, FRI / SP1 FRI), which is **not** a skip — those are
opt-outs at the conformance-runner level, not test-level skips. See
`conformance/README.md` for the per-fixture allowlist.

### Pre-existing breakages found during the audit (now fixed)

- **SLH-DSA codegen miscompile, 5 of 6 FIPS 205 SHA2 parameter sets (audit #2)** —
  `conformance/script_execution_test.go` `TestSLHDSA128f_ScriptExecution`,
  `TestSLHDSA192s_ScriptExecution`, `TestSLHDSA192f_ScriptExecution`,
  `TestSLHDSA256s_ScriptExecution`, `TestSLHDSA256f_ScriptExecution`. Adding
  real script-execution coverage for the five SLH-DSA parameter sets that
  previously had only self-produced byte goldens (128s was already executed)
  surfaced that the compiled script REJECTED a genuinely valid signature for
  all five — funds-lockable, and green because nothing ever executed it.
  Root-caused to TWO independent bugs in the SLH-DSA verify emitter, byte-ported
  into all 7 tiers (non-allowlisted fixtures ⇒ cross-tier hex parity guaranteed
  all shared the defect):
  1. `emitSLHHmsg`'s final MGF1 block was appended in reversed order
     (`block || resultAcc` via a spurious `swap`) whenever the digest needs
     more than one 32-byte SHA-256 block (`digestLen > 32`) — every set except
     128s (digestLen=30). Fixed to `resultAcc || block` (bare `OP_CAT`).
  2. `emitSLHFors`'s FORS-index bit-window capped `take` at 2 bytes; the correct
     bound is `ceil((bitOffset + a) / 8)`, which needs 3 bytes for `a=14`
     (192s/256s) at `bitOffset ∈ {4,6}`. `a ≤ 8` sets and 128s's lucky `a=12`
     alignment never needed a 3rd byte. Fixed to the ceil form.
  **Now FIXED** across all 7 tiers (TS reference + byte-identical Go/Rust/Python/
  Ruby/Zig/Java ports); the five affected `expected-script.hex` goldens were
  regenerated fold-OFF and re-verified byte-identical across all tiers, and the
  five accept tests now assert the script ACCEPTS a valid signature (verified on
  the go-sdk interpreter). Scope: this fixed INTERNAL consistency (runar signer
  ↔ on-chain verifier). #137 has since fixed EXTERNAL conformance too, for the
  128-bit sets: the native verifier and the emitted script both accept the NIST
  ACVP `SLH-DSA-SHA2-128s` vector (tgId 31 / tcId 422). True FIPS-205
  conformance for 192/256 additionally needs SHA-512 (FIPS 205 §11.2.2/11.2.3),
  which Bitcoin Script cannot express (no `OP_SHA512`), so those four parameter
  sets remain SHA-256-only and self-consistent rather than standard-conformant.

- `examples/sol/go-dsl-bytestring-literal/GoDslBytestringLiteral.runar.sol` —
  Sol parser rejected the capitalised `Int` type alias used in the cross-format
  Go-DSL fixture. Added `Int` / `Uint` to the type-name table in
  `packages/runar-compiler/src/passes/01-parse-sol.ts`.
- `examples/ruby/conditional-data-output/ConditionalDataOutput.runar.rb` — Ruby
  parser didn't recognise the `Bool` type alias. Added `Bool` to the type-name
  table in `packages/runar-compiler/src/passes/01-parse-ruby.ts`.
- `examples/ruby/if-without-else-multi-temp/StackTrackerReproV10min.runar.rb` —
  Ruby parser tracked declared locals globally per method, so a fresh
  `name = expr` inside a sibling `if` branch was emitted as an
  `assignment` against an out-of-scope local, triggering a spurious
  "Undefined variable" typecheck error. Fixed by snapshotting / restoring
  `declaredLocals` around each `if` / `elsif` / `else` / `unless` / `for`
  body so per-branch lexical scoping matches the typechecker's model.
- `packages/runar-sdk/src/__tests__/anf-interpreter-strict.spec.ts` — the
  pre-existing TDD spec imported `executeStrict` and `AssertionFailureError`
  from `anf-interpreter`, neither of which existed. Implemented the strict
  mode in `packages/runar-sdk/src/anf-interpreter.ts` so the spec now
  passes: `executeStrict()` mirrors `computeNewStateAndDataOutputs()` but
  throws `AssertionFailureError(methodName, bindingName)` on the first
  falsy `assert` predicate (handles both the dedicated `assert` ANF node
  and the `call(assert, ...)` lowering path). Crypto built-ins still
  mock-return `true`.
- `compilers/rust/tests/multiformat_tests.rs` and
  `compilers/rust/tests/parser_format_tests.rs` — every conformance-fixture
  driven test had a `eprintln!("SKIP: ...") + return` guard. In
  `multiformat_tests.rs` the `read_conformance_format` helper looked for
  `<test>/<test>.runar.<ext>` (which never existed — sources live in
  `examples/...` and are referenced via `source.json`), so every
  format-dispatch test, structure-check test, and cross-format consistency
  loop silently skipped — `cargo test` reported green without running any
  parser assertion. Replaced the helper with the same `source.json` resolver
  that `parser_format_tests.rs` uses (now `panic!`-ing on a missing fixture
  rather than returning `None`) and removed every `Some(s) => s, None => return`
  guard. The `parser_format_tests.rs` resolver was already correct, but its
  "parser produced no contract" fallbacks were also silent returns: those
  branches were dead (every parser produces a contract for the conformance
  fixture today), so they were converted to `panic!` so a future regression
  fails loudly. Net effect: 28 Rust parser tests now actually exercise their
  assertions; the suite still reports the same passing count, but is no
  longer a false-positive.
- `integration/zig/src/*_test.zig` — 162 `catch |err| { std.log.warn("...skipping..."); return; }`
  blocks plus 4 `else { std.log.warn("unexpectedly succeeded"); }` patterns
  across 28 files. The Zig test runner reports a function that catches an
  error and bare-returns as PASSED, so the suite was reporting pass without
  running its assertions. Converted every `compileContract` catch to `try`
  (the contracts compile fine — the catch was leftover scaffolding from an
  earlier compiler-completeness gap), every contract.call positive-test
  silent skip to `try` (real failures now surface as test errors), and every
  silent-pass-on-unexpected-success to `return error.TestUnexpectedResult`.
  CI gains a `lint-no-silent-skips` job that fails on reintroduction of any
  of these surface markers. See `.github/workflows/ci.yml`.

## How to verify locally

```bash
# Slow crypto tests (drop `-short` to opt in):
cd compilers/go && go test ./... -count=1
cd integration/go && go test -tags=integration ./... -count=1

# BRC-100 wallet round-trip across all 7 SDKs:
RUNAR_WALLET_ENDPOINT=https://your-brc100-wallet/ pnpm test
RUNAR_WALLET_ENDPOINT=... cd packages/runar-go && go test ./...
RUNAR_WALLET_ENDPOINT=... cd packages/runar-py && python3 -m pytest
RUNAR_WALLET_ENDPOINT=... cd packages/runar-rs && cargo test
RUNAR_WALLET_ENDPOINT=... cd packages/runar-zig && zig build test
RUNAR_WALLET_ENDPOINT=... cd packages/runar-rb && bundle exec rspec
RUNAR_WALLET_ENDPOINT=... cd packages/runar-java && gradle test

# Cross-compiler vitest suites (require all toolchains; skip-with-warning locally,
# hard-fail in CI):
CI=true npx vitest run
```
