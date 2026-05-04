# Test Skip Inventory

This file is the audit of every explicit test-skip in the Rúnar test corpus, classified
by category. It exists so a reviewer can tell at a glance which skips are intentional
preconditions ("Environmental"), which are placeholders for unimplemented work
("Gap"), and which are leftover obsolete guards ("Stale"). The expectation is that
the **Stale** column stays empty: any new stale skip should be removed in the same PR
as the change that made it obsolete, and any new Gap skip should carry a `TODO(...)`
comment naming the missing piece.

## Categories

- **Environmental** — the test depends on a precondition that the local machine may
  not satisfy (live regtest node, BRC-100 wallet endpoint, optional toolchain, large
  fixture file regenerated out of band, `-short` flag for >10 s tests, missing
  optional examples directory). The skip is correct; running the test under the
  documented precondition makes it execute.
- **Gap** — functionality is not yet implemented. The skip masks a real gap and
  carries a `TODO(...)` so it shows up in code-search.
- **Stale** — the skip is obsolete; the test should run unconditionally. The audit
  removes these and replaces them with the actual assertion.

## Inventory

| Test | File:line | Category | Rationale |
|---|---|---|---|
| `TestWOTS_ScriptExecution` (+ `_TamperedSig`, `_WrongMessage`) | `conformance/script_execution_test.go:1080,1110,1141` | Environmental | WOTS+ script execution is several seconds per test. Run with `go test -count=1 ./...` (no `-short`) to enable. |
| `TestSLHDSA_ScriptExecution` (+ `_TamperedSig`, `_WrongMessage`) | `conformance/script_execution_test.go:1179,1230,1268` | Environmental | SLH-DSA generates a ~248 KB script; running it through the BSV interpreter takes minutes. Drop `-short` to enable. |
| `TestWOTS_ValidSpend` (+ `_TamperedSig`, `_WrongMessage`) | `integration/go/wots_test.go:168,219,268` | Environmental | Same WOTS+ slowness; integration suite already requires `-tags=integration` + regtest, dropping `-short` enables. |
| `TestSLHDSA_*` regtest tests | `integration/go/slhdsa_test.go:173,219,263` | Environmental | Same SLH-DSA cost note as conformance row. |
| `TestGroth16WA_Regtest_Deploy_SP1` (+ `_Spend`, `_Tamper`, `_Tamper2`) | `integration/go/groth16_wa_test.go:418,437,459,506` | Environmental | Witness-assisted Groth16 verifier produces a ~470 KB locking script; full deploy + spend round-trip is multi-second. |
| `TestGroth16WA_SDK_*` | `integration/go/groth16_wa_sdk_test.go:113,178` | Environmental | Same Groth16 WA cost. |
| `TestSchnorr_ValidProof` / `TestSchnorr_TamperedProof` | `integration/go/schnorr_zkp_test.go:289,343` | Environmental | Schnorr verifier exercises full secp256k1 EC scalar-mul on the interpreter; multi-second. |
| `TestCLI_Groth16WA_SP1` | `compilers/go/groth16_wa_cli_test.go:21` | Environmental | Builds the compiler binary and runs an end-to-end CLI invocation against the SP1 v6.0.0 fixture (~10 s). |
| `TestGroth16WA_EndToEnd_SP1Proof_Script` | `packages/runar-go/bn254witness/sp1_script_test.go:207` | Environmental | Script execution of the Groth16-WA verifier against the SP1 fixture is minutes-long on the go-sdk interpreter. |
| `TestVerifyEvmGuest` / `TestSp1FriEvmGuest_*` | `packages/runar-go/sp1fri/verify_test.go:71`, `compilers/go/codegen/sp1_fri_test.go:2114,2118` | Environmental | The `tests/vectors/sp1/fri/evm-guest/proof.postcard` fixture lives outside git LFS — regenerate via `tests/vectors/sp1/fri/evm-guest/regen/` to enable. |
| `TestSp1Fri_FoldRow` arity-skip branches | `compilers/go/codegen/sp1_fri_test.go:1274,1600` | Environmental | Test only handles arity = 2; SP1 fixtures use arity = 2, so the skip is a future-proof guard for higher-arity SP1 builds. |
| `TestGroth16WA_G2Subgroup_RejectsOutOfSubgroup` | `compilers/go/codegen/bn254_groth16_subgroup_test.go:470` | Environmental | Sweeps `MapToCurve2` seeds 1..32 to find an off-subgroup G2 vector. The cofactor is ~2²⁵⁵ so the loop almost always succeeds; the skip is a defensive guard for the (effectively impossible) "all 32 seeds landed in G2" case. |
| `TestParse_ErrorHasSourceLocation` | `compilers/go/frontend/parser_test.go:923` | Environmental | Defensive guard: if a future parser change produces no error for the malformed input, the location-shape assertion can't be made — skip rather than false-pass. |
| `TestSourceCompile_*` (P2PKH / Arithmetic / BooleanLogic / IfElse / BoundedLoop / MultiMethod / Stateful / IRvsSourceMatch / AllConformanceFromSource / TestCompilerParity_AllConformance) | `compilers/go/compiler/compiler_test.go:899,926,947,964,978,992,1006,1051,1117,1186` | Environmental | Defensive guard for `conformance/tests/<dir>/source.json` missing — only fires if the conformance fixtures are not checked out (e.g. compiler is consumed as an extracted module). When the repo is checked out normally, every fixture exists and these tests run. |
| `TestSource_LoadsRunarSource` (multiformat) | `compilers/go/compiler/compiler_multiformat_test.go:47,57,216,327,362,406` | Environmental | Same conformance-fixture-missing guard for `.runar.{ts,sol,move,go,rs,py,zig,rb,java}` cross-format tests. |
| `TestIntegrationCompiler` (per-fixture loader) | `compilers/go/compiler/integration_test.go:48,95` | Environmental | `expected-ir.json` missing — same conformance-fixture-missing guard. Build-tag `//go:build integration`. |
| `TestWalletClient_LiveEndpoint_RoundTrip` | `packages/runar-go/sdk_wallet_client_integration_test.go:130` | Environmental | Set `RUNAR_WALLET_ENDPOINT` to a BRC-100 wallet URL to enable. Optional `RUNAR_WALLET_AUTH`, `RUNAR_WALLET_BASKET`. |
| `BRC-100 WalletClient live endpoint` | `packages/runar-sdk/src/__tests__/wallet-client.spec.ts:47` | Environmental | Same `RUNAR_WALLET_ENDPOINT` precondition as Go. |
| `BRC-100 WalletClient live endpoint round-trip` | `packages/runar-zig/src/sdk_wallet_client_integration_test.zig:96` | Environmental | Same `RUNAR_WALLET_ENDPOINT` precondition as Go. |
| `walletClientLiveRoundTrip` | `packages/runar-java/src/test/java/runar/lang/sdk/WalletClientIntegrationTest.java:44` | Environmental | `@EnabledIfEnvironmentVariable("RUNAR_WALLET_ENDPOINT")` — same precondition as Go. |
| `test_wallet_client_live_round_trip` | `packages/runar-py/tests/test_wallet_client_integration.py:61` | Environmental | Same `RUNAR_WALLET_ENDPOINT` precondition as Go. |
| `wallet_client_live_round_trip` | `packages/runar-rs/tests/wallet_client_integration.rs:47` | Environmental | Same `RUNAR_WALLET_ENDPOINT` precondition as Go. |
| `BRC-100 WalletClient live endpoint` | `integration/ruby/spec/wallet_client_spec.rb:107` | Environmental | Same `RUNAR_WALLET_ENDPOINT` precondition as Go. |
| `Cross-compiler: TS IR -> Go Script` (+ Rust / Python / Zig / Ruby / Java suites, ~10 `describe.skipIf(...)` blocks) | `packages/runar-compiler/src/__tests__/cross-compiler.test.ts:661,738,824,933,987,1031,1081,1126,1169,1210,1252` | Environmental | CI-strict: when `CI=true` or `GITHUB_ACTIONS=true`, missing toolchains hard-fail via `assertNoMissingCompilersInCi()`. Local devs without a given toolchain see a one-line WARNING and the suite skips. See `cross-compiler.test.ts:13-51` for the gating. |
| `BRC-100 WalletClient live endpoint (skipped)` sentinel | `packages/runar-sdk/src/__tests__/wallet-client.spec.ts:77` | Environmental | Sentinel placeholder so vitest reports "discovered-but-skipped" rather than empty when `RUNAR_WALLET_ENDPOINT` is unset. Mirrors the Ruby spec sibling. |
| `CurlHttpTransport live GET hits httpbin` / `StdHttpTransport live GET hits httpbin` | `packages/runar-zig/src/sdk_http_client.zig:331,341` | Environmental | Set `RUNAR_HTTP_LIVE=1` to exercise the real HTTPS GET path. |
| `e2e FixedArray: TicTacToe v2 ...` / `e2e MultiSig2of3 ...` | `compilers/zig/src/tests/e2e.zig:657,663,725` | Environmental | Skips if the example source can't be opened — only fires when the Zig test binary runs from outside `compilers/zig/` (e.g. an extracted module without `examples/`). |
| Zig `script_integration_test` (compileRunarScriptHex) | `packages/runar-zig/src/script_integration_test.zig:79,145` | Environmental | Skips if the TypeScript compiler dist bundle isn't built — run `pnpm -r build` first to enable. |
| `TestRubyCompilerParity::test_ruby_compiler_parity_all` | `compilers/python/tests/test_source_compile.py:169` | Environmental | Defensive guard for `.runar.rb` source missing — fires only if a conformance fixture's `source.json` doesn't list `.runar.rb`. Today every fixture has Ruby coverage, so the skip never fires. |
| `test_compile_check_accepts_valid_p2pkh` | `packages/runar-py/tests/test_compile_check.py:16` | Environmental | Defensive guard for `examples/python/p2pkh/P2PKH.runar.py` missing — fires only when the package is consumed without the examples tree. |
| Ruby multi-format conformance tests (~14 tests) | `compilers/ruby/test/test_multi_format.rb:21,22,29,59,140,172` | Environmental | Defensive guards for missing conformance fixtures / `.runar.zig` source. Run from repo root so they all resolve. |
| Ruby compiler conformance tests | `compilers/ruby/test/test_compiler.rb:158,162,170,174,223,228` | Environmental | Defensive guards for missing conformance fixtures. Run from repo root to satisfy. |
| `IntegrationBase.ensureNode` (Java) | `integration/java/src/test/java/runar/integration/helpers/IntegrationBase.java:43` | Environmental | `Assumptions.assumeTrue(System.getProperty("runar.integration") == "true")`. Run with `gradle test -Drunar.integration=true` and a regtest node up. |

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
