# Changelog

All notable changes to Rúnar are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Performance

- **Conformance runner now parallel.** `conformance/runner/runner.ts` rewritten to spawn compiler subprocesses concurrently with bounded concurrency (default `cpus/4`, capped at 8; override with `RUNAR_CONFORMANCE_CONCURRENCY`). `pnpm run conformance:multi` now finishes in under five minutes on a typical dev box, down from 30+ minutes serial.
- **Java compile daemon.** `compilers/java`'s `Cli` gained a `--daemon` mode (line-delimited JSON-RPC on stdin/stdout). The conformance runner starts one persistent JVM per run instead of paying ~1.5 s of cold-start per compile. Disable with `RUNAR_JAVA_DAEMON=0`.
- **`node --import tsx` instead of `npx tsx`.** Hot paths (`integration/java/.../helpers/ContractCompiler.java`, `integration/go/helpers/compiler.go`, `conformance/runner/runner.ts`) now resolve the tsx loader directly, skipping the per-call npm package-manager overhead.
- **Per-class compile cache for Java integration.** `ContractCompiler` now caches `RunarArtifact` by absolute source path in a `ConcurrentHashMap`, so test classes that hit the same contract from many `@Test` methods only compile it once per JVM.
- **Optional native pre-build.** `conformance/runner/index.ts` accepts `--prebuild` (or `RUNAR_PREBUILD=1`) to build Go / Rust / Zig / Java compiler binaries before the test loop. Off by default to preserve CI flows that ship prebuilt artifacts via `actions/download-artifact`.
- **Parallel-per-language regtest.** New `pnpm run integration:all:parallel` (and `:run` variant) at `integration/run-all-parallel.sh` spins up one bitcoin-sv regtest container per language on a unique RPC port and runs the seven integration suites concurrently. `integration/regtest.sh` extended with a backwards-compatible `<name> <rpcport> <p2pport> <zmqport>` argument set so multiple instances can coexist.

## [0.5.0] — 2026-04-29

### Added

- **Java as the seventh native compiler + SDK tier**, completing the shipped portion of [`docs/java-tier-plan.md`](docs/java-tier-plan.md).

  Compiler (`compilers/java/`):
  - Parse → Validate → Typecheck → ANF Lower → ANF Optimize → Constant Fold → Expand Fixed Arrays → Stack Lower → Peephole → Emit pipeline in pure Java 17 with zero external parser dependencies (uses `javax.tools.JavaCompiler` + `com.sun.source.tree`).
  - Rúnar AST + ANF IR schemas as Java records + sealed interfaces; RFC 8785 / JCS canonical JSON serializer producing byte-identical output to the other six compilers.
  - Built-in registry mirroring `packages/runar-lang/src/builtins.ts` (124 signatures).
  - Stack IR + peephole (all 24 rules ported) + emit producing byte-identical Bitcoin Script hex across the conformance suite.
  - Cross-format parsers via `ParserDispatch.java`: the Java compiler accepts `.runar.{ts,sol,move,py,go,rs,zig,rb,java}` so it can consume every other Rúnar surface format.
  - Crypto codegen modules: SHA-256 (`Sha256.java`), full secp256k1 (`Ec.java`), SLH-DSA + WOTS+ (`SlhDsa.java`, `Wots.java`), Rabin (`Rabin.java`), Blake3 (`Blake3.java`), and NIST P-256 / P-384 (`P256P384.java`). Java-tier crypto codegen is now at parity with the six peer compilers (BN254 Groth16 and SP1 STARK codegen remain Go-only across the project).

  SDK (`packages/runar-java/`):
  - `RunarContract`, `RunarArtifact`, `Provider`/`MockProvider`/`RPCProvider`/`WhatsOnChainProvider`/`GorillaPoolProvider`/`WalletProvider` (BRC-100 `BRC100Wallet`), `Signer`/`LocalSigner`/`MockSigner`/`ExternalSigner`, `TransactionBuilder`, `StateSerializer`, `UtxoSelector`, `FeeEstimator`, `CompileCheck` (composite-builds the `compilers/java` Gradle project), `OpPushTx`, `RawTx`/`RawTxParser`.
  - Multi-signer API (`PreparedCall` + `prepareCall`/`finalizeCall`).
  - Typed contract codegen (under `runar.lang.sdk.codegen`).
  - Off-chain runtime simulator (`ContractSimulator` + `MockCrypto` + `Preimage`) for native-Java unit testing with real hashes + real secp256k1 EC + mocked signature-verify.
  - ANF interpreter (`AnfInterpreter.java`) for off-chain execution against compiled artifacts.
  - Full domain-type set (`Addr`, `Sig`, `PubKey`, `ByteString`, `Bigint`, `Sha256Digest`, `Ripemd160`, `SigHashPreimage`, `RabinSig`/`RabinPubKey`, `Point`/`P256Point`/`P384Point`, `OpCodeType`, `FixedArray<T>`).
  - 1sat ordinals: `Inscription` envelope plus BSV-20 / BSV-21 mint + transfer helpers (`ordinals/Bsv20.java`, `ordinals/Bsv21.java`, `ordinals/TokenWallet.java`).

  Examples (`examples/java/`): 21 ported contracts with JUnit 5 tests (P2PKH, Counter, BoundedCounter, Auction, TicTacToe, Escrow, OrdinalNFT, BSV-20/BSV-21 tokens, CovenantVault, OraclePriceFeed, MathDemo, BitwiseOps, RawOutputTest, DataOutputTest, MessageBoard, SimpleNFT, FungibleToken, P256Wallet, plus a wiring smoke test).

  Integration (`integration/java/`): Gradle harness with `RpcProvider` / `RpcClient` / `IntegrationWallet` helpers, wired into `integration/run-all.sh`, targeting BSV regtest and Teranode. Tests are gated by `-Drunar.integration=true` and skip cleanly when the backend is absent.

  Conformance: Java compiler wired into `conformance/runner/runner.ts` (byte-identical ANF + hex checks across the suite); Java SDK driver at `conformance/sdk-output/tools/java-driver/` makes all 41 SDK-output fixtures produce identical locking scripts across all seven SDKs; Java included in `conformance/fuzzer/differential.ts` and `ir-differential.ts`.

  Playground (`examples/end2end-example/webapp`): Java added as a selectable input language with a P2PKH default template.

  Documentation: `docs/formats/java.md` format guide; README language badges + supported-formats matrix updated.

  CI: `java-compiler` and `java-sdk` jobs (split, gated as required) running on JDK 17 Temurin via `gradle/actions/setup-gradle`.

- **Formal verification (Lean 4)** in `runar-verification/`:
  - Phase 1: Lean 4 ANF formal model bootstrapped + CI integration.
  - Phase 3: Verified ANF → Stack → Bitcoin Script pipeline; 25/46 byte-exact PipelineGolden cases.
  - Phase 4: Operational soundness theorem + SHA-256 codegen helpers.
  - Tail-recursive peephole shadows lift the stack-overflow bound on large programs; verification job runs independently in CI.

- **SP1 FRI verifier (R10)** in `compilers/go` and `packages/runar-go`:
  - Off-chain Plonky3 STARK + FRI verifier in Go (Phase 1.5), plus postcard decoder and KoalaBear FRI fixture.
  - On-chain `runar.VerifySP1FRI` Bitcoin Script verifier emitted by the Go compiler (Steps 1 → 11 + reduced-opening accumulator, conditional colinearity fold, Merkle verify, Ext4 macros, final-poly Horner, commit-phase absorbs + beta squeezes).
  - Host-side encoder + production-scale fixture; deploys + spends on real BSV regtest at production scale.
  - Compiler-frontend tests + mainnet readiness doc closing R10 polish.

- **BN254 Groth16-WA verifier** in the Go compiler:
  - End-to-end MSM binding, soundness-gap closures, generic Groth16 path correctness, cross-compiler primitives port.
  - `BigintBig` DSL type plus operator helpers for `.runar.go` contracts; `BN254 *Big` wrappers and `KoalaBear` / `BN254` / `G1` `FuncSig`s registered in Rust, Python, Ruby, and Zig type-checkers.
  - `addDataOutput` intrinsic plus `Sha256` rename across all SDKs.
  - Note: full BN254 / KoalaBear / Poseidon2 codegen remains Go-only by design; the other six tiers consume it through cross-compiler primitive registration and runtime helpers.

- **NIST P-256 and P-384 ECDSA support** across the project:
  - `P256Point` / `P384Point` types and 14 builtin stubs in `runar-lang`.
  - P-256 / P-384 Bitcoin Script codegen modules (TypeScript, Go, Rust, Python, Zig, Ruby, Java); P-256 / P-384 stack-lowering dispatch wired in `05-stack-lower.ts`.
  - `P256Wallet` example contracts for TypeScript, Go, Rust, Python, and Java.
  - Conformance tests for P-256 wallet and primitives across all SDKs; on-chain integration tests for Go and TypeScript (P-256) plus P-384 examples and integration tests.
  - Off-chain helpers in `runar-go`; bundled / production secp256k1 fallbacks aligned per language.

- **`FixedArray<T,N>` state and parameters** across all seven compilers and SDKs:
  - `expand-fixed-arrays` pass that flattens `FixedArray` props to scalar siblings, plus a marker-gated regrouping pass that re-assembles them in the ABI (with nested-array support via chain markers).
  - Statement-form dispatch for runtime reads; `array_value` handling in stateValueToAnf.
  - `runar-py`, `runar-rs`, `runar-go`, `runar-rb`, `runar-zig`, and `runar-java` SDKs flatten + regroup `FixedArray` state and constructor args.
  - TS SDK round-trips `FixedArray` state as a JS array.
  - Examples: TicTacToe v2 and Grid2x2 `FixedArray` contracts in TS, Go, Rust, Python, Ruby, Zig, and Java; byte-equality v2 acceptance test.
  - Spec: `FixedArray<T,N>` semantics documented in `spec/`.

- **1sat ordinals support** in all SDKs:
  - 1sat ordinals envelope and BSV-20 / BSV-21 mint + transfer helpers across TS, Go, Rust, Python, Ruby, Zig, and Java.
  - Ordinal contract examples (OrdinalNFT, BSV-20, BSV-21) ported to Go, Python, Rust, Zig, Ruby, and Java.
  - Live `WalletClient` integration in the Ruby SDK with mock-backed spec coverage; deploy-then-call lifecycle spec.

- **SDK output conformance suite** (`conformance/sdk-output/`):
  - Cross-SDK locking-script parity harness covering all 7 SDKs.
  - Generator script + golden inputs; per-language driver tools (TS, Go, Rust, Python, Ruby, Zig, Java).
  - All 41 SDK-output fixtures produce byte-identical deployed locking scripts across every SDK; manifest-driven runner with `array_literal` goldens and an ANF interpreter parity test.
  - Wired as `pnpm conformance:sdk`; documented design + implementation plan.

- **IR-based differential fuzzer** (`conformance/fuzzer/ir-differential.ts`) running across all six (now seven, with Java) compilers; native golden-diff harnesses added for all five non-TS compilers; conformance migrated to use `examples/` as the canonical contract source.

- **Cross-compiler parser parity** across all 9 surface formats:
  - Closed all 406 multi-format conformance gaps; cross-compiler `.runar.java` support (Bigint.of/.value() identity, Bigint method lowering, `assertThat` rewrite).
  - Zig parser handles `[N]T` fields and indexing, FixedArray shape from Ruby, hexToBytes from TS; Ruby parser supports `@var[i] = expr` assignment; Go DSL composite literals and else-if chains; Rust DSL strips `.clone()`; Python and Zig port `liftBranchUpdateProps`.
  - Shift operators (`<<`, `>>`) added to `.runar.sol`, `.runar.move`, `.runar.go`, and `.runar.rs` parsers.

- **Zig SDK production HTTP transports** (`packages/runar-zig`):
  - Real `WhatsOnChainProvider`, `GorillaPoolProvider`, and `RPCProvider` HTTP transports; orphan SDK tests wired up.
  - `TokenWallet`, codegen, and `estimateCallFee` helpers; deploy → call E2E tests; `Sha256Digest` test; Zig 0.16 API support throughout.

- **Ruby compiler real crypto**:
  - Real WOTS+ and SLH-DSA verifier implementations (replacing mocks).
  - Real BLAKE3 runtime; `WalletClient` mock-backed spec coverage.
  - Merkle proof mocks added; helper name-collision fixes.

- **`runar-rs-macros` rewrite**: syn-based proc-macro implementation with trybuild compile-fail coverage.

- **Static analyzer enhancements**: flag unconditionally-successful paths and inconsistent branch depths; emit a `PATHS_TRUNCATED` finding when the `MAX_PATHS` cap is hit.

- **CLI**: WIF-checksum verification; six-language `runar init` scaffolding; backfilled command tests; pre-warm compiler import to avoid CI test timeout.

- **Cross-compiler primitives**: `bb_ext4` (BabyBear extension-4) runtime helpers added to Rust, Python, and Zig (alongside the existing Go implementation); `BbExt4Inv` re-exported from `runar-go`.

- **Documentation**: all 7 SDK READMEs rewritten to a shared 19-section structure (Section 12 expanded across Go/Py/Rust/Ruby); `docs/formats/` updated to list all 6 compilers as supported for `.sol` and `.move`; whitepaper PDF regenerated to match six-compiler reality (Java-tier whitepaper update tracked separately); root cruft removed.

### Fixed

- NULLFAIL in multi-method stateful contracts (float64 satoshi truncation); reproduction tests added.
- `constructorSlots` `paramIndex` correctness; ANF interpreter readonly field lookup; constructor args passed to the ANF interpreter so readonly field access works during off-chain simulation.
- `deserialize_state` allowlist extended to match the validator across TS, Go, Python, Ruby, and Rust; Zig `statePropSize` `P384Point` data-corruption bug fixed alongside the full state-type allowlist.
- `addDataOutput` payloads now emitted as real tx outputs (R9).
- ByteString state checkSig failure in multi-method stateful contracts; missing `_newAmount` in terminal stateful unlock; `codeSepIndexSlots` substitution wired across Go, Rust, Python, Zig, and Ruby SDKs.
- Merkle on-chain `OP_SPLIT` bug; Ruby and Python `len()` codegen now emit `OP_NIP` after `OP_SIZE`.
- Compiler stack divergence bugs across Python, Ruby, Zig, and Go (documented in compiler-stack-divergence bug report); achieve integration-test parity.
- `liftBranchUpdateProps` ported to Python and Zig; `else-if` chains parse correctly in the Go DSL.
- TicTacToe Zig divergence (91-byte) closed against the TS reference; v1/v2 contracts ported to inline P2PKH form.
- Go runtime math builtins: false-overflow panics removed; `<<` / `>>` mapping corrected in the `.runar.go` parser; variable name preserved past `=` in `parseVariableDecl`.
- IR schema aligned with real artifact + ANF output; `StateField.initialValue` widened to a real array.
- Zig SDK: `liveHttpEnabled()` no longer requires libc; `std.testing.environ` initialized in the custom test runner; P-384 sqrt exponent corrected.
- Python `LocalSigner` falls back to bundled ECDSA when `bsv-sdk` is absent.
- Java SDK: `RunarContract.call()` unlocking-script construction wired up; testnet/regtest P2PKH addresses accepted in `Base58Check`; integration `LocalSigner` wraps and reports a regtest address.
- Numerous CI fixes: integration suites hard-fail when the regtest node is unavailable instead of silently skipping; Rust regtest tests gated behind a feature flag; Go integration timeouts raised for large Groth16 WA broadcasts; turbo's default test pipeline excludes `integration/ts`; pre-existing TS / Zig / Ruby CI failures repaired.

## [0.4.5] — 2026-04-29

### Fixed

- Runtime guard for `pow` exponent cap across all six compilers (issue #34): exponents exceeding the maximum safe integer boundary now raise a compile-time or runtime error rather than silently producing incorrect output. Includes red/green conformance fixture and corrected test prologues.
- Param-type lookup scoped to the current method in all six compilers (TypeScript, Go, Rust, Python, Zig, Ruby), preventing false type errors when identically-named parameters appear in different methods.

## [0.4.4] — 2026-03-28

### Fixed

- Ruby `Gemfile.lock` files updated to 0.4.4; Ruby version entry added to `bump-version.sh`.
- Hardcoded version expectations in Go, Python, and Rust compiler tests corrected after version bump.

### Changed

- Removed stale planning documents.

## [0.4.3] — 2026-03-27

### Fixed

- Six compiler bugs resolved across the TypeScript, Go, Rust, Python, Zig, and Ruby compilers (tracked in `COMPILER-BUGS.md`).

### Changed

- Example contract tests upgraded to run the full 6-pass compilation pipeline (parse → validate → typecheck → ANF → stack → emit).
- `bump-version.sh` now auto-commits and creates a git tag.

## [0.4.2] — 2026-03-27

### Fixed

- Compiler bugs across Rust, Python, Move, Go, and Ruby format parsers.
- Type checker correctly handles `addOutput`/`addRawOutput` calls expressed as `member_expr` callees.

### Added

- Targeted regression tests for each compiler bug to prevent recurrence.

## [0.4.1] — 2026-03-25

### Fixed

- All known limitations in the Zig and Ruby compilers resolved.

## [0.4.0] — 2026-03-25

### Added

- **Zig as the fifth native compiler** (`compilers/zig/`): full parse → validate → typecheck → ANF → stack → emit pipeline (~18K LOC); deployment SDK in `packages/runar-zig/` (transaction building, signing, integration tests against regtest); `runar init --lang zig` and `codegen --lang zig`; bsvz script-engine integration; `runar.Readonly(T)` for explicit readonly fields; `assert_probe` infrastructure with negative-path coverage; full e2e (compile `.runar.zig` → verify in bsvz with real ECDSA).
- **Ruby as the sixth native compiler** (`compilers/ruby/`): full parse → validate → typecheck → ANF → stack → emit pipeline in pure Ruby; registered in conformance runner and differential fuzzer.
- **Ruby LSP addon** (`compilers/ruby/lib/ruby_lsp/`): `IndexingEnhancement` for property declarations, hover documentation for builtins/properties/types, completion lists derived from hover docs, and parameter-type annotations via `runar_public`/`params`.
- `.runar.zig` parser registered in TypeScript, Go, Rust, and Python compilers; Zig compiler also adds `.runar.{ts,sol,move,go,rs,py,rb}` parsers for cross-format parity.
- Zig `call()` method in the SDK, with `codeSeparatorIndices` and `_newAmount` wired correctly; Zig integration tests extended.
- Ruby and Zig added to `integration/run-all.sh`; Zig uses native compiler binary.
- `CompileResult` type and `compile_from_source_with_result()` added to the Python compiler (pass 5-01 parity).
- Structured `Diagnostic` type in Go and Rust `ParseResult`; `ErrorStrings()` / `error_strings()` accessors for callers that want flat strings.
- Source locations surfaced in Go and Python type-checker diagnostics.
- `codeSeparatorIndex`, `codeSeparatorIndices`, and `anfIr` fields added to the Go compiler's `Artifact` JSON output.
- `OpCodeType` constant added to the Ruby gem.
- CI: Ruby compiler job; Zig example tests; Go SDK tests; Zig integration pipeline.

### Fixed

- Ruby `liftBranchUpdateProps` missing from ANF lowering; SDK `require` path corrected.
- Ruby forward-declaration of `ser_binding` in the artifact JSON serializer.
- Ruby: removed trailing-underscore convention from builtin names (breaking change within the pre-1.0 series).
- Ruby: `add_output`/`add_raw_output`/`get_state_script` bare calls rewritten to `this.method()` form.
- Zig: conformance mismatches with TypeScript gold standard resolved.
- Zig: `FunctionPatterns` test `new_state` limited to mutable fields only.
- Zig: `constructorSlots` now emitted from stack-lowering placeholder ops.
- Zig `bsvz` dependency resolved via `build.zig.zon` for CI.
- Go `parseRbNumber` reports an error instead of silently returning 0.

## [0.3.4] — 2026-03-21

### Added

- Source locations in compiler diagnostics across all compilers (TypeScript, Go, Rust, Python); diagnostic messages now include file, line, and column information.

## [0.3.3] — 2026-03-21

### Added

- `ByteString` support for stateful contract state fields: `ByteString`-typed properties can be used as mutable state in `StatefulSmartContract`, with correct serialization and deserialization in the continuation output.
- Restructured `runar init` to match real-world project layout.

### Fixed

- Replaced `require('@bsv/sdk')` with `import` in `ecdsa.ts` for ESM compatibility.

## [0.3.2] — 2026-03-17

### Fixed

- `addRawOutput` wired into the TypeScript type checker and test interpreter; previously the call was accepted syntactically but not validated or executed.
- Release scripts made resilient to re-runs (idempotent publish flow).

## [0.3.1] — 2026-03-17

### Fixed

- Codegen moved to a separate `runar-compiler/codegen` subpath export for browser compatibility (avoids pulling Node.js-only modules into browser bundles).
- `Cargo.lock` files updated after v0.3.0 crates.io publish.

### Added

- Release scripts for version bumping and publishing (`scripts/bump-version.sh`, `scripts/publish.sh`).

## [0.3.0] — 2026-03-16

### Added

- **Template-based SDK code generation** for Go, Rust, and Python: `runar codegen` produces typed wrapper classes/structs from compiled artifacts.
- **ANF constant folding** optimizer enabled across all four compilers (TypeScript, Go, Rust, Python); can be disabled with `--disable-constant-folding` for conformance testing.
- `sha256Compress` / `sha256Finalize` SDK implementations in all four languages, with Blake3 and SHA-256 test coverage.
- `blake3Compress` and `blake3Hash` builtins across all four compilers; `P2Blake3PKH` example contract in all six input formats.
- `ArrayLiteralExpression` and `checkMultiSig` support across all four compilers.
- Mock preimage helper (`mockPreimage`) for stateful contract off-chain execution.
- ANF interpreter in the TypeScript SDK for computing stateful contract state transitions automatically.
- `prepareCall` / `finalizeCall` multi-signer API in all four SDKs.
- Typed contract codegen: `runar codegen` produces language-specific wrapper classes.
- **Property initializers** (`= value` defaults on contract properties) across all four compilers; initialized properties excluded from auto-generated constructors.
- `WalletSigner` (BRC-100 wallet integration) in the TypeScript SDK.
- `debug` CLI command; source maps and IR debug snapshots included in compiled artifacts.
- Source locations added to Go and Python type-checker diagnostics.
- Conformance test suite expanded to all 27 cases across Go, Rust, and Python; `source.json` references resolved.
- Multi-language integration test suites (TypeScript, Go, Rust, Python, Zig, Ruby) in `integration/`.
- EC ANF optimizer alias rules; extended peephole optimizer.
- Undefined variable detection via `ParserCore`; Go and Rust TypeScript-format parsers.
- SDK uses `Transaction` objects instead of raw hex across all four languages.
- Fee rate unit changed from sat/byte to sat/KB across all four SDKs.

### Fixed

- `if`-without-`else` silently skipping body in compiled Bitcoin Script.
- EC scalar multiplication overflow; SDK `CLEANSTACK` bug; `add_output` preimage field.
- EC optimizer alias rules use `load_const` instead of `load_param`.
- `@ref:` aliases skipped in constant folding to prevent incorrect string comparisons.
- Various CI and documentation fixes.

## [0.2.0] — 2026-03-09

### Added

- **Python as the sixth input format** and fourth compiler implementation (`compilers/python/`): full parse → validate → typecheck → ANF → stack → emit pipeline; snake_case identifiers converted to camelCase in the AST; `@public` decorator for public methods; `Readonly[T]` for stateful readonly properties.
- **Real secp256k1 ECDSA signing** in all four runtime SDKs via `LocalSigner` (TypeScript uses `@bsv/sdk`; Go uses `go-sdk`; Rust uses `k256`; Python uses bundled pure-Python ECDSA with optional `bsv-sdk` acceleration).
- **EC codegen primitives**: `ecAdd`, `ecMul`, `ecMulGen`, `ecNegate`, `ecOnCurve`, `ecModReduce`, `ecEncodeCompressed`, `ecMakePoint`, `ecPointX`, `ecPointY`; `Point` 64-byte type (`x[32] || y[32]`); `EC_P`, `EC_N`, `EC_G` constants.
- **Post-quantum signature verification**: `verifyWOTS` (~10 KB script) and `verifySLHDSA_SHA2_*` (six FIPS 205 parameter sets, 200–900 KB scripts); RFC 8391 tweakable hash in WOTS+ chain verification; hybrid ECDSA + WOTS/SLH-DSA wallet support with real crypto.
- **Go and Rust deployment SDKs** (`packages/runar-go/sdk_*.go`, `packages/runar-rs/src/sdk/`): `RunarContract`, `MockProvider`, `LocalSigner`, `MockSigner`/`ExternalSigner`, `BuildDeployTransaction`, `BuildCallTransaction`, state serialization; constructor args spliced at byte offsets from `constructorSlots`.
- `OP_CODESEPARATOR` auto-inserted for stateful contracts; `codeSeparatorIndex` and `codeSeparatorIndices` in compiled artifact.
- `ByteString` bitwise operators (`&`, `|`, `^`, `~`) and `addRawOutput` intrinsic across all compilers.
- `sha256Compress` / `sha256Finalize` built-ins and script-level SHA-256 partial verification.
- Conditional `addOutput` support (outputs contingent on branch execution).
- `WalletSigner` (BRC-100) in the TypeScript SDK.
- `prepareCall` / `finalizeCall` multi-signer API.
- Typed contract codegen: `runar codegen` generates TypeScript/Go/Rust wrapper classes from artifacts.
- Property initializers (`= value` defaults) across all compilers.
- `runar-lang/runtime` subpath export for off-chain contract simulation.
- **PriceBet** and **Blackjack** webapps and regtest demos in `examples/end2end-example/`.
- Comprehensive integration test suites for all example contracts; SDK `OP_PUSH_TX` support; `getRawTransaction` helper.
- BSV-20 / BSV-21 token contract examples ported across all input formats.
- int64 overflow detection in Go and Rust runtimes.

### Fixed

- OP_RETURN state extraction bug in locking scripts.
- Constructor arg append replaced with byte-offset splicing in `getLockingScript`.
- Rabin signature stack order; `sign(0)` divide-by-zero; `right()` semantics.
- Terminal-assert `if`/`else` stack cleanup ported to Rust compiler.
- `composePoint` coordinate swap; Rust `ecMul` encoding.
- `_newAmount` parameter used for stateful continuation output satoshis.
- Fee rounding when calculating transaction fees in the TypeScript SDK.
- Dual-sig escrow, covenant output verification, Fiat-Shamir challenge, and conformance deduplication (security audit findings).
- `OP_REVERSE` replaced with `OP_DIV` in `log2`; `log2` accuracy corrected.
- `OP_INVERT` implemented correctly across all compilers.
- Positional index used for state field initialization from constructor args.
