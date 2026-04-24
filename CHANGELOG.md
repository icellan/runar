# Changelog

All notable changes to Rúnar are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- **Java as the seventh native compiler + SDK tier**, covering milestones
  M1–M18 of [`docs/java-tier-plan.md`](docs/java-tier-plan.md).

  Compiler (`compilers/java/`):
  - Parse → Validate → Typecheck → ANF Lower → Stack Lower → Peephole → Emit pipeline in pure Java 17 with zero external parser dependencies (uses `javax.tools.JavaCompiler` + `com.sun.source.tree`).
  - Rúnar AST + ANF IR schemas as Java records + sealed interfaces; RFC 8785 / JCS canonical JSON serializer producing byte-identical output to the other six compilers.
  - Built-in registry mirroring `packages/runar-lang/src/builtins.ts` (124 signatures).
  - Stack IR + peephole (all 24 rules ported) + emit producing byte-identical Bitcoin Script hex for P2PKH, Counter, and every non-crypto-heavy fixture (22/42 conformance fixtures at time of commit).
  - Crypto codegen: SHA-256 (`sha256Compress`, `sha256Finalize`) and full secp256k1 (`ecAdd`/`ecMul`/`ecMulGen`/`ecNegate`/`ecOnCurve`/`ecModReduce`/`ecEncodeCompressed`/`ecMakePoint`/`ecPointX`/`ecPointY`). Post-quantum (SLH-DSA, WOTS+), Groth16 (BN254), and SP1 STARK (BabyBear/KoalaBear/Poseidon2) codegen is deferred per the plan's explicit scope-down option and tracked as follow-up work.
  - `.runar.java` parser in every existing compiler (TypeScript, Go, Rust, Python, Zig, Ruby) so any compiler can consume the Java surface format (M7).

  SDK (`packages/runar-java/`):
  - `RunarContract`, `RunarArtifact`, `Provider`/`MockProvider`/`WalletProvider` (BRC-100), `Signer`/`LocalSigner`/`MockSigner`/`ExternalSigner`, `TransactionBuilder`, `StateSerializer`, `UtxoSelector`, `FeeEstimator`, `CompileCheck`.
  - Multi-signer API (`PreparedCall` + `prepareCall`/`finalizeCall`).
  - Typed contract codegen (`TypedContractGenerator`).
  - Off-chain runtime simulator (`ContractSimulator` + `MockCrypto` + `Preimage`) for native-Java unit testing with real hashes + real secp256k1 EC + mocked signature-verify.
  - Full domain-type set (`Addr`, `Sig`, `PubKey`, `ByteString`, `Bigint`, `Sha256Digest`, `Ripemd160`, `SigHashPreimage`, `RabinSig`/`RabinPubKey`, `Point`/`P256Point`/`P384Point`, `OpCodeType`, `FixedArray<T>`).

  Examples (`examples/java/`):
  - 17 ported contracts (P2PKH, Counter, BoundedCounter, Auction, TicTacToe, Escrow, OrdinalNFT, BSV-20/BSV-21 tokens, CovenantVault, OraclePriceFeed, MathDemo, BitwiseOps, RawOutputTest, DataOutputTest, MessageBoard, SimpleNFT, FungibleToken) with JUnit 5 tests.

  Integration (`integration/java/`):
  - Gradle integration-test harness wired into `integration/run-all.sh`, targeting both BSV regtest and Teranode. Tests are gated by `-Drunar.integration=true` and skip cleanly when the backend is absent.

  Conformance:
  - Java compiler wired into `conformance/runner/runner.ts` (byte-identical ANF + hex checks).
  - Java SDK driver at `conformance/sdk-output/tools/java-driver/`; all 41 SDK-output fixtures produce identical locking scripts across all seven SDKs.
  - Java included in `conformance/fuzzer/differential.ts` and `ir-differential.ts`; ~1,900 random contracts fuzzed with zero Java-specific divergences.

  Playground: `examples/end2end-example/webapp` accepts `.runar.java` input with a P2PKH default template (M17).

  Documentation: `docs/formats/java.md` format guide; README language badge + supported-formats matrix updated; this CHANGELOG entry.

  CI: `java-compiler` job in `.github/workflows/ci.yml` running on JDK 17 Temurin via `gradle/actions/setup-gradle`. After M18, the job is gating-required (`continue-on-error` removed).

### Deferred / follow-up

- Post-quantum codegen (SLH-DSA 6 parameter sets, WOTS+), Groth16 BN254 field operations, SP1 STARK support (BabyBear / KoalaBear / Poseidon2 / Merkle), Blake3, and NIST P-256 / P-384 codegen. All isolated modules under `compilers/java/src/main/java/runar/compiler/codegen/` with the same wiring pattern as SHA-256 / secp256k1; drop-in additions.
- Full integration-test execution against regtest and Teranode in CI (the Gradle harness is wired; enabling it requires provisioning the backends in the CI environment).
- Stack-tier hex parity across the remaining 20 conformance fixtures that exercise the deferred crypto families above.

## [0.4.4] — prior state (no changelog before this entry)

First changelog entry; prior versions are documented via git history.
Run `git log --oneline v0.4.4` for the pre-changelog release notes.
