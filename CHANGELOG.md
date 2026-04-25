# Changelog

All notable changes to Rúnar are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- **Java as the seventh native compiler + SDK tier**, covering the
  shipped portion of [`docs/java-tier-plan.md`](docs/java-tier-plan.md).

  Compiler (`compilers/java/`):
  - Parse → Validate → Typecheck → ANF Lower → Stack Lower → Peephole → Emit pipeline in pure Java 17 with zero external parser dependencies (uses `javax.tools.JavaCompiler` + `com.sun.source.tree`).
  - Rúnar AST + ANF IR schemas as Java records + sealed interfaces; RFC 8785 / JCS canonical JSON serializer producing byte-identical output to the other six compilers.
  - Built-in registry mirroring `packages/runar-lang/src/builtins.ts` (124 signatures).
  - Stack IR + peephole (all 24 rules ported) + emit producing byte-identical Bitcoin Script hex for the `.runar.java` fixtures the Java front-end can currently parse (P2PKH, Counter, and the rest of the non-crypto-heavy contracts).
  - Crypto codegen: SHA-256 (`sha256Compress`, `sha256Finalize`) and full secp256k1 (`ecAdd`/`ecMul`/`ecMulGen`/`ecNegate`/`ecOnCurve`/`ecModReduce`/`ecEncodeCompressed`/`ecMakePoint`/`ecPointX`/`ecPointY`). Post-quantum (SLH-DSA, WOTS+), Groth16 (BN254), SP1 STARK (BabyBear/KoalaBear/Poseidon2), Blake3, and NIST P-256 / P-384 codegen are tracked below as in-flight follow-ups.
  - `.runar.java` parser in every existing compiler (TypeScript, Go, Rust, Python, Zig, Ruby) so the other six compilers can consume the Java surface format. The reverse direction — the Java compiler parsing `.runar.ts` / `.runar.sol` / `.runar.move` / `.runar.py` / `.runar.go` / `.runar.rs` / `.runar.zig` / `.runar.rb` — is in-flight (see below).

  SDK (`packages/runar-java/`):
  - `RunarContract`, `RunarArtifact`, `Provider`/`MockProvider`/`WalletProvider` (BRC-100), `Signer`/`LocalSigner`/`MockSigner`/`ExternalSigner`, `TransactionBuilder`, `StateSerializer`, `UtxoSelector`, `FeeEstimator`, `CompileCheck`.
  - Multi-signer API (`PreparedCall` + `prepareCall`/`finalizeCall`).
  - Typed contract codegen (under `runar.lang.sdk.codegen`).
  - Off-chain runtime simulator (`ContractSimulator` + `MockCrypto` + `Preimage`) for native-Java unit testing with real hashes + real secp256k1 EC + mocked signature-verify.
  - Full domain-type set (`Addr`, `Sig`, `PubKey`, `ByteString`, `Bigint`, `Sha256Digest`, `Ripemd160`, `SigHashPreimage`, `RabinSig`/`RabinPubKey`, `Point`/`P256Point`/`P384Point`, `OpCodeType`, `FixedArray<T>`).
  - Basic 1sat ordinals envelope (`Inscription` + `RunarContract.withInscription`).

  Examples (`examples/java/`):
  - 18 ported contracts (P2PKH, Counter, BoundedCounter, Auction, TicTacToe, Escrow, OrdinalNFT, BSV-20/BSV-21 tokens, CovenantVault, OraclePriceFeed, MathDemo, BitwiseOps, RawOutputTest, DataOutputTest, MessageBoard, SimpleNFT, FungibleToken, plus a wiring smoke test) with JUnit 5 tests.

  Integration (`integration/java/`):
  - Gradle integration-test harness with `RpcProvider` / `RpcClient` / `IntegrationWallet` helpers, wired into `integration/run-all.sh`, targeting BSV regtest. Tests are gated by `-Drunar.integration=true` and skip cleanly when the backend is absent.

  Conformance:
  - Java compiler wired into `conformance/runner/runner.ts` (byte-identical ANF + hex checks for the fixtures the Java front-end can currently parse, e.g. `java-p2pkh`). The remainder of the 48 compiler-conformance fixtures await the cross-format parsers below.
  - Java SDK driver at `conformance/sdk-output/tools/java-driver/`; all 41 SDK-output fixtures produce identical locking scripts across all seven SDKs.
  - Java included in `conformance/fuzzer/differential.ts` and `ir-differential.ts` for `.runar.java` inputs.

  Playground: `examples/end2end-example/webapp` accepts `.runar.java` input with a P2PKH default template.

  Documentation: `docs/formats/java.md` format guide; README language badge + supported-formats matrix updated; this CHANGELOG entry.

  CI: `java-compiler` job in `.github/workflows/ci.yml` running on JDK 17 Temurin via `gradle/actions/setup-gradle`.

### In-flight (Java tier)

- Cross-format parsers in the Java compiler (`.runar.ts`, `.runar.sol`, `.runar.move`, `.runar.py`, `.runar.go`, `.runar.rs`, `.runar.zig`, `.runar.rb`) and the matching extension-based dispatcher in `Cli` / a `ParserDispatch` helper. Until these land, the Java compiler accepts only `.runar.java` sources and therefore fails the bulk of the 48 compiler-conformance fixtures (which carry their source in TypeScript / Solidity / Move / Python / Go / Rust / Zig / Ruby variants).
- SLH-DSA codegen module (`compilers/java/src/main/java/runar/compiler/codegen/SlhDsa.java`) for the six FIPS 205 parameter sets, plus WOTS+.
- NIST P-256 and P-384 codegen module (`P256P384.java`) covering the `verifyP256` / `verifyP384` builtins and primitives.
- Blake3 codegen module (`Blake3.java`) for the `blake3` / `blake3Compress` builtins.
- `expand_fixed_arrays` pass mirroring the other six compilers (currently fixed-array expansion is not implemented in the Java pipeline).
- `constant_fold` pass mirroring `src/optimizer/constant-fold.ts` (the `--disable-constant-folding` flag is accepted by the Java CLI but the pass itself has not yet been ported).
- `anf_optimize` pass (the post-ANF optimizer that runs before stack lowering in the other six compilers).
- Production providers in the Java SDK: `RpcProvider`, `WhatsOnChainProvider`, `GorillaPoolProvider`. Today the SDK ships only `MockProvider` and `WalletProvider` (BRC-100); the integration-test harness has its own `RpcProvider` helper that will be promoted into the SDK.
- ANF interpreter in the Java SDK (parity with the Zig SDK's `runar.lang.sdk` ANF interpreter) for off-chain execution against compiled artifacts.
- BSV-20 / BSV-21 mint + transfer helpers in the Java SDK. The ordinals envelope helper exists (`Inscription`); the token-specific mint / transfer / state helpers do not.
- OP_PUSHTX / sighash-preimage injection support in the Java compiler (no `OP_PUSHTX` opcode wiring or sighash-preimage construction in `StackLower`/`AnfLower` yet).
- Full integration-test execution against regtest and Teranode in CI (the Gradle harness is wired; enabling it requires provisioning the backends in the CI environment).
- Compiler-conformance hex parity across all 48 fixtures (gated on the cross-format parsers and the deferred crypto-codegen modules above).

## [0.4.4] — prior state (no changelog before this entry)

First changelog entry; prior versions are documented via git history.
Run `git log --oneline v0.4.4` for the pre-changelog release notes.
