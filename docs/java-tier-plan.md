# Java as a Native Compiler + SDK Tier — Design Plan

**Status:** Proposal / Phase 1 (skeleton only)
**Target release:** v0.5+ (aligns with current `0.4.x` cadence)

## Context

Rúnar maintains six independent compiler implementations today — TypeScript (reference), Go, Rust, Python, Zig, and Ruby — all held to byte-identical output at the ANF IR and Bitcoin Script hex boundary. Every SDK ships in lockstep. This document specifies the addition of Java as the seventh tier: a new compiler in `compilers/java/`, a deployment SDK in `packages/runar-java/`, the `.runar.java` contract surface format, and the corresponding parser in every existing compiler.

Java is the highest-leverage language to add next: broad enterprise reach, a mature crypto ecosystem (BouncyCastle), and a surface syntax that maps cleanly to the existing annotation-tagged conventions used in Go (struct tags) and Rust (attributes).

## Pipeline (ground truth, ten stages)

Every compiler must implement these passes in order; Java is no exception:

1. Parse — source → Rúnar AST (`ContractNode`)
2. Validate — language-subset constraints
3. Typecheck — type consistency + builtin-call enforcement
4. Expand fixed arrays — inline `FixedArray<T,N>` to scalar properties
5. ANF lower — AST → ANF IR (`packages/runar-ir-schema/src/anf-ir.ts`)
6. Constant fold (optional, off by default — conformance mode disables it)
7. EC optimize — EC operation fusions
8. Stack lower — ANF → Stack IR
9. Peephole — Stack IR optimization (always on)
10. Emit — Stack IR → hex Bitcoin Script

**Canonical JSON:** RFC 8785 JCS. Implementation reference: `packages/runar-ir-schema/src/canonical-json.ts`. BigInt encoded as bare JSON integers, sorted UTF-16 code-unit keys, no whitespace, no trailing zeros. Java must match byte-for-byte.

**Conformance CLI contract** (every compiler binary must accept these):
- `--source <path> --emit-ir --disable-constant-folding` → canonical ANF JSON on stdout
- `--source <path> --hex --disable-constant-folding` → hex script on stdout
- `--ir <path> --hex` → compile a pre-generated ANF JSON to hex (used by `cross-compiler.test.ts`)

Reference invocations: `conformance/runner/runner.ts:220-230` (Go), `:268-290` (Rust), `:343-360` (Python).

## Toolchain

| Concern | Choice | Rationale |
|---|---|---|
| JDK | **17 LTS** (compile target) | Broad compatibility; records + pattern matching available. Local dev on 21 is fine. |
| Parser | **JavaParser 3.25+** | Typed AST with symbol resolution. Alternative (`com.sun.source.tree`) requires javac internals and is brittle. |
| Canonical JSON | **Hand-rolled JCS serializer** | RFC 8785 is ~300 lines. Avoid pulling Jackson transitively. |
| Build | **Gradle 8 (Kotlin DSL)** | Multi-module: `:compiler`, `:sdk`, `:cli`. Native image via `application` plugin produces `runar-java` launcher. |
| Crypto (SDK) | **BouncyCastle 1.78+** | secp256k1, SHA-256, RIPEMD-160, ECDSA, BIP-143. Single jar, audit-ready. |
| HTTP (SDK) | **JDK `java.net.http.HttpClient`** | No Apache HTTP / OkHttp dep. |
| JSON (SDK) | **Jackson Core only** (no databind) | Avoids reflection; keeps GraalVM-native-image-compatible. |
| Testing | **JUnit 5 + AssertJ** | Standard. |
| Distribution | Shaded fat jar at `compilers/java/build/libs/runar-java.jar` + launcher script `compilers/java/bin/runar-java` | Matches Go/Rust/Python/Zig/Ruby binary discovery pattern in `conformance/runner/runner.ts:79-103`. |

No Spring, no Jakarta EE, no Guice, no Guava. Minimal dep surface.

## Contract surface syntax (`.runar.java`)

Match Python/Go/Rust idiom: annotations, one contract class per file, `super(...)` first statement of constructor.

```java
package runar.examples.p2pkh;

import runar.lang.*;
import static runar.lang.Builtins.*;

public class P2PKH extends SmartContract {
    @Readonly Addr pubKeyHash;

    public P2PKH(Addr pubKeyHash) {
        super(pubKeyHash);
        this.pubKeyHash = pubKeyHash;
    }

    @Public
    public void unlock(Sig sig, PubKey pubKey) {
        assertThat(hash160(pubKey).equals(pubKeyHash));
        assertThat(checkSig(sig, pubKey));
    }
}
```

### Design resolutions

- **Annotations as tags.** `@Readonly` on fields, `@Public` on methods, `@Stateful` at the class level when extending `StatefulSmartContract` (optional; derived from the base class). Direct analog of Go struct tags and Rust attributes.
- **No snake→camel conversion.** Java identifiers are already camelCase.
- **Equality.** `.equals(...)` on domain types; the validator coerces `a.equals(b)` to the `==` AST node for ByteString-subtyped values. No `Runar.eq(...)` helper.
- **bigint.** `java.math.BigInteger`. Literals via `BigInteger.valueOf(7)` or pre-declared constants. No syntactic sugar. Validator accepts `BigInteger.valueOf(N)` with integer `N` as a bigint literal.
- **Property initializers.** Java field initializers (`@Readonly Bigint count = BigInteger.valueOf(0);`) map to ANF `initialValue`. Python's rule applies: initialized properties are excluded from the auto-generated constructor.
- **Assertions.** `assertThat(expr)` from `runar.lang.Builtins` (static import). Maps to `assert` AST node.
- **Conditional multi-output.** Standard `if (...) { this.addOutput(...); }` — lowers through ANF identically to all other languages.
- **SmartContract vs StatefulSmartContract.** Base class selection as in other languages. `parentClass` AST field populated from `extends`.

## Directory layout

```
compilers/java/
  settings.gradle.kts
  build.gradle.kts
  gradle/wrapper/...                          # generated via `gradle wrapper` on first bootstrap
  bin/runar-java                              # launcher script (shaded jar + java -jar)
  src/main/java/runar/compiler/
    Cli.java                                  # --source/--ir/--hex/--emit-ir/--disable-constant-folding
    Compiler.java                             # pipeline orchestrator
    ir/  ContractNode.java  AnfProgram.java  AnfValue.java  StackIr.java ...
    frontend/
      ParserDispatch.java                     # .runar.{ts,sol,move,py,go,rs,zig,rb,java} → AST
      parser/
        JavaParser_Runar.java                 # .runar.java parser (JavaParser-backed)
        TsParser.java  SolParser.java  MoveParser.java  PyParser.java
        GoParser.java  RsParser.java  ZigParser.java  RbParser.java
    passes/
      Validate.java  Typecheck.java  ExpandFixedArrays.java  AnfLower.java
    codegen/
      StackLower.java  Peephole.java  Emit.java
      Ec.java  Sha256.java  SlhDsa.java
      KoalaBear.java  BabyBear.java  Bn254.java  Poseidon2.java  Merkle.java
    canonical/Jcs.java                        # RFC 8785 canonical JSON serializer
  src/test/java/runar/compiler/               # JUnit 5, one test class per pass

packages/runar-java/
  build.gradle.kts
  src/main/java/runar/lang/
    SmartContract.java  StatefulSmartContract.java
    types/ (Addr, Sig, PubKey, ByteString, Bigint, Point, P256Point, P384Point, Sha256Digest,
            SigHashPreimage, RabinSig, RabinPubKey, OpCodeType, FixedArray)
    Builtins.java                             # hash160, checkSig, ecAdd, etc. (static methods)
    CompileCheck.java                         # parse+validate+typecheck for in-test validation
    runtime/ (MockCrypto, Preimage, ContractSimulator)
    sdk/
      RunarContract.java
      Provider.java  MockProvider.java  WhatsOnChainProvider.java  RpcProvider.java
      WalletProvider.java                     # BRC-100
      Signer.java  LocalSigner.java  MockSigner.java  ExternalSigner.java
      TransactionBuilder.java                 # buildDeployTransaction, buildCallTransaction
      StateSerializer.java  UtxoSelector.java  FeeEstimator.java
      PreparedCall.java                       # multi-signer prepareCall/finalizeCall
      codegen/TypedContractGenerator.java     # typed Java wrappers from compiled artifact

examples/java/
  build.gradle.kts
  src/main/java/runar/examples/{p2pkh,counter,auction,escrow,token-ft,token-nft,...}/
    <Contract>.runar.java
  src/test/java/...
    <Contract>Test.java                       # JUnit 5 + CompileCheck + off-chain simulator

integration/java/                             # ported from integration/{python,go,rust}/
docs/formats/java.md                          # mirror docs/formats/python.md
.github/workflows/ci.yml                      # add java-compiler job
```

## Cross-compiler parser work

Every existing compiler must learn to parse `.runar.java`. Per the CLAUDE.md checklist ("Adding a New Input Format Parser"):

| Compiler | Parser file to add | Dispatch to update |
|---|---|---|
| TypeScript | `packages/runar-compiler/src/passes/01-parse-java.ts` | `packages/runar-compiler/src/passes/01-parse.ts` + `src/index.ts` |
| Go | `compilers/go/frontend/parser_java.go` | `frontend.ParseSource()` |
| Rust | `compilers/rust/src/frontend/parser_java.rs` | `parser::parse_source()` |
| Python | `compilers/python/runar_compiler/frontend/parser_java.py` | `parser_dispatch.py` |
| Zig | `compilers/zig/src/frontend/parser_java.zig` | `parseSource()` |
| Ruby | `compilers/ruby/lib/frontend/parser_java.rb` | `parse_source()` |

These are hand-written recursive-descent parsers in each language (no javac available outside Java). Each only needs to handle the Rúnar subset of Java syntax — class declaration, annotated fields, annotated methods, `super(...)` calls, expressions drawn from the Rúnar surface. Consistent shape with existing `parser_go.py`, `parser_rust.py`, `parser_ruby.py`, etc.

### Conformance runner wiring

- `conformance/runner/runner.ts:11-12` — add `JAVA_COMPILER_DIR`
- `conformance/runner/runner.ts:51-60` — add `{ ext: '.runar.java', compilers: [...,'java'] }` entry, add `'java'` to every other format's `compilers` list
- `conformance/runner/runner.ts:33-45` — add `javaCompiler?: CompilerOutput` to `ConformanceResult`
- Add `findJavaBinary()` and `runJavaCompiler()` mirroring Go/Rust patterns

### Cross-compiler test wiring

`packages/runar-compiler/src/__tests__/cross-compiler.test.ts` — add a Java suite that feeds TS-generated ANF IR to the Java binary and asserts hex parity on P2PKH, HashLock, Escrow, and every `examples/ts/` contract.

## Sequenced milestones

One reviewable PR per milestone. Conventional Commits (`feat(compiler/java): …`). No AI attribution in commit messages.

1. **`docs: java tier design plan`** — land this document in `docs/java-tier-plan.md` for review. *(This PR, commit 1.)*
2. **`feat(compiler/java): project skeleton`** — Gradle skeleton for `compilers/java/`, `packages/runar-java/`, `examples/java/`. CLI stub prints version. Wires CI job `java-compiler` with `continue-on-error: true`. *(This PR, commit 2.)*
3. **`feat(compiler/java): parse/validate/typecheck for .runar.java`** — JavaParser-backed frontend, validator, typechecker. Unit tests per pass. No ANF yet.
4. **`feat(compiler/java): ANF lowering + canonical JSON`** — ANF pass + RFC 8785 JCS serializer. Hook into `conformance/runner/runner.ts`. Run golden-file conformance. *Do not proceed until all existing fixtures match.*
5. **`feat(compiler/java): stack lowering + emit`** — Stack IR, peephole, emit. Hex-level conformance must pass across all conformance fixtures.
6. **`feat(compiler/java): EC + SHA-256 + crypto codegen`** — port `ec-codegen`, `sha256-codegen`, `slh_dsa`, BabyBear, KoalaBear, BN254, Poseidon2 modules. Validate against `post-quantum-*`, `ec-primitives`, `p256-primitives`, `p384-primitives` fixtures.
7. **`feat(compiler/*): .runar.java parser across all existing compilers`** — one commit per compiler (6 commits) or a cross-cutting commit. Each adds the hand-written `.runar.java` parser and dispatch entry.
8. **`feat(runar-java): core SDK`** — types, base classes, builtin stubs, Provider/Signer interfaces, MockProvider, LocalSigner, MockSigner, ExternalSigner, TransactionBuilder, StateSerializer, UtxoSelector, FeeEstimator, CompileCheck.
9. **`feat(runar-java): multi-signer API + BRC-100 WalletProvider`** — `PreparedCall`, `prepareCall()`/`finalizeCall()`, WalletProvider with BIP-143 local sighash + remote ECDSA.
10. **`feat(runar-java): typed contract codegen`** — `TypedContractGenerator` emits `.java` wrappers from compiled artifacts.
11. **`feat(runar-java): off-chain runtime simulator`** — mirror of `packages/runar-lang/src/runtime/` for native-Java unit-test-time execution.
12. **`feat(examples/java): port all example contracts`** — 30+ contracts (match Python's 39 where source overlaps). Each with a JUnit 5 test exercising the off-chain simulator and `CompileCheck`.
13. **`test(integration/java): regtest + Teranode integration`** — hook into `integration/regtest.sh`, `integration/teranode.sh`, `integration/run-all.sh`. Port the existing integration test matrix.
14. **`test(conformance/sdk-output): java SDK parity`** — add Java SDK to `conformance/sdk-output/` so deployed locking scripts match across all 7 SDKs.
15. **`feat(conformance/fuzzer): include java in differential harness`** — extend `conformance/fuzzer/differential.ts` and `ir-differential.ts`.
16. **`docs: add java format guide + update README matrix`** — `docs/formats/java.md` (mirror `python.md` structure). README language badge + feature matrix. Add `CHANGELOG.md` if not already present.
17. **`feat(playground): java input support`** — add Java to `examples/end2end-example/webapp/compiler.go` dispatch (linked Go compiler; depends on milestone 7 delivering the Go-side parser).
18. **`ci: gate java-compiler as required`** — drop `continue-on-error`. Java compiler job and all downstream jobs become required.

## Verification

Milestones 4, 5, 7 are the conformance gates. Each executor must run before declaring the milestone done:

1. **Compiler unit tests:** `cd compilers/java && ./gradlew test`
2. **ANF conformance:** `npx tsx conformance/runner/runner.ts` — Java column passes every fixture under `conformance/tests/`. `irMatch` and `scriptMatch` both `true` in every `ConformanceResult`.
3. **Cross-compiler tests:** `pnpm --filter runar-compiler test -- cross-compiler` — Java hex matches TS reference.
4. **SDK conformance:** `pnpm run conformance:sdk` — Java SDK produces identical locking scripts to the other SDKs across all SDK-conformance contracts.
5. **Fuzzer:** `cd conformance/fuzzer && pnpm run fuzz:ir` — no cross-compiler divergences involving Java over a 10-minute run.
6. **Integration:**
   - `pnpm run integration:svnode -- --lang java`
   - `pnpm run integration:teranode -- --lang java`
7. **Example tests:** `cd examples/java && ./gradlew test`
8. **CI:** all jobs in `.github/workflows/ci.yml` green on the final commit, `java-compiler` no longer `continue-on-error`.

If any verification step fails, the bug is in the Java implementation — **do not** modify other compilers, shared fixtures, or the conformance harness.

## Hard constraints

- **Byte-identical ANF + hex** against the existing six compilers on every conformance fixture. If Java diverges, Java is wrong.
- **No modifications** to existing compilers, shared ANF fixtures, or `conformance/runner/runner.ts` invariants beyond additive wiring.
- **No new builtins, no new types.** The set is frozen at what `packages/runar-lang/src/builtins.ts` and `packages/runar-lang/src/types.ts` expose on the day work lands.
- **No heavy frameworks.** Plain Java + JavaParser + BouncyCastle + Jackson Core. No Spring, Jakarta EE, Guice, or Guava.
- **No bytecode rewriting, no annotation processors, no compiler plugins** for ergonomics. Contracts are plain Java. BigInteger + `.equals()` is the tax.
- **No Kotlin or Scala** in this PR stream. Java only.
- **No optimizer drift.** EC optimizer + peephole match existing compilers' behavior exactly.

## Open questions for maintainer

(Unresolved; non-blocking for Phase 1 skeleton.)

1. **Java package root.** `runar.lang` / `runar.compiler` / `runar.sdk`, or `io.runar.*`, or `build.runar.*`? Determines group ID for Maven Central if publishing.
2. **Publishing target.** Maven Central or GitHub Packages?
3. **GraalVM native-image.** Nice-to-have for launcher startup (~20 ms vs ~400 ms JVM cold start). Worth the build-time cost in CI?
4. **Builtin naming.** Confirm uppercase-acronym preservation: `verifyWOTS`, `verifySLHDSA_SHA2_128s`, etc. Matches Python explicit mappings.
5. **Integration harness.** `integration/run-all.sh` is bash-orchestrated. Java integration: shared bash harness or Gradle task that reuses existing setup scripts?
6. **`continue-on-error` window.** Proposed: milestones 2–6 ride as non-blocking, dropped at milestone 7 once `.runar.java` parsers land in every existing compiler.
