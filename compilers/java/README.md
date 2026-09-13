# Rúnar Java Compiler

Reference implementation of the Rúnar compiler pipeline in Java. Compiles
`.runar.java` (and the other Rúnar input formats, once milestone 7 lands)
to Bitcoin SV Script, producing byte-identical output to the other six
compilers in this repository.

## Status

**Production.** Full pipeline is wired (parse → validate → expand-fixed-arrays
→ typecheck → ANF lower → optional constant-fold → ANF cleanup → stack lower
→ peephole → emit). All 9 input formats parse via `ParserDispatch`. Conformance
runner, fuzzer differential harness, and cross-compiler hex-equality tests
include this binary alongside the other six tiers. See
[`docs/java-tier-plan.md`](../../docs/java-tier-plan.md) for the milestone history.

## Requirements

- JDK 17 (compile target). JDK 21 LTS works for local development.
- The Gradle wrapper (`gradlew` / `gradlew.bat`) is committed at Gradle 8.5,
  so no system `gradle` install is required. The wrapper downloads its
  pinned distribution on first invocation.

## Build & Run

```bash
cd compilers/java
./gradlew build              # compile + run tests
./gradlew installDist        # produce an executable layout under build/install/
./build/install/runar-java-compiler/bin/runar-java --version
```

## CLI Contract

Every Rúnar compiler binary must accept the following flags. The Java
CLI implements all of these end-to-end.

| Flag combination | Behavior |
|---|---|
| `--source <path> --emit-ir --disable-constant-folding` | Emit canonical ANF JSON on stdout |
| `--source <path> --hex --disable-constant-folding` | Emit Bitcoin Script hex on stdout |
| `--ir <path> --hex` | Compile a pre-generated ANF JSON to hex |
| `--version` | Print `runar-java x.y.z` |

The Java CLI also accepts these, which this table used to omit entirely
(R-232). `--parse-only` was additionally missing from `--help`, so it was a
working flag no output mentioned:

| Flag | Behavior |
|---|---|
| `--parse-only` | Run passes 1-2 only and print `parser ok`. Used by the conformance runner's all-tier parser-only matrix |
| `--emit-ir-to <path>` | Write the same ANF JSON `--emit-ir` prints to a file and KEEP compiling, so one process yields both artefacts |
| `--emit-source-map <path>` | Write the artifact's sourceMap JSON to a path; runs independently of `--emit-ir` / `--hex` |
| `--emit-artifact <path>` | Write the deployable artifact JSON to a path |
| `--daemon` | Line-delimited JSON RPC on stdin/stdout, for the conformance runner's Java daemon |
| `-h`, `--help` | Print the flag list and exit |

`tests/r232-java-cli-flags-documented.test.ts` keeps both surfaces honest: every
flag the CLI accepts must appear in `--help` and in this table.

The conformance runner at `conformance/runner/runner.ts` exercises this
contract once the binary is registered there (milestone 4).
