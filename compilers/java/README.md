# Rúnar Java Compiler

Reference implementation of the Rúnar compiler pipeline in Java. Compiles
`.runar.java` (and the other Rúnar input formats, once milestone 7 lands)
to Bitcoin SV Script, producing byte-identical output to the other six
compilers in this repository.

## Status

**Phase 1 — skeleton.** CLI stub prints version and rejects flags with an
explicit "not yet implemented" error. No pipeline passes are wired up
yet; see [`docs/java-tier-plan.md`](../../docs/java-tier-plan.md) for the
milestone sequence.

## Requirements

- JDK 17 (compile target). JDK 21 LTS works for local development.
- Gradle 8.5+. Install via [SDKMAN!](https://sdkman.io/) or Homebrew
  (`brew install gradle`). CI uses `gradle/actions/setup-gradle@v3` so
  no wrapper jar is committed initially.

First-time contributors can generate the Gradle wrapper once:

```bash
cd compilers/java
gradle wrapper --gradle-version 8.10
```

## Build & Run

```bash
cd compilers/java
gradle build              # compile + run tests
gradle installDist        # produce an executable layout under build/install/
./build/install/runar-java-compiler/bin/runar-java --version
```

## CLI Contract (target)

Every Rúnar compiler binary must accept the following flags. The Java
CLI currently stubs all of these; real behavior lands in milestones 3–6.

| Flag combination | Behavior |
|---|---|
| `--source <path> --emit-ir --disable-constant-folding` | Emit canonical ANF JSON on stdout |
| `--source <path> --hex --disable-constant-folding` | Emit Bitcoin Script hex on stdout |
| `--ir <path> --hex` | Compile a pre-generated ANF JSON to hex |
| `--version` | Print `runar-java x.y.z` |

The conformance runner at `conformance/runner/runner.ts` exercises this
contract once the binary is registered there (milestone 4).
