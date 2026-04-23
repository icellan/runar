# examples/java

Rúnar contracts written in Java. Each contract lives in its own
subdirectory with a `.runar.java` extension and a JUnit 5 test class.

## Status

**Phase 1 — one example.** Only `p2pkh/P2PKH.runar.java` is committed,
as a surface-level sanity check that the runar-java SDK exposes enough
shape to compile a real contract. The full port of the existing
example set (30+ contracts) lands in milestone 12.

## Build & Test

```bash
cd examples/java
gradle build     # compiles against packages/runar-java
gradle test      # runs JUnit 5
```

The `.runar.java` files compile with `javac` directly — Rúnar treats
them as plain Java source until the compiler frontend (milestone 3)
reads them for AST extraction.
