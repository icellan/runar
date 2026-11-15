# Rúnar Multi-Format Input

Rúnar's canonical input format is TypeScript (`.runar.ts`). In addition, eight **experimental** alternative input formats are available. All formats compile through the same pipeline and produce identical Bitcoin Script output for equivalent contracts.

Every one of the seven compilers (TypeScript, Go, Rust, Python, Zig, Ruby, Java) parses all nine formats. That is the frontend-parity invariant in [CLAUDE.md](../../CLAUDE.md), and CI enforces it with the all-tier parser-only matrix (`conformance/runner/index.ts --parser-only`): every compiler parses every (fixture, format) pair. The one recorded exception is `FixedArray<T, N>` on the Java surface, which javac cannot parse; fixtures that use it carry a `parserSkip` entry for `.runar.java` (see [java.md](./java.md)).

---

## How It Works

The Rúnar compiler auto-detects the input format by file extension:

| Extension | Format | Description |
|-----------|--------|-------------|
| `.runar.ts` | TypeScript | Canonical format. Full IDE support via `tsc`. |
| `.runar.zig` | Zig | Native Zig syntax. |
| `.runar.sol` | Solidity-like | Familiar syntax for Ethereum developers. |
| `.runar.move` | Move-like | Resource-oriented, inspired by Sui/Aptos Move. |
| `.runar.go` | Go | Native Go syntax with struct tags. |
| `.runar.rs` | Rust DSL | Idiomatic Rust with attribute macros. |
| `.runar.py` | Python | Python syntax with decorators and snake_case. |
| `.runar.rb` | Ruby | Lightweight DSL with `prop`, `runar_public`, `@var` access. |
| `.runar.java` | Java | Plain Java classes with `@Public` / `@Readonly` annotations and `BigInteger`. |

All seven compilers accept every row of this table.

All formats parse into the same `ContractNode` AST. From that point forward, the pipeline is identical: validate, typecheck, ANF lower, optimize, stack lower, emit.

```
  .runar.ts ──┐
  .runar.zig ─┤
  .runar.sol ──┤
  .runar.move ─┤
  .runar.py ───┼──► ContractNode AST ──► Validate ──► TypeCheck ──► ANF ──► Stack ──► Bitcoin Script
  .runar.rb ───┤
  .runar.go ───┤
  .runar.rs ───┤
  .runar.java ─┘
```

---

## Format Comparison

| Feature | TypeScript | Zig | Solidity | Move | Python | Ruby | Go | Rust | Java |
|---------|-----------|-----|----------|------|--------|------|-----|------|------|
| Status | **Stable** | Experimental | Experimental | Experimental | Experimental | Experimental | Experimental | Experimental | Experimental |
| IDE support | Full (`tsc`) | Full (`zls`) | Syntax highlighting | Syntax highlighting | Full (`pyright`) | Full (Ruby LSP) | Full (`go vet`) | Full (`rustc`) | Full (`javac`) |
| Parsed by | All 7 compilers | All 7 compilers | All 7 compilers | All 7 compilers | All 7 compilers | All 7 compilers | All 7 compilers | All 7 compilers | All 7 compilers |
| Stateless contracts | Yes | Yes | Yes | Yes | Yes | Yes | Yes | Yes | Yes |
| Stateful contracts | Yes | Yes | Yes | Yes | Yes | Yes | Yes | Yes | Yes |
| `addOutput` | Yes | Yes | Yes | Yes | Yes | Yes | Yes | Yes | Yes |
| Ternary expressions | Yes | No (use `if`) | Yes | Yes | No (use if/else) | Yes | No (use if/else) | Yes | Yes |
| `FixedArray<T, N>` | Yes | Yes | Yes | Yes | Yes | Yes | Yes | Yes | No (javac parse error) |
| Learning curve (from TS) | None | Medium | Low | Medium | Low | Low | Medium | Medium | Low |

---

## Compiler Support Matrix

Each compiler has a native format (the one written in its own language), and every compiler parses all nine formats:

| Compiler | Native format | Also parses |
|----------|--------------|-------------|
| TypeScript (`runar-compiler`) | `.runar.ts` | the other eight |
| Go (`compilers/go`) | `.runar.go` | the other eight |
| Rust (`compilers/rust`) | `.runar.rs` | the other eight |
| Python (`compilers/python`) | `.runar.py` | the other eight |
| Zig (`compilers/zig`) | `.runar.zig` | the other eight |
| Ruby (`compilers/ruby`) | `.runar.rb` | the other eight |
| Java (`compilers/java`) | `.runar.java` | the other eight |

Frontend parity has no exceptions at the parser level; Stack-IR and hex parity are scoped per fixture (see the second invariant in [CLAUDE.md](../../CLAUDE.md) and `conformance/README.md`).

---

## Choosing a Format

- **TypeScript** is the recommended format for production use. It has the best tooling and is the canonical reference for the language spec.
- **Zig** is the native format for the Zig compiler. Use it when you want Zig-native syntax, the `packages/runar-zig` testing/runtime helpers, `cd examples/zig && zig build test`, and the Zig benchmark harness.
- **Solidity-like** helps Ethereum developers transfer existing knowledge. The syntax is intentionally close to Solidity but compiles to Bitcoin Script.
- **Move-like** appeals to developers from the Sui/Aptos ecosystem who prefer resource-oriented thinking.
- **Python** appeals to data science and scripting-oriented developers. Uses snake_case identifiers (auto-converted to camelCase in the AST), `@public` decorators, and indentation-based blocks.
- **Ruby** uses a lightweight DSL (`prop`, `runar_public`) that keeps types in the code channel. Idiomatic Ruby with `@var` instance variable access.
- **Go** is for teams already using the Go compiler who want to write contracts in idiomatic Go.
- **Rust DSL** is for teams already using the Rust compiler who want to write contracts in idiomatic Rust.
- **Java** is for JVM teams. Contracts are plain Java classes parsed with the JDK's own `javax.tools.JavaCompiler`; `FixedArray<T, N>` is not available on this surface.

---

## Format Reference Documents

- [TypeScript Format](./typescript.md) — canonical reference
- [Solidity-like Format](./solidity.md)
- [Move-like Format](./move.md)
- [Zig Format](./zig.md)
- [Go Format](./go.md)
- [Rust DSL Format](./rust.md)
- [Python Format](./python.md)
- [Ruby Format](./ruby.md)
- [Java Format](./java.md)

---

## Experimental Status

All non-TypeScript formats are **experimental**. This means:

1. The syntax may change in future releases without a deprecation cycle.
2. Edge cases may not be fully handled compared to the TypeScript parser.
3. Error messages from alternative parsers may be less precise than the TypeScript parser.
4. The conformance suite parses every fixture in all nine formats with all seven compilers, but edge-case coverage may lag behind the TypeScript parser for newly added language features.

The underlying compilation pipeline (validate through emit) is the same regardless of input format and is fully stable.
