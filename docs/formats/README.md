# Rúnar Multi-Format Input

Rúnar's canonical input format is TypeScript (`.runar.ts`). In addition, seven **experimental** alternative input formats are available. All formats compile through the same pipeline and produce identical Bitcoin Script output for equivalent contracts. Some are portable across multiple compilers, while others are native frontends for a smaller subset of implementations.

---

## How It Works

The Rúnar compiler auto-detects the input format by file extension:

| Extension | Format | Description |
|-----------|--------|-------------|
| `.runar.ts` | TypeScript | Canonical format. Full IDE support via `tsc`. |
| `.runar.zig` | Zig | Native Zig syntax. Parsed by the TypeScript and Zig compilers. |
| `.runar.sol` | Solidity-like | Familiar syntax for Ethereum developers. |
| `.runar.move` | Move-like | Resource-oriented, inspired by Sui/Aptos Move. |
| `.runar.go` | Go | Native Go syntax with struct tags. Go and Python compilers. |
| `.runar.rs` | Rust DSL | Idiomatic Rust with attribute macros. Rust and Python compilers. |
| `.runar.py` | Python | Python syntax with decorators and snake_case. All compilers. |
| `.runar.rb` | Ruby | Lightweight DSL with `prop`, `runar_public`, `@var` access. |

All formats parse into the same `ContractNode` AST. From that point forward, the pipeline is identical: validate, typecheck, ANF lower, optimize, stack lower, emit.

```
  .runar.ts ──┐
  .runar.zig ─┤
  .runar.sol ──┤
  .runar.move ─┤
  .runar.py ───┼──► ContractNode AST ──► Validate ──► TypeCheck ──► ANF ──► Stack ──► Bitcoin Script
  .runar.rb ───┤
  .runar.go ───┤
  .runar.rs ───┘
```

---

## Format Comparison

| Feature | TypeScript | Zig | Solidity | Move | Python | Ruby | Go | Rust |
|---------|-----------|-----|----------|------|--------|------|-----|------|
| Status | **Stable** | Experimental | Experimental | Experimental | Experimental | Experimental | Experimental | Experimental |
| IDE support | Full (`tsc`) | Full (`zls`) | Syntax highlighting | Syntax highlighting | Full (`pyright`) | Basic | Full (`go vet`) | Full (`rustc`) |
| TS compiler | Yes | Yes | Yes | Yes | Yes | Yes | No | No |
| Zig compiler | Yes | **Yes (native)** | No | No | No | No | No | No |
| Go compiler | Yes | No | Yes | Yes | Yes | Yes | **Yes (native)** | No |
| Rust compiler | Yes | No | Yes | Yes | Yes | Yes | No | **Yes (native)** |
| Python compiler | Yes | No | Yes | Yes | **Yes (native)** | Yes | Yes | Yes |
| Stateless contracts | Yes | Yes | Yes | Yes | Yes | Yes | Yes | Yes |
| Stateful contracts | Yes | Yes | Yes | Yes | Yes | Yes | Yes | Yes |
| `addOutput` | Yes | Yes | Yes | Yes | Yes | Yes | Yes | Yes |
| Ternary expressions | Yes | No (use `if`) | Yes | Yes | No (use if/else) | Yes | No (use if/else) | Yes |
| Learning curve (from TS) | None | Medium | Low | Medium | Low | Low | Medium | Medium |

---

## Compiler Support Matrix

Each compiler has a primary native format plus support for the shared formats:

| Compiler | Native format | Also supports |
|----------|--------------|---------------|
| TypeScript (`runar-compiler`) | `.runar.ts` | `.runar.zig`, `.runar.sol`, `.runar.move`, `.runar.py`, `.runar.rb` |
| Zig (`compilers/zig`) | `.runar.zig` | `.runar.ts`, ANF IR JSON |
| Go (`compilers/go`) | `.runar.go` | `.runar.ts`, `.runar.sol`, `.runar.move`, `.runar.py`, `.runar.rb` |
| Rust (`compilers/rust`) | `.runar.rs` | `.runar.ts`, `.runar.sol`, `.runar.move`, `.runar.py`, `.runar.rb` |
| Python (`compilers/python`) | `.runar.py` | `.runar.ts`, `.runar.sol`, `.runar.move`, `.runar.go`, `.runar.rs`, `.runar.rb` |

The broadest portable formats today are `.runar.ts`, `.runar.sol`, `.runar.move`, and `.runar.rb`. Ruby is supported by the TypeScript, Go, Rust, and Python compilers. Python is supported by the TypeScript, Go, Rust, and Python compilers. Zig is supported by the TypeScript and Zig compilers. Go and Rust remain native formats for the Go/Python and Rust/Python compiler pairs, respectively.

---

## Choosing a Format

- **TypeScript** is the recommended format for production use. It has the best tooling, is the canonical reference for the language spec, and is supported by all compilers.
- **Zig** is the native format for the Zig compiler and is also understood by the TypeScript compiler for shared AST/script conformance. Use it when you want Zig-native syntax, the `packages/runar-zig` testing/runtime helpers, `cd examples/zig && zig build test`, and the Zig benchmark harness.
- **Solidity-like** helps Ethereum developers transfer existing knowledge. The syntax is intentionally close to Solidity but compiles to Bitcoin Script.
- **Move-like** appeals to developers from the Sui/Aptos ecosystem who prefer resource-oriented thinking.
- **Python** appeals to data science and scripting-oriented developers. Uses snake_case identifiers (auto-converted to camelCase in the AST), `@public` decorators, and indentation-based blocks.
- **Ruby** uses a lightweight DSL (`prop`, `runar_public`) that keeps types in the code channel. Idiomatic Ruby with `@var` instance variable access.
- **Go** is for teams already using the Go compiler who want to write contracts in idiomatic Go.
- **Rust DSL** is for teams already using the Rust compiler who want to write contracts in idiomatic Rust.

---

## Format Reference Documents

- [Solidity-like Format](./solidity.md)
- [Move-like Format](./move.md)
- [Zig Format](./zig.md)
- [Go Format](./go.md)
- [Rust DSL Format](./rust.md)
- [Python Format](./python.md)
- [Ruby Format](./ruby.md)

---

## Experimental Status

All non-TypeScript formats are **experimental**. This means:

1. The syntax may change in future releases without a deprecation cycle.
2. Edge cases may not be fully handled compared to the TypeScript parser.
3. Error messages from alternative parsers may be less precise than the TypeScript parser.
4. The conformance test suite covers the portable frontends and growing native frontend coverage, but edge-case coverage may lag behind the TypeScript parser for newly added language features.

The underlying compilation pipeline (validate through emit) is the same regardless of input format and is fully stable.
