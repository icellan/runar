# Rúnar — TypeScript-to-Bitcoin Script Compiler

## Project Overview

Rúnar compiles a strict subset of TypeScript into Bitcoin SV Script. Developers write smart contracts as TypeScript classes extending `SmartContract` (stateless) or `StatefulSmartContract` (stateful), and the compiler produces Bitcoin Script locking scripts.

Three independent compiler implementations (TypeScript, Go, Rust) must produce identical output for the same input. Contracts can also be written in Solidity-like, Move-style, Go, or Rust DSL syntax — all formats compile to the same AST and produce identical Bitcoin Script.

## Repository Structure

```
packages/
  runar-lang/          # Language: base classes, types, builtins (developer imports)
  runar-compiler/      # TypeScript compiler: parser → validator → typecheck → ANF → stack → emit
  runar-ir-schema/     # Shared IR type definitions and JSON schemas
  runar-testing/       # TestContract API, Script VM, interpreter, fuzzer
  runar-sdk/           # Deployment SDK (providers, signers, contract interaction)
  runar-cli/           # CLI tool
  runar-go/            # Go mock package: types, mock crypto, real hashes, CompileCheck()
  runar-rs/            # Rust mock crate: prelude types, mock crypto, real hashes, compile_check()
  runar-rs-macros/     # Rust proc-macro crate: #[runar::contract], #[public], #[readonly]
compilers/
  go/                 # Go compiler implementation
  rust/               # Rust compiler implementation
conformance/          # Cross-compiler conformance test suite (multi-format)
examples/
  ts/                 # TypeScript contracts + vitest tests
  go/                 # Go contracts + go test (native Go tests + Rúnar compile checks)
  rust/               # Rust contracts + cargo test (native Rust tests + Rúnar compile checks)
  sol/                # Solidity-like contracts + vitest tests
  move/               # Move-style contracts + vitest tests
  sdk-usage/          # SDK usage reference docs (not runnable)
spec/                 # Language specification (grammar, semantics, type system)
docs/                 # User-facing documentation
  formats/            # Format-specific guides (solidity.md, move.md, go.md, rust.md)
go.work              # Go workspace: compilers/go + examples/go + conformance + packages/runar-go
```

## Build & Test

```bash
pnpm install                                    # Install dependencies
pnpm run build                                  # Build all packages (turbo)
npx vitest run                                  # Run all TypeScript tests (packages + all format examples)
cd compilers/go && go test ./...                # Run Go compiler tests
cd compilers/rust && cargo test                 # Run Rust compiler tests
cd examples/go && go test ./...                 # Run Go contract tests (business logic + Rúnar compile check)
cd examples/rust && cargo test                  # Run Rust contract tests (business logic + Rúnar compile check)
```

## Compiler Pipeline

Each pass is a pure function in `packages/runar-compiler/src/passes/`:

1. **01-parse.ts** — Source → Rúnar AST (`ContractNode`). Auto-dispatches by file extension:
   - `.runar.ts` → TypeScript parser (ts-morph)
   - `.runar.sol` → Solidity-like parser (hand-written recursive descent)
   - `.runar.move` → Move-style parser (hand-written recursive descent)
2. **02-validate.ts** — Language subset constraints (no mutation of the AST)
3. **03-typecheck.ts** — Type consistency verification. Rejects calls to non-Rúnar functions (Math.floor, console.log, etc.)
4. **04-anf-lower.ts** — AST → A-Normal Form IR (flattened let-bindings)
5. **05-stack-lower.ts** — ANF → Stack IR (Bitcoin Script stack operations)
6. **06-emit.ts** — Stack IR → hex-encoded Bitcoin Script

The optimizer (`src/optimizer/constant-fold.ts`) runs between passes 4 and 5.

Go and Rust compilers have their own parser dispatch:
- Go: `frontend.ParseSource()` handles `.runar.ts`, `.runar.sol`, `.runar.move`, `.runar.go`
- Rust: `parser::parse_source()` handles `.runar.ts`, `.runar.sol`, `.runar.move`, `.runar.rs`

## Key Conventions

### AST Types Are Defined in Two Places
`packages/runar-compiler/src/ir/runar-ast.ts` and `packages/runar-ir-schema/src/runar-ast.ts` must stay in sync. Both define `ContractNode`, `PropertyNode`, `MethodNode`, etc.

### Adding a New ANF Value Kind
When adding a new ANF IR node (like `add_output`), update ALL of these:
- `packages/runar-compiler/src/ir/anf-ir.ts` — add interface + union member
- `packages/runar-compiler/src/passes/04-anf-lower.ts` — emit the new node
- `packages/runar-compiler/src/passes/05-stack-lower.ts` — handle in `lowerBinding` dispatch + `collectRefs`
- `packages/runar-compiler/src/optimizer/constant-fold.ts` — add to `foldValue`, `collectRefsInValue`, `hasSideEffects`
- `compilers/go/ir/types.go` — add fields to `ANFValue` struct
- `compilers/go/ir/loader.go` — add to `knownKinds`
- `compilers/go/codegen/stack.go` — add to `collectRefs` + `lowerBinding` dispatch
- `compilers/go/frontend/anf_lower.go` — emit the new node
- `compilers/rust/src/ir/mod.rs` — add enum variant to `ANFValue`
- `compilers/rust/src/ir/loader.rs` — add to `KNOWN_KINDS` + `kind_name`
- `compilers/rust/src/codegen/stack.rs` — add to `collect_refs` + `lower_binding` dispatch
- `compilers/rust/src/frontend/anf_lower.rs` — emit the new node

### Adding a New Input Format Parser
When adding a new frontend format parser:
- Add the parser file in `packages/runar-compiler/src/passes/01-parse-{format}.ts`
- Add dispatch case in `01-parse.ts` based on file extension
- Export from `packages/runar-compiler/src/index.ts`
- Add equivalent parser in Go (`compilers/go/frontend/parser_{format}.go`) and Rust (`compilers/rust/src/frontend/parser_{format}.rs`)
- Add dispatch in Go `ParseSource()` and Rust `parse_source()`
- Auto-generated constructors MUST include `super()` as the first statement
- Type names must map to Rúnar primitives (e.g., `int` → `bigint`, `Int` → `bigint`)
- Add format docs in `docs/formats/`

### Three Compilers Must Stay in Sync
Any language feature change must be implemented in TypeScript, Go, AND Rust. Cross-compiler tests in `packages/runar-compiler/src/__tests__/cross-compiler.test.ts` validate consistency. The conformance suite in `conformance/` has 9 golden-file tests (including WOTS+ and SLH-DSA) that all 3 compilers must pass.

### Contract Model
- `SmartContract` — stateless, all properties `readonly`, developer writes full logic
- `StatefulSmartContract` — compiler auto-injects `checkPreimage` at method entry and state continuation at exit
- `this.addOutput(satoshis, ...values)` — multi-output intrinsic; values are positional matching mutable properties in declaration order
- `parentClass` field on `ContractNode` discriminates between the two base classes
- Only Rúnar built-in functions and contract methods are allowed — the type checker rejects calls to unknown functions like `Math.floor()` or `console.log()`

### Testing Contracts

**TypeScript** (vitest):
```typescript
import { TestContract } from 'runar-testing';

const counter = TestContract.fromSource(source, { count: 0n });
counter.call('increment');
expect(counter.state.count).toBe(1n);

// Multi-format: pass fileName to select parser
const solCounter = TestContract.fromSource(solSource, { count: 0n }, 'Counter.runar.sol');
```

**Go** (go test):
```go
func TestCounter_Increment(t *testing.T) {
    c := &Counter{Count: 0}
    c.Increment()
    if c.Count != 1 { t.Errorf("expected 1, got %d", c.Count) }
}

func TestCounter_Compile(t *testing.T) {
    if err := runar.CompileCheck("Counter.runar.go"); err != nil {
        t.Fatalf("Rúnar compile check failed: %v", err)
    }
}
```

**Rust** (cargo test):
```rust
#[path = "Counter.runar.rs"]
mod contract;
use contract::*;

#[test]
fn test_increment() {
    let mut c = Counter { count: 0 };
    c.increment();
    assert_eq!(c.count, 1);
}

#[test]
fn test_compile() {
    runar::compile_check(include_str!("Counter.runar.rs"), "Counter.runar.rs").unwrap();
}
```

`TestContract` uses the interpreter (not the VM) — it tests business logic with mocked crypto (`checkSig` always true, `checkPreimage` always true). Go and Rust tests run contracts as native code with mock types from the `runar` package/crate.

The `CompileCheck` / `compile_check` functions run the contract through the Rúnar frontend (parse → validate → typecheck) to verify it's valid Rúnar that will compile to Bitcoin Script.

### Module Resolution
- pnpm workspace packages are not hoisted to root `node_modules`. The `vitest.config.ts` at root provides aliases so `examples/` tests can import `runar-testing` by name.
- `go.work` at the project root connects `compilers/go`, `examples/go`, `conformance`, and `packages/runar-go` so `import "runar"` resolves everywhere.
- Rust example tests use `Cargo.toml` at `examples/rust/` with `[[test]]` entries pointing to each contract's `_test.rs` file.

## Style

- No decorators in the Rúnar language — TypeScript's own keywords (`public`, `private`, `readonly`) provide all expressiveness
- One contract class per source file
- Constructor must call `super(...)` as first statement, passing all properties
- Public methods are spending entry points; private methods are inlined helpers
- `assert()` is the primary control mechanism — scripts fail if any assert is false
- Only Rúnar built-in functions are allowed — no arbitrary function calls (Math, console, etc.)
- Built-in math functions: `abs`, `min`, `max`, `within`, `safediv`, `safemod`, `clamp`, `sign`, `pow`, `mulDiv`, `percentOf`, `sqrt`, `gcd`, `divmod`, `log2`, `bool`
- Shift operators `<<` and `>>` compile to `OP_LSHIFT` and `OP_RSHIFT`
- Post-quantum signature verification (experimental): `verifyWOTS` (one-time, ~10 KB script), `verifySLHDSA_SHA2_*` (6 FIPS 205 parameter sets, 200-900 KB scripts)
- SLH-DSA codegen lives in a separate module: `packages/runar-compiler/src/passes/slh-dsa-codegen.ts` (TS), `compilers/go/codegen/slh_dsa.go` (Go), `compilers/rust/src/codegen/slh_dsa.rs` (Rust)
