# Rúnar — TypeScript-to-Bitcoin Script Compiler

## Project Overview

Rúnar compiles a strict subset of TypeScript into Bitcoin SV Script. Developers write smart contracts as TypeScript classes extending `SmartContract` (stateless) or `StatefulSmartContract` (stateful), and the compiler produces Bitcoin Script locking scripts.

Six independent compiler implementations (TypeScript, Go, Rust, Python, Zig, Ruby) must produce identical output for the same input. Contracts can also be written in Solidity-like, Move-style, Go, Rust DSL, Python, Zig, or Ruby syntax — all formats compile to the same AST and produce identical Bitcoin Script.

## Repository Structure

```
packages/
  runar-lang/          # Language: base classes, types, builtins (developer imports)
  runar-compiler/      # TypeScript compiler: parser → validator → typecheck → ANF → stack → emit
  runar-ir-schema/     # Shared IR type definitions and JSON schemas
  runar-testing/       # TestContract API, Script VM, interpreter, fuzzer
  runar-sdk/           # Deployment SDK (providers, signers, contract interaction)
  runar-cli/           # CLI tool
  runar-go/            # Go package: types, mock crypto, real hashes, CompileCheck(), deployment SDK
  runar-rs/            # Rust crate: prelude types, mock crypto, real hashes, compile_check(), deployment SDK
  runar-rs-macros/     # Rust proc-macro crate: #[runar::contract], #[public], #[readonly]
  runar-py/            # Python package: types, mock crypto, real hashes, EC operations, deployment SDK
  runar-zig/           # Zig package: types, mock crypto, real hashes, deployment SDK
  runar-rb/            # Ruby gem: types, mock crypto, real hashes, deployment SDK
compilers/
  go/                 # Go compiler implementation
  rust/               # Rust compiler implementation
  python/             # Python compiler implementation
  zig/                # Zig compiler implementation
  ruby/               # Ruby compiler implementation
conformance/          # Cross-compiler conformance test suite (multi-format)
examples/
  ts/                 # TypeScript contracts + vitest tests
  go/                 # Go contracts + go test (native Go tests + Rúnar compile checks)
  rust/               # Rust contracts + cargo test (native Rust tests + Rúnar compile checks)
  sol/                # Solidity-like contracts + vitest tests
  move/               # Move-style contracts + vitest tests
  python/             # Python contracts + pytest tests
  sdk-usage/          # SDK usage reference docs (not runnable)
end2end-example/      # End-to-end example (ts, go, rust, sol, move, webapp, webapp-blackjack)
spec/                 # Language specification (grammar, semantics, type system)
docs/                 # User-facing documentation
  formats/            # Format-specific guides (solidity.md, move.md, go.md, rust.md, python.md)
integration/          # On-chain integration tests (ts, go, rust, python) + regtest tooling
go.work              # Go workspace: compilers/go + conformance + end2end-example/go + end2end-example/webapp + end2end-example/webapp-blackjack + examples/go + integration/go + packages/runar-go
```

## Build & Test

```bash
pnpm install                                    # Install dependencies
pnpm run build                                  # Build all packages (turbo)
npx vitest run                                  # Run all TypeScript tests (packages + all format examples)
cd compilers/go && go test ./...                # Run Go compiler tests
cd compilers/rust && cargo test                 # Run Rust compiler tests
cd packages/runar-go && go test ./...           # Run Go SDK + mock package tests
cd packages/runar-rs && cargo test              # Run Rust SDK + crate tests
cd examples/go && go test ./...                 # Run Go contract tests (business logic + Rúnar compile check)
cd examples/rust && cargo test                  # Run Rust contract tests (business logic + Rúnar compile check)
cd packages/runar-py && python3 -m pytest       # Run Python SDK + package tests
cd examples/python && PYTHONPATH=../../packages/runar-py python3 -m pytest  # Run Python contract tests
cd compilers/zig && zig build test              # Run Zig compiler tests
cd compilers/ruby && rake test                  # Run Ruby compiler tests
cd packages/runar-zig && zig build test         # Run Zig SDK + package tests
```

## Compiler Pipeline

Each pass is a pure function in `packages/runar-compiler/src/passes/`:

1. **01-parse.ts** — Source → Rúnar AST (`ContractNode`). Auto-dispatches by file extension:
   - `.runar.ts` → TypeScript parser (ts-morph)
   - `.runar.sol` → Solidity-like parser (hand-written recursive descent)
   - `.runar.move` → Move-style parser (hand-written recursive descent)
   - `.runar.py` → Python parser (hand-written tokenizer with INDENT/DEDENT + recursive descent)
2. **02-validate.ts** — Language subset constraints (no mutation of the AST)
3. **03-typecheck.ts** — Type consistency verification. Rejects calls to non-Rúnar functions (Math.floor, console.log, etc.)
4. **04-anf-lower.ts** — AST → A-Normal Form IR (flattened let-bindings)
5. **05-stack-lower.ts** — ANF → Stack IR (Bitcoin Script stack operations)
6. **06-emit.ts** — Stack IR → hex-encoded Bitcoin Script

The constant folding optimizer (`src/optimizer/constant-fold.ts`) is available between passes 4 and 5 but disabled by default to preserve ANF conformance (see whitepaper Section 4.5).
The peephole optimizer (`src/optimizer/peephole.ts`) runs on Stack IR between passes 5 and 6 (always enabled).

Go, Rust, and Python compilers have their own parser dispatch:
- Go: `frontend.ParseSource()` handles `.runar.ts`, `.runar.sol`, `.runar.move`, `.runar.go`, `.runar.py`
- Rust: `parser::parse_source()` handles `.runar.ts`, `.runar.sol`, `.runar.move`, `.runar.rs`, `.runar.py`
- Python: `parse_source()` handles `.runar.ts`, `.runar.sol`, `.runar.move`, `.runar.go`, `.runar.rs`, `.runar.py`

## Key Conventions

### AST Types Are Defined in Two Places
`packages/runar-compiler/src/ir/runar-ast.ts` and `packages/runar-ir-schema/src/runar-ast.ts` must stay in sync. Both define `ContractNode`, `PropertyNode`, `MethodNode`, etc.

### Adding a New ANF Value Kind
When adding a new ANF IR node (like `add_output`), update ALL of these:
- `packages/runar-compiler/src/ir/anf-ir.ts` — add interface + union member
- `packages/runar-compiler/src/passes/04-anf-lower.ts` — emit the new node
- `packages/runar-compiler/src/passes/05-stack-lower.ts` — handle in `lowerBinding` dispatch + `collectRefs`
- `packages/runar-compiler/src/optimizer/constant-fold.ts` — add to `foldValue`, `collectRefsFromValue`, `hasSideEffect`
- `compilers/go/ir/types.go` — add fields to `ANFValue` struct
- `compilers/go/ir/loader.go` — add to `knownKinds`
- `compilers/go/codegen/stack.go` — add to `collectRefs` + `lowerBinding` dispatch
- `compilers/go/frontend/anf_lower.go` — emit the new node
- `compilers/rust/src/ir/mod.rs` — add enum variant to `ANFValue`
- `compilers/rust/src/ir/loader.rs` — add to `KNOWN_KINDS` + `kind_name`
- `compilers/rust/src/codegen/stack.rs` — add to `collect_refs` + `lower_binding` dispatch
- `compilers/rust/src/frontend/anf_lower.rs` — emit the new node
- `compilers/python/runar_compiler/ir/types.py` — add to ANF value types
- `compilers/python/runar_compiler/frontend/anf_lower.py` — emit the new node
- `compilers/python/runar_compiler/codegen/stack.py` — add to `collect_refs` + `lower_binding` dispatch
- `compilers/zig/src/ir/types.zig` — add to ANF value types
- `compilers/zig/src/frontend/anf_lower.zig` — emit the new node
- `compilers/zig/src/codegen/stack.zig` — add to `collectRefs` + `lowerBinding` dispatch
- `compilers/ruby/lib/ir/types.rb` — add to ANF value types
- `compilers/ruby/lib/frontend/anf_lower.rb` — emit the new node
- `compilers/ruby/lib/codegen/stack.rb` — add to `collect_refs` + `lower_binding` dispatch

### Adding a New Input Format Parser
When adding a new frontend format parser:
- Add the parser file in `packages/runar-compiler/src/passes/01-parse-{format}.ts`
- Add dispatch case in `01-parse.ts` based on file extension
- Export from `packages/runar-compiler/src/index.ts`
- Add equivalent parser in Go (`compilers/go/frontend/parser_{format}.go`), Rust (`compilers/rust/src/frontend/parser_{format}.rs`), Python (`compilers/python/runar_compiler/frontend/parser_{format}.py`), Zig (`compilers/zig/src/frontend/parser_{format}.zig`), and Ruby (`compilers/ruby/lib/frontend/parser_{format}.rb`)
- Add dispatch in Go `ParseSource()`, Rust `parse_source()`, Python `parse_source()`, Zig `parseSource()`, and Ruby `parse_source()`
- Auto-generated constructors MUST include `super()` as the first statement
- Type names must map to Rúnar primitives (e.g., `int` → `bigint`, `Int` → `bigint`)
- Add format docs in `docs/formats/`

### Six Compilers Must Stay in Sync
Any language feature change must be implemented in TypeScript, Go, Rust, Python, Zig, AND Ruby. Cross-compiler tests in `packages/runar-compiler/src/__tests__/cross-compiler.test.ts` validate consistency. The conformance suite in `conformance/` has golden-file tests (including WOTS+, SLH-DSA, and EC primitives) that all 6 compilers must pass. The SDK output conformance suite in `conformance/sdk-output/` verifies all 6 SDKs produce identical deployed locking scripts.

### Contract Model
- `SmartContract` — stateless, all properties `readonly`, developer writes full logic
- `StatefulSmartContract` — compiler auto-injects `checkPreimage` at method entry and state continuation at exit
- `this.addOutput(satoshis, ...values)` — multi-output intrinsic; values are positional matching mutable properties in declaration order
- `this.addRawOutput(satoshis, scriptBytes)` — raw output intrinsic; creates an output with caller-specified script bytes instead of the contract's own codePart
- `parentClass` field on `ContractNode` discriminates between the two base classes
- Only Rúnar built-in functions and contract methods are allowed — the type checker rejects calls to unknown functions like `Math.floor()` or `console.log()`
- **Property initializers**: Properties can have `= value` defaults (literal values only: BigIntLiteral, BoolLiteral, ByteStringLiteral). Initialized properties are excluded from auto-generated constructors. Go/Rust DSL formats use a private `init()` method pattern instead of inline syntax. The AST `PropertyNode` has an optional `initializer` field; ANF `initialValue` is populated from it.

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

**Python** (pytest):
```python
from conftest import load_contract
from runar import hash160, mock_sig, mock_pub_key

contract_mod = load_contract("P2PKH.runar.py")
P2PKH = contract_mod.P2PKH

def test_unlock():
    pk = mock_pub_key()
    c = P2PKH(pub_key_hash=hash160(pk))
    c.unlock(mock_sig(), pk)
```

`TestContract` uses the interpreter (not the VM) — it tests business logic with mocked crypto (`checkSig` always true, `checkPreimage` always true). Go, Rust, and Python tests run contracts as native code with mock types from the `runar` package/crate.

The `CompileCheck` / `compile_check` functions run the contract through the Rúnar frontend (parse → validate → typecheck) to verify it's valid Rúnar that will compile to Bitcoin Script.

### Deployment SDK (4 languages)

All four languages have equivalent deployment SDKs for interacting with compiled contracts on-chain:

**TypeScript** (`packages/runar-sdk/`): `RunarContract`, `MockProvider`, `WhatsOnChainProvider`, `LocalSigner` (wraps @bsv/sdk for ECDSA + BIP-143), `buildDeployTransaction`, `buildCallTransaction`, state serialization.

**Go** (`packages/runar-go/sdk_*.go`): `RunarContract`, `MockProvider`, `LocalSigner` (wraps go-sdk for ECDSA + BIP-143), `MockSignerImpl`/`ExternalSigner`, `BuildDeployTransaction`, `BuildCallTransaction`, state serialization.

**Rust** (`packages/runar-rs/src/sdk/`): `RunarContract`, `MockProvider`, `LocalSigner` (k256 ECDSA + manual BIP-143), `MockSigner`/`ExternalSigner`, `build_deploy_transaction`, `build_call_transaction`, state serialization.

**Python** (`packages/runar-py/runar/sdk/`): `RunarContract`, `MockProvider`, `MockSigner`/`ExternalSigner`, `build_deploy_transaction`, `build_call_transaction`, state serialization. Zero required dependencies (hashlib is stdlib). Python contracts use snake_case names which the parser converts to camelCase in the AST.

Key SDK concepts:
- `RunarContract` wraps a compiled artifact + constructor args, manages state and UTXO tracking
- `Provider` interface abstracts blockchain access (UTXO lookup, tx broadcast)
- `Signer` interface abstracts key management (sign, get pubkey, get address)
- State is serialized as Bitcoin Script push data after an OP_RETURN separator
- Constructor args are spliced into the locking script at byte offsets specified by `constructorSlots`
- UTXO selection uses largest-first strategy with fee-aware iteration
- Fee estimation uses actual script sizes (not hardcoded P2PKH assumptions)

### Module Resolution
- pnpm workspace packages are not hoisted to root `node_modules`. The `vitest.config.ts` at root provides aliases so `examples/` tests can import `runar-testing` by name.
- `go.work` at the project root connects `compilers/go`, `conformance`, `end2end-example/go`, `end2end-example/webapp`, `end2end-example/webapp-blackjack`, `examples/go`, and `packages/runar-go` so `import runar "github.com/icellan/runar/packages/runar-go"` resolves everywhere.
- Rust example tests use `Cargo.toml` at `examples/rust/` with `[[test]]` entries pointing to each contract's `_test.rs` file.

## Style

- No decorators in the Rúnar language (except Python format which uses `@public`) — TypeScript's own keywords (`public`, `private`, `readonly`) provide all expressiveness
- Python contracts use snake_case identifiers which the parser converts to camelCase in the AST (`pub_key_hash` → `pubKeyHash`, `check_sig` → `checkSig`). Uses `Readonly[T]` for readonly properties in stateful contracts, `//` for integer division, `and`/`or`/`not` for boolean operators, and `assert_(expr)` or `assert expr` for assertions
- One contract class per source file
- Constructor must call `super(...)` as first statement, passing all properties
- Public methods are spending entry points; private methods are inlined helpers
- `assert()` is the primary control mechanism — scripts fail if any assert is false
- Only Rúnar built-in functions are allowed — no arbitrary function calls (Math, console, etc.)
- Built-in math functions: `abs`, `min`, `max`, `within`, `safediv`, `safemod`, `clamp`, `sign`, `pow`, `mulDiv`, `percentOf`, `sqrt`, `gcd`, `divmod`, `log2`, `bool`
- Built-in EC (secp256k1) functions: `ecAdd`, `ecMul`, `ecMulGen`, `ecNegate`, `ecOnCurve`, `ecModReduce`, `ecEncodeCompressed`, `ecMakePoint`, `ecPointX`, `ecPointY`
- `Point` type: 64-byte ByteString subtype (x[32] || y[32], big-endian unsigned, no prefix byte). EC constants: `EC_P`, `EC_N`, `EC_G` (from `runar-lang/src/ec.ts`)
- Shift operators `<<` and `>>` compile to `OP_LSHIFT` and `OP_RSHIFT`
- Bitwise operators (`&`, `|`, `^`, `~`) work on both `bigint` and `ByteString` operands
- `sha256Compress(state, block)` and `sha256Finalize(state, remaining, msgBitLen)` for partial SHA-256 verification
- `this.addRawOutput(satoshis, scriptBytes)` creates outputs with arbitrary script bytes (not stateful continuations)
- OP_CODESEPARATOR is automatically inserted for stateful contracts; artifact includes `codeSeparatorIndex` and `codeSeparatorIndices` fields
- Post-quantum signature verification (experimental): `verifyWOTS` (one-time, ~10 KB script), `verifySLHDSA_SHA2_*` (6 FIPS 205 parameter sets, 200-900 KB scripts)
- SLH-DSA codegen lives in a separate module: `packages/runar-compiler/src/passes/slh-dsa-codegen.ts` (TS), `compilers/go/codegen/slh_dsa.go` (Go), `compilers/rust/src/codegen/slh_dsa.rs` (Rust), `compilers/python/runar_compiler/codegen/slh_dsa.py` (Python)
- EC codegen lives in a separate module: `packages/runar-compiler/src/passes/ec-codegen.ts` (TS), `compilers/go/codegen/ec.go` (Go), `compilers/rust/src/codegen/ec.rs` (Rust), `compilers/python/runar_compiler/codegen/ec.py` (Python)
- SHA-256 codegen lives in a separate module: `packages/runar-compiler/src/passes/sha256-codegen.ts` (TS), `compilers/go/codegen/sha256.go` (Go), `compilers/rust/src/codegen/sha256.rs` (Rust), `compilers/python/runar_compiler/codegen/sha256.py` (Python)
