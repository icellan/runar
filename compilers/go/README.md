# Rúnar Go Compiler

**Alternative Rúnar compiler implemented in Go.**

---

## Status

| Phase | Description | Status |
|---|---|---|
| **Phase 1** | IR consumer: accepts canonical ANF IR JSON, performs stack lowering and emission (Passes 5-6). | Implemented |
| **Phase 2** | Full frontend: parses `.runar.ts` source files directly (Passes 1-4), produces canonical ANF IR. | Implemented |

Phase 1 validates that the Go implementation can produce identical Bitcoin Script from the same ANF IR as the reference compiler. Phase 2 adds an independent frontend that must produce byte-identical ANF IR.

---

## Architecture

### Phase 1: IR Consumer

```
  ANF IR (JSON)  -->  [Stack Lower]  -->  [Peephole]  -->  [Emit]  -->  Bitcoin Script
                      Go pass 5         Optimize        Go pass 6
```

The Go compiler reads the canonical ANF IR JSON (produced by the TS reference compiler or any other conforming compiler) and performs stack scheduling and opcode emission. This is the simplest path to a working alternative backend.

### Phase 2: Full Frontend

```
  .runar.ts  -->  [Parse]  -->  [Validate]  -->  [Typecheck]  -->  [ANF Lower]
                tree-sitter    Go pass 2        Go pass 3        Go pass 4
                frontend
                                                                     |
                                                                     v
                                                                 ANF IR (JSON)
                                                                     |
                                                                     v
            [Stack Lower]  -->  [Peephole]  -->  [Emit]  -->  Bitcoin Script
            Go pass 5          Optimize        Go pass 6
```

The parsing frontend uses **tree-sitter-typescript** for parsing `.runar.ts` files. tree-sitter provides a concrete syntax tree (CST) that the Go code walks to build the Rúnar AST. This avoids depending on the TypeScript compiler.

Why tree-sitter instead of a custom parser? Rúnar source files are valid TypeScript. Parsing TypeScript correctly (including its expression grammar, ASI rules, and contextual keywords) is non-trivial. tree-sitter has a battle-tested TypeScript grammar maintained by the tree-sitter community.

Multi-format source files (`.runar.sol`, `.runar.move`, `.runar.go`, `.runar.py`) are parsed by hand-written recursive descent parsers that produce the same Rúnar AST.

### Dedicated Codegen Modules

- `codegen/ec.go` — EC point operations (`ecAdd`, `ecMul`, `ecMulGen`, `ecNegate`, `ecOnCurve`, etc.)
- `codegen/slh_dsa.go` — SLH-DSA (SPHINCS+) signature verification
- `codegen/optimizer.go` — Peephole optimizer (runs on Stack IR between stack lowering and emit)

### ANF EC Optimizer (Pass 4.5)

The `frontend/anf_optimize.go` module implements 12 algebraic EC simplification rules that run between ANF lowering and stack lowering. This pass is always enabled and eliminates redundant EC operations (e.g., `ecAdd(P, ecNegate(P))` → identity, `ecMul(G, k)` → `ecMulGen(k)`).

---

## Building

```bash
cd compilers/go
go build -o runar-compiler-go .
```

### Prerequisites

- Go 1.26+
- cgo support (for tree-sitter TypeScript parser, bundled via go-tree-sitter)

---

## Running

### Phase 1: IR Consumer Mode

```bash
# Compile from ANF IR to Bitcoin Script (full artifact JSON)
runar-compiler-go --ir input-anf.json

# Output only the script hex
runar-compiler-go --ir input-anf.json --hex

# Output only the script ASM
runar-compiler-go --ir input-anf.json --asm

# Write output to a file
runar-compiler-go --ir input-anf.json --output artifact.json
```

### Phase 2: Full Compilation

```bash
# Full compilation from source (outputs artifact JSON)
runar-compiler-go --source MyContract.runar.ts

# Output only hex
runar-compiler-go --source MyContract.runar.ts --hex

# Dump ANF IR for conformance checking
runar-compiler-go --source MyContract.runar.ts --emit-ir

# Write output to a file
runar-compiler-go --source MyContract.runar.ts --output artifacts/MyContract.json
```

### `groth16-wa` subcommand: BN254 Groth16 verifier with baked-in VK

The `groth16-wa` subcommand is a dedicated compiler backend that does not
go through the Rúnar DSL pipeline. It consumes a `.groth16.vk.json`
verifying key (see `spec/groth16_wa_vk.schema.json` for the schema) and
emits a Rúnar artifact whose locking script is a witness-assisted BN254
Groth16 verifier with that VK pre-baked in. Changing the VK requires
regenerating the artifact.

```bash
runar-compiler-go groth16-wa \
  --vk examples/go/SP1Verifier.groth16.vk.json \
  --out examples/go/SP1Verifier.runar.json
```

Options:

- `--vk <path>`: path to the input VK JSON (required).
- `--out <path>`: path for the generated artifact JSON (required).
- `--name <ContractName>`: contract name to record in the artifact (default: `Groth16Verifier`).
- `--modulo-threshold <int>`: bytes threshold for deferred mod reduction. Default `0` produces a ~703 KB script (strict mod reduction — recommended). The 2048-byte value from the nChain paper is not recommended on today's go-sdk interpreter.

The emitted artifact has `groth16WA.numPubInputs` and `groth16WA.vkDigest`
fields so downstream consumers can sanity-check which VK was baked in
without having to re-derive it from the script bytes.

---

## Conformance Testing

The Go compiler must pass the same conformance suite as the TypeScript reference compiler.

For each test case in `conformance/tests/`:

1. Read `*.runar.ts` source as input.
2. Run the full pipeline (Passes 1-6).
3. Compare script hex output with `expected-script.hex` (string equality).
4. If `expected-ir.json` exists, also compile from IR and verify the IR-compiled script matches the source-compiled script.

Most conformance tests also include multi-format variants (`.runar.sol`, `.runar.move`) that are tested through the same pipeline. The Go compiler additionally supports `.runar.go` native format via a hand-written recursive descent parser.

```bash
# Run conformance from repo root
pnpm run conformance:go

# Or directly
cd compilers/go
go test -v -run TestSourceCompile ./...
```

---

## Testing

```bash
cd compilers/go
go test ./...
```

Unit tests cover each pass independently, using synthetic IR inputs and asserting structural properties of the output. Source compilation tests (`TestSourceCompile_*`) verify the full pipeline against conformance test cases.

---

## Known Limitation: `Bigint = int64` Overflow

### Background

Rúnar's `Bigint` type maps to Bitcoin Script numbers, which are **arbitrary precision** — there is no upper or lower bound on the integers Bitcoin Script can represent. However, the Go runtime package (`packages/runar-go`) aliases `Bigint` to `int64`, which has a range of approximately ±9.2 × 10¹⁸. The Rust crate (`packages/runar-rs`) has the same limitation with `i64`.

### Why not `big.Int`?

Go does not support operator overloading. If `Bigint` were `*big.Int`, contract code could not use natural arithmetic:

```go
// What you want to write (works with int64):
total := price * quantity

// What you'd have to write with big.Int:
total := new(big.Int).Mul(price, quantity)
```

The entire point of Rúnar's Go (and Rust) DSL is that contracts look like normal code with `+`, `-`, `*`, `/` operators. Using `big.Int` would destroy that ergonomics completely — every arithmetic expression becomes a method-call chain, `==` stops working (you need `.Cmp()`), and the code no longer looks anything like the TypeScript/Solidity/Move equivalents.

This is a fundamental Go language limitation, not a design choice we can work around.

### What Bitcoin Script actually supports

When your contract is compiled and deployed on-chain, all arithmetic happens in Bitcoin Script's stack machine, which uses **arbitrary-precision integers**. There is no overflow. The int64 limitation exists **only** during native Go/Rust testing — it does not affect the compiled contract.

### What overflow detection covers

Built-in math functions in `packages/runar-go` and `packages/runar-rs` include overflow detection and will **panic** instead of silently wrapping:

| Function | What's checked |
|----------|----------------|
| `Pow(base, exp)` | Accumulation loop overflow |
| `MulDiv(a, b, c)` | Intermediate `a * b` overflow |
| `PercentOf(amount, bps)` | Intermediate `amount * bps` overflow |
| `Sqrt(n)` | Newton's method addition overflow |
| `Abs(n)` | `Abs(MinInt64)` not representable |
| `Gcd(a, b)` | `|MinInt64|` not representable |
| `Num2Bin(v, length)` | `|MinInt64|` not representable |

These panics include a message pointing here and noting that Bitcoin Script has no such limitation.

### What overflow detection does NOT cover

Direct use of Go operators (`+`, `*`, `-`) in your contract code is **not** checked. Go silently wraps on int64 overflow — there is no way to intercept this without replacing all operators with function calls, which defeats the purpose of the DSL.

```go
// This will silently wrap if it overflows — NOT detected:
result := a * b + c

// This WILL panic on overflow — detected:
result := runar.MulDiv(a, b, 1) // use built-in functions for large intermediates
```

### When you might hit this

- Token amounts exceeding ~9.2 × 10¹⁸ (e.g., tokens with 18 decimals and large supplies)
- EC scalar arithmetic (secp256k1 field order ≈ 1.16 × 10⁷⁷)
- Exponentiation with large bases or exponents
- Intermediate products in financial calculations

### Recommendations

1. **Use built-in math functions** (`Pow`, `MulDiv`, `PercentOf`) instead of raw operators for calculations that might produce large intermediates. These have overflow detection.

2. **Verify numeric correctness with TypeScript tests.** TypeScript uses native `bigint` which has no size limit. If your TS tests pass but Go tests overflow, the contract is correct — the Go test environment is the limitation.

3. **Use the deployment SDK for end-to-end testing.** `RunarContract` + `BuildDeployTransaction` compiles your contract to Bitcoin Script and deploys it. The on-chain execution uses arbitrary-precision arithmetic regardless of which language you wrote the contract in.
