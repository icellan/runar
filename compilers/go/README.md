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

Multi-format source files (`.runar.sol`, `.runar.move`, `.runar.go`, `.runar.py`, `.runar.rs`, `.runar.zig`, `.runar.rb`, `.runar.java`) are parsed by hand-written recursive descent parsers that produce the same Rúnar AST (`frontend/parser.go`'s format dispatch).

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

### Supported build path: `go.work`, not standalone `go get`

This module imports `github.com/icellan/runar/packages/runar-go` (for
`debug.go`'s `ScriptVM` wrapper and `compiler/groth16_wa.go`'s
`bn254witness` helpers), and `packages/runar-go` imports back from this
module (`codegen`, `frontend`) — the two are a cross-module cycle resolved
today only by the root `go.work` file's `use ./compilers/go` and
`use ./packages/runar-go` directives, which make both modules resolve to
this local checkout regardless of version pins. Building or testing from
within this checkout (`cd compilers/go && go build ./...`, no `GOWORK`
override) is the supported and CI-exercised path.

A standalone build (`GOWORK=off go build ./...`) or `go get` of this module
from outside this repository is **not** currently supported: this module has
no `require` for `packages/runar-go` at all, and even adding one would
resolve against `packages/runar-go`'s latest published tag, which predates
`packages/runar-go/bn254witness` — a package this module's non-test source
(`compiler/groth16_wa.go`) already imports — and also predates
`packages/runar-go/sp1fri`, imported only by this module's own test files.
Publishing tags that close the cycle is tracked separately as N-204.

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

# Stop after parse + validate (no codegen); exits 0 printing a "parser ok" marker
runar-compiler-go --source MyContract.runar.ts --parse-only

# Write the ANF IR JSON to a file (same bytes --emit-ir prints) and keep compiling
runar-compiler-go --source MyContract.runar.ts --emit-ir-to anf.json --output artifact.json

# Disable the ANF constant-folding optimizer (for byte-exact replay against fold-OFF goldens)
runar-compiler-go --source MyContract.runar.ts --disable-constant-folding

# Write artifact.sourceMap JSON after a successful compile
runar-compiler-go --source MyContract.runar.ts --emit-source-map MyContract.sourcemap.json

# Supply a Groth16 verifying key, required when the contract calls assertGroth16WitnessAssisted
runar-compiler-go --source MyContract.runar.ts --groth16-wa-vk MyContract.groth16.vk.json
```

### Flags

| Flag | Applies to | Description |
|---|---|---|
| `--ir <path>` | Phase 1 | Path to ANF IR JSON file |
| `--source <path>` | Phase 2 | Path to `.runar.{ts,sol,move,go,py,rs,zig,rb,java}` source file |
| `--output <path>` | both | Output artifact path (default: stdout) |
| `--hex` | both | Output only the script hex (no artifact JSON) |
| `--asm` | both | Output only the script ASM (no artifact JSON) |
| `--emit-ir` | Phase 2 | Output only the ANF IR JSON (requires `--source`) |
| `--emit-ir-to <path>` | Phase 2 | Write the ANF IR JSON (same bytes as `--emit-ir`) to this path and CONTINUE compiling (requires `--source`) |
| `--parse-only` | Phase 2 | Stop after parse + validate; exits 0 with a `parser ok` marker (requires `--source`) |
| `--disable-constant-folding` | both | Disable the ANF constant folding pass |
| `--emit-source-map <path>` | both | After a successful compile, write `artifact.sourceMap` JSON to this path |
| `--groth16-wa-vk <path>` | both | Path to a SP1-format Groth16 `vk.json` file; required to compile a `--source`/`--ir` contract whose method body calls `assertGroth16WitnessAssisted` (F-305). Distinct from the `groth16-wa` subcommand below, which synthesizes a bare fixed-VK verifier and takes no `--source`/`--ir` file at all. |

### `debug` subcommand: step-through Bitcoin Script execution

Wraps `packages/runar-go`'s `ScriptVM` (itself a wrapper around the BSV SDK's
script interpreter) to print a per-opcode execution trace, non-interactively:

```bash
runar-compiler-go debug --script <hex> [--unlock <hex>] [--max-stack-bytes <n>]
runar-compiler-go debug --artifact <path> [--unlock <hex>]
```

Options:

- `--script <hex>`: locking-script hex (required unless `--artifact` is used).
- `--artifact <path>`: compiled artifact JSON path; uses its `script` field as the locking hex.
- `--unlock <hex>`: unlocking-script hex (default: empty).
- `--max-stack-bytes <n>`: max bytes of each printed stack element (`0` = full; default `32`).

Each line printed is `step=<n>  ctx=<unlocking|locking>  offset=<byte>  op=<name>  stack=[...]`,
followed by a final `final: pass|fail  ops=<n>  stack=[...]` summary. Exits 1 if the script
does not end in a successful (truthy top-of-stack, no evaluation error) state.

### `groth16-wa` subcommand: BN254 Groth16 verifier with baked-in VK

The `groth16-wa` subcommand is a dedicated compiler backend that does not
go through the Rúnar DSL pipeline. It consumes a `.groth16.vk.json`
verifying key (see `spec/groth16_wa_vk.schema.json` for the schema) and
emits a Rúnar artifact whose locking script is a witness-assisted BN254
Groth16 verifier with that VK pre-baked in. Changing the VK requires
regenerating the artifact.

The **public inputs are baked in too**, via `--pub`, and the command fails
without them. A Groth16 verifier that does not fix its public inputs proves
only that *some* statement was satisfied: the spender picks a public-input
vector they can satisfy, mints an honest proof for it, and the script
accepts. The emitted verifier recomputes `IC[0] + Σ pub_j·IC[j+1]` on-chain
and requires it to equal the prover-supplied `prepared_inputs`, then
requires each `pub_j` to equal the pinned value.

```bash
runar-compiler-go groth16-wa \
  --vk examples/go/SP1Verifier.groth16.vk.json \
  --out examples/go/SP1Verifier.runar.json \
  --pub 66357586313644860799771794752501372267945898538662503063451090361394363786 \
  --pub 847835036251654310728024989634801415315612733526607753937102182742950003855 \
  --pub 0 \
  --pub 248831628400185611740479071450564250193912070693925013182243127282342200944 \
  --pub 0
```

Options:

- `--vk <path>`: path to the input VK JSON (required).
- `--out <path>`: path for the generated artifact JSON (required).
- `--pub <scalar>`: a public-input scalar to pin into the verifier, as a decimal integer. Repeat once per public input; the count must match `vk.numPubInputs`, which the on-chain MSM binding currently fixes at 5 (the SP1 Groth16 arity). Required.
- `--name <ContractName>`: contract name to record in the artifact (default: `Groth16Verifier`).
- `--modulo-threshold <int>`: bytes threshold for deferred mod reduction. Default `0` produces a ~1.4 MB script (strict mod reduction — recommended). The 2048-byte value from the nChain paper is not recommended on today's go-sdk interpreter.

The emitted artifact has `groth16WA.numPubInputs`, `groth16WA.vkDigest` and
`groth16WA.publicInputs` fields so downstream consumers can sanity-check
which VK and which statement were baked in without having to re-derive them
from the script bytes.

Spenders must build the unlocking witness with
`bn254witness.BuildFromProofWithInputs` (not `GenerateWitness`) — the
verifier reads the five public-input scalars off the witness stack.

---

## Conformance Testing

The Go compiler must pass the same conformance suite as the TypeScript reference compiler.

For each test case in `conformance/tests/`:

1. Read `*.runar.ts` source as input.
2. Run the full pipeline (Passes 1-6).
3. Compare script hex output with `expected-script.hex` (string equality).
4. If `expected-ir.json` exists, also compile from IR and verify the IR-compiled script matches the source-compiled script.

Every conformance fixture ships source in all nine formats (`.runar.ts`, `.runar.sol`, `.runar.move`, `.runar.go`, `.runar.py`, `.runar.rs`, `.runar.zig`, `.runar.rb`, `.runar.java`); the Go compiler's hand-written recursive descent parsers cover all eight non-TypeScript formats, so `--source` accepts any of them.

```bash
# Byte-exact golden check: compiles every conformance/tests/* fixture from
# source (fold-OFF, the mode the checked-in goldens were stamped under) and
# compares both the script hex and the ANF IR against the checked-in
# expected-script.hex / expected-ir.json.
cd compilers/go
go test -v -run TestConformanceGoldens .
```

`pnpm run conformance:go` (repo root) runs `go test -v -run TestSourceCompile
./...` instead — the example-based `TestSourceCompile_*` tests, which
exercise the pipeline end to end but do NOT byte-compare against the
goldens. Run `TestConformanceGoldens` directly, as above, for the real
golden check.

---

## Testing

```bash
cd compilers/go
go test ./...
```

Unit tests cover each pass independently, using synthetic IR inputs and asserting structural properties of the output. Source compilation tests (`TestSourceCompile_*`) verify the full pipeline against conformance test cases. `TestConformanceGoldens` (see "Conformance Testing" above) is the byte-exact golden comparison; it also runs here since `go test ./...` applies no `-run` filter.

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
