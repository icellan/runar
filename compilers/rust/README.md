# Rúnar Rust Compiler

**Alternative Rúnar compiler implemented in Rust.**

---

## Status

| Phase | Description | Status |
|---|---|---|
| **Phase 1** | IR consumer: accepts canonical ANF IR JSON, performs stack lowering and emission (Passes 5-6). | Implemented |
| **Phase 2** | Full frontend: parses `.runar.ts` source files directly (Passes 1-4), produces canonical ANF IR. | Implemented |

Phase 1 validates that the Rust implementation can produce identical Bitcoin Script from the same ANF IR as the reference compiler. Phase 2 adds an independent frontend that must produce byte-identical ANF IR.

---

## Architecture

### Phase 1: IR Consumer

```
  ANF IR (JSON)  -->  [Stack Lower]  -->  [Peephole]  -->  [Emit]  -->  Bitcoin Script
                      Rust pass 5        Optimize        Rust pass 6
```

The Rust compiler reads canonical ANF IR JSON and performs stack scheduling and opcode emission.

### Phase 2: Full Frontend

```
  .runar.ts  -->  [Parse]  -->  [Validate]  -->  [Typecheck]  -->  [ANF Lower]
                SWC parser     Rust pass 2      Rust pass 3      Rust pass 4
                frontend
                                                                     |
                                                                     v
                                                                 ANF IR (JSON)
                                                                     |
                                                                     v
            [Stack Lower]  -->  [Peephole]  -->  [Emit]  -->  Bitcoin Script
            Rust pass 5        Optimize        Rust pass 6
```

The parsing frontend uses **SWC** (Speedy Web Compiler) for parsing `.runar.ts` files. SWC is a Rust-native TypeScript/JavaScript parser that provides a full AST. Since SWC is already written in Rust, it integrates naturally as a library dependency.

Why SWC instead of tree-sitter or a custom parser? SWC provides a typed Rust AST rather than a generic CST, reducing the amount of manual tree-walking needed. It is also the fastest TypeScript parser available, which matters for large projects. The Rust ecosystem already depends heavily on SWC for tooling (Next.js, Parcel, Deno), so it is well-maintained.

Multi-format source files (`.runar.sol`, `.runar.move`, `.runar.rs`, `.runar.py`) are parsed by hand-written recursive descent parsers that produce the same Rúnar AST.

### Dedicated Codegen Modules

- `src/codegen/ec.rs` — EC point operations (`ecAdd`, `ecMul`, `ecMulGen`, `ecNegate`, `ecOnCurve`, etc.)
- `src/codegen/slh_dsa.rs` — SLH-DSA (SPHINCS+) signature verification
- `src/codegen/optimizer.rs` — Peephole optimizer (runs on Stack IR between stack lowering and emit)

### ANF EC Optimizer (Pass 4.5)

The `src/frontend/anf_optimize.rs` module implements 12 algebraic EC simplification rules that run between ANF lowering and stack lowering. This pass is always enabled and eliminates redundant EC operations (e.g., `ecAdd(P, ecNegate(P))` → identity, `ecMul(G, k)` → `ecMulGen(k)`).

---

## Building

```bash
cd compilers/rust
cargo build --release

# The binary is at target/release/runar-compiler-rust
```

### Prerequisites

- Rust (2021 edition)
- Cargo

---

## Running

### Phase 1: IR Consumer Mode

```bash
# Compile from ANF IR to Bitcoin Script (full artifact JSON)
runar-compiler-rust --ir input-anf.json

# Output only the script hex
runar-compiler-rust --ir input-anf.json --hex

# Output only the script ASM
runar-compiler-rust --ir input-anf.json --asm

# Write output to a file (-o is shorthand for --output)
runar-compiler-rust --ir input-anf.json --output artifact.json
runar-compiler-rust --ir input-anf.json -o artifact.json
```

### Phase 2: Full Compilation

```bash
# Full compilation from source (outputs artifact JSON)
runar-compiler-rust --source MyContract.runar.ts

# Output only hex
runar-compiler-rust --source MyContract.runar.ts --hex

# Dump ANF IR for conformance checking
runar-compiler-rust --source MyContract.runar.ts --emit-ir

# Write output to a file (-o is shorthand for --output)
runar-compiler-rust --source MyContract.runar.ts --output artifacts/MyContract.json
runar-compiler-rust --source MyContract.runar.ts -o artifacts/MyContract.json
```

---

## Conformance Testing

The Rust compiler must pass the same conformance suite as the TypeScript reference compiler.

For each test case in `conformance/tests/`:

1. Read `*.runar.ts` source as input.
2. Run the full pipeline (Passes 1-6).
3. Compare script hex output with `expected-script.hex` (string equality).
4. If `expected-ir.json` exists, also compile from IR and verify the IR-compiled script matches the source-compiled script.

```bash
# Run conformance from repo root
pnpm run conformance:rust

# Or directly
cd compilers/rust
cargo test --test compiler_tests
```

---

## Testing

```bash
cd compilers/rust
cargo test
```

Unit tests cover each pass independently, using synthetic IR inputs and asserting structural properties of the output. Integration tests in `tests/compiler_tests.rs` run the full pipeline against conformance test cases. Multi-format tests in `tests/multiformat_tests.rs` verify `.runar.sol`, `.runar.move`, and `.runar.rs` parsing.

---

## Known Limitation: `Bigint = i64` Overflow

### Background

Rúnar's `Bigint` type maps to Bitcoin Script numbers, which are **arbitrary precision** — there is no upper or lower bound on the integers Bitcoin Script can represent. However, the Rust runtime crate (`packages/runar-rs`) aliases `Bigint` to `i64`, which has a range of approximately ±9.2 × 10¹⁸. The Go package (`packages/runar-go`) has the same limitation with `int64`.

### Why not a big-integer type?

Rust, like Go, does not support operator overloading for arbitrary types in the way needed here. While Rust *does* have trait-based operator overloading, using a wrapper type around `num-bigint` would mean:

- Every arithmetic expression requires the wrapper to implement `Add`, `Sub`, `Mul`, `Div`, `Rem`, `Neg`, `BitAnd`, `BitOr`, `BitXor`, `Shl`, `Shr`, plus all `*Assign` variants
- Comparison with integer literals (`x > 0`) stops working without `From<i64>` conversions everywhere
- Pattern matching and `match` guards on ranges break
- The ergonomic cost is high for a test-time convenience that doesn't affect compiled output

The entire point of Rúnar's Rust DSL is that contracts look like normal code with `+`, `-`, `*`, `/` operators. A big-integer wrapper would add friction to every arithmetic expression for a limitation that only exists in native Rust tests.

### What Bitcoin Script actually supports

When your contract is compiled and deployed on-chain, all arithmetic happens in Bitcoin Script's stack machine, which uses **arbitrary-precision integers**. There is no overflow. The i64 limitation exists **only** during native Rust testing — it does not affect the compiled contract.

### What overflow detection covers

Built-in math functions in `packages/runar-rs` include overflow detection and will **panic** instead of silently wrapping:

| Function | What's checked |
|----------|----------------|
| `pow(base, exp)` | Accumulation loop overflow (`checked_mul`) |
| `mul_div(a, b, c)` | Intermediate `a * b` overflow (`checked_mul`) |
| `percent_of(amount, bps)` | Intermediate `amount * bps` overflow (`checked_mul`) |
| `sqrt(n)` | Newton's method addition overflow (`checked_add`) |
| `gcd(a, b)` | `i64::MIN.abs()` not representable (`checked_abs`) |

These panics include a message noting that Bitcoin Script has no such limitation.

### What overflow detection does NOT cover

Direct use of Rust operators (`+`, `*`, `-`) in your contract code is **not** checked in release mode. In debug mode, Rust panics on overflow by default, but release builds silently wrap. There is no way to intercept operator overflow without replacing all operators with function calls or a wrapper type, which defeats the purpose of the DSL.

```rust
// Debug mode: panics on overflow. Release mode: silently wraps. NOT detected:
let result = a * b + c;

// This WILL panic on overflow in all modes — detected:
let result = mul_div(a, b, 1); // use built-in functions for large intermediates
```

### When you might hit this

- Token amounts exceeding ~9.2 × 10¹⁸ (e.g., tokens with 18 decimals and large supplies)
- EC scalar arithmetic (secp256k1 field order ≈ 1.16 × 10⁷⁷)
- Exponentiation with large bases or exponents
- Intermediate products in financial calculations

### Recommendations

1. **Use built-in math functions** (`pow`, `mul_div`, `percent_of`) instead of raw operators for calculations that might produce large intermediates. These have overflow detection.

2. **Verify numeric correctness with TypeScript tests.** TypeScript uses native `bigint` which has no size limit. If your TS tests pass but Rust tests overflow, the contract is correct — the Rust test environment is the limitation.

3. **Use the deployment SDK for end-to-end testing.** `RunarContract` + `build_deploy_transaction` compiles your contract to Bitcoin Script and deploys it. The on-chain execution uses arbitrary-precision arithmetic regardless of which language you wrote the contract in.
