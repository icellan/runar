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
  ANF IR (JSON)  -->  [Stack Lower]  -->  [Emit]  -->  Bitcoin Script
                      Rust pass 5        Rust pass 6
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
            [Stack Lower]  -->  [Emit]  -->  Bitcoin Script
            Rust pass 5        Rust pass 6
```

The parsing frontend uses **SWC** (Speedy Web Compiler) for parsing `.runar.ts` files. SWC is a Rust-native TypeScript/JavaScript parser that provides a full AST. Since SWC is already written in Rust, it integrates naturally as a library dependency.

Why SWC instead of tree-sitter or a custom parser? SWC provides a typed Rust AST rather than a generic CST, reducing the amount of manual tree-walking needed. It is also the fastest TypeScript parser available, which matters for large projects. The Rust ecosystem already depends heavily on SWC for tooling (Next.js, Parcel, Deno), so it is well-maintained.

Multi-format source files (`.runar.sol`, `.runar.move`, `.runar.rs`) are parsed by hand-written recursive descent parsers that produce the same Rúnar AST.

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
3. Compare ANF IR output with `expected-ir.json` (byte-identical SHA-256).
4. Compare script output with `expected-script.hex` (if present).

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
