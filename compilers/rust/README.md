# Rúnar Rust Compiler

**Alternative Rúnar compiler implemented in Rust.**

---

## Status

| Phase | Description | Status |
|---|---|---|
| **Phase 1** | IR consumer: accepts canonical ANF IR JSON, performs stack lowering and emission (Passes 5-6). | Implemented |
| **Phase 2** | Full frontend: parses `.runar.ts` source files directly (Passes 1-4), produces canonical ANF IR. | Implemented (untested) |

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

A secondary benefit: the Rust compiler can be compiled to **WebAssembly**, enabling in-browser contract compilation. SWC already supports WASM targets.

---

## Building

```bash
cd compilers/rust
cargo build --release

# The binary is at target/release/runar-rust
```

### Prerequisites

- Rust 1.75+ (2024 edition)
- Cargo

### WASM Build (optional)

```bash
# Install wasm-pack
cargo install wasm-pack

# Build for WASM
wasm-pack build --target web
```

This produces a WASM module that can compile Rúnar contracts in the browser.

---

## Running

### Phase 1: IR Consumer Mode

```bash
# Compile from ANF IR to Bitcoin Script
./runar-rust emit --ir input-anf.json --output script.hex

# Verify against expected script
./runar-rust verify --ir input-anf.json --expected expected-script.hex
```

### Phase 2: Full Compilation (when available)

```bash
# Full compilation from source
./runar-rust compile MyContract.runar.ts --output artifacts/MyContract.json

# Dump ANF IR for conformance checking
./runar-rust compile MyContract.runar.ts --ir-only --output anf-ir.json
```

---

## Conformance Testing

The Rust compiler must pass the same conformance suite as the TypeScript reference compiler.

### Phase 1 Conformance

For each test case in `conformance/tests/`:

1. Read `expected-ir.json` as input.
2. Run stack lowering and emission.
3. Compare output with `expected-script.hex` (if present).

```bash
# Run Phase 1 conformance from repo root
pnpm run conformance:rust

# Or directly
cd compilers/rust
cargo test --test conformance
```

### Phase 2 Conformance

For each test case:

1. Read `*.runar.ts` as input.
2. Run the full pipeline (Passes 1-6).
3. Compare ANF IR output with `expected-ir.json` (byte-identical SHA-256).
4. Compare script output with `expected-script.hex` (if present).

---

## Testing

```bash
cd compilers/rust
cargo test
```

Unit tests cover each pass independently, using synthetic IR inputs and asserting structural properties of the output. Integration tests run the full pipeline against the conformance suite.
