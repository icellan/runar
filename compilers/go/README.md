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
  ANF IR (JSON)  -->  [Stack Lower]  -->  [Emit]  -->  Bitcoin Script
                      Go pass 5          Go pass 6
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
            [Stack Lower]  -->  [Emit]  -->  Bitcoin Script
            Go pass 5          Go pass 6
```

The parsing frontend uses **tree-sitter-typescript** for parsing `.runar.ts` files. tree-sitter provides a concrete syntax tree (CST) that the Go code walks to build the Rúnar AST. This avoids depending on the TypeScript compiler.

Why tree-sitter instead of a custom parser? Rúnar source files are valid TypeScript. Parsing TypeScript correctly (including its expression grammar, ASI rules, and contextual keywords) is non-trivial. tree-sitter has a battle-tested TypeScript grammar maintained by the tree-sitter community.

Multi-format source files (`.runar.sol`, `.runar.move`, `.runar.go`) are parsed by hand-written recursive descent parsers that produce the same Rúnar AST.

---

## Building

```bash
cd compilers/go
go build -o runar-compiler-go .
```

### Prerequisites

- Go 1.22+
- tree-sitter C library (for Phase 2 frontend)

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

---

## Conformance Testing

The Go compiler must pass the same conformance suite as the TypeScript reference compiler.

For each test case in `conformance/tests/`:

1. Read `*.runar.ts` source as input.
2. Run the full pipeline (Passes 1-6).
3. Compare ANF IR output with `expected-ir.json` (byte-identical SHA-256).
4. Compare script output with `expected-script.hex` (if present).

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
