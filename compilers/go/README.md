# TSOP Go Compiler

**Alternative TSOP compiler implemented in Go.**

---

## Status

| Phase | Description | Status |
|---|---|---|
| **Phase 1** | IR consumer: accepts canonical ANF IR JSON, performs stack lowering and emission (Passes 5-6). | Implemented |
| **Phase 2** | Full frontend: parses `.tsop.ts` source files directly (Passes 1-4), produces canonical ANF IR. | Implemented |

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
  .tsop.ts  -->  [Parse]  -->  [Validate]  -->  [Typecheck]  -->  [ANF Lower]
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

The parsing frontend uses **tree-sitter-typescript** for parsing `.tsop.ts` files. tree-sitter provides a concrete syntax tree (CST) that the Go code walks to build the TSOP AST. This avoids depending on the TypeScript compiler.

Why tree-sitter instead of a custom parser? TSOP source files are valid TypeScript. Parsing TypeScript correctly (including its expression grammar, ASI rules, and contextual keywords) is non-trivial. tree-sitter has a battle-tested TypeScript grammar maintained by the tree-sitter community.

---

## Building

```bash
cd compilers/go
go build -o tsop-go ./cmd/tsop-go

# Or with make
make build
```

### Prerequisites

- Go 1.22+
- tree-sitter C library (for Phase 2 frontend)

---

## Running

### Phase 1: IR Consumer Mode

```bash
# Compile from ANF IR to Bitcoin Script
./tsop-go emit --ir input-anf.json --output script.hex

# Verify against expected script
./tsop-go verify --ir input-anf.json --expected expected-script.hex
```

### Phase 2: Full Compilation (when available)

```bash
# Full compilation from source
./tsop-go compile MyContract.tsop.ts --output artifacts/MyContract.json

# Dump ANF IR for conformance checking
./tsop-go compile MyContract.tsop.ts --ir-only --output anf-ir.json
```

---

## Conformance Testing

The Go compiler must pass the same conformance suite as the TypeScript reference compiler.

### Phase 1 Conformance

For each test case in `conformance/tests/`:

1. Read `expected-ir.json` as input.
2. Run stack lowering and emission.
3. Compare output with `expected-script.hex` (if present).

```bash
# Run Phase 1 conformance from repo root
pnpm run conformance:go

# Or directly
cd compilers/go
go test ./conformance/...
```

### Phase 2 Conformance

For each test case:

1. Read `*.tsop.ts` as input.
2. Run the full pipeline (Passes 1-6).
3. Compare ANF IR output with `expected-ir.json` (byte-identical SHA-256).
4. Compare script output with `expected-script.hex` (if present).

---

## Testing

```bash
cd compilers/go
go test ./...
```

Unit tests cover each pass independently, using synthetic IR inputs and asserting structural properties of the output.
