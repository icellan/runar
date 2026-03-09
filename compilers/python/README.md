# Rúnar Python Compiler

**Alternative Rúnar compiler implemented in Python.**

---

## Status

| Phase | Description | Status |
|---|---|---|
| **Phase 1** | IR consumer: accepts canonical ANF IR JSON, performs stack lowering and emission (Passes 5-6). | Implemented |
| **Phase 2** | Full frontend: parses source files directly (Passes 1-4), produces canonical ANF IR. | Implemented |

Phase 1 validates that the Python implementation can produce identical Bitcoin Script from the same ANF IR as the reference compiler. Phase 2 adds an independent frontend that must produce byte-identical ANF IR.

---

## Architecture

### Phase 1: IR Consumer

```
  ANF IR (JSON)  -->  [Stack Lower]  -->  [Peephole]  -->  [Emit]  -->  Bitcoin Script
                      Python pass 5      Optimize        Python pass 6
```

The Python compiler reads canonical ANF IR JSON and performs stack scheduling and opcode emission.

### Phase 2: Full Frontend

```
  .runar.*  -->  [Parse]  -->  [Validate]  -->  [Typecheck]  -->  [ANF Lower]
              hand-written    Python pass 2    Python pass 3    Python pass 4
              parsers
                                                                     |
                                                                     v
                                                                 ANF IR (JSON)
                                                                     |
                                                                     v
            [Stack Lower]  -->  [Peephole]  -->  [Emit]  -->  Bitcoin Script
            Python pass 5      Optimize        Python pass 6
```

The Python compiler supports **all six input formats** via hand-written recursive descent parsers — the most of any compiler:

| Extension | Parser Module |
|-----------|---------------|
| `.runar.ts` | `frontend/parser_ts.py` |
| `.runar.sol` | `frontend/parser_sol.py` |
| `.runar.move` | `frontend/parser_move.py` |
| `.runar.go` | `frontend/parser_go.py` |
| `.runar.rs` | `frontend/parser_rust.py` |
| `.runar.py` | `frontend/parser_python.py` |

All parsers produce the same Rúnar AST (`ContractNode`), and from that point the pipeline is identical.

### Dedicated Codegen Modules

- `codegen/ec.py` — EC point operations (`ecAdd`, `ecMul`, `ecMulGen`, `ecNegate`, `ecOnCurve`, etc.)
- `codegen/slh_dsa.py` — SLH-DSA (SPHINCS+) signature verification
- `codegen/optimizer.py` — Peephole optimizer (runs on Stack IR between stack lowering and emit)

### ANF EC Optimizer (Pass 4.5)

The `frontend/anf_optimize.py` module implements 12 algebraic EC simplification rules that run between ANF lowering and stack lowering. This pass is always enabled and eliminates redundant EC operations (e.g., `ecAdd(P, ecNegate(P))` → identity, `ecMul(G, k)` → `ecMulGen(k)`).

---

## Building

No build step required — the compiler is pure Python.

### Prerequisites

- Python 3.10+
- No external dependencies

---

## Running

```bash
# Full compilation from source (outputs artifact JSON)
python -m runar_compiler --source MyContract.runar.ts

# Output only hex
python -m runar_compiler --source MyContract.runar.ts --hex

# Output only ASM
python -m runar_compiler --source MyContract.runar.ts --asm

# Dump ANF IR for conformance checking
python -m runar_compiler --source MyContract.runar.ts --emit-ir

# Write output to a file
python -m runar_compiler --source MyContract.runar.ts --output artifacts/MyContract.json

# Compile from ANF IR JSON
python -m runar_compiler --ir input-anf.json
python -m runar_compiler --ir input-anf.json --hex
python -m runar_compiler --ir input-anf.json --output artifact.json
```

---

## Conformance Testing

The Python compiler must pass the same conformance suite as the TypeScript reference compiler.

For each test case in `conformance/tests/`:

1. Read source files as input.
2. Run the full pipeline (Passes 1-6).
3. Compare script hex output with `expected-script.hex` (string equality).
4. If `expected-ir.json` exists, also compile from IR and verify the IR-compiled script matches the source-compiled script.

Conformance tests include multi-format variants (`.runar.sol`, `.runar.move`, `.runar.go`, `.runar.rs`, `.runar.py`) that are all tested through the same pipeline.

```bash
# Run conformance from repo root
pnpm run conformance:python

# Or directly
cd conformance
python3 -m pytest test_conformance.py -v
```

---

## Testing

```bash
cd compilers/python
python3 -m pytest
```

---

## Project Structure

```
runar_compiler/
  __init__.py
  __main__.py           # CLI entry point
  compiler.py           # Pipeline orchestrator (parse → validate → typecheck → ANF → stack → emit)
  frontend/
    ast_nodes.py        # Rúnar AST node types (ContractNode, PropertyNode, MethodNode, etc.)
    parser_dispatch.py  # File extension → parser dispatch
    parser_ts.py        # .runar.ts parser
    parser_sol.py       # .runar.sol parser
    parser_move.py      # .runar.move parser
    parser_go.py        # .runar.go parser
    parser_rust.py      # .runar.rs parser
    parser_python.py    # .runar.py parser
    validator.py        # Pass 2: Language subset validation
    typecheck.py        # Pass 3: Type checking
    anf_lower.py        # Pass 4: AST → ANF IR
    anf_optimize.py     # Pass 4.5: ANF EC optimizer (12 algebraic rules)
  ir/
    types.py            # ANF IR type definitions
    loader.py           # ANF IR JSON loader
  codegen/
    stack.py            # Pass 5: ANF → Stack IR
    optimizer.py        # Peephole optimizer
    emit.py             # Pass 6: Stack IR → Bitcoin Script
    ec.py               # EC point operation codegen
    slh_dsa.py          # SLH-DSA signature verification codegen
```
