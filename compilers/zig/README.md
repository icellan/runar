# Runar Zig Compiler

A Zig 0.15 implementation of the Runar Bitcoin Script compiler. It produces byte-identical Bitcoin Script to the reference TypeScript compiler and the other maintained compiler implementations in this repository.

## Build

```bash
zig build          # Compile the runar-zig binary
zig build test     # Run unit + e2e tests
zig build conformance # Run 27 golden-file conformance tests
zig build run -- compile examples/P2PKH.runar.zig  # Compile a contract
```

## CLI Usage

```bash
# Full pipeline: source → Bitcoin Script artifact JSON
runar-zig compile <file.runar.zig>
runar-zig compile <file.runar.ts>

# IR consumer: ANF IR JSON → Bitcoin Script (passes 5-6 only)
runar-zig compile-ir <anf-ir.json>

# Flag mode (conformance runner compatible)
runar-zig --source <file> --emit-ir                # Output canonical ANF IR JSON
runar-zig --source <file> --hex                    # Output script hex only
runar-zig --source <file> --disable-constant-folding
```

## Benchmarking

Benchmark tooling for the Zig compiler lives outside the compiler core. The default harness compares Zig against the TypeScript implementation, and it can optionally run the Rust compiler on the same workloads for cross-implementation checks.

Use the benchmark runner from repo root:

```bash
python3 compilers/zig/scripts/benchmark_compare.py source
python3 compilers/zig/scripts/benchmark_compare.py ir
python3 compilers/zig/scripts/benchmark_compare.py source --with-rust
```

For workload definitions, prerequisites, JSON output, committed manifests, and reproducible command examples, see [benchmarks/README.md](/Users/satchmo/code/runar/compilers/zig/benchmarks/README.md).

## .runar.zig Syntax

```zig
const runar = @import("runar");

pub const P2PKH = struct {
    pub const Contract = runar.SmartContract;

    pub_key_hash: runar.Addr,

    pub fn init(pub_key_hash: runar.Addr) P2PKH {
        return .{ .pub_key_hash = pub_key_hash };
    }

    pub fn unlock(self: *const P2PKH, sig: runar.Sig, pub_key: runar.PubKey) void {
        runar.assert(runar.hash160(pub_key) == self.pub_key_hash);
        runar.assert(runar.checkSig(sig, pub_key));
    }
};
```

### Conventions

| Concept | Zig Syntax |
|---------|-----------|
| Contract type | `pub const Contract = runar.SmartContract;` or `runar.StatefulSmartContract;` |
| Readonly property | `field: runar.Type,` (all fields in SmartContract) |
| Mutable property | `field: i64 = 0,` (fields with defaults in StatefulSmartContract) |
| Constructor | `pub fn init(...) Name { return .{ ... }; }` |
| Public method | `pub fn name(self: *const Name, ...) void { ... }` |
| Private method | `fn name(self: *const Name, ...) Type { ... }` |
| Builtins | `runar.assert(...)`, `runar.hash160(...)`, `runar.checkSig(...)` |
| Types | `runar.PubKey`, `runar.Sig`, `runar.Addr`, `runar.ByteString`, `i64`, `bool` |

## Architecture

19K LOC across 16 files implementing all 6 compilation passes plus 4 optimizer passes:

| File | LOC | Pass |
|------|-----|------|
| `passes/parse_zig.zig` | 1,200 | Pass 1: .runar.zig recursive descent parser |
| `passes/parse_ts.zig` | 2,200 | Pass 1: .runar.ts recursive descent parser |
| `passes/validate.zig` | 1,060 | Pass 2: AST validation (types, readonly, recursion) |
| `passes/typecheck.zig` | 1,640 | Pass 3: Type checking (60+ builtin signatures, affine types) |
| `passes/anf_lower.zig` | 1,670 | Pass 4: AST → ANF IR (A-Normal Form) |
| `passes/constant_fold.zig` | 1,350 | Pass 4.25: Compile-time constant folding |
| `passes/ec_optimizer.zig` | 800 | Pass 4.5: Elliptic curve algebraic optimization (12 rules) |
| `passes/stack_lower.zig` | 2,050 | Pass 5: ANF IR → Bitcoin Script stack operations |
| `passes/peephole.zig` | 780 | Pass 5.5: Peephole optimization (30 rules) |
| `codegen/emit.zig` | 1,070 | Pass 6: Stack IR → hex Bitcoin Script + artifact JSON |
| `codegen/opcodes.zig` | 740 | 96 Bitcoin Script opcodes + encoding utilities |
| `ir/types.zig` | 480 | Complete IR type system (AST, ANF, Stack IR, Artifact) |
| `ir/json.zig` | 2,100 | ANF IR JSON parser + RFC 8785 canonical serializer |
| `tests/conformance.zig` | 770 | 27 golden-file conformance test harness |
| `tests/e2e.zig` | 450 | End-to-end source → hex tests |
| `main.zig` | 290 | CLI entry point + pipeline wiring |

## Dependencies

Zero. Uses only Zig's standard library.

## Status

- **IR consumer pipeline** (compile-ir): Fully functional. Parses ANF IR JSON, runs stack lowering + peephole + emit.
- **Full source pipeline** (compile): Wired end-to-end. Parser, validator, typechecker, ANF lowerer all implemented. Some edge cases in Zig→ANF constructor translation still in progress.
- **Conformance**: 27 golden-file tests wired through `zig build conformance`.
- **Security**: Audited for stack correctness, JSON parsing safety, integer overflow, MINIMALDATA compliance. All CRITICAL/HIGH findings fixed.
