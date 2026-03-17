# Zig Benchmark Harness

This directory contains benchmark inputs and documentation for the Zig compiler benchmark harness.

The harness is isolated from the compiler implementation:

- It does not modify `build.zig`, `src/**`, or `tests/**`.
- It compares Zig against the TypeScript implementation using artifacts already present in the repository.
- It can optionally include the Rust compiler on the same workloads.
- Its default suites are limited to contracts that are suitable for parity-checked benchmarking.
- It supports two modes:
  - `source`: end-to-end source compilation, `.runar.ts -> hex`
  - `ir`: backend-only compilation, `expected-ir.json -> hex`

## Files

- `contracts-source.txt`: default contracts for full source benchmarks
- `contracts-source-representative.txt`: larger parity-clean source suite for shareable benchmark summaries
- `contracts-source-cross-impl.txt`: parity-clean source suite shared across Zig, Rust, and TypeScript
- `contracts-ir.txt`: default contracts for backend-only benchmarks
- [`../scripts/benchmark_compare.py`](/Users/satchmo/code/runar/compilers/zig/scripts/benchmark_compare.py): main benchmark runner
- [`../scripts/ts_compile_source_hex.mjs`](/Users/satchmo/code/runar/compilers/zig/scripts/ts_compile_source_hex.mjs): TS full-source helper
- [`../scripts/ts_compile_ir_hex.mjs`](/Users/satchmo/code/runar/compilers/zig/scripts/ts_compile_ir_hex.mjs): TS backend-only helper

## What It Benchmarks

This harness uses the TypeScript implementation as the baseline. It reports `source` and `ir` separately, and it only computes aggregate speedups from parity-matched rows.

`source` mode measures:

- Zig: `runar-zig --source <file> --hex`
- TypeScript: `runar-compiler` `compile(source, { fileName })`
- Optional Rust: `runar-compiler-rust --source <file> --hex`

`ir` mode measures:

- Zig: `runar-zig compile-ir <expected-ir.json> --hex`
- TypeScript: `lowerToStack(anf)` + peephole + `emit(stack)`
- Optional Rust: `runar-compiler-rust --ir <expected-ir.json> --hex`

## Prerequisites

Build the Zig binary in release mode first:

```bash
cd /Users/satchmo/code/runar/compilers/zig
zig build -Doptimize=ReleaseFast
```

The TypeScript side uses `packages/runar-compiler/dist`. If that build is stale, rebuild it once from repo root:

```bash
pnpm --filter runar-compiler build
```

## Run Instructions

Run the default full-source comparison suite:

```bash
cd /Users/satchmo/code/runar
python3 compilers/zig/scripts/benchmark_compare.py source
```

Run the shared Zig/Rust/TypeScript source suite:

```bash
cd /Users/satchmo/code/runar
python3 compilers/zig/scripts/benchmark_compare.py source \
  --with-rust \
  --contracts-file compilers/zig/benchmarks/contracts-source-cross-impl.txt
```

Run the default backend-only comparison suite:

```bash
cd /Users/satchmo/code/runar
python3 compilers/zig/scripts/benchmark_compare.py ir
```

Use a specific Node binary:

```bash
python3 compilers/zig/scripts/benchmark_compare.py source --node-bin node
```

Benchmark a specific contract without editing the list files:

```bash
python3 compilers/zig/scripts/benchmark_compare.py source --contract basic-p2pkh
```

Print the resolved default contract list:

```bash
python3 compilers/zig/scripts/benchmark_compare.py ir --list-contracts
```

Use more iterations:

```bash
python3 compilers/zig/scripts/benchmark_compare.py source --iterations 20 --warmup 3
```

Tag a run and increase the per-process timeout:

```bash
python3 compilers/zig/scripts/benchmark_compare.py source --label m2-releasefast --timeout-sec 180
```

Use a custom contract list:

```bash
python3 compilers/zig/scripts/benchmark_compare.py source --contracts-file compilers/zig/benchmarks/contracts-source.txt
```

Run the committed representative source suite:

```bash
python3 compilers/zig/scripts/benchmark_compare.py source --contracts-file compilers/zig/benchmarks/contracts-source-representative.txt
```

Run the committed cross-implementation source suite:

```bash
python3 compilers/zig/scripts/benchmark_compare.py source \
  --with-rust \
  --contracts-file compilers/zig/benchmarks/contracts-source-cross-impl.txt
```

Write machine-readable results:

```bash
python3 compilers/zig/scripts/benchmark_compare.py ir --json-out /tmp/runar-zig-bench.json
```

Print only the suite summary:

```bash
python3 compilers/zig/scripts/benchmark_compare.py source --summary-only
```

Show the fully resolved benchmark commands:

```bash
python3 compilers/zig/scripts/benchmark_compare.py source --show-commands
```

Keep going across failures while collecting a broad report:

```bash
python3 compilers/zig/scripts/benchmark_compare.py source --keep-going --allow-failures
```

Show helper usage:

```bash
node compilers/zig/scripts/ts_compile_source_hex.mjs --help
node compilers/zig/scripts/ts_compile_ir_hex.mjs --help
```

The TypeScript helper CLIs also accept a positional file path:

```bash
node compilers/zig/scripts/ts_compile_source_hex.mjs conformance/tests/basic-p2pkh/basic-p2pkh.runar.ts
node compilers/zig/scripts/ts_compile_ir_hex.mjs conformance/tests/basic-p2pkh/expected-ir.json
```

## Reproducible Runs

For a compact, repeatable run that is easy to share in a PR or issue:

```bash
cd /Users/satchmo/code/runar
python3 compilers/zig/scripts/benchmark_compare.py source \
  --contract basic-p2pkh \
  --warmup 2 \
  --iterations 10 \
  --summary-only \
  --json-out /tmp/runar-zig-source-basic-p2pkh.json
```

For a broader exploratory sweep:

```bash
cd /Users/satchmo/code/runar
python3 compilers/zig/scripts/benchmark_compare.py source \
  --keep-going \
  --allow-failures \
  --json-out /tmp/runar-zig-source-suite.json
```

## Report Shape

The Python runner now:

- normalizes Zig and TypeScript hex before comparing
- measures participating compilers in alternating order to reduce run-order bias
- prints a run header, a per-contract table, and an aggregate summary
- reports `p90`/`p95` latency alongside mean timing so startup jitter is visible
- reports per-contract errors without losing already collected results
- exits non-zero on mismatches or benchmark errors by default
- writes structured JSON with `schema_version`, `config`, `environment`, `summary`, and `results`
- supports `--summary-only` for CI logs or quick spot checks
- supports `--show-commands` so the exact command pair for each contract is visible
- stores per-sample timings, workload size (`input_bytes`), per-tool variability (`cv_pct`), and first-difference metadata for hex mismatches
- records SHA-256 hashes for benchmark inputs, helper scripts, the benchmarked native binaries, and the TypeScript `dist` tree so runs can be compared against the same artifacts
- rejects `ir` benchmark inputs whose numeric `load_const` values exceed JavaScript's safe integer range, rather than benchmarking them unsafely

## Notes

- The runner verifies hex equality for each benchmarked implementation and reports mismatches.
- Aggregate speedups only include parity-matched rows, and mismatched rows are shown as `n/a` in the speedup column. Do not make performance claims from mismatched contracts.
- JSON output includes the git commit, dirty-state flag, host/platform details, Python version, Node version, Zig toolchain version, selected helper paths, contract-list hash, artifact hashes, and measurement order so runs can be compared later with less guesswork.
- Use `--keep-going --allow-failures` when collecting exploratory results from a suite that may still contain mismatches. For shareable or CI-facing results, use the default strict exit behavior.
- Publish benchmark claims only from a committed contract manifest whose rows all parity-match.
- Treat `source` and `ir` as separate workloads. Report them separately rather than blending them into one headline number.
- Compare runs only on the same machine, same build mode, same Node/Zig toolchain versions, and the same hashed benchmark artifacts. These numbers are cold CLI subprocess timings, not in-process compiler microbenchmarks.
