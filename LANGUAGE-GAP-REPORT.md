# Runar Cross-Language Gap Analysis Report

Generated: 2026-03-29
Golden standard: TypeScript (`packages/runar-compiler/`)
Languages audited: Go, Rust, Python, Ruby, Zig

## Executive Summary

The Runar project maintains five independent compiler implementations (Go, Rust, Python, Ruby, Zig) targeting identical Bitcoin Script output from the same input contracts. Overall, the ecosystem is remarkably mature: **Go, Rust, and Python are at near-complete parity** with the TypeScript golden standard across all pipeline stages, codegen modules, and built-in functions. Ruby achieves full feature parity but has significant test coverage gaps (21% of TypeScript test count). **Zig is the outlier** — while its backend (stack lowering, codegen, emission) is complete and clean, it is missing 6 of 8 format parsers, making it unable to compile Solidity, Move, Go, Rust, Python, or Ruby format contracts.

The single most critical systemic gap is **test coverage disparity**: TypeScript has 697 compiler test cases, while Go has 429 (62%), Rust has 567 (81%), Python has 544 (78%), Ruby has 144 (21%), and Zig has 414 (59%). No non-TypeScript compiler matches TS in parser-specific unit tests — most have minimal coverage for format parsers other than their native format. The conformance suite (28 golden-file tests) partially compensates but tests compilation output, not edge cases.

A secondary systemic issue is **conformance format coverage asymmetry**: Python is tested against 7 of 8 input formats in conformance, Go and Rust against 6, while Ruby and Zig are only tested against 2 each (per `conformance/formats.json`). This means parser bugs in less-tested formats could go undetected.

---

## Per-Language Findings

### Go

**Overall parity score**: NEAR-COMPLETE

#### Pipeline Completeness
| Stage | TS File(s) | Go File(s) | Status |
|-------|-----------|------------|--------|
| Parse (TS) | `01-parse.ts` (1,147 lines) | `frontend/parser.go` (1,307 lines) | ✅ |
| Parse (Sol) | `01-parse-sol.ts` (933 lines) | `frontend/parser_sol.go` (1,243 lines) | ✅ |
| Parse (Move) | `01-parse-move.ts` (791 lines) | `frontend/parser_move.go` (1,373 lines) | ✅ |
| Parse (Go) | `01-parse-go.ts` (1,130 lines) | `frontend/parser_gocontract.go` (756 lines) | ✅ |
| Parse (Rust) | `01-parse-rust.ts` (1,155 lines) | `frontend/parser_rustmacro.go` (1,317 lines) | ✅ |
| Parse (Python) | `01-parse-python.ts` (1,609 lines) | `frontend/parser_python.go` (1,876 lines) | ✅ |
| Parse (Ruby) | `01-parse-ruby.ts` (1,770 lines) | `frontend/parser_ruby.go` (1,915 lines) | ✅ |
| Parse (Zig) | `01-parse-zig.ts` (1,328 lines) | `frontend/parser_zig.go` (1,695 lines) | ✅ |
| Validate | `02-validate.ts` (758 lines) | `frontend/validator.go` (586 lines) | ✅ |
| Typecheck | `03-typecheck.ts` (1,440 lines) | `frontend/typecheck.go` (977 lines) | ✅ |
| ANF Lower | `04-anf-lower.ts` (1,545 lines) | `frontend/anf_lower.go` (1,700 lines) | ✅ |
| Stack Lower | `05-stack-lower.ts` (4,435 lines) | `codegen/stack.go` (3,991 lines) | ✅ |
| Emit | `06-emit.ts` (623 lines) | `codegen/emit.go` (589 lines) | ✅ |
| EC Codegen | `ec-codegen.ts` (819 lines) | `codegen/ec.go` (884 lines) | ✅ |
| SHA-256 Codegen | `sha256-codegen.ts` (365 lines) | `codegen/sha256.go` (599 lines) | ✅ |
| BLAKE3 Codegen | `blake3-codegen.ts` (447 lines) | `codegen/blake3.go` (640 lines) | ✅ |
| SLH-DSA Codegen | `slh-dsa-codegen.ts` (1,357 lines) | `codegen/slh_dsa.go` (1,490 lines) | ✅ |
| Constant Fold | `optimizer/constant-fold.ts` (581 lines) | `frontend/constant_fold.go` (581 lines) | ✅ |
| Peephole | `optimizer/peephole.ts` (543 lines) | `codegen/optimizer.go` (283 lines) | ⚠️ Smaller |
| ANF-EC Optimizer | `optimizer/anf-ec.ts` (327 lines) | `frontend/anf_optimize.go` (531 lines) | ✅ |

#### Missing Language Constructs
- `buildChangeOutput` not registered in Go typecheck builtin map (`typecheck.go`). Present in TS (`03-typecheck.ts:144`), Python (`typecheck.py:156`), and Ruby (`typecheck.rb:105`). Handled correctly at codegen level (`codegen/stack.go:1134`) and ANF lowering (`anf_lower.go:229`), so this is a cosmetic inconsistency — the function is compiler-internal and never appears in user source code.

#### Test Gaps
- TS test count: **697** (30 files)
- Go test count: **429** (20 files)
- **Coverage ratio: 62%**
- Missing test equivalents:
  - No equivalent to `e2e.test.ts` (37 tests)
  - No equivalent to `cross-compiler.test.ts` (10 tests)
  - No equivalent to `examples.test.ts` (6 tests)
- Thin parser tests: Sol (5 vs 33), Move (5 vs 34), Python (5 vs 43), Ruby (13 vs 82)

#### Conformance Gaps
- Go is registered in `conformance/formats.json` for 6 of 8 formats: `.runar.ts`, `.runar.sol`, `.runar.move`, `.runar.py`, `.runar.go`, `.runar.rb`
- Not registered for: `.runar.rs`, `.runar.zig`
- Script execution tests (`conformance/script_execution_test.go`): 11 of 28 contract directories have real Bitcoin Script VM execution (including stateful-counter with increment, decrement, and wrong-state-failure tests). 17 directories lack script execution coverage.

#### Stub/Placeholder Inventory
| File | Function/Method | Evidence |
|------|----------------|----------|
| (none) | (none) | Zero stubs, TODOs, or FIXMEs found in entire `compilers/go/` |

#### Unique to Go (not in TS)
- Go uses tree-sitter for TypeScript parsing (`parser.go`) vs TS using ts-morph — different parsing technology for the same format
- `RpcProvider` implementation (`packages/runar-go/rpc_provider.go`, 279 lines) — direct Bitcoin node RPC connectivity
- ANF interpreter for verification (`packages/runar-go/anf_interpreter.go`, 869 lines)

---

### Rust

**Overall parity score**: NEAR-COMPLETE

#### Pipeline Completeness
| Stage | TS File(s) | Rust File(s) | Status |
|-------|-----------|--------------|--------|
| Parse (TS) | `01-parse.ts` (1,147 lines) | `frontend/parser.rs` (1,618 lines) | ✅ |
| Parse (Sol) | `01-parse-sol.ts` (933 lines) | `frontend/parser_sol.rs` (1,595 lines) | ✅ |
| Parse (Move) | `01-parse-move.ts` (791 lines) | `frontend/parser_move.rs` (1,782 lines) | ✅ |
| Parse (Go) | `01-parse-go.ts` (1,130 lines) | `frontend/parser_gocontract.rs` (1,776 lines) | ✅ |
| Parse (Rust) | `01-parse-rust.ts` (1,155 lines) | `frontend/parser_rustmacro.rs` (1,362 lines) | ✅ |
| Parse (Python) | `01-parse-python.ts` (1,609 lines) | `frontend/parser_python.rs` (2,507 lines) | ✅ |
| Parse (Ruby) | `01-parse-ruby.ts` (1,770 lines) | `frontend/parser_ruby.rs` (2,614 lines) | ✅ |
| Parse (Zig) | `01-parse-zig.ts` (1,328 lines) | `frontend/parser_zig.rs` (2,405 lines) | ✅ |
| Validate | `02-validate.ts` (758 lines) | `frontend/validator.rs` (1,002 lines) | ✅ |
| Typecheck | `03-typecheck.ts` (1,440 lines) | `frontend/typecheck.rs` (1,597 lines) | ✅ |
| ANF Lower | `04-anf-lower.ts` (1,545 lines) | `frontend/anf_lower.rs` (2,350 lines) | ✅ |
| Stack Lower | `05-stack-lower.ts` (4,435 lines) | `codegen/stack.rs` (5,575 lines) | ✅ |
| Emit | `06-emit.ts` (623 lines) | `codegen/emit.rs` (1,240 lines) | ✅ |
| EC Codegen | `ec-codegen.ts` (819 lines) | `codegen/ec.rs` (923 lines) | ✅ |
| SHA-256 Codegen | `sha256-codegen.ts` (365 lines) | `codegen/sha256.rs` (632 lines) | ✅ |
| BLAKE3 Codegen | `blake3-codegen.ts` (447 lines) | `codegen/blake3.rs` (698 lines) | ✅ |
| SLH-DSA Codegen | `slh-dsa-codegen.ts` (1,357 lines) | `codegen/slh_dsa.rs` (1,593 lines) | ✅ |
| Constant Fold | `optimizer/constant-fold.ts` (581 lines) | `frontend/constant_fold.rs` (1,229 lines) | ✅ |
| Peephole | `optimizer/peephole.ts` (543 lines) | `codegen/optimizer.rs` (730 lines) | ✅ |
| ANF-EC Optimizer | `optimizer/anf-ec.ts` (327 lines) | `frontend/anf_optimize.rs` (1,127 lines) | ✅ |

#### Missing Language Constructs
- `buildChangeOutput` not registered in Rust typecheck builtin map (`typecheck.rs`). Same cosmetic gap as Go — handled at codegen/ANF level, never appears in user source.

#### Test Gaps
- TS test count: **697** (30 files)
- Rust test count: **567** (22 files)
- **Coverage ratio: 81%**
- Test distribution is well-balanced across parser, frontend, and codegen modules
- Fewer dedicated parser test files vs TS, but inline `#[test]` modules in each parser file compensate

#### Conformance Gaps
- Rust is registered in `conformance/formats.json` for 6 of 8 formats: `.runar.ts`, `.runar.sol`, `.runar.move`, `.runar.py`, `.runar.rs`, `.runar.rb`
- Not registered for: `.runar.go`, `.runar.zig`
- Full participation in all 28 conformance tests

#### Stub/Placeholder Inventory
| File | Function/Method | Evidence |
|------|----------------|----------|
| (none) | (none) | Zero `todo!()`, `unimplemented!()`, TODOs, or FIXMEs found |

#### Unique to Rust (not in TS)
- Uses SWC for TypeScript parsing (`parser.rs`) — a Rust-native TS/JS parser
- `CompileOptions` struct includes `parse_only`, `validate_only`, `typecheck_only` flags for incremental compilation stopping points — TS achieves this differently via its pass-by-pass API
- Most comprehensive integration test suite (`integration/rust/tests/`, 5,286 lines across 19 files)

---

### Python

**Overall parity score**: COMPLETE

#### Pipeline Completeness
| Stage | TS File(s) | Python File(s) | Status |
|-------|-----------|----------------|--------|
| Parse (TS) | `01-parse.ts` (1,147 lines) | `frontend/parser_ts.py` (1,344 lines) | ✅ |
| Parse (Sol) | `01-parse-sol.ts` (933 lines) | `frontend/parser_sol.py` (1,157 lines) | ✅ |
| Parse (Move) | `01-parse-move.ts` (791 lines) | `frontend/parser_move.py` (1,184 lines) | ✅ |
| Parse (Go) | `01-parse-go.ts` (1,130 lines) | `frontend/parser_go.py` (1,649 lines) | ✅ |
| Parse (Rust) | `01-parse-rust.ts` (1,155 lines) | `frontend/parser_rust.py` (1,230 lines) | ✅ |
| Parse (Python) | `01-parse-python.ts` (1,609 lines) | `frontend/parser_python.py` (1,403 lines) | ✅ |
| Parse (Ruby) | `01-parse-ruby.ts` (1,770 lines) | `frontend/parser_ruby.py` (1,685 lines) | ✅ |
| Parse (Zig) | `01-parse-zig.ts` (1,328 lines) | `frontend/parser_zig.py` (1,557 lines) | ✅ |
| Validate | `02-validate.ts` (758 lines) | `frontend/validator.py` (590 lines) | ✅ |
| Typecheck | `03-typecheck.ts` (1,440 lines) | `frontend/typecheck.py` (906 lines) | ✅ |
| ANF Lower | `04-anf-lower.ts` (1,545 lines) | `frontend/anf_lower.py` (1,091 lines) | ✅ |
| Stack Lower | `05-stack-lower.ts` (4,435 lines) | `codegen/stack.py` (3,526 lines) | ✅ |
| Emit | `06-emit.ts` (623 lines) | `codegen/emit.py` (492 lines) | ✅ |
| EC Codegen | `ec-codegen.ts` (819 lines) | `codegen/ec.py` (920 lines) | ✅ |
| SHA-256 Codegen | `sha256-codegen.ts` (365 lines) | `codegen/sha256.py` (562 lines) | ✅ |
| BLAKE3 Codegen | `blake3-codegen.ts` (447 lines) | `codegen/blake3.py` (644 lines) | ✅ |
| SLH-DSA Codegen | `slh-dsa-codegen.ts` (1,357 lines) | `codegen/slh_dsa.py` (1,181 lines) | ✅ |
| Constant Fold | `optimizer/constant-fold.ts` (581 lines) | `frontend/constant_fold.py` (488 lines) | ✅ |
| Peephole | `optimizer/peephole.ts` (543 lines) | `codegen/optimizer.py` (255 lines) | ✅ |
| ANF-EC Optimizer | `optimizer/anf-ec.ts` (327 lines) | `frontend/anf_optimize.py` (394 lines) | ✅ |

#### Missing Language Constructs
- None. Python has exact 1:1 built-in function parity with TypeScript (all 73 functions including `buildChangeOutput`).

#### Test Gaps
- TS test count: **697** (30 files)
- Python test count: **544** (13 files)
- **Coverage ratio: 78%**
- Well-distributed across all pipeline stages
- Dedicated Zig parser test file (`test_parser_zig.py`, 64 tests) shows thorough coverage for the newest format

#### Conformance Gaps
- Python is registered in `conformance/formats.json` for **7 of 8 formats** — the widest coverage of any compiler: `.runar.ts`, `.runar.sol`, `.runar.move`, `.runar.py`, `.runar.go`, `.runar.rs`, `.runar.rb`
- Not registered for: `.runar.zig` — despite having a fully implemented Zig parser (`parser_zig.py`, 1,557 lines). This parser is never exercised by conformance tests.

#### Stub/Placeholder Inventory
| File | Function/Method | Evidence |
|------|----------------|----------|
| (none) | (none) | Zero `raise NotImplementedError`, TODOs, or FIXMEs found |

#### Unique to Python (not in TS)
- Widest conformance format coverage (7/8 formats) — Python is the only compiler besides TS that parses `.runar.go` and `.runar.rs` formats (alongside their native compilers)
- Zero external dependencies for the SDK (`packages/runar-py/`) — uses only Python stdlib (`hashlib`, `hmac`, etc.)

---

### Ruby

**Overall parity score**: NEAR-COMPLETE

#### Pipeline Completeness
| Stage | TS File(s) | Ruby File(s) | Status |
|-------|-----------|--------------|--------|
| Parse (TS) | `01-parse.ts` (1,147 lines) | `frontend/parser_ts.rb` (1,524 lines) | ✅ |
| Parse (Sol) | `01-parse-sol.ts` (933 lines) | `frontend/parser_sol.rb` (1,419 lines) | ✅ |
| Parse (Move) | `01-parse-move.ts` (791 lines) | `frontend/parser_move.rb` (1,122 lines) | ✅ |
| Parse (Go) | `01-parse-go.ts` (1,130 lines) | `frontend/parser_go.rb` (1,336 lines) | ✅ |
| Parse (Rust) | `01-parse-rust.ts` (1,155 lines) | `frontend/parser_rust.rb` (1,544 lines) | ✅ |
| Parse (Python) | `01-parse-python.ts` (1,609 lines) | `frontend/parser_python.rb` (1,680 lines) | ✅ |
| Parse (Ruby) | `01-parse-ruby.ts` (1,770 lines) | `frontend/parser_ruby.rb` (1,781 lines) | ✅ |
| Parse (Zig) | `01-parse-zig.ts` (1,328 lines) | `frontend/parser_zig.rb` (1,756 lines) | ✅ |
| Validate | `02-validate.ts` (758 lines) | `frontend/validator.rb` (614 lines) | ✅ |
| Typecheck | `03-typecheck.ts` (1,440 lines) | `frontend/typecheck.rb` (858 lines) | ✅ |
| ANF Lower | `04-anf-lower.ts` (1,545 lines) | `frontend/anf_lower.rb` (1,658 lines) | ✅ |
| Stack Lower | `05-stack-lower.ts` (4,435 lines) | `codegen/stack.rb` (3,000 lines) | ✅ |
| Emit | `06-emit.ts` (623 lines) | `codegen/emit.rb` (596 lines) | ✅ |
| EC Codegen | `ec-codegen.ts` (819 lines) | `codegen/ec.rb` (1,072 lines) | ✅ |
| SHA-256 Codegen | `sha256-codegen.ts` (365 lines) | `codegen/sha256.rb` (588 lines) | ✅ |
| BLAKE3 Codegen | `blake3-codegen.ts` (447 lines) | `codegen/blake3.rb` (626 lines) | ✅ |
| SLH-DSA Codegen | `slh-dsa-codegen.ts` (1,357 lines) | `codegen/slh_dsa.rb` (1,354 lines) | ✅ |
| Constant Fold | `optimizer/constant-fold.ts` (581 lines) | `frontend/constant_fold.rb` (525 lines) | ✅ |
| Peephole | `optimizer/peephole.ts` (543 lines) | `codegen/optimizer.rb` (231 lines) | ✅ |
| ANF-EC Optimizer | `optimizer/anf-ec.ts` (327 lines) | `frontend/anf_optimize.rb` (479 lines) | ✅ |

#### Missing Language Constructs
- None. All 66+ built-in functions present including `buildChangeOutput` (`typecheck.rb:105`).

#### Test Gaps
- TS test count: **697** (30 files)
- Ruby test count: **144** (8 files)
- **Coverage ratio: 21%** — the lowest of all compilers
- **12 of 30 TS test categories have no Ruby equivalent:**
  - Parser tests for Python, Move, Sol, Zig, Rust, Go formats (6 missing)
  - ANF lower tests, ANF-EC optimizer tests (2 missing)
  - IR loader tests, assembler tests, emit tests, EC tests (4 missing)
- Only 2 parser-specific test files: `test_parser_ts.rb` (5 tests) and `test_parser_ruby.rb` (4 tests)
- Conformance tests (28 golden-file) provide baseline coverage but don't test edge cases

#### Conformance Gaps
- Ruby is registered in `conformance/formats.json` for only 2 of 8 formats: `.runar.ts`, `.runar.rb`
- Not registered for: `.runar.sol`, `.runar.move`, `.runar.py`, `.runar.go`, `.runar.rs`, `.runar.zig`
- Despite having all 8 parsers implemented, 6 parsers have zero conformance test coverage
- All 28 golden-file tests pass for the 2 registered formats

#### Stub/Placeholder Inventory
| File | Function/Method | Evidence |
|------|----------------|----------|
| (none) | (none) | Zero `raise NotImplementedError`, TODOs, or FIXMEs found |

#### Unique to Ruby (not in TS)
- Ruby LSP addon (`packages/runar-rb/lib/ruby_lsp/runar/`): hover info (325 lines), completion (141 lines), indexing (156 lines), addon (68 lines) — editor integration not available for other languages
- Divergence documentation (`packages/runar-rb/divergence/`) documenting cross-language SDK differences for Ruby, Python, TS, Go, Rust
- DSL helpers (`packages/runar-rb/lib/runar/dsl.rb`, 81 lines) for idiomatic Ruby contract usage

---

### Zig

**Overall parity score**: PARTIAL

#### Pipeline Completeness
| Stage | TS File(s) | Zig File(s) | Status |
|-------|-----------|-------------|--------|
| Parse (TS) | `01-parse.ts` (1,147 lines) | `passes/parse_ts.zig` (2,236 lines) | ✅ |
| Parse (Sol) | `01-parse-sol.ts` (933 lines) | — | ❌ MISSING |
| Parse (Move) | `01-parse-move.ts` (791 lines) | — | ❌ MISSING |
| Parse (Go) | `01-parse-go.ts` (1,130 lines) | — | ❌ MISSING |
| Parse (Rust) | `01-parse-rust.ts` (1,155 lines) | — | ❌ MISSING |
| Parse (Python) | `01-parse-python.ts` (1,609 lines) | — | ❌ MISSING |
| Parse (Ruby) | `01-parse-ruby.ts` (1,770 lines) | — | ❌ MISSING |
| Parse (Zig) | `01-parse-zig.ts` (1,328 lines) | `passes/parse_zig.zig` (1,608 lines) | ✅ |
| Validate | `02-validate.ts` (758 lines) | `passes/validate.zig` (1,138 lines) | ✅ |
| Typecheck | `03-typecheck.ts` (1,440 lines) | `passes/typecheck.zig` (1,659 lines) | ✅ |
| ANF Lower | `04-anf-lower.ts` (1,545 lines) | `passes/anf_lower.zig` (1,790 lines) | ✅ |
| Stack Lower | `05-stack-lower.ts` (4,435 lines) | `passes/stack_lower.zig` (4,435 lines) | ✅ |
| Emit | `06-emit.ts` (623 lines) | `codegen/emit.zig` (1,264 lines) | ✅ |
| EC Codegen | `ec-codegen.ts` (819 lines) | `passes/helpers/ec_emitters.zig` (916 lines) | ✅ |
| SHA-256 Codegen | `sha256-codegen.ts` (365 lines) | `passes/helpers/sha256_emitters.zig` (601 lines) | ✅ |
| BLAKE3 Codegen | `blake3-codegen.ts` (447 lines) | `passes/helpers/blake3_emitters.zig` (645 lines) | ✅ |
| SLH-DSA Codegen | `slh-dsa-codegen.ts` (1,357 lines) | `passes/helpers/pq_emitters.zig` (1,468 lines) | ✅ |
| Constant Fold | `optimizer/constant-fold.ts` (581 lines) | `passes/constant_fold.zig` (1,437 lines) | ✅ |
| Peephole | `optimizer/peephole.ts` (543 lines) | `passes/peephole.zig` (764 lines) | ✅ |
| ANF-EC Optimizer | `optimizer/anf-ec.ts` (327 lines) | `passes/ec_optimizer.zig` (667 lines) | ✅ |

#### Missing Language Constructs
- **6 format parsers missing** — the Zig compiler cannot compile `.runar.sol`, `.runar.move`, `.runar.go`, `.runar.rs`, `.runar.py`, or `.runar.rb` files. Confirmed at `main.zig:138-145` where `detectFormat()` only recognizes `.runar.ts`, `.runar.zig`, and `.json` (ANF IR). Unknown extensions return `error.UnsupportedFormat`.
- `split` built-in function missing from typecheck (`typecheck.zig`). Present in TS at `03-typecheck.ts:109` as `['split', { params: ['ByteString', 'bigint'], returnType: 'ByteString' }]`. Not found in Zig's builtin registry (65/66 builtins). Any contract using `split()` will fail type checking in the Zig compiler.

#### Test Gaps
- TS test count: **697** (30 files)
- Zig test count: **414** (24 files)
- **Coverage ratio: 59%**
- Tests are well-distributed across all pipeline stages with inline `test` blocks in every module
- Conformance tests (28) cover all backend behavior via JSON IR input
- No parser tests for the 6 missing format parsers (expected, since the parsers don't exist)

#### Conformance Gaps
- Zig is registered in `conformance/formats.json` for only 2 of 8 formats: `.runar.ts`, `.runar.zig`
- The conformance tests (`tests/conformance.zig`) test all 28 golden-file contracts but use the JSON IR path (passes 5-6 only), bypassing the parser entirely. This means the Zig backend is fully conformance-tested, but its 2 parsers receive no multi-compiler cross-validation.
- Not registered for: `.runar.sol`, `.runar.move`, `.runar.py`, `.runar.go`, `.runar.rs`, `.runar.rb`

#### Stub/Placeholder Inventory
| File | Function/Method | Evidence |
|------|----------------|----------|
| (none) | (none) | Zero `@panic`, `unreachable` (as stub), TODOs, or FIXMEs found |

#### Unique to Zig (not in TS)
- **Standalone DCE pass** (`passes/dce.zig`, 233 lines) — the only compiler with a reusable dead code elimination module. Used internally by the EC optimizer; explicitly NOT run as a standalone pipeline stage (would incorrectly remove bindings from private method bodies, per comment at `main.zig:276-280`).
- **Dual ANF representation** — supports both canonical TypeScript-matching ANF value kinds (17 variants) and legacy JSON IR kinds (13 additional variants) in a single `ANFValue` union. Other compilers only support the canonical format.
- **O(1) StackMap lookup** — uses a parallel hash map for variable name lookups during stack lowering. Other compilers use linear scans.
- Inline tests in every source file — Zig idiom embeds tests alongside implementation code rather than in separate test files.

---

## Cross-Cutting Issues

### 1. Conformance Format Coverage is Highly Asymmetric

Per `conformance/formats.json`, compilers have dramatically different format coverage in conformance testing:

| Compiler | Formats Tested | Missing From Conformance |
|----------|---------------|--------------------------|
| TypeScript | 5 (.ts, .sol, .move, .py, .rb) | .go, .rs, .zig |
| Go | 6 (.ts, .sol, .move, .py, .go, .rb) | .rs, .zig |
| Rust | 6 (.ts, .sol, .move, .py, .rs, .rb) | .go, .zig |
| Python | 7 (.ts, .sol, .move, .py, .go, .rs, .rb) | .zig |
| Ruby | 2 (.ts, .rb) | .sol, .move, .py, .go, .rs, .zig |
| Zig | 2 (.ts, .zig) | .sol, .move, .py, .go, .rs, .rb |

Ruby has 8 parsers but only 2 are conformance-tested. Python has a Zig parser but it's not registered in formats.json. The TypeScript compiler itself is not tested for `.runar.go`, `.runar.rs`, or `.runar.zig` formats in conformance — despite having parsers for all three.

### 2. `buildChangeOutput` Builtin Registration is Inconsistent

This compiler-internal builtin is registered in the typecheck pass of TypeScript (`03-typecheck.ts:144`), Python (`typecheck.py:156`), Ruby (`typecheck.rb:105`), and Zig (`typecheck.zig`) — but NOT in Go (`typecheck.go`) or Rust (`typecheck.rs`). While functionally irrelevant (it's auto-injected by ANF lowering, not user-written), the inconsistency means the compilers don't have identical error messages for invalid edge-case inputs.

### 3. Test Coverage Drops Sharply Outside TypeScript

| Compiler | Test Count | % of TS | Parser Tests | Codegen Tests |
|----------|-----------|---------|-------------|---------------|
| TypeScript | 697 | 100% | 270+ (8 files) | 92+ (5 files) |
| Rust | 567 | 81% | Inline in each parser | 64+ (3 files) |
| Python | 544 | 78% | 185+ (3 files) | 58+ (2 files) |
| Go | 429 | 62% | 84 (8 files, thin) | 98 (3 files) |
| Zig | 414 | 59% | 49 (2 files) | Inline |
| Ruby | 144 | 21% | 9 (2 files) | 25 (1 file) |

Ruby's 21% test coverage is concerning given it has full feature parity. The conformance suite provides a safety net, but unit tests catch edge cases and regressions that golden-file tests miss.

### 4. Zig's Parser Gap Breaks Multi-Format Promise

The project's value proposition is "write in any of 8 formats, compile with any of 6 compilers." Zig only supports 2 formats, breaking this promise. Every other compiler supports all 8 formats. The Zig backend is complete and clean — the gap is purely in the frontend.

### 5. Go Script Execution — Stateful Contract Bug (RESOLVED)

The conformance suite's `script_execution_test.go` had a skipped `TestStateful_Increment` with a TODO claiming stack ordering bugs in stateful contract compilation. Investigation confirmed the underlying bugs were fixed in prior commits — the compiled hex matches the golden standard. The test has been replaced with full OP_PUSH_TX / BIP-143 execution tests (increment, decrement, and wrong-state failure) that all pass.

---

## Recommended Priority Actions

1. **[CRITICAL] Add 6 missing format parsers to Zig compiler** — Sol, Move, Go, Rust, Python, Ruby parsers are needed to achieve format parity. This is the single largest gap and affects ~8,000 lines of parser code that need to be written. Consider porting from the Rust or Go implementations as they have the most similar low-level coding style.

2. **[HIGH] Register Ruby's 6 untested parsers in `conformance/formats.json`** — Ruby has all 8 parsers implemented but only 2 are conformance-tested. Adding `"ruby"` to the Sol, Move, Python, Go, Rust entries would immediately validate 6 more parsers against golden files with zero new code.

3. **[HIGH] Register Python's Zig parser in `conformance/formats.json`** — Python has a fully implemented Zig parser (`parser_zig.py`, 1,557 lines) that is never conformance-tested. Adding `"python"` to the `.runar.zig` entry would enable cross-validation.

4. **[RESOLVED] Go stateful contract execution tests** — The skipped test has been replaced with full OP_PUSH_TX execution tests (increment, decrement, wrong-state failure) that all pass. The underlying compilation bugs were already fixed in prior commits.

5. **[MEDIUM] Add `split` builtin to Zig typecheck** — The `split` function (splits a ByteString at a given position) is missing from Zig's builtin registry. One-line fix in `typecheck.zig`.

6. **[MEDIUM] Add `buildChangeOutput` to Go and Rust typecheck builtins** — Cosmetic inconsistency, but needed for strict cross-compiler parity in error reporting.

7. **[MEDIUM] Increase Ruby test coverage** — Ruby has 144 tests (21% of TS). Priority areas: format parser unit tests (currently 9 tests for 8 parsers), ANF lowering tests (0 tests), and emit tests (0 tests). Target: at least 50% of TS test count.

8. **[LOW] Register TypeScript's Go/Rust/Zig parsers in `conformance/formats.json`** — The TS compiler has parsers for `.runar.go`, `.runar.rs`, and `.runar.zig` but these are not conformance-tested. Adding them would increase cross-compiler validation.

9. **[LOW] Expand Go's conformance script execution tests** — Only 10 of 28 contract directories have Bitcoin Script VM execution in Go. The remaining 18 should be added as script execution tests to validate end-to-end correctness.
