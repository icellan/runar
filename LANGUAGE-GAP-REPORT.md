# Rúnar Cross-Language Gap Analysis Report

Generated: 2026-03-29
Golden standard: TypeScript (`packages/runar-compiler/`, `packages/runar-testing/`)
Languages audited: Go, Rust, Python, Ruby, Zig
Input format parsers audited: Solidity-like, Move-style (implemented within each compiler, not standalone)

## Executive Summary

The Rúnar project maintains five independent compiler implementations (Go, Rust, Python, Ruby, Zig) targeting identical Bitcoin Script output from the same input contracts. Overall, the ecosystem is remarkably mature: **Go, Rust, Python, and Ruby are at full or near-complete feature parity** with the TypeScript golden standard across all pipeline stages, codegen modules, and built-in functions. All four implement the complete 6-pass nanopass pipeline, all 17 ANF value kinds, all special codegen modules (EC, SHA-256, BLAKE3, SLH-DSA), and all 8 input format parsers.

**Zig is the outlier** — while its backend (stack lowering, codegen, emission, all special codegen) is complete and production-grade, it only supports 2 of 8 input format parsers (`.runar.zig` and `.runar.ts`), making it unable to compile Solidity, Move, Go, Rust, Python, or Ruby format contracts from source.

The single most critical systemic gap is **conformance format coverage asymmetry**: while all 28 conformance tests have contract files in all 8 formats, the `conformance/formats.json` registry only exercises a subset of compilers per format. Ruby has all 8 parsers but only 2 are conformance-tested. Python has a Zig parser that is never conformance-tested. TypeScript itself isn't tested for `.runar.go`, `.runar.rs`, or `.runar.zig` formats.

A secondary issue is **test coverage disparity**: TypeScript has 819 compiler tests + 260 runtime/testing tests (1,079 total), while Ruby has only 116 compiler tests (11% of TS compiler count). Go (429), Rust (567), Python (544), and Zig (414) are healthier but still below TS.

---

## Per-Language Findings

### Go

**Overall parity score**: NEAR-COMPLETE

#### Pipeline Completeness
| Stage | TS File(s) | Go File(s) | Status |
|-------|-----------|------------|--------|
| Parse (TS) | `01-parse.ts` | `frontend/parser.go` (tree-sitter) | ✅ |
| Parse (Sol) | `01-parse-sol.ts` | `frontend/parser_sol.go` (1,243 lines) | ✅ |
| Parse (Move) | `01-parse-move.ts` | `frontend/parser_move.go` (1,373 lines) | ✅ |
| Parse (Go) | `01-parse-go.ts` | `frontend/parser_gocontract.go` (756 lines) | ✅ |
| Parse (Rust) | `01-parse-rust.ts` | `frontend/parser_rustmacro.go` (1,317 lines) | ✅ |
| Parse (Python) | `01-parse-python.ts` | `frontend/parser_python.go` (1,876 lines) | ✅ |
| Parse (Ruby) | `01-parse-ruby.ts` | `frontend/parser_ruby.go` (1,915 lines) | ✅ |
| Parse (Zig) | `01-parse-zig.ts` | `frontend/parser_zig.go` (1,695 lines) | ✅ |
| Validate | `02-validate.ts` | `frontend/validator.go` | ✅ |
| Typecheck | `03-typecheck.ts` | `frontend/typecheck.go` | ✅ |
| ANF Lower | `04-anf-lower.ts` | `frontend/anf_lower.go` | ✅ |
| Constant Fold | `optimizer/constant-fold.ts` | `frontend/constant_fold.go` | ✅ |
| ANF-EC Optimizer | `optimizer/anf-ec.ts` | `frontend/anf_optimize.go` | ✅ |
| Stack Lower | `05-stack-lower.ts` | `codegen/stack.go` | ✅ |
| Peephole | `optimizer/peephole.ts` | `codegen/optimizer.go` (283 lines) | ⚠️ Smaller |
| Emit | `06-emit.ts` | `codegen/emit.go` | ✅ |
| EC Codegen | `ec-codegen.ts` | `codegen/ec.go` | ✅ |
| SHA-256 Codegen | `sha256-codegen.ts` | `codegen/sha256.go` | ✅ |
| BLAKE3 Codegen | `blake3-codegen.ts` | `codegen/blake3.go` | ✅ |
| SLH-DSA Codegen | `slh-dsa-codegen.ts` | `codegen/slh_dsa.go` | ✅ |

#### Missing Language Constructs
- `buildChangeOutput` not registered in Go typecheck builtin map (`typecheck.go`). Present in TS (`03-typecheck.ts:144`), Python, and Ruby. Handled at codegen/ANF level — cosmetic inconsistency only, since this function is compiler-internal and never appears in user source code.

#### Test Gaps
- TS compiler test count: **819** (30 files)
- Go compiler test count: **429** (20 files)
- **Coverage ratio: 52%**
- Missing test equivalents:
  - No equivalent to `e2e.test.ts` (37 tests)
  - No equivalent to `cross-compiler.test.ts` (10 tests)
  - No equivalent to `examples.test.ts` (9 tests)
- Thin parser tests: Sol (5 vs 33), Move (5 vs 34), Python (5 vs 43), Ruby (13 vs 83)

#### Conformance Gaps
- Registered in `conformance/formats.json` for 6 of 8 formats: `.runar.ts`, `.runar.sol`, `.runar.move`, `.runar.py`, `.runar.go`, `.runar.rb`
- Not registered for: `.runar.rs`, `.runar.zig`
- Go has a dedicated script execution test (`conformance/script_execution_test.go`) that runs Bitcoin Script VM execution for a subset of the 28 contracts

#### Stub/Placeholder Inventory
| File | Function/Method | Evidence |
|------|----------------|----------|
| (none) | (none) | Zero stubs, TODOs, or FIXMEs found in `compilers/go/` |

#### Unique to Go (not in TS)
- Uses tree-sitter for TypeScript parsing (`parser.go`) vs TS using ts-morph
- `RpcProvider` implementation (`packages/runar-go/rpc_provider.go`) — direct Bitcoin node RPC connectivity
- ANF interpreter for state auto-computation (`packages/runar-go/anf_interpreter.go`, 869 lines)

---

### Rust

**Overall parity score**: NEAR-COMPLETE

#### Pipeline Completeness
| Stage | TS File(s) | Rust File(s) | Status |
|-------|-----------|--------------|--------|
| Parse (TS) | `01-parse.ts` | `frontend/parser.rs` (SWC-based, 1,618 lines) | ✅ |
| Parse (Sol) | `01-parse-sol.ts` | `frontend/parser_sol.rs` (1,595 lines) | ✅ |
| Parse (Move) | `01-parse-move.ts` | `frontend/parser_move.rs` (1,782 lines) | ✅ |
| Parse (Go) | `01-parse-go.ts` | `frontend/parser_gocontract.rs` (1,776 lines) | ✅ |
| Parse (Rust) | `01-parse-rust.ts` | `frontend/parser_rustmacro.rs` (1,362 lines) | ✅ |
| Parse (Python) | `01-parse-python.ts` | `frontend/parser_python.rs` (2,507 lines) | ✅ |
| Parse (Ruby) | `01-parse-ruby.ts` | `frontend/parser_ruby.rs` (2,614 lines) | ✅ |
| Parse (Zig) | `01-parse-zig.ts` | `frontend/parser_zig.rs` (2,405 lines) | ✅ |
| Validate | `02-validate.ts` | `frontend/validator.rs` (1,002 lines) | ✅ |
| Typecheck | `03-typecheck.ts` | `frontend/typecheck.rs` (1,597 lines) | ✅ |
| ANF Lower | `04-anf-lower.ts` | `frontend/anf_lower.rs` (2,350 lines) | ✅ |
| Constant Fold | `optimizer/constant-fold.ts` | `frontend/constant_fold.rs` (1,229 lines) | ✅ |
| ANF-EC Optimizer | `optimizer/anf-ec.ts` | `frontend/anf_optimize.rs` (1,127 lines) | ✅ |
| Stack Lower | `05-stack-lower.ts` | `codegen/stack.rs` (5,575 lines) | ✅ |
| Peephole | `optimizer/peephole.ts` | `codegen/optimizer.rs` (730 lines) | ✅ |
| Emit | `06-emit.ts` | `codegen/emit.rs` (1,240 lines) | ✅ |
| EC Codegen | `ec-codegen.ts` | `codegen/ec.rs` (923 lines) | ✅ |
| SHA-256 Codegen | `sha256-codegen.ts` | `codegen/sha256.rs` (632 lines) | ✅ |
| BLAKE3 Codegen | `blake3-codegen.ts` | `codegen/blake3.rs` (698 lines) | ✅ |
| SLH-DSA Codegen | `slh-dsa-codegen.ts` | `codegen/slh_dsa.rs` (1,593 lines) | ✅ |

#### Missing Language Constructs
- `buildChangeOutput` not registered in Rust typecheck builtin map (`typecheck.rs`). Same cosmetic gap as Go — handled at codegen/ANF level, never appears in user source.

#### Test Gaps
- TS compiler test count: **819** (30 files)
- Rust compiler test count: **567** (22 files: 291 in `tests/`, 276 inline in `src/`)
- **Coverage ratio: 69%**
- Test distribution is well-balanced across parser, frontend, and codegen modules
- Inline `#[test]` modules in each parser file provide per-parser coverage

#### Conformance Gaps
- Registered in `conformance/formats.json` for 6 of 8 formats: `.runar.ts`, `.runar.sol`, `.runar.move`, `.runar.py`, `.runar.rs`, `.runar.rb`
- Not registered for: `.runar.go`, `.runar.zig`

#### Stub/Placeholder Inventory
| File | Function/Method | Evidence |
|------|----------------|----------|
| (none) | (none) | Zero `todo!()`, `unimplemented!()`, TODOs, or FIXMEs found |

#### Unique to Rust (not in TS)
- Uses SWC for TypeScript parsing — a Rust-native TS/JS parser
- `CompileOptions` includes `parse_only`, `validate_only`, `typecheck_only` flags for incremental compilation stopping points
- Proc-macro crate (`packages/runar-rs-macros/`) providing `#[runar::contract]`, `#[public]`, `#[runar::methods]` attributes
- Most comprehensive integration test suite (`integration/rust/`)

---

### Python

**Overall parity score**: COMPLETE

#### Pipeline Completeness
| Stage | TS File(s) | Python File(s) | Status |
|-------|-----------|----------------|--------|
| Parse (TS) | `01-parse.ts` | `frontend/parser_ts.py` (1,344 lines) | ✅ |
| Parse (Sol) | `01-parse-sol.ts` | `frontend/parser_sol.py` (1,157 lines) | ✅ |
| Parse (Move) | `01-parse-move.ts` | `frontend/parser_move.py` (1,184 lines) | ✅ |
| Parse (Go) | `01-parse-go.ts` | `frontend/parser_go.py` (1,649 lines) | ✅ |
| Parse (Rust) | `01-parse-rust.ts` | `frontend/parser_rust.py` (1,230 lines) | ✅ |
| Parse (Python) | `01-parse-python.ts` | `frontend/parser_python.py` (1,403 lines) | ✅ |
| Parse (Ruby) | `01-parse-ruby.ts` | `frontend/parser_ruby.py` (1,685 lines) | ✅ |
| Parse (Zig) | `01-parse-zig.ts` | `frontend/parser_zig.py` (1,557 lines) | ✅ |
| Validate | `02-validate.ts` | `frontend/validator.py` (590 lines) | ✅ |
| Typecheck | `03-typecheck.ts` | `frontend/typecheck.py` (906 lines) | ✅ |
| ANF Lower | `04-anf-lower.ts` | `frontend/anf_lower.py` (1,091 lines) | ✅ |
| Constant Fold | `optimizer/constant-fold.ts` | `frontend/constant_fold.py` (488 lines) | ✅ |
| ANF-EC Optimizer | `optimizer/anf-ec.ts` | `frontend/anf_optimize.py` (394 lines) | ✅ |
| Stack Lower | `05-stack-lower.ts` | `codegen/stack.py` (3,526 lines) | ✅ |
| Peephole | `optimizer/peephole.ts` | `codegen/optimizer.py` (255 lines) | ✅ |
| Emit | `06-emit.ts` | `codegen/emit.py` (492 lines) | ✅ |
| EC Codegen | `ec-codegen.ts` | `codegen/ec.py` (920 lines) | ✅ |
| SHA-256 Codegen | `sha256-codegen.ts` | `codegen/sha256.py` (562 lines) | ✅ |
| BLAKE3 Codegen | `blake3-codegen.ts` | `codegen/blake3.py` (644 lines) | ✅ |
| SLH-DSA Codegen | `slh-dsa-codegen.ts` | `codegen/slh_dsa.py` (1,181 lines) | ✅ |

#### Missing Language Constructs
- None. Python has exact 1:1 built-in function parity with TypeScript (all 73 functions including `buildChangeOutput`).

#### Test Gaps
- TS compiler test count: **819** (30 files)
- Python compiler test count: **544** (12 files)
- **Coverage ratio: 66%**
- Well-distributed across all pipeline stages
- Dedicated Zig parser test file (`test_parser_zig.py`, 64 tests) shows thorough coverage for the newest format

#### Conformance Gaps
- Registered in `conformance/formats.json` for **7 of 8 formats** — the widest coverage of any compiler: `.runar.ts`, `.runar.sol`, `.runar.move`, `.runar.py`, `.runar.go`, `.runar.rs`, `.runar.rb`
- Not registered for: `.runar.zig` — despite having a fully implemented Zig parser (`parser_zig.py`, 1,557 lines). This parser is never exercised by conformance tests.

#### Stub/Placeholder Inventory
| File | Function/Method | Evidence |
|------|----------------|----------|
| (none) | (none) | Zero `raise NotImplementedError`, TODOs, or FIXMEs found |

#### Unique to Python (not in TS)
- Widest conformance format coverage (7/8 formats)
- Zero external dependencies for the SDK (`packages/runar-py/`) — uses only Python stdlib (`hashlib`, `hmac`, etc.)
- 23 example contracts with pytest suites

---

### Ruby

**Overall parity score**: NEAR-COMPLETE

#### Pipeline Completeness
| Stage | TS File(s) | Ruby File(s) | Status |
|-------|-----------|--------------|--------|
| Parse (TS) | `01-parse.ts` | `frontend/parser_ts.rb` (1,524 lines) | ✅ |
| Parse (Sol) | `01-parse-sol.ts` | `frontend/parser_sol.rb` (1,419 lines) | ✅ |
| Parse (Move) | `01-parse-move.ts` | `frontend/parser_move.rb` (1,122 lines) | ✅ |
| Parse (Go) | `01-parse-go.ts` | `frontend/parser_go.rb` (1,336 lines) | ✅ |
| Parse (Rust) | `01-parse-rust.ts` | `frontend/parser_rust.rb` (1,544 lines) | ✅ |
| Parse (Python) | `01-parse-python.ts` | `frontend/parser_python.rb` (1,680 lines) | ✅ |
| Parse (Ruby) | `01-parse-ruby.ts` | `frontend/parser_ruby.rb` (1,781 lines) | ✅ |
| Parse (Zig) | `01-parse-zig.ts` | `frontend/parser_zig.rb` (1,756 lines) | ✅ |
| Validate | `02-validate.ts` | `frontend/validator.rb` (614 lines) | ✅ |
| Typecheck | `03-typecheck.ts` | `frontend/typecheck.rb` (858 lines) | ✅ |
| ANF Lower | `04-anf-lower.ts` | `frontend/anf_lower.rb` (1,658 lines) | ✅ |
| Constant Fold | `optimizer/constant-fold.ts` | `frontend/constant_fold.rb` (525 lines) | ✅ |
| ANF-EC Optimizer | `optimizer/anf-ec.ts` | `frontend/anf_optimize.rb` (479 lines) | ✅ |
| Stack Lower | `05-stack-lower.ts` | `codegen/stack.rb` (3,000 lines) | ✅ |
| Peephole | `optimizer/peephole.ts` | `codegen/optimizer.rb` (231 lines) | ✅ |
| Emit | `06-emit.ts` | `codegen/emit.rb` (596 lines) | ✅ |
| EC Codegen | `ec-codegen.ts` | `codegen/ec.rb` (1,072 lines) | ✅ |
| SHA-256 Codegen | `sha256-codegen.ts` | `codegen/sha256.rb` (588 lines) | ✅ |
| BLAKE3 Codegen | `blake3-codegen.ts` | `codegen/blake3.rb` (626 lines) | ✅ |
| SLH-DSA Codegen | `slh-dsa-codegen.ts` | `codegen/slh_dsa.rb` (1,354 lines) | ✅ |

#### Missing Language Constructs
- None. All 66+ built-in functions present including `buildChangeOutput` (`typecheck.rb:105`).

#### Test Gaps
- TS compiler test count: **819** (30 files)
- Ruby compiler test count: **116** (8 files)
- **Coverage ratio: 14%** — the lowest of all compilers
- **Multiple TS test categories have no Ruby equivalent:**
  - Parser tests for Python, Move, Sol, Zig, Rust, Go formats (6 missing)
  - ANF lower tests, ANF-EC optimizer tests (2 missing)
  - IR loader tests, assembler tests, EC tests (3 missing)
- Only 2 parser-specific test files: `test_parser_ts.rb` and `test_parser_ruby.rb`
- Conformance tests (28 golden-file) provide baseline coverage but don't test edge cases
- Ruby SDK tests are more extensive (683 spec assertions in `packages/runar-rb/spec/`)

#### Conformance Gaps
- Registered in `conformance/formats.json` for only **2 of 8 formats**: `.runar.ts`, `.runar.rb`
- Not registered for: `.runar.sol`, `.runar.move`, `.runar.py`, `.runar.go`, `.runar.rs`, `.runar.zig`
- Despite having all 8 parsers implemented, 6 parsers have zero conformance test coverage

#### Stub/Placeholder Inventory
| File | Function/Method | Evidence |
|------|----------------|----------|
| (none) | (none) | Zero `raise NotImplementedError`, TODOs, or FIXMEs found |

#### Unique to Ruby (not in TS)
- Ruby LSP addon (`packages/runar-rb/lib/ruby_lsp/runar/`): hover info, completion, indexing — editor integration not available for other languages
- DSL helpers (`packages/runar-rb/lib/runar/dsl.rb`, 81 lines) for idiomatic Ruby contract property declarations
- Missing 1 example contract vs TS: `message-board` (21 vs 22 examples)

---

### Zig

**Overall parity score**: PARTIAL

#### Pipeline Completeness
| Stage | TS File(s) | Zig File(s) | Status |
|-------|-----------|-------------|--------|
| Parse (TS) | `01-parse.ts` | `passes/parse_ts.zig` (2,236 lines) | ✅ |
| Parse (Sol) | `01-parse-sol.ts` | — | ❌ MISSING |
| Parse (Move) | `01-parse-move.ts` | — | ❌ MISSING |
| Parse (Go) | `01-parse-go.ts` | — | ❌ MISSING |
| Parse (Rust) | `01-parse-rust.ts` | — | ❌ MISSING |
| Parse (Python) | `01-parse-python.ts` | — | ❌ MISSING |
| Parse (Ruby) | `01-parse-ruby.ts` | — | ❌ MISSING |
| Parse (Zig) | `01-parse-zig.ts` | `passes/parse_zig.zig` (1,608 lines) | ✅ |
| Validate | `02-validate.ts` | `passes/validate.zig` (1,138 lines) | ✅ |
| Typecheck | `03-typecheck.ts` | `passes/typecheck.zig` (1,659 lines) | ✅ |
| ANF Lower | `04-anf-lower.ts` | `passes/anf_lower.zig` (1,790 lines) | ✅ |
| Constant Fold | `optimizer/constant-fold.ts` | `passes/constant_fold.zig` (1,437 lines) | ✅ |
| ANF-EC Optimizer | `optimizer/anf-ec.ts` | `passes/ec_optimizer.zig` (667 lines) | ✅ |
| Stack Lower | `05-stack-lower.ts` | `passes/stack_lower.zig` (4,435 lines) | ✅ |
| Peephole | `optimizer/peephole.ts` | `passes/peephole.zig` (764 lines) | ✅ |
| Emit | `06-emit.ts` | `codegen/emit.zig` | ✅ |
| EC Codegen | `ec-codegen.ts` | `passes/helpers/ec_emitters.zig` (916 lines) | ✅ |
| SHA-256 Codegen | `sha256-codegen.ts` | `passes/helpers/sha256_emitters.zig` (601 lines) | ✅ |
| BLAKE3 Codegen | `blake3-codegen.ts` | `passes/helpers/blake3_emitters.zig` (645 lines) | ✅ |
| SLH-DSA Codegen | `slh-dsa-codegen.ts` | `passes/helpers/pq_emitters.zig` (1,468 lines) | ✅ |

#### Missing Language Constructs
- **6 format parsers missing** — the Zig compiler cannot compile `.runar.sol`, `.runar.move`, `.runar.go`, `.runar.rs`, `.runar.py`, or `.runar.rb` files. Confirmed at `main.zig:138-145` where `detectFormat()` only recognizes `.runar.ts`, `.runar.zig`, and `.json` (ANF IR). Unknown extensions return `error.UnsupportedFormat`.
- **`split` builtin missing from typecheck** (`typecheck.zig`). Present in TS at `03-typecheck.ts:109`. Not found in Zig's `builtin_functions` static string map. Any contract using `split()` will fail type checking in the Zig compiler.

#### Test Gaps
- TS compiler test count: **819** (30 files)
- Zig compiler test count: **414** (inline tests across all source files)
- **Coverage ratio: 51%**
- Tests are well-distributed across all pipeline stages (Zig idiom: inline `test` blocks alongside implementation)
- No parser tests for the 6 missing format parsers (expected, since the parsers don't exist)

#### Conformance Gaps
- Registered in `conformance/formats.json` for only **2 of 8 formats**: `.runar.ts`, `.runar.zig`
- Conformance tests use JSON IR path (passes 5-6 only), so the Zig backend is fully conformance-tested, but its 2 parsers receive no multi-compiler cross-validation
- Not registered for: `.runar.sol`, `.runar.move`, `.runar.py`, `.runar.go`, `.runar.rs`, `.runar.rb`

#### Stub/Placeholder Inventory
| File | Function/Method | Evidence |
|------|----------------|----------|
| (none) | (none) | Zero `@panic`-as-stub, TODOs, or FIXMEs found |

#### Unique to Zig (not in TS)
- **Standalone DCE pass** (`passes/dce.zig`, 233 lines) — the only compiler with a reusable dead code elimination module
- **Dual ANF representation** — supports both canonical TypeScript-matching ANF value kinds (17 variants) and legacy JSON IR kinds (13 additional variants) in a single `ANFValue` union
- **O(1) StackMap lookup** — uses a parallel hash map for variable name lookups during stack lowering; other compilers use linear scans
- Inline tests in every source file — Zig idiom embeds tests alongside implementation code
- 23 example contracts with dedicated test suites

---

## Input Format Coverage (Solidity-like, Move-style)

Solidity-like and Move-style are input format parsers implemented within each compiler, not standalone compiler implementations. They produce the same AST as TypeScript and compile to identical Bitcoin Script.

### Format Parser Matrix

| Format | TS | Go | Rust | Python | Ruby | Zig |
|--------|----|----|------|--------|------|-----|
| `.runar.ts` | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| `.runar.sol` | ✅ | ✅ | ✅ | ✅ | ✅ | ❌ |
| `.runar.move` | ✅ | ✅ | ✅ | ✅ | ✅ | ❌ |
| `.runar.go` | ✅ | ✅ | ✅ | ✅ | ✅ | ❌ |
| `.runar.rs` | ✅ | ✅ | ✅ | ✅ | ✅ | ❌ |
| `.runar.py` | ✅ | ✅ | ✅ | ✅ | ✅ | ❌ |
| `.runar.rb` | ✅ | ✅ | ✅ | ✅ | ✅ | ❌ |
| `.runar.zig` | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |

### Solidity-like / Move-style Example Coverage

Both Solidity-like and Move-style formats have **17 of 22 example contracts** (vs TypeScript's 22). Missing from both:
- `convergence-proof`
- `function-patterns`
- `post-quantum-wallet`
- `schnorr-zkp`
- `sphincs-wallet`

All 28 conformance tests have `.runar.sol` and `.runar.move` contract files.

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

Ruby has 8 parsers but only 2 are conformance-tested. Python has a Zig parser but it's not registered. The TypeScript compiler itself is not tested for `.runar.go`, `.runar.rs`, or `.runar.zig` formats in conformance — despite having parsers for all three.

### 2. `buildChangeOutput` Builtin Registration is Inconsistent

This compiler-internal builtin is registered in the typecheck pass of TypeScript, Python, and Ruby — but NOT in Go or Rust. While functionally irrelevant (it's auto-injected by ANF lowering), the inconsistency means the compilers don't have identical error messages for edge-case inputs.

### 3. Test Coverage Drops Sharply Outside TypeScript

| Compiler | Compiler Tests | % of TS (819) | SDK Tests | Example Contracts |
|----------|---------------|---------------|-----------|-------------------|
| TypeScript | 819 | 100% | 309 | 22 |
| Rust | 567 | 69% | 4,796* | 23 |
| Python | 544 | 66% | 337 | 23 |
| Go | 429 | 52% | 272 | 22 |
| Zig | 414 | 51% | 85 | 23 |
| Ruby | 116 | 14% | 683 | 21 |

*Rust SDK test count includes inline tests across all `packages/runar-rs/` source files.

Ruby's 14% compiler test coverage is concerning given it has full feature parity. The conformance suite provides a safety net, but unit tests catch edge cases and regressions that golden-file tests miss.

### 4. Zig's Parser Gap Breaks Multi-Format Promise

The project's value proposition is "write in any of 8 formats, compile with any of 6 compilers." Zig only supports 2 of 8 formats from source, breaking this promise. Every other compiler supports all 8 formats. The Zig backend is complete and clean — the gap is purely in the frontend (6 missing parsers, ~10,000 lines of code to write).

### 5. `split` Builtin Missing from Zig Typecheck

The `split` function (splits a ByteString at a given position, returns `[ByteString, ByteString]`) is registered in TypeScript (`03-typecheck.ts:109`), Go, Rust, Python, and Ruby typecheckers — but missing from Zig's `builtin_functions` in `typecheck.zig`. Any contract using `split()` will fail type checking in the Zig compiler. One-line fix.

---

## SDK Parity Summary

All 6 languages have deployment SDKs. Key comparison:

| Feature | TS | Go | Rust | Python | Ruby | Zig |
|---------|----|----|------|--------|------|-----|
| RunarContract wrapper | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| MockProvider | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| LocalSigner (ECDSA) | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| ExternalSigner | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| WalletSigner | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| WhatsOnChain Provider | ✅ | ✅ | ✅ | ✅ | ✅ | — |
| RPC Provider | ✅ | ✅ | ✅ | ✅ | ✅ | — |
| State serialization | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| ANF interpreter | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| OP_PUSH_TX | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| Token wallet | ✅ | ✅ | ✅ | ✅ | ✅ | — |
| Real EC arithmetic | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| Real ECDSA | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| compile_check() | — | ✅ | ✅ | — | — | ✅ |

---

## Conformance Test Coverage

All 28 conformance test directories have contract files in all 8 formats:

| Test | .ts | .sol | .move | .go | .rs | .py | .rb | .zig |
|------|-----|------|-------|-----|-----|-----|-----|------|
| arithmetic | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| auction | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| basic-p2pkh | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅* |
| blake3 | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| boolean-logic | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| bounded-loop | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| convergence-proof | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| covenant-vault | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| ec-demo | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| ec-primitives | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| escrow | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| function-patterns | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| if-else | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| if-without-else | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| math-demo | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| multi-method | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| oracle-price | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| post-quantum-slhdsa | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| post-quantum-wallet | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| post-quantum-wots | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| property-initializers | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| schnorr-zkp | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| sphincs-wallet | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| stateful | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| stateful-bytestring | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| stateful-counter | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| token-ft | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| token-nft | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |

*basic-p2pkh Zig file is named `P2PKH.runar.zig` (contract name convention) vs `basic-p2pkh.runar.zig` (directory name convention)

---

## Recommended Priority Actions

1. **[CRITICAL] Add 6 missing format parsers to Zig compiler** — Sol, Move, Go, Rust, Python, Ruby parsers are needed to achieve format parity. This is the single largest gap (~10,000 lines of parser code). Consider porting from the Go or Python implementations.

2. **[HIGH] Register Ruby's 6 untested parsers in `conformance/formats.json`** — Ruby has all 8 parsers implemented but only 2 are conformance-tested. Adding `"ruby"` to the Sol, Move, Python, Go, Rust, Zig format entries would immediately validate 6 more parsers against golden files with zero new code.

3. **[HIGH] Register Python's Zig parser in `conformance/formats.json`** — Python has a fully implemented Zig parser (`parser_zig.py`, 1,557 lines) that is never conformance-tested. Adding `"python"` to the `.runar.zig` entry would enable cross-validation.

4. **[HIGH] Register TypeScript's Go/Rust/Zig parsers in `conformance/formats.json`** — The TS compiler has parsers for `.runar.go`, `.runar.rs`, and `.runar.zig` but these are not conformance-tested.

5. **[MEDIUM] Add `split` builtin to Zig typecheck** — The `split` function is missing from Zig's builtin registry. One-line fix in `typecheck.zig`.

6. **[MEDIUM] Add `buildChangeOutput` to Go and Rust typecheck builtins** — Cosmetic inconsistency but needed for strict cross-compiler parity in error reporting.

7. **[MEDIUM] Increase Ruby compiler test coverage** — Ruby has 116 tests (14% of TS). Priority areas: format parser unit tests (currently only 2 files for 8 parsers), ANF lowering tests (0 tests), emit tests (0 tests). Target: at least 50% of TS test count (~410 tests).

8. **[MEDIUM] Add 5 missing Solidity/Move examples** — Both Sol and Move are missing convergence-proof, function-patterns, post-quantum-wallet, schnorr-zkp, and sphincs-wallet examples.

9. **[LOW] Add Ruby `message-board` example** — Ruby has 21 examples vs TS's 22, missing only message-board.

10. **[LOW] Zig SDK: add WhatsOnChain/RPC providers and TokenWallet** — Minor SDK gaps for production deployment scenarios.
