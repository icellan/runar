# Rúnar Cross-Language Gap Analysis Report

Generated: 2026-03-29
Golden standard: TypeScript
Languages audited: Go, Rust, Python, Ruby, Zig (compilers + SDKs)

## Executive Summary

The Rúnar project maintains 6 compiler implementations and 6 SDKs across TypeScript, Go, Rust, Python, Ruby, and Zig. **Go and Rust compilers are the closest to full parity** with TypeScript — both implement all 6 pipeline passes, all 17 ANF value kinds, all built-in functions, all 4 codegen modules (SHA-256, BLAKE3, EC, SLH-DSA), and all 3 optimizers with zero stubs or TODOs. **Python is also near-complete** with a few codegen-level bugs (dead `__array_access` dispatch, missing `exit` builtin). **Ruby is the weakest compiler** — it has only 2 of 8 format parsers, 16 tests (vs 753 in TS), and two stubbed builtins. **Zig is functionally strong** (414 tests, all 28 conformance tests passing) but has only 2 format parsers.

The single most critical systemic gap is **the Zig format parser**: no compiler except TypeScript can parse `.runar.zig` files. The second most impactful gap is the **Ruby compiler's missing 5 format parsers and minimal test coverage**, which makes it the least production-ready alternative compiler. Across all SDKs, the **BRC-100 wallet integration** (WalletProvider, WalletSigner, deployWithWallet) and **WhatsOnChainProvider** are consistently absent — these are TypeScript-only features tied to the browser/wallet ecosystem.

---

## Per-Language Findings

### Go Compiler

**Overall parity score**: NEAR-COMPLETE

#### Pipeline Completeness
| Stage | TS File(s) | Go File(s) | Status |
|-------|-----------|------------|--------|
| Pass 1: Parse | `passes/01-parse.ts` + 7 format parsers | `frontend/parser.go` + 6 format parsers | ✅ (missing Zig) |
| Pass 2: Validate | `passes/02-validate.ts` | `frontend/validator.go` | ✅ |
| Pass 3: Typecheck | `passes/03-typecheck.ts` | `frontend/typecheck.go` | ✅ |
| Pass 4: ANF Lower | `passes/04-anf-lower.ts` | `frontend/anf_lower.go` | ✅ |
| Pass 4.25: Constant Fold | `optimizer/constant-fold.ts` | `frontend/constant_fold.go` | ✅ |
| Pass 4.5: EC Optimize | `optimizer/anf-ec.ts` | `frontend/anf_optimize.go` | ✅ |
| Pass 5: Stack Lower | `passes/05-stack-lower.ts` | `codegen/stack.go` | ✅ |
| Pass 5.5: Peephole | `optimizer/peephole.ts` | `codegen/optimizer.go` | ✅ |
| Pass 6: Emit | `passes/06-emit.ts` | `codegen/emit.go` | ✅ |
| SHA-256 Codegen | `passes/sha256-codegen.ts` | `codegen/sha256.go` | ✅ |
| BLAKE3 Codegen | `passes/blake3-codegen.ts` | `codegen/blake3.go` | ✅ |
| EC Codegen | `passes/ec-codegen.ts` | `codegen/ec.go` | ✅ |
| SLH-DSA Codegen | `passes/slh-dsa-codegen.ts` | `codegen/slh_dsa.go` | ✅ |

#### Missing Language Constructs
- **Zig format parser** (`.runar.zig`): TS has `01-parse-zig.ts` (1328 LOC). Go has no `parser_zig.go` — `frontend/parser.go:41-58` has no `.runar.zig` case.
- **`exit()` builtin in stack lowering**: TS maps `exit` to `OP_VERIFY` at `05-stack-lower.ts:1105-1116`. Go recognizes `exit` in typecheck (`typecheck.go:109`) but has no handler in `codegen/stack.go` — falls through to unknown function path.
- **BigIntLiteral overflow risk**: Go AST uses `int64` for `BigIntLiteral.Value` (`ast.go:202`) while TS uses `bigint`. Literals exceeding 2^63-1 (e.g., EC curve constants) overflow at parse time. ANF IR layer correctly uses `*big.Int`.

#### Test Gaps
- TS test count: ~753
- Go test count: 410
- No direct per-file mapping (Go tests are organized differently), but coverage spans all passes.
- Go has 55 additional conformance script execution tests in `conformance/script_execution_test.go` (unique to Go).

#### Conformance Gaps
All 28 conformance tests are covered (27 in standard suite + `stateful-bytestring` addressed through bulk tests).

#### Stub/Placeholder Inventory
None. Zero `// TODO`, `// FIXME`, or stub functions found. All `panic()` calls are argument-count validation guards or assertion-style safety checks.

#### Unique to Go (not in TS)
- **Tree-sitter TS parser**: Uses `go-tree-sitter` instead of ts-morph for `.runar.ts` parsing.
- **`CompileFromIR` / `CompileSourceToIR`**: Explicit public API for partial pipeline execution.
- **`CompileFromSourceWithResult`**: Rich result struct with panic recovery and partial results.
- **Conformance script execution tests**: 55 tests executing compiled scripts through go-sdk's Bitcoin Script interpreter.

---

### Go SDK

**Overall parity score**: NEAR-COMPLETE

#### API Surface
| Feature | TS SDK | Go SDK | Status |
|---------|--------|--------|--------|
| RunarContract (deploy, call, prepareCall, finalizeCall) | Yes | Yes | ✅ |
| Provider interface (7 methods) | Yes | Yes | ✅ |
| MockProvider | Yes | Yes | ✅ |
| WhatsOnChainProvider | Yes | -- | ❌ MISSING |
| RPCProvider | Yes | Yes | ✅ |
| WalletProvider (BRC-100) | Yes | -- | ❌ MISSING |
| LocalSigner (real ECDSA + BIP-143) | Yes | Yes | ✅ |
| ExternalSigner | Yes | Yes | ✅ |
| WalletSigner (BRC-100) | Yes | -- | ❌ MISSING |
| buildDeployTransaction / selectUtxos | Yes | Yes | ✅ |
| buildCallTransaction | Yes | Yes | ✅ |
| State serialization/deserialization | Yes | Yes | ✅ |
| computeOpPushTx | Yes | Yes | ✅ |
| computeNewState (ANF interpreter) | Yes | Yes | ✅ |
| TokenWallet | Yes | -- | ❌ MISSING |
| extractConstructorArgs / matchesArtifact | Yes | -- | ❌ MISSING |
| deployWithWallet / fromUtxo | Yes | -- | ❌ MISSING |
| buildP2PKHScript (pubkey auto-hash) | Yes | Partial | ⚠️ PARTIAL |
| Codegen (generateGo) | TS generates TS | Go generates Go | ✅ |

- Go test count: 245 (7 test files)

---

### Rust Compiler

**Overall parity score**: COMPLETE

#### Pipeline Completeness
| Stage | TS File(s) | Rust File(s) | Status |
|-------|-----------|-------------|--------|
| Pass 1: Parse | `passes/01-parse.ts` + 7 format parsers | `frontend/parser.rs` + 6 format parsers | ✅ (missing Zig) |
| Pass 2: Validate | `passes/02-validate.ts` | `frontend/validator.rs` (1002 lines) | ✅ |
| Pass 3: Typecheck | `passes/03-typecheck.ts` | `frontend/typecheck.rs` (1597 lines) | ✅ |
| Pass 4: ANF Lower | `passes/04-anf-lower.ts` | `frontend/anf_lower.rs` (2339 lines) | ✅ |
| Pass 4.25: Constant Fold | `optimizer/constant-fold.ts` | `frontend/constant_fold.rs` (1229 lines) | ✅ |
| Pass 4.5: EC Optimize | `optimizer/anf-ec.ts` | `frontend/anf_optimize.rs` (1127 lines) | ✅ |
| Pass 5: Stack Lower | `passes/05-stack-lower.ts` | `codegen/stack.rs` (5563 lines) | ✅ |
| Pass 5.5: Peephole | `optimizer/peephole.ts` | `codegen/optimizer.rs` (730 lines) | ✅ |
| Pass 6: Emit | `passes/06-emit.ts` | `codegen/emit.rs` (1240 lines) | ✅ |
| Artifact Assembly | `artifact/assembler.ts` | `artifact.rs` (278 lines) | ✅ |
| SHA-256 Codegen | `passes/sha256-codegen.ts` | `codegen/sha256.rs` (632 lines) | ✅ |
| BLAKE3 Codegen | `passes/blake3-codegen.ts` | `codegen/blake3.rs` (698 lines) | ✅ |
| EC Codegen | `passes/ec-codegen.ts` | `codegen/ec.rs` (923 lines) | ✅ |
| SLH-DSA Codegen | `passes/slh-dsa-codegen.ts` | `codegen/slh_dsa.rs` (1593 lines) | ✅ |

#### Missing Language Constructs
- **Zig format parser** (`.runar.zig`): No `parser_zig.rs`. `parser.rs:1134-1156` does not handle `.runar.zig`.
- **Conformance test `stateful-bytestring`**: Not listed in test arrays (27 of 28 covered).
- **BigIntLiteral precision**: `ast.rs:279` uses `i64` while TS uses arbitrary-precision `bigint`. ANF IR uses `i128` which partially mitigates.

#### Test Gaps
- Rust test count: 556 (21 test files including inline `#[cfg(test)]` modules)
- No missing builtins. All operators, all ANF kinds match.

#### Conformance Gaps
27 of 28 conformance tests covered. Missing: `stateful-bytestring`.

#### Stub/Placeholder Inventory
None. Zero `todo!()`, `unimplemented!()`, `// TODO`, or `// FIXME` found.

#### Unique to Rust (not in TS)
- **SWC-based TS parser**: Uses `swc_ecma_parser` (Rust-native) instead of ts-morph — zero Node.js dependency.
- **Panic-safe compilation**: Uses `std::panic::catch_unwind` for stack lowering/emit stages.
- **Self-contained timestamp**: Manual UTC formatting without chrono crate (Howard Hinnant's algorithm).

---

### Rust SDK

**Overall parity score**: NEAR-COMPLETE

#### API Surface
| Feature | TS SDK | Rust SDK | Status |
|---------|--------|----------|--------|
| RunarContract (deploy, call, prepareCall, finalizeCall) | Yes | Yes | ✅ |
| Provider trait (7 methods) | Yes (async) | Yes (sync) | ✅ |
| MockProvider | Yes | Yes | ✅ |
| WhatsOnChainProvider | Yes | -- | ❌ MISSING |
| RPCProvider | Yes | Yes | ✅ |
| WalletProvider (BRC-100) | Yes | -- | ❌ MISSING |
| LocalSigner (k256 ECDSA + manual BIP-143) | Yes | Yes | ✅ |
| ExternalSigner | Yes | Yes | ✅ |
| WalletSigner (BRC-100) | Yes | -- | ❌ MISSING |
| buildDeployTransaction / selectUtxos | Yes | Yes | ✅ |
| buildCallTransaction | Yes | Yes | ✅ |
| State serialization/deserialization | Yes | Yes | ✅ |
| computeOpPushTx | Yes | Yes | ✅ |
| computeNewState (ANF interpreter) | Yes | Yes (1089 lines) | ✅ |
| TokenWallet | Yes | -- | ❌ MISSING |
| extractConstructorArgs / matchesArtifact | Yes | -- | ❌ MISSING |
| deployWithWallet | Yes | -- | ❌ MISSING |
| compile_check | N/A | Yes | ✅ (Rust-specific) |
| Proc macros (#[contract], #[public]) | N/A | Yes (runar-rs-macros) | ✅ (Rust-specific) |
| Codegen (generate_rust) | TS generates TS | Rust generates Rust | ✅ |

- Rust SDK test count: 267 (including 168 SDK-specific tests across 10 modules)

---

### Python Compiler

**Overall parity score**: NEAR-COMPLETE

#### Pipeline Completeness
| Stage | TS File(s) | Python File(s) | Status |
|-------|-----------|----------------|--------|
| Pass 1: Parse | `passes/01-parse.ts` + 7 format parsers | `frontend/parser_dispatch.py` + 7 parsers | ✅ (missing Zig) |
| Pass 2: Validate | `passes/02-validate.ts` | `frontend/validator.py` (590 lines) | ✅ |
| Pass 3: Typecheck | `passes/03-typecheck.ts` | `frontend/typecheck.py` (904 lines) | ⚠️ PARTIAL (missing `split`, `buildChangeOutput`) |
| Pass 4: ANF Lower | `passes/04-anf-lower.ts` | `frontend/anf_lower.py` (1091 lines) | ✅ |
| Pass 4.25: Constant Fold | `optimizer/constant-fold.ts` | `frontend/constant_fold.py` (488 lines) | ✅ |
| Pass 4.5: EC Optimize | `optimizer/anf-ec.ts` | `frontend/anf_optimize.py` (388 lines) | ✅ |
| Pass 5: Stack Lower | `passes/05-stack-lower.ts` | `codegen/stack.py` (3512 lines) | ⚠️ PARTIAL (see below) |
| Pass 5.5: Peephole | `optimizer/peephole.ts` | `codegen/optimizer.py` (255 lines) | ✅ |
| Pass 6: Emit | `passes/06-emit.ts` | `codegen/emit.py` (492 lines) | ✅ |
| SHA-256 Codegen | `passes/sha256-codegen.ts` | `codegen/sha256.py` (562 lines) | ✅ |
| BLAKE3 Codegen | `passes/blake3-codegen.ts` | `codegen/blake3.py` (644 lines) | ✅ |
| EC Codegen | `passes/ec-codegen.ts` | `codegen/ec.py` (920 lines) | ✅ |
| SLH-DSA Codegen | `passes/slh-dsa-codegen.ts` | `codegen/slh_dsa.py` (1181 lines) | ✅ |

#### Missing Language Constructs
- **Zig format parser**: No `parser_zig.py`. Not dispatched in `compiler.py` or `parser_dispatch.py`.
- **`exit()` builtin**: Present in typecheck (`typecheck.py:140`) but not handled in `codegen/stack.py:_lower_call`. Falls through to general builtin lookup and emits incorrect push-0 placeholder.
- **`__array_access` dead code**: `_lower_array_access` exists at `stack.py:2542` but is never called from `_lower_call` — contracts using indexed byte access emit incorrect script.
- **`arrayLengths` tracking for checkMultiSig**: TS tracks array_literal element counts (`05-stack-lower.ts:328`) for nSigs/nPKs pushes. Python's `_lower_check_multi_sig` does not emit count values — may produce incorrect `OP_CHECKMULTISIG` scripts.
- **Typecheck missing `split` and `buildChangeOutput`**: These builtin signatures are in TS `03-typecheck.ts:109,144` but absent from Python's typecheck. Contracts compile but arguments aren't type-validated.
- **DCE missing `add_raw_output` side-effect**: `anf_optimize.py:_has_side_effect` does not include `add_raw_output` — binding could be incorrectly eliminated.
- **DCE missing `script_bytes`/`elements` ref tracking**: `_collect_refs` does not track these fields for `add_raw_output` and `array_literal`.

#### Test Gaps
- Python test count: 480 functions (583 with parametrization), 11 test files
- Missing conformance test: `stateful-bytestring` (27 of 28 covered)

#### Stub/Placeholder Inventory
None. Zero `raise NotImplementedError`, `# TODO`, or `# FIXME` found.

#### Unique to Python (not in TS)
- Conservative DCE: `_has_side_effect` includes `if` and `loop` (TS does not) — less optimization, not incorrect.
- `len()` stack handling differs from TS (matches Go approach) — functionally equivalent.

---

### Python SDK

**Overall parity score**: NEAR-COMPLETE

#### API Surface
| Feature | TS SDK | Python SDK | Status |
|---------|--------|------------|--------|
| RunarContract (deploy, call, prepare_call, finalize_call, from_txid) | Yes | Yes | ✅ |
| Provider ABC (7 methods) | Yes (async) | Yes (sync) | ✅ |
| MockProvider | Yes | Yes | ✅ |
| WhatsOnChainProvider | Yes | -- | ❌ MISSING |
| RPCProvider | Yes | Yes (stdlib urllib) | ✅ |
| WalletProvider (BRC-100) | Yes | -- | ❌ MISSING |
| LocalSigner | Yes | Yes (optional bsv-sdk) | ✅ |
| ExternalSigner | Yes | Yes | ✅ |
| WalletSigner (BRC-100) | Yes | -- | ❌ MISSING |
| Transaction builders | Yes | Yes | ✅ |
| State management | Yes | Yes | ✅ |
| computeOpPushTx | Yes | Yes (pure Python) | ✅ |
| computeNewState (ANF interpreter) | Yes | Yes (554 lines) | ✅ |
| TokenWallet | Yes | -- | ❌ MISSING |
| extractConstructorArgs / matchesArtifact | Yes | -- | ❌ MISSING |
| deployWithWallet | Yes | -- | ❌ MISSING |
| Codegen (generate_python) | TS generates TS | Python generates Python | ✅ |

- Python SDK test count: 303 (16 test files)
- Extra: `MockSigner`, `insert_unlocking_script` helper

---

### Ruby Compiler

**Overall parity score**: PARTIAL

#### Pipeline Completeness
| Stage | TS File(s) | Ruby File(s) | Status |
|-------|-----------|--------------|--------|
| Pass 1: Parse | `passes/01-parse.ts` + 7 format parsers | `compiler.rb` + `parser_ts.rb`, `parser_ruby.rb` | ⚠️ PARTIAL (2 of 8) |
| Pass 2: Validate | `passes/02-validate.ts` | `frontend/validator.rb` (614 lines) | ✅ |
| Pass 3: Typecheck | `passes/03-typecheck.ts` | `frontend/typecheck.rb` (858 lines) | ✅ |
| Pass 4: ANF Lower | `passes/04-anf-lower.ts` | `frontend/anf_lower.rb` (1636 lines) | ✅ |
| Pass 4.25: Constant Fold | `optimizer/constant-fold.ts` | `frontend/constant_fold.rb` (525 lines) | ✅ |
| Pass 4.5: EC Optimize | `optimizer/anf-ec.ts` | `frontend/anf_optimize.rb` (479 lines) | ✅ |
| Pass 5: Stack Lower | `passes/05-stack-lower.ts` | `codegen/stack.rb` (2932 lines) | ⚠️ PARTIAL (2 stubs) |
| Pass 5.5: Peephole | `optimizer/peephole.ts` | `codegen/optimizer.rb` (231 lines) | ✅ |
| Pass 6: Emit | `passes/06-emit.ts` | `codegen/emit.rb` (596 lines) | ✅ |
| SHA-256 Codegen | `passes/sha256-codegen.ts` | `codegen/sha256.rb` (588 lines) | ✅ |
| BLAKE3 Codegen | `passes/blake3-codegen.ts` | `codegen/blake3.rb` (626 lines) | ✅ |
| EC Codegen | `passes/ec-codegen.ts` | `codegen/ec.rb` (1072 lines) | ✅ |
| SLH-DSA Codegen | `passes/slh-dsa-codegen.ts` | `codegen/slh_dsa.rb` (1354 lines) | ✅ |

#### Missing Language Constructs
- **5 format parsers missing**: `compiler.rb:107-134` dispatches to `parser_sol.rb`, `parser_move.rb`, `parser_go.rb`, `parser_rust.rb`, `parser_python.rb` — **none of these files exist**. Attempting to compile these formats raises `LoadError`.
- **`exit()` builtin**: Present in typecheck but missing from `codegen/stack.rb`.
- **`reverseBytes` is a stub**: `codegen/stack.rb:1725-1726` — marked `# TODO: Full implementation in Part 2`. Does not emit actual byte-reversal opcodes — contracts using `reverseBytes` produce incorrect script.
- **`checkMultiSig` is incomplete**: `codegen/stack.rb:1713-1714` — marked `# TODO: Full implementation in Part 2`. Missing `OP_0` prefix for Bitcoin's off-by-one behavior.

#### Test Gaps
- TS test count: ~753
- Ruby test count: **16** (3 test files)
- Missing test files: All equivalent test categories from TS (parser per-format tests, typecheck tests, ANF lower tests, stack lower tests, optimizer tests, e2e tests, cross-compiler tests, blake3 tests, ec tests, sha256 tests)
- Only **2 of 28** conformance tests are run (`basic-p2pkh` for `.ts` and `.rb` formats)

#### Stub/Placeholder Inventory
| File:Line | Evidence |
|-----------|----------|
| `codegen/stack.rb:1714` | `# TODO: Full implementation in Part 2` — `_lower_check_multi_sig` |
| `codegen/stack.rb:1726` | `# TODO: Full implementation in Part 2` — `_lower_reverse_bytes` |

#### Unique to Ruby (not in TS)
- **Token constant collision**: Both `parser_ts.rb` and `parser_ruby.rb` define `TOK_EOF`, `TOK_IDENT`, etc. as module-level constants in the same `RunarCompiler::Frontend` module with different values. Loading both parsers corrupts tokenization. Tests work around this with subprocess isolation.
- **Ruby DSL format**: Supports idiomatic Ruby syntax (`class Foo < Runar::SmartContract`, `prop :name, Type`, `@instance_var`, `runar_public`).

---

### Ruby SDK

**Overall parity score**: NEAR-COMPLETE

#### API Surface
| Feature | TS SDK | Ruby SDK | Status |
|---------|--------|----------|--------|
| RunarContract (deploy, call, prepare_call, finalize_call, from_txid) | Yes | Yes | ✅ |
| Provider / MockProvider / RPCProvider | Yes | Yes | ✅ |
| WhatsOnChainProvider | Yes | -- | ❌ MISSING |
| WalletProvider / WalletSigner (BRC-100) | Yes | -- | ❌ MISSING |
| LocalSigner (real ECDSA via bsv-sdk gem) | Yes | Yes | ✅ |
| ExternalSigner / MockSigner | Yes | Yes | ✅ |
| Transaction builders (deploy + call) | Yes | Yes | ✅ |
| State management | Yes | Yes | ✅ |
| computeOpPushTx | Yes | Yes | ✅ |
| computeNewState (ANF interpreter) | Yes | Yes | ✅ |
| TokenWallet | Yes | -- | ❌ MISSING |
| extractConstructorArgs / matchesArtifact | Yes | -- | ❌ MISSING |
| Codegen (generate_ruby) | TS generates TS | Ruby generates Ruby | ✅ |

- Ruby SDK test count: ~675 (24 spec files — strongest test suite of any non-TS SDK)
- Extra: Ruby LSP addon (hover, completion, indexing — 64 dedicated tests), pure Ruby ECDSA, DSL module

---

### Zig Compiler

**Overall parity score**: NEAR-COMPLETE

#### Pipeline Completeness
| Stage | TS File(s) | Zig File(s) | Status |
|-------|-----------|-------------|--------|
| Pass 1: Parse | `passes/01-parse.ts` + 7 format parsers | `passes/parse_ts.zig` + `passes/parse_zig.zig` | ⚠️ PARTIAL (2 of 8) |
| Pass 2: Validate | `passes/02-validate.ts` | `passes/validate.zig` | ✅ |
| Pass 3: Typecheck | `passes/03-typecheck.ts` | `passes/typecheck.zig` | ✅ |
| Pass 4: ANF Lower | `passes/04-anf-lower.ts` | `passes/anf_lower.zig` | ✅ |
| Pass 4.25: Constant Fold | `optimizer/constant-fold.ts` | `passes/constant_fold.zig` | ✅ |
| Pass 4.3: DCE | (embedded in constant-fold.ts) | `passes/dce.zig` (standalone, 233 lines) | ✅ (extracted) |
| Pass 4.5: EC Optimize | `optimizer/anf-ec.ts` | `passes/ec_optimizer.zig` | ✅ |
| Pass 5: Stack Lower | `passes/05-stack-lower.ts` | `passes/stack_lower.zig` (4435 lines) | ✅ |
| Pass 5.5: Peephole | `optimizer/peephole.ts` | `passes/peephole.zig` | ✅ |
| Pass 6: Emit | `passes/06-emit.ts` | `codegen/emit.zig` + `codegen/opcodes.zig` | ✅ |
| SHA-256 Codegen | `passes/sha256-codegen.ts` | `passes/helpers/sha256_emitters.zig` | ✅ |
| BLAKE3 Codegen | `passes/blake3-codegen.ts` | `passes/helpers/blake3_emitters.zig` | ✅ |
| EC Codegen | `passes/ec-codegen.ts` | `passes/helpers/ec_emitters.zig` | ✅ |
| SLH-DSA Codegen | `passes/slh-dsa-codegen.ts` | `passes/helpers/pq_emitters.zig` | ✅ |

#### Missing Language Constructs
- **6 format parsers missing**: Sol, Move, Python, Go, Rust, Ruby. Only `.runar.ts` and `.runar.zig` are supported via native parsing (plus IR JSON consumer mode).

#### Test Gaps
- Zig test count: 414 (24 test locations across source files)
- All 28 conformance tests pass (best conformance coverage of any alternative compiler)

#### Stub/Placeholder Inventory
None. All `unreachable` uses are legitimate switch exhaustiveness guards.

#### Unique to Zig (not in TS)
- **Standalone DCE pass** (`dce.zig`): TS embeds DCE in constant-fold.ts. Zig extracts it as a reusable standalone pass.
- **Legacy ANF variants**: IR types include 11 legacy variants for JSON IR consumer compatibility.
- **Zig validation mode**: Validator relaxes `super()` requirement for Zig's field-initialization syntax.
- **`--disable-constant-folding` CLI flag**: Exposed as CLI option.
- **Arena allocator pattern**: Explicit lifetime management throughout.

---

### Zig SDK

**Overall parity score**: PARTIAL

#### API Surface
| Feature | TS SDK | Zig SDK | Status |
|---------|--------|---------|--------|
| RunarContract (deploy, call) | Yes | Yes | ✅ |
| Provider / MockProvider | Yes | Yes (MockProvider only) | ⚠️ PARTIAL |
| WhatsOnChainProvider | Yes | -- | ❌ MISSING |
| RPCProvider | Yes | -- | ❌ MISSING |
| WalletProvider / WalletSigner | Yes | -- | ❌ MISSING |
| LocalSigner (real ECDSA via bsvz) | Yes | Yes | ✅ |
| ExternalSigner / MockSigner | Yes | Yes | ✅ |
| buildDeployTransaction / selectUtxos | Yes | Yes | ✅ |
| buildCallTransaction | Yes | Basic (no multi-output/multi-input) | ⚠️ PARTIAL |
| State management | Yes | Yes | ✅ |
| computeOpPushTx | Yes | Yes (via bsvz) | ✅ |
| computeNewState (ANF interpreter) | Yes | -- | ❌ MISSING |
| prepareCall / finalizeCall | Yes | -- | ❌ MISSING |
| fromTxId / fromUtxo | Yes | -- | ❌ MISSING |
| TokenWallet | Yes | -- | ❌ MISSING |
| extractConstructorArgs / matchesArtifact | Yes | -- | ❌ MISSING |
| Advanced CallOptions (multi-output, additional inputs) | Yes | -- | ❌ MISSING |
| Contract authoring (types, builtins, EC, PQ) | Yes | Yes (all present) | ✅ |
| compile_check | N/A | Yes | ✅ |

The Zig SDK is a **full deployment SDK** (not just testing support) — it handles deploy, call (stateless + stateful with OP_PUSH_TX), real ECDSA signing, and broadcasting. But it has more gaps than Go/Rust/Python/Ruby SDKs, particularly missing network providers, ANF interpreter, and advanced call patterns.

---

## Cross-Cutting Issues

### 1. No Compiler Except TypeScript Parses `.runar.zig`
The Zig format parser (`01-parse-zig.ts`, 1328 lines) exists only in the TS compiler. Go, Rust, Python, Ruby, and even the Zig compiler itself cannot parse arbitrary `.runar.zig` files authored in the Zig DSL format from other compilers (Zig compiler has its own native parser, but other compilers cannot consume Zig-format contracts). This blocks cross-compiler conformance testing for Zig-format contracts.

### 2. `exit()` Builtin Missing from 4 of 5 Alternative Compilers
The `exit()` function (mapped to `OP_VERIFY` in TS at `05-stack-lower.ts:1105`) is **missing from Go, Python, and Ruby stack lowering**. Rust is the only alternative compiler that handles it. Contracts using `exit()` silently produce incorrect script in 3 compilers.

### 3. BRC-100 Wallet Integration is TypeScript-Only
`WalletProvider`, `WalletSigner`, and `deployWithWallet()` exist only in the TS SDK. No other language has these — a consistent gap across Go, Rust, Python, Ruby, and Zig SDKs. This is partially expected (BRC-100 is browser/wallet-centric), but limits non-TS deployments to RPC-based workflows.

### 4. WhatsOnChainProvider Missing from All Non-TS SDKs
The HTTP-based WhatsOnChain provider for mainnet/testnet UTXO queries is absent from all 5 non-TS SDKs. This means all non-TS languages require either a local Bitcoin node (RPCProvider) or a custom Provider implementation for mainnet access.

### 5. TokenWallet, extractConstructorArgs, matchesArtifact Missing Everywhere
These three TS SDK utilities are absent from all 5 alternative SDKs — a consistent gap suggesting they may be newer additions not yet ported.

### 6. BigIntLiteral Precision in Go and Rust ASTs
Both Go (`int64`) and Rust (`i64`) use fixed-width integers for AST-level `BigIntLiteral.Value`. TS uses arbitrary-precision `bigint`. While the ANF IR layer uses big integers in both languages, extremely large numeric literals in source code could overflow during parsing.

### 7. Ruby Compiler Is Significantly Behind
The Ruby compiler has the most gaps of any implementation: 5 missing parsers, 2 stubbed builtins, a token constant namespace collision, and only 16 tests (vs 410-556 in Go/Rust). It's the only compiler with active `# TODO` stubs in production codegen paths.

### 8. Conformance Test `stateful-bytestring` Missing from 3 Compilers
Rust, Python, and (likely) Ruby do not test the `stateful-bytestring` conformance case. Go and Zig cover all 28.

---

## Recommended Priority Actions

1. **Add `exit()` builtin to Go, Python, and Ruby stack lowering** — Silent incorrect script generation is the highest-severity bug class. Map to `OP_VERIFY` matching TS behavior. Estimated effort: 5-10 lines per compiler.

2. **Fix Python `__array_access` dead code** — `_lower_array_access` exists but is never called from `_lower_call` dispatch. Contracts with indexed access produce wrong output. Single-line dispatch fix.

3. **Fix Python DCE `add_raw_output` side-effect marking** — `_has_side_effect` must include `add_raw_output` to prevent incorrect elimination. Also add `script_bytes`/`elements` to `_collect_refs`.

4. **Complete Ruby `reverseBytes` and `checkMultiSig`** — Both are marked `# TODO: Full implementation in Part 2`. Any contract using these builtins produces incorrect script.

5. **Add Zig format parser to Go, Rust, and Python compilers** — Currently only TS can parse `.runar.zig`. This blocks cross-compiler conformance for Zig-format contracts. Each parser is ~1000-1300 lines of hand-written recursive descent.

6. **Expand Ruby compiler test coverage** — 16 tests is critically low. Prioritize: (a) run all 28 conformance golden-file tests, (b) add per-pass unit tests matching Go/Rust coverage, (c) resolve the token constant collision that requires subprocess isolation.

7. **Add missing format parsers to Ruby compiler** — 5 of 7 are referenced in dispatch code but files don't exist. Sol and Move are highest priority (shared with most conformance tests).

8. **Add `stateful-bytestring` conformance test to Rust and Python** — Simple addition to test arrays.

9. **Add WhatsOnChainProvider to at least Go and Rust SDKs** — These are the most production-ready alternatives and need mainnet access without a local node.

10. **Port TokenWallet, extractConstructorArgs, matchesArtifact to all SDKs** — Consistent gap across all non-TS languages. Start with Go and Rust as highest-adoption targets.
