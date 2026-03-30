# Runar Gap Fix Plan

Generated: 2026-03-29
Based on: LANGUAGE-GAP-REPORT.md

## Fix Strategy

While all 6 compilers pass the 28 conformance tests using `.runar.ts` input, **multi-format conformance testing reveals 119 failures out of 224 tests** (53% failure rate). The core compiler backends are solid, but cross-format parser integration has significant bugs — particularly Go's Sol/Move/Python parsers failing auto-constructor generation, Python's missing `.runar.zig` dispatch, and Rust's Move parser issues.

Recommended order: (1) Fix the **critical cross-format parser bugs** first (Go, Python, Rust) since these represent real compilation failures. (2) Fix test infrastructure (Zig memory leaks). (3) Update `formats.json` only AFTER parser bugs are fixed and multi-format conformance passes. (4) Add missing examples. (5) Expand integration tests.

## Critical Parser Fixes (do these first)

### Fix GO-0: Fix Go Sol/Move/Python parser auto-constructor generation

- **Gap report reference**: Cross-Cutting Issues §1 (multi-format conformance failures)
- **What**: Go compiler fails to compile `.runar.sol`, `.runar.move`, and `.runar.py` format contracts because the parsers for these formats don't generate auto-constructors with `super()` calls. Error: "constructor must call super() as its first statement; property 'X' must be assigned in the constructor". This affects even basic-p2pkh (simplest contract). The Go `.runar.ts` parser generates constructors correctly — the fix is to port this logic to the other parsers.
- **Files to modify**:
  - `compilers/go/frontend/parser_sol.go`: Add auto-constructor generation for Solidity contracts. Look at how `parser.go` (TS parser) generates the `ConstructorNode` with `super()` call and property assignments, and replicate in the Sol parser.
  - `compilers/go/frontend/parser_move.go`: Same for Move parser
  - `compilers/go/frontend/parser_python.go`: Same for Python parser
- **Dependencies**: None
- **Scope**: medium (4-16 hours) — needs understanding of each parser's AST generation and how the TS parser auto-generates constructors
- **Acceptance criteria**: `cd conformance && npx tsx runner/index.ts --multi-format --filter basic-p2pkh` passes for `.runar.sol`, `.runar.move`, `.runar.py` formats with Go compiler
- **Verification command**: `cd conformance && npx tsx runner/index.ts --multi-format --filter basic-p2pkh`

### Fix PY-0: Add missing `.runar.zig` dispatch to Python compiler

- **Gap report reference**: Cross-Cutting Issues §1 (Python compiler fails on .runar.zig)
- **What**: `compilers/python/runar_compiler/compiler.py:128` falls through to `raise ValueError` before reaching `.runar.zig`. The parser `parser_dispatch.py:49-51` and `parser_zig.py` both exist and work. The fix is to add the `.runar.zig` `elif` branch to `compiler.py`'s `_parse_source()` function.
- **Files to modify**:
  - `compilers/python/runar_compiler/compiler.py`: Add between lines 127 and 128:
    ```python
    elif lower.endswith(".runar.zig"):
        from runar_compiler.frontend.parser_zig import parse_zig
        return parse_zig(source, file_name)
    ```
  - Also update the error message at line 131 to include `.runar.zig`
- **Dependencies**: None
- **Scope**: trivial (< 1 hour)
- **Acceptance criteria**: `cd conformance && npx tsx runner/index.ts --multi-format --filter basic-p2pkh` passes for `.runar.zig` format with Python compiler
- **Verification command**: `python3 -m runar_compiler --source conformance/tests/basic-p2pkh/P2PKH.runar.zig --hex` (from `compilers/python/`)

### Fix RUST-0: Fix Rust Move parser "No struct declaration" failures

- **Gap report reference**: Cross-Cutting Issues §1 (Rust .runar.move parser failures)
- **What**: Rust's Move parser fails on some contracts with "No 'struct' declaration found in module". Investigate `compilers/rust/src/frontend/parser_move.rs` to determine why struct declarations aren't being recognized for multi-format conformance contracts.
- **Files to modify**:
  - `compilers/rust/src/frontend/parser_move.rs`: Fix struct declaration parsing
- **Dependencies**: None
- **Scope**: small to medium (1-8 hours) — needs investigation of specific failure cases
- **Acceptance criteria**: `cd conformance && npx tsx runner/index.ts --multi-format --filter token-nft` passes for `.runar.move` with Rust compiler
- **Verification command**: `cd conformance && npx tsx runner/index.ts --multi-format`

### Fix RUST-1: Fix Rust `.runar.rs` format IR/script mismatches

- **Gap report reference**: Cross-Cutting Issues §1 (IR and script mismatch for .runar.rs)
- **What**: Some contracts compiled from `.runar.rs` format produce different IR and script hex than from `.runar.ts`. This means the Rust macro parser generates a different AST than the TS parser for equivalent contracts.
- **Files to modify**:
  - `compilers/rust/src/frontend/parser_rustmacro.rs`: Investigate and fix AST generation differences
- **Dependencies**: None
- **Scope**: medium (4-16 hours) — requires diffing IR output between formats to identify AST divergence
- **Acceptance criteria**: Multi-format conformance passes for `.runar.rs` format across all test cases
- **Verification command**: `cd conformance && npx tsx runner/index.ts --multi-format`

## Cross-Cutting Fixes

### Fix CC-1: Update `conformance/formats.json` AFTER parser fixes

- **Gap report reference**: Cross-Cutting Issues §1b
- **What**: After parser bugs are fixed (GO-0, PY-0, RUST-0, RUST-1), update `formats.json` to reflect the expanded format support. Currently the file intentionally restricts testing to working combinations.
- **Files to modify**:
  - `conformance/formats.json`: Update each format entry's `compilers` array
  - `conformance/runner/runner.ts:51-60`: Update the `INPUT_FORMATS` constant to match
- **Dependencies**: GO-0, PY-0, RUST-0, RUST-1 (all parser fixes must land first)
- **Scope**: trivial (< 1 hour)
- **Acceptance criteria**: `npx tsx conformance/runner/index.ts --multi-format` passes with expanded compiler lists
- **Verification command**: `cd conformance && npx tsx runner/index.ts --multi-format`

### Fix CC-2: Clean up outdated/misleading comments

- **Gap report reference**: Go §Known Issues, Ruby §Stub/Placeholder Inventory
- **What**: Two misleading comments:
  1. `compilers/go/frontend/anf_ec_optimizer_test.go:627` — says "Rule 10 is not implemented" but Rule 10 works
  2. `compilers/ruby/lib/runar_compiler/codegen/stack.rb:848` — says "TODO: will be added in Part 2" but implementations are present
- **Files to modify**:
  - `compilers/go/frontend/anf_ec_optimizer_test.go`: Update lines 626-629
  - `compilers/ruby/lib/runar_compiler/codegen/stack.rb`: Update line 848 comment
- **Scope**: trivial (< 1 hour)
- **Acceptance criteria**: No misleading TODO/not-implemented comments remain
- **Verification command**: `cd compilers/go && go test ./frontend/ -run AddMulGen -v` and `cd compilers/ruby && rake test`

---

## Zig Fixes

Overall gap severity: COMPLETE (test cleanup issues only)
Recommended fix order: ZIG-1, then ZIG-2

### Fix ZIG-1: Fix 12 memory leaks in Zig test suite

- **Gap report reference**: Zig §Test Infrastructure Issues
- **What**: 12 memory leaks in `zig build test` cause the test runner to exit with error code 1 despite all 458 tests passing. All leaks are in test code, not in the compiler implementation.
- **Root cause**: Test functions in `parse_ruby.zig` allocate token arrays and error arrays without freeing them.
- **Files to modify**:
  - `compilers/zig/src/passes/parse_ruby.zig`: Add `defer` cleanup in test functions at lines 2074-2409. Each test that calls `parseRuby()` or creates a `Tokenizer` needs to clean up the allocated token array and error array.
  - `compilers/zig/src/passes/dce.zig`: Fix resource cleanup in test "eliminateDeadBindings preserves side-effecting bindings"
- **Pattern to apply**: In each test function:
  ```zig
  // Before:
  const result = parseRuby(allocator, source, "P2PKH.runar.rb");
  // ... assertions ...

  // After:
  const result = parseRuby(allocator, source, "P2PKH.runar.rb");
  defer allocator.free(result.errors);
  // ... assertions ...
  ```
  The exact cleanup depends on what `parseRuby` returns — may need to also free the tokens array if it's part of the return type.
- **Dependencies**: None
- **Scope**: small (1-4 hours)
- **Acceptance criteria**: `zig build test` passes with 0 leaked allocations and exit code 0
- **Verification command**: `cd compilers/zig && zig build test`

### Fix ZIG-2: Expand Zig on-chain integration tests

- **Gap report reference**: On-Chain Integration Test Coverage Matrix, Cross-Cutting Issues §3
- **What**: Zig only has 7 integration test contracts vs 16-20 for other languages. Add integration tests for the 13+ contracts covered by other languages.
- **Files to create** in `integration/zig/src/`:
  - `auction_test.zig` — port from `integration/go/auction_test.go`
  - `convergence_proof_test.zig` — port from `integration/go/convergence_proof_test.go`
  - `covenant_vault_test.zig` — port from `integration/go/covenant_vault_test.go`
  - `ec_isolation_test.zig` — port from `integration/go/ec_isolation_test.go`
  - `fungible_token_test.zig` — port from `integration/go/token_ft_test.go`
  - `nft_test.zig` — port from `integration/go/token_nft_test.go`
  - `oracle_price_test.zig` — port from `integration/go/oracle_price_test.go`
  - `schnorr_zkp_test.zig` — port from `integration/go/schnorr_zkp_test.go`
  - `sphincs_wallet_test.zig` — port from `integration/rust/tests/sphincs_wallet.rs`
  - `tic_tac_toe_test.zig` — port from `integration/go/tic_tac_toe_test.go`
  - `post_quantum_wallet_test.zig` — port from `integration/rust/tests/post_quantum_wallet.rs`
- **Dependencies**: Fix ZIG-1 first (so CI is clean)
- **Scope**: large (16+ hours) — each test requires adapting the testing harness and contract interaction patterns to Zig
- **Acceptance criteria**: Zig integration test count reaches at least 17 (matching Go/Rust)
- **Verification command**: `cd integration/zig && zig build test`

---

## Solidity-like Format Fixes

Overall gap severity: NEAR-COMPLETE (missing examples only)
Recommended fix order: SOL-1

### Fix SOL-1: Add 5 missing Solidity-like example contracts

- **Gap report reference**: Example Contract Integration Coverage Matrix (5 ❌ entries for Sol)
- **What**: Create example contracts and tests for 5 contracts that exist in all other formats but are missing from `examples/sol/`.
- **Files to create**:
  - `examples/sol/convergence-proof/ConvergenceProof.runar.sol` — copy from `conformance/tests/convergence-proof/convergence-proof.runar.sol`
  - `examples/sol/convergence-proof/ConvergenceProof.test.ts` — port from `examples/ts/convergence-proof/ConvergenceProof.test.ts`
  - `examples/sol/function-patterns/FunctionPatterns.runar.sol` — copy from `conformance/tests/function-patterns/function-patterns.runar.sol`
  - `examples/sol/function-patterns/FunctionPatterns.test.ts` — port from `examples/ts/function-patterns/FunctionPatterns.test.ts`
  - `examples/sol/post-quantum-wallet/PostQuantumWallet.runar.sol` — copy from `conformance/tests/post-quantum-wallet/post-quantum-wallet.runar.sol`
  - `examples/sol/post-quantum-wallet/PostQuantumWallet.test.ts` — port from `examples/ts/post-quantum-wallet/PostQuantumWallet.test.ts`
  - `examples/sol/schnorr-zkp/SchnorrZKP.runar.sol` — copy from `conformance/tests/schnorr-zkp/schnorr-zkp.runar.sol`
  - `examples/sol/schnorr-zkp/SchnorrZKP.test.ts` — port from `examples/ts/schnorr-zkp/SchnorrZKP.test.ts`
  - `examples/sol/sphincs-wallet/SPHINCSWallet.runar.sol` — copy from `conformance/tests/sphincs-wallet/sphincs-wallet.runar.sol`
  - `examples/sol/sphincs-wallet/SPHINCSWallet.test.ts` — port from `examples/ts/sphincs-wallet/SPHINCSWallet.test.ts`
- **Dependencies**: None
- **Scope**: small (1-4 hours) — contracts exist in conformance, tests need adaptation from TS tests (change `fromSource` calls to pass Sol source and `.runar.sol` filename)
- **Acceptance criteria**: `npx vitest run examples/sol/` passes with all 22 contract test suites
- **Verification command**: `npx vitest run examples/sol/`

---

## Move-style Format Fixes

Overall gap severity: NEAR-COMPLETE (missing examples only)
Recommended fix order: MOVE-1

### Fix MOVE-1: Add 5 missing Move-style example contracts

- **Gap report reference**: Example Contract Integration Coverage Matrix (5 ❌ entries for Move)
- **What**: Same 5 contracts as SOL-1 but for Move format.
- **Files to create**:
  - `examples/move/convergence-proof/ConvergenceProof.runar.move` — copy from `conformance/tests/convergence-proof/convergence-proof.runar.move`
  - `examples/move/convergence-proof/ConvergenceProof.test.ts` — port from TS test
  - `examples/move/function-patterns/FunctionPatterns.runar.move` — from conformance
  - `examples/move/function-patterns/FunctionPatterns.test.ts` — port from TS test
  - `examples/move/post-quantum-wallet/PostQuantumWallet.runar.move` — from conformance
  - `examples/move/post-quantum-wallet/PostQuantumWallet.test.ts` — port from TS test
  - `examples/move/schnorr-zkp/SchnorrZKP.runar.move` — from conformance
  - `examples/move/schnorr-zkp/SchnorrZKP.test.ts` — port from TS test
  - `examples/move/sphincs-wallet/SPHINCSWallet.runar.move` — from conformance
  - `examples/move/sphincs-wallet/SPHINCSWallet.test.ts` — port from TS test
- **Dependencies**: None
- **Scope**: small (1-4 hours)
- **Acceptance criteria**: `npx vitest run examples/move/` passes with all 22 contract test suites
- **Verification command**: `npx vitest run examples/move/`

---

## Ruby Fixes

Overall gap severity: COMPLETE (one missing example)
Recommended fix order: RUBY-1

### Fix RUBY-1: Add missing message-board example

- **Gap report reference**: Ruby §Test Gaps, Example Contract Integration Coverage Matrix
- **What**: `examples/ruby/message-board/` does not exist. All other formats have this contract.
- **Files to create**:
  - `examples/ruby/message-board/MessageBoard.runar.rb` — port from `examples/ts/message-board/MessageBoard.runar.ts` to Ruby syntax
  - `examples/ruby/message-board/message_board_spec.rb` — port from `examples/ts/message-board/MessageBoard.test.ts` to RSpec style
- **Dependencies**: None
- **Scope**: trivial (< 1 hour)
- **Acceptance criteria**: `cd examples/ruby && bundle exec rspec message-board/` passes
- **Verification command**: `cd examples/ruby && bundle exec rspec message-board/message_board_spec.rb`

---

## Python Fixes

Overall gap severity: COMPLETE (skipped tests only)
Recommended fix order: PY-1

### Fix PY-1: Investigate and enable Python sphincs-wallet tests

- **Gap report reference**: Python §Test Gaps
- **What**: 4 tests in `examples/python/sphincs-wallet/test_sphincs_wallet.py` are skipped with reason "slh-dsa p...". These should either be enabled (if they pass with acceptable runtime) or marked with `@pytest.mark.slow` instead of unconditionally skipping.
- **Files to modify**:
  - `examples/python/sphincs-wallet/test_sphincs_wallet.py`: Check the skip conditions and either remove them or change to `@pytest.mark.slow`
- **Dependencies**: None
- **Scope**: trivial (< 1 hour)
- **Acceptance criteria**: Tests are either (a) passing when run with `pytest --run-slow` or (b) documented with a clear performance-related skip reason
- **Verification command**: `cd examples/python && PYTHONPATH=../../packages/runar-py python3 -m pytest sphincs-wallet/ -v`

---

## Summary Statistics

| Language/Area | Total fixes | Trivial | Small | Medium | Large | Unknown |
|---------------|------------|---------|-------|--------|-------|---------|
| Go (parser) | 1 | 0 | 0 | 1 | 0 | 0 |
| Python (parser) | 1 | 1 | 0 | 0 | 0 | 0 |
| Rust (parser) | 2 | 0 | 1 | 1 | 0 | 0 |
| Cross-cutting | 2 | 2 | 0 | 0 | 0 | 0 |
| Zig | 2 | 0 | 1 | 0 | 1 | 0 |
| Solidity-like | 1 | 0 | 1 | 0 | 0 | 0 |
| Move-style | 1 | 0 | 1 | 0 | 0 | 0 |
| Ruby | 1 | 1 | 0 | 0 | 0 | 0 |
| Python (other) | 1 | 1 | 0 | 0 | 0 | 0 |
| **Total** | **12** | **5** | **4** | **2** | **1** | **0** |

## Suggested Execution Order

### Milestone 1: Fix critical cross-format parser bugs (GO-0, PY-0, RUST-0, RUST-1)
- Fix PY-0: Add `.runar.zig` dispatch to Python compiler (trivial, 5 minutes)
- Fix GO-0: Fix Go Sol/Move/Python parser auto-constructors (medium, highest impact — fixes most multi-format failures)
- Fix RUST-0: Fix Rust Move parser struct detection (small to medium)
- Fix RUST-1: Fix Rust `.runar.rs` IR/script mismatches (medium)
- **After this milestone**: Multi-format conformance failures drop from 119 to near-zero

### Milestone 2: Update conformance infrastructure (CC-1, CC-2, ZIG-1)
- Fix CC-1: Update `formats.json` to include all now-working compilers per format
- Fix CC-2: Clean up misleading comments
- Fix ZIG-1: Fix Zig test memory leaks
- **After this milestone**: `--multi-format` conformance tests all compilers for all formats; Zig CI green

### Milestone 3: Example coverage parity (SOL-1, MOVE-1, RUBY-1, PY-1)
- Fix SOL-1: Add 5 Sol examples
- Fix MOVE-1: Add 5 Move examples
- Fix RUBY-1: Add Ruby message-board
- Fix PY-1: Enable/investigate Python sphincs-wallet tests
- **After this milestone**: All formats have equivalent example coverage

### Milestone 4: Integration test expansion (ZIG-2)
- Fix ZIG-2: Expand Zig integration tests from 7 to 17+ contracts
- **After this milestone**: All languages have comparable on-chain integration test coverage
