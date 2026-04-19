# Rúnar Conformance Tests

**Cross-compiler conformance test suite ensuring all Rúnar compilers produce identical output.**

The conformance suite is the enforcement mechanism for Rúnar's multi-compiler strategy. It contains golden-file test cases (source + expected IR + expected script), a test runner, and a differential fuzzer. Every Rúnar compiler -- TypeScript, Go, Rust, Python, Zig, and Ruby -- must pass the full suite.

---

## Purpose

Rúnar defines a **canonical IR conformance boundary** at the ANF level. For any given source program, all conforming compilers must produce byte-identical ANF IR (serialized via RFC 8785). The conformance suite verifies this property.

Additionally, the compiled Bitcoin Script output must be identical across compilers. The script is the final artifact deployed on-chain, so even a single-byte difference could mean a different locking script hash and a non-functional contract.

---

## Test Structure

Each test case is a directory containing:

```
tests/
+-- basic-p2pkh/
|   +-- basic-p2pkh.runar.ts      # Source contract (TypeScript)
|   +-- basic-p2pkh.runar.sol     # Source contract (Solidity-like)
|   +-- basic-p2pkh.runar.move    # Source contract (Move-style)
|   +-- basic-p2pkh.runar.go      # Source contract (Go)
|   +-- basic-p2pkh.runar.rs      # Source contract (Rust)
|   +-- basic-p2pkh.runar.py      # Source contract (Python)
|   +-- basic-p2pkh.runar.zig     # Source contract (Zig)
|   +-- basic-p2pkh.runar.rb      # Source contract (Ruby)
|   +-- basic-p2pkh.runar.json    # Reference artifact (JSON AST, not tested by runner)
|   +-- expected-ir.json          # Expected ANF IR (canonical JSON)
|   +-- expected-script.hex       # Expected compiled script (hex string)
|
+-- arithmetic/
|   +-- arithmetic.runar.ts
|   +-- arithmetic.runar.sol      # (+ .move, .go, .rs, .py variants; .json is a reference artifact)
|   +-- expected-ir.json
|   +-- expected-script.hex
|
+-- boolean-logic/
|   +-- boolean-logic.runar.ts    # (+ multi-format variants)
|   +-- expected-ir.json
|   +-- expected-script.hex
|
+-- if-else/
|   +-- if-else.runar.ts          # (+ multi-format variants)
|   +-- expected-ir.json
|   +-- expected-script.hex
|
+-- bounded-loop/
|   +-- bounded-loop.runar.ts     # (+ multi-format variants)
|   +-- expected-ir.json
|   +-- expected-script.hex
|
+-- multi-method/
|   +-- multi-method.runar.ts     # (+ .sol, .move, .go, .rs, .py variants)
|   +-- expected-ir.json
|   +-- expected-script.hex
|
+-- stateful/
|   +-- stateful.runar.ts         # (+ multi-format variants)
|   +-- expected-ir.json
|   +-- expected-script.hex
|
+-- post-quantum-wots/
|   +-- post-quantum-wots.runar.ts
|   +-- expected-ir.json
|   +-- expected-script.hex
|
+-- post-quantum-slhdsa/
|   +-- post-quantum-slhdsa.runar.ts
|   +-- expected-ir.json
|   +-- expected-script.hex
|
+-- ec-primitives/
|   +-- ec-primitives.runar.ts
|   +-- expected-ir.json
|   +-- expected-script.hex
|
+-- auction/                       # (+ 15 more test directories)
+-- convergence-proof/
+-- covenant-vault/
+-- ec-demo/
+-- escrow/
+-- function-patterns/
+-- math-demo/
+-- oracle-price/
+-- post-quantum-wallet/
+-- property-initializers/
+-- schnorr-zkp/
+-- sphincs-wallet/
+-- stateful-counter/
+-- token-ft/
+-- token-nft/
```

> **Note:** Most test directories also contain multi-format source variants (`.runar.sol`, `.runar.move`, `.runar.go`, `.runar.rs`, `.runar.py`, `.runar.zig`, `.runar.rb`). All format variants must produce the same ANF IR and script output. A handful of test directories currently only have `.runar.ts` sources (e.g. `add-data-output`, `add-raw-output`, `babybear-ext4`, `bitwise-ops`, `cross-covenant`, `ec-unit`, `merkle-proof`, `state-covenant`) and one (`go-dsl-bytestring-literal`) is Go-only. Several test directories also include `.runar.json` (JSON AST) files; these are reference artifacts for tooling and are **not** tested by the conformance runner.

### File Roles

| File | Purpose |
|---|---|
| `*.runar.ts` | The source contract. Input to the compiler. |
| `expected-ir.json` | The expected ANF IR output. Canonical JSON (RFC 8785, no whitespace, sorted keys). The SHA-256 of this file is the conformance check. |
| `expected-script.hex` | The expected compiled Bitcoin Script as a hex string. If present, the compiler's script output must match exactly. |

---

## How the Test Runner Works

The runner (in `runner/`) performs these steps for each test case:

```
For each test directory:
  1. Read the .runar.ts source file.
  2. Invoke the compiler under test to produce ANF IR.
  3. Serialize the compiler's ANF IR using canonical JSON (RFC 8785).
  4. Compare SHA-256(compiler_output) with SHA-256(expected-ir.json).
  5. If expected-script.hex exists:
     a. Invoke the compiler to produce the final script.
     b. Compare the script hex with expected-script.hex.
  6. Report pass/fail.
```

### Running the Conformance Suite

```bash
# Run all conformance tests (TypeScript compiler)
pnpm test

# Output as JSON or Markdown
pnpm run test:json
pnpm run test:markdown

# Filter to a specific test
pnpm run test:filter -- arithmetic

# Test all input format variants (.ts, .sol, .move, .go, .rs, .py, .zig, .rb)
pnpm test -- --multi-format

# Run cross-SDK locking-script conformance (all 6 SDK tools)
pnpm run sdk-output
```

The runner compiles each test case with the TypeScript reference compiler and compares the output against the golden files.

---

## How to Add New Test Cases

1. Create a new directory under `tests/` with a descriptive name:

```bash
mkdir conformance/tests/my-new-test
```

2. Write the source contract:

```bash
# conformance/tests/my-new-test/my-new-test.runar.ts
```

3. Generate the expected IR using the reference compiler:

```bash
runar compile conformance/tests/my-new-test/my-new-test.runar.ts --ir
# Canonical JSON serialization (RFC 8785) is applied automatically.
# Copy the ANF IR output to expected-ir.json
```

4. Optionally generate the expected script:

```bash
runar compile conformance/tests/my-new-test/my-new-test.runar.ts
# Copy the script hex to expected-script.hex
```

5. Run the conformance suite to verify the new test passes:

```bash
pnpm test
```

---

## Differential Fuzzing

The fuzzer (in `fuzzer/`) generates random valid Rúnar programs and tests compiler correctness by comparing against the reference interpreter.

### How It Works

```
  +----------+      +-----------+      +----------+
  |  Fuzzer   | --> | Compiler  | --> | Script VM |
  | generates |     | compiles  |     | executes  |
  | random    |     | to script |     |           |
  | .runar.ts  |     |           |     |           |
  +----------+      +-----------+      +----------+
       |                  |                  |
       |                  v                  v
       |           +-------------+    +-----------+
       +---------> | Interpreter | -->| Compare   |
                   | evaluates   |    | results   |
                   | ANF IR      |    |           |
                   +-------------+    +-----------+
                                           |
                                      pass / MISMATCH
```

If the compiler + VM produce a different result than the interpreter, a bug has been found. The fuzzer saves the failing program for reproduction.

### Running the Fuzzer

```bash
# Run 100 random programs (default)
pnpm run fuzz

# Run 10 programs with verbose output
pnpm run fuzz:quick

# Run with a specific count and seed (for reproducibility)
pnpm run fuzz -- --num 5000 --seed 42

# Use fast-check property-based mode (with shrinking)
pnpm run fuzz:property
```

---

## Golden File Management

Golden files (`expected-ir.json`, `expected-script.hex`) are checked into version control. When the spec changes in a way that affects IR output:

1. Update the spec documents in `spec/`.
2. Update the reference compiler.
3. Regenerate all golden files:

```bash
pnpm run update-golden
```

4. Review the diffs to verify the changes are expected.
5. Commit the updated golden files alongside the compiler changes.

Golden file updates should always be reviewed carefully. An unexpected change in a golden file indicates either a compiler bug or an unintended spec change.

---

## Current Test Cases (42)

| Test | Exercises | Has Script Golden |
|---|---|---|
| `add-data-output` | `this.addDataOutput(satoshis, bytes)` intrinsic (TS-only fixture) | Yes |
| `add-raw-output` | `this.addRawOutput(satoshis, scriptBytes)` intrinsic (TS-only fixture) | Yes |
| `arithmetic` | Binary arithmetic operations (+, -, *, /, %) | Yes |
| `auction` | Stateful auction with bidding and closing | Yes |
| `babybear` | BabyBear prime-field arithmetic | Yes |
| `babybear-ext4` | BabyBear Ext4 extension-field operations (TS-only fixture) | Yes |
| `basic-p2pkh` | Property loading, hash160, checkSig, assert | Yes |
| `bitwise-ops` | Bitwise operators (&, \|, ^, ~, <<, >>) on bigint + ByteString (TS-only fixture) | Yes |
| `blake3` | BLAKE3 compression + full-hash builtins | Yes |
| `boolean-logic` | Logical operators (&&, \|\|, !), short-circuit lowering | Yes |
| `bounded-loop` | Loop unrolling in ANF IR | Yes |
| `convergence-proof` | Convergence proof patterns | Yes |
| `covenant-vault` | Covenant spending constraints | Yes |
| `cross-covenant` | Cross-contract covenant validation (TS-only fixture) | Yes |
| `ec-demo` | EC point operation demos | Yes |
| `ec-primitives` | EC point operations (ecAdd, ecMul, ecMulGen, etc.) | Yes |
| `ec-unit` | Fine-grained EC unit tests (TS-only fixture) | Yes |
| `escrow` | Multi-party escrow with multiple spending paths | Yes |
| `function-patterns` | Private helper methods and function call patterns | Yes |
| `go-dsl-bytestring-literal` | `.runar.go` DSL `ByteString` literal grammar (Go-only fixture) | Yes |
| `if-else` | Conditional branches in ANF IR | Yes |
| `if-without-else` | if-only conditionals | Yes |
| `math-demo` | Built-in math functions (abs, min, max, sqrt, pow, etc.) | Yes |
| `merkle-proof` | Merkle-root verification (TS-only fixture) | Yes |
| `multi-method` | Method dispatch table generation | Yes |
| `oracle-price` | Rabin signature oracle price feed | Yes |
| `p256-primitives` | NIST P-256 EC primitives | Yes |
| `p256-wallet` | P-256 wallet contract | Yes |
| `p384-primitives` | NIST P-384 EC primitives | Yes |
| `p384-wallet` | P-384 wallet contract | Yes |
| `post-quantum-slhdsa` | SLH-DSA (SPHINCS+) signature verification | Yes |
| `post-quantum-wallet` | WOTS+ wallet contract | Yes |
| `post-quantum-wots` | WOTS+ hash chain signature verification | Yes |
| `property-initializers` | Default values on contract properties | Yes |
| `schnorr-zkp` | Schnorr zero-knowledge proof (EC ops) | Yes |
| `sphincs-wallet` | SLH-DSA wallet contract | Yes |
| `state-covenant` | Stateful covenant constraints (TS-only fixture) | Yes |
| `stateful` | State updates, checkPreimage, getStateScript | Yes |
| `stateful-bytestring` | Stateful ByteString mutations | Yes |
| `stateful-counter` | Stateful counter with increment | Yes |
| `token-ft` | Fungible token with split/merge | Yes |
| `token-nft` | NFT with transfer/burn | Yes |

### SDK-output conformance (41 fixtures, 6 SDKs)

`sdk-output/tests/` contains 41 additional fixtures (one `input.json` + one
`expected-locking.hex` per directory). The runner in `sdk-output/runner/sdk-runner.ts`
compiles each fixture through all six SDK tools in `sdk-output/tools/` (TypeScript,
Go, Python, Ruby, Rust, Zig) and asserts byte-identical locking-script hex across
every SDK. Invoke with `pnpm run sdk-output`.
