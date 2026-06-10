# Testing Guide

This guide covers how to test Rúnar smart contracts at every level, from unit tests of individual contracts to property-based fuzzing and cross-compiler conformance testing.

---

## TypeScript Unit Testing with Vitest

TypeScript contract tests use vitest. Contract tests compile a `.runar.ts` file to an artifact, then execute methods against the built-in Script VM.

### Basic Test Structure

```typescript
import { describe, it, expect } from 'vitest';
import {
  TestContract,
} from 'runar-testing';
import { readFileSync } from 'fs';

const source = readFileSync('contracts/P2PKH.runar.ts', 'utf8');

describe('P2PKH', () => {
  const pubKeyHash = '89abcdef01234567890abcdef01234567890abcd';
  const contract = TestContract.fromSource(source, { pubKeyHash });

  it('succeeds with valid signature and matching pubkey', () => {
    const sig = '3044022...'; // valid DER signature hex
    const pubKey = '02abc...'; // matching compressed pubkey hex

    const result = contract.call('unlock', { sig, pubKey });
    expect(result.success).toBe(true);
  });

  it('fails with wrong pubkey', () => {
    const sig = '3044022...';
    const wrongPubKey = '03def...'; // different pubkey

    const result = contract.call('unlock', { sig, pubKey: wrongPubKey });
    expect(result.success).toBe(false);
  });
});
```

### Running Tests

```bash
# Run all tests
pnpm test

# Run tests for a specific file
pnpm test -- P2PKH.test.ts

# Run in watch mode
pnpm test -- --watch
```

---

## Native-Language Unit Testing

Each of the six native frontends ships its own example tree that uses the host language's test runner. The native `runar` package/crate/gem/jar provides type aliases, mock crypto, real hash functions, and a `CompileCheck` / `compile_check` entry point that re-runs the contract through the frontend (parse → validate → typecheck).

The quick-reference commands per CLAUDE.md ⇒ "Build & Test":

- **Go** — `cd examples/go && go test ./...`
- **Rust** — `cd examples/rust && cargo test`
- **Python** — `cd examples/python && PYTHONPATH=../../packages/runar-py python3 -m pytest`
- **Zig** — `cd examples/zig && zig build test`
- **Ruby** — `cd examples/ruby && bundle exec rspec` (the compiler itself is exercised via `cd compilers/ruby && rake test`)
- **Java** — `cd examples/java && ./gradlew test`

The Zig example suite is backed by `packages/runar-zig`, which provides the `runar` module, compile-check helpers, fixtures, and the native helper/runtime surface used by `examples/zig/*/*_test.zig`. Some Zig examples now execute the real contract module directly; others still rely on mirror coverage where the current Zig execution model is not yet natural enough.

The Java example suite uses JUnit 5 via the committed Gradle wrapper. `runar.lang.sdk.CompileCheck` invokes the real compiler frontend (composite-built from `compilers/java`), and `runar.lang.runtime.ContractSimulator` lets Java tests run the compiled artifact against real hashes + real secp256k1 with mocked sig-verify — a Java-only off-chain capability covered in detail under [Cryptographic verification in tests](#cryptographic-verification-in-tests).

The full per-tier tooling for Go, Rust, Python, Zig, Ruby, and Java is documented in [Testing Go Contracts](#testing-go-contracts) and [Testing Rust Contracts](#testing-rust-contracts) below, plus the comparison table under [Cross-Language Testing Comparison](#cross-language-testing-comparison).

---

## Using TestContract (Interpreter-Based Testing)

`TestContract` is the primary test helper. It compiles a contract from source, uses the **interpreter** (not the Script VM) to execute methods, and tracks state changes.

> **Important:** `TestContract` uses mocked ECDSA cryptographic operations — `checkSig`, `checkMultiSig`, and `checkPreimage` always return `true`. This is intentional: it lets you test business logic (state transitions, assertions, arithmetic) without managing real keys or signatures. The post-quantum (`verifyWOTS`, `verifySLHDSA_SHA2_*`) and Schnorr / EC-arithmetic builtins are **not** mocked — they execute the real algorithm in the interpreter. See [Cryptographic verification in tests](#cryptographic-verification-in-tests) below for the full mocked-vs-real list and the escape hatches for exercising real ECDSA / preimage rejection.

### Creating an Instance

```typescript
import { TestContract } from 'runar-testing';

// From source code with initial state
const contract = TestContract.fromSource(source, { count: 0n });

// Multi-format: pass fileName to select the parser
const solContract = TestContract.fromSource(solSource, { count: 0n }, 'Counter.runar.sol');

// From a file path
const contract = TestContract.fromFile('contracts/Counter.runar.ts', { count: 0n });
```

The `initialState` is a `Record<string, unknown>` mapping property names to their initial values.

### Calling Methods

```typescript
const result = contract.call('methodName', { arg1: value1, arg2: value2 });
```

Arguments are passed as a `Record<string, unknown>` with named keys matching the method parameter names:

| Rúnar Type | Argument Format |
|----------|----------------|
| `bigint` | `bigint` value (e.g., `42n`) |
| `boolean` | `true` or `false` |
| `PubKey`, `Sig`, `ByteString`, etc. | Hex-encoded string |

The return value is a `TestCallResult` object:

```typescript
interface TestCallResult {
  success: boolean;          // true if all assertions passed
  error?: string;            // error message if a method assertion failed
  outputs: OutputSnapshot[]; // outputs registered via addOutput (stateful contracts)
}
```

### Reading State

After calling a method, read the updated state:

```typescript
const counter = TestContract.fromSource(source, { count: 0n });
counter.call('increment');
expect(counter.state.count).toBe(1n);
```

### Configuring Mock Preimage

For stateful contracts that inspect transaction preimage fields (e.g., time locks, input amounts), use `setMockPreimage()` to override the default mock values:

```typescript
const contract = TestContract.fromSource(source, { deadline: 1000n });

// Override the locktime preimage field for this test
contract.setMockPreimage({ locktime: 2000n });

const result = contract.call('spend', { sig, pubKey });
expect(result.success).toBe(true);
```

`setMockPreimage` accepts a partial `MockPreimage` object with the following optional fields:

| Field | Type | Description |
|-------|------|-------------|
| `locktime` | `bigint` | Mock nLocktime value |
| `amount` | `bigint` | Mock input amount (satoshis) |
| `version` | `bigint` | Mock transaction version |
| `sequence` | `bigint` | Mock input nSequence |

---

## Cryptographic verification in tests

`TestContract` runs contracts through the ANF interpreter, not a Bitcoin Script VM. The interpreter mocks the ECDSA / preimage builtins so you can write business-logic tests without managing real keys, signatures, or transaction sighashes. The trade-off: a `TestContract` test that "rejects a bad signature" by passing a malformed `sig` value **does not actually exercise ECDSA verification** — `checkSig` returned `true` either way. The rejection in such a test, if there is one, comes from some *other* assertion in the method (a hash mismatch, a state check, etc.), not from the signature being invalid.

This applies symmetrically to every native-tier mock package: `runar` (Go), `runar::prelude` (Rust), `runar` (Python), `runar` (Zig), `runar` (Ruby), and `runar.lang` (Java) all ship `MockSig` / `mock_sig` / `MockPubKey` / `MockPreimage` helpers plus mock `CheckSig` / `CheckPreimage` that always return `true`. Native-tier tests are running the contract as plain code in the host language — they verify business logic, not on-chain cryptographic acceptance.

### What is mocked vs. real in the interpreter

| Builtin | Behavior in interpreter | Notes |
|---------|------------------------|-------|
| `checkSig` | **Mocked → always `true`** | Real ECDSA verification requires a transaction sighash that the interpreter does not synthesize. |
| `checkMultiSig` | **Mocked → always `true`** | Same reason as `checkSig`. |
| `checkPreimage` | **Mocked → always `true`** | The interpreter does not synthesize a BIP-143 preimage; use `setMockPreimage` to control the *fields* the contract reads. |
| `verifyRabinSig` | **Mocked → always `true`** | Rabin verification is not implemented in the interpreter. |
| `verifyWOTS` | **Real** | Runs the actual WOTS+ verification (hash-chain replay). A bad WOTS+ signature *does* fail this check. |
| `verifySLHDSA_SHA2_*` | **Real** (all 6 parameter sets) | Runs the actual FIPS 205 verifier. |
| `sha256`, `hash160`, `hash256`, `ripemd160` | **Real** | Standard hash functions. |
| `sha256Compress`, `sha256Finalize` | **Real** | Partial-block SHA-256 primitives. |
| `ecAdd`, `ecMul`, `ecMulGen`, `ecNegate`, `ecOnCurve`, `ecModReduce`, `ecEncodeCompressed`, `ecMakePoint`, `ecPointX`, `ecPointY` | **Real** | secp256k1 field/group arithmetic. Schnorr-ZKP and other EC-arithmetic contracts therefore *do* fail the interpreter when the math is wrong. |
| All math / bitwise / preimage-extractor builtins | **Real** (or fixed test values for preimage extractors) | See the `TestContract` mock-preimage table for the configurable subset. |

The pattern: **mocked = anything whose real implementation needs an ECDSA / Bitcoin sighash context the interpreter does not own**; **real = anything that's a pure function of its inputs** (hashes, EC arithmetic, hash-based PQ signatures, modular arithmetic). PQ and Schnorr-ZKP contracts are exempt from BUG-005's caveats for exactly this reason.

### Escape hatches for real-crypto rejection

If you genuinely need to assert that *the on-chain signature check would reject this input*, `TestContract` is not the right tool. Pick one of:

1. **`ScriptVM` (TypeScript, Go, Rust, Python).** Each of these tiers wraps an upstream BSV SDK's Bitcoin Script interpreter (see CLAUDE.md ⇒ "Off-chain Script VM (`ScriptVM`)" for the exact wrapper and per-tier capabilities). `ScriptVM` executes the *compiled* locking + unlocking scripts and runs real `OP_CHECKSIG` / `OP_CHECKSIGVERIFY` against the supplied signature, pubkey, and sighash. This is the only off-chain path that exercises real ECDSA verification. **Zig, Ruby, and Java have no `ScriptVM`** — by documented project policy, no canonical upstream BSV SDK script interpreter is usable for those tiers (Ruby/Java have no `bsv-blockchain` SDK; the Zig `bsvz` engine does not compile on the repo's Zig 0.16 toolchain).
2. **Regtest integration tests (all 7 tiers).** `integration/{ts,go,rust,python,ruby,zig,java}` ship end-to-end harnesses that deploy the compiled contract to a local BSV regtest node and spend it for real. Real keys, real ECDSA, real preimage. This is the canonical real-crypto rejection path for Zig, Ruby, and Java.
3. **Conformance byte-parity (all 7 tiers).** The conformance suite verifies all 7 compilers produce byte-identical Stack IR + script hex for every fixture (subject to the per-fixture `compilers` allowlist). If the TS compiler's compiled hex passes a real-crypto ScriptVM test, and the Zig/Ruby/Java compilers produce the same bytes, the on-chain behavior is the same — but byte-parity is *semantic* assurance, not a VM-level rejection test in those tiers.

### Concrete example: this test does NOT prove signature rejection

```typescript
import { TestContract } from 'runar-testing';

const contract = TestContract.fromSource(p2pkhSource, { pubKeyHash });

it('rejects a bad signature', () => {
  // This test fails for the WRONG reason. `checkSig` is mocked to return true,
  // so the rejection (if any) comes from the assert(hash160(pubKey) === this.pubKeyHash)
  // line, not from the signature being malformed.
  const result = contract.call('unlock', {
    sig: '00'.repeat(70),       // intentionally garbage
    pubKey: validCompressedPk,  // hash160 still matches pubKeyHash
  });
  expect(result.success).toBe(false); // FAILS — the interpreter accepts this.
});
```

To actually exercise ECDSA rejection, use `ScriptVM` (TS/Go/Rust/Python) or a regtest integration test (all 7 tiers):

```typescript
import { ScriptVM, hexToBytes } from 'runar-testing';
import { compile } from 'runar-compiler';

const vm = new ScriptVM();
const artifact = compile(p2pkhSource, { fileName: 'P2PKH.runar.ts' });

it('on-chain script rejects a bad signature', () => {
  const lockingScript = hexToBytes(artifact.script);
  // Build an unlocking script that pushes a garbage signature + a valid pubkey.
  const unlockingScript = buildUnlockingScript({
    sig: '00'.repeat(70),
    pubKey: validCompressedPk,
  });
  const result = vm.execute(unlockingScript, lockingScript, sighashCtx);
  expect(result.success).toBe(false); // PASSES — OP_CHECKSIG genuinely rejects.
});
```

For Zig, Ruby, and Java contracts, drop the `ScriptVM` step and write the equivalent rejection test in `integration/{zig,ruby,java}` against regtest. The Java SDK additionally exposes `runar.lang.runtime.ContractSimulator`, which runs compiled artifacts against real hashes and real secp256k1 with mocked signature-verify — useful for shape/round-trip assertions on the compiled artifact, but **not** a substitute for real-ECDSA rejection (it still mocks the sig check).

---

## Script VM Testing (Compiled Script Execution)

The `ScriptVM` class can be used directly for lower-level testing without the `TestSmartContract` wrapper. Unlike `TestContract` (which interprets ANF IR with mocked crypto), `ScriptVM` executes actual compiled Bitcoin Script opcodes.

```typescript
import { ScriptVM, hexToBytes, bytesToHex, disassemble } from 'runar-testing';

const vm = new ScriptVM();

// Execute raw scripts
const unlockingScript = hexToBytes('0151'); // OP_TRUE
const lockingScript = hexToBytes('69');     // OP_VERIFY
const result = vm.execute(unlockingScript, lockingScript);

console.log(result.success);    // true
console.log(result.opsExecuted); // 2

// Disassemble a script for debugging
const asm = disassemble(lockingScript);
console.log(asm); // "OP_VERIFY"
```

### VM Utilities

```typescript
import {
  encodeScriptNumber,
  decodeScriptNumber,
  isTruthy,
  hexToBytes,
  bytesToHex,
} from 'runar-testing';

// Encode/decode Script numbers
const encoded = encodeScriptNumber(42n);  // Uint8Array
const decoded = decodeScriptNumber(encoded); // 42n

// Check if a stack element is truthy
isTruthy(new Uint8Array([0x01])); // true
isTruthy(new Uint8Array([]));     // false (OP_FALSE)
```

### Interactive step-through debugger: `runar debug`

`runar debug <artifact>` opens an interactive REPL that runs the compiled Bitcoin Script one opcode at a time, with breakpoints, stack inspection, and source-map mapping back to the original Rúnar source line. It is the step-mode counterpart to `ScriptVM` — built on the same per-tier upstream BSV script interpreter wrapper.

**Available in: TypeScript, Go, Rust, Python.** **Not available in: Zig, Ruby, Java.**

The reason mirrors the [Off-chain Script VM (`ScriptVM`)](../CLAUDE.md) policy: `runar debug` needs the same underlying script interpreter that `ScriptVM` wraps, and no canonical upstream BSV SDK script interpreter is currently usable for the Zig, Ruby, or Java tiers (no `bsv-blockchain` SDK exists for Ruby or Java; the Zig `bsvz` script engine does not compile on the repo's Zig 0.16 toolchain). Per project policy, those three tiers do **not** ship a hand-written Script VM, and therefore do not ship a `runar debug` CLI. See CLAUDE.md ⇒ "Off-chain Script VM (`ScriptVM`)" for the authoritative explanation — this guide does not duplicate it.

**Recommended workflow for Zig, Ruby, Java users who need step-level inspection:**

1. **ANF interpreter** — write the test against the `runar-testing`-style harness in your tier (the native `runar` package's `CompileCheck` + the contract-as-native-code pattern shown earlier in this guide). The interpreter does not single-step opcodes, but it does evaluate the same ANF IR the compiler emits, so you can pinpoint the *line* of contract logic that fails — just not the *opcode* it lowered to.
2. **Regtest** — deploy the compiled artifact to a local BSV regtest node via `integration/{zig,ruby,java}`. You can rebuild the locking + unlocking scripts by hand, run them through `bitcoin-cli`'s script-decoding tools, and step the failing path that way. Slower than `runar debug`, but it's the canonical real-VM path for these tiers.
3. **Cross-tier `runar debug`** — for any contract written in a format the TS / Go / Rust / Python frontends accept (every format does — frontend parity is a hard project invariant), you can compile the contract with the Java/Ruby/Zig frontend, then re-compile the same source with `runar` (TS) and run `runar debug` on the TS-tier artifact. Because all 7 compilers produce byte-identical Stack IR + script hex for non-allowlisted fixtures, stepping the TS artifact tells you what the Java/Ruby/Zig artifact does on-chain.

---

## Reference Interpreter for Oracle Testing

The reference interpreter (`RunarInterpreter`) evaluates ANF IR directly, without compiling to Bitcoin Script. It serves as an oracle: if the compiled script and the interpreter produce different results for the same inputs, there is a bug.

```typescript
import { RunarInterpreter } from 'runar-testing';
import type { RunarValue } from 'runar-testing';
import { compile } from 'runar-compiler';

// Compile the contract to get the AST (ContractNode)
const result = compile(source, { fileName: 'P2PKH.runar.ts' });
const contractNode = result.contract!; // ContractNode (from CompileResult, not artifact)

// Create interpreter with property values (constructor args).
// Unlike TestContract (which accepts plain JS values), RunarInterpreter
// requires RunarValue wrappers for all values:
//   { kind: 'bigint', value: 42n }
//   { kind: 'boolean', value: true }
//   { kind: 'bytes', value: hexToBytes('abcd') }
const interpreter = new RunarInterpreter({
  pubKeyHash: { kind: 'bytes', value: hexToBytes('89abcdef...') },
});

// Optionally set the contract node for reuse across multiple calls
interpreter.setContract(contractNode);

// Execute a method with RunarValue-wrapped arguments
const interpResult = interpreter.executeMethod(contractNode, 'unlock', {
  sig: { kind: 'bytes', value: hexToBytes('3044022...') },
  pubKey: { kind: 'bytes', value: hexToBytes('02abc...') },
});

// interpResult.success: boolean
// interpResult.error?: string (if an assertion failed)
// interpResult.returnValue?: RunarValue (for private methods)
```

### Comparing Interpreter and VM Results

```typescript
it('compiler and interpreter agree', () => {
  const vmResult = contract.call('unlock', { sig, pubKey });
  const interpResult = interpreter.executeMethod(contractNode, 'unlock', {
    sig: { kind: 'bytes', value: hexToBytes(sig) },
    pubKey: { kind: 'bytes', value: hexToBytes(pubKey) },
  });

  // Both should agree on success/failure
  expect(vmResult.success).toBe(interpResult.success);
});
```

This pattern is the foundation of differential testing. If they ever disagree, you have found a compiler bug.

---

## Property-Based Fuzzing

Rúnar includes property-based testing generators built on fast-check. These generate random valid Rúnar contracts and verify compiler correctness.

### Built-in Generators

```typescript
import {
  arbContract,
  arbStatelessContract,
  arbArithmeticContract,
  arbCryptoContract,
} from 'runar-testing';
```

| Generator | Produces |
|-----------|----------|
| `arbContract` | Random valid Rúnar contract source |
| `arbStatelessContract` | Random contract with only `readonly` properties |
| `arbArithmeticContract` | Contract focusing on arithmetic operations |
| `arbCryptoContract` | Contract using cryptographic built-ins |

### Using with fast-check

```typescript
import { describe, it } from 'vitest';
import * as fc from 'fast-check';
import { arbStatelessContract } from 'runar-testing';
import { compile } from 'runar-compiler';

describe('compiler fuzzing', () => {
  it('never crashes on valid input', () => {
    fc.assert(
      fc.property(arbStatelessContract, (source) => {
        // The compiler should never throw on valid Rúnar
        const artifact = compile(source);
        expect(artifact).toBeDefined();
        expect(artifact.script).toBeTruthy();
      }),
      { numRuns: 1000 },
    );
  });
});
```

### Differential Fuzzing

The conformance fuzzer in `packages/runar-testing/src/fuzzer/` generates random programs and checks that the compiler + VM produce the same result as the interpreter:

```bash
# Run the differential fuzzer
pnpm run fuzz -- --iterations 10000

# Run with a specific seed for reproducibility
pnpm run fuzz -- --seed 42 --iterations 5000

# Run until a mismatch is found
pnpm run fuzz -- --until-fail
```

The fuzzer follows this pipeline:

```
Generate random .runar.ts --> Compile to ANF IR --> Compile to Script
                         |                    |
                         v                    v
                    Interpret ANF IR     Execute in VM
                         |                    |
                         v                    v
                    Compare results: must match
```

If the results disagree, the failing program is saved for reproduction. This is inspired by CSmith (Yang et al., PLDI 2011) and is the primary mechanism for finding compiler bugs.

---

## Testing Go Contracts

Go contracts are tested as native Go code using Go's standard `testing` package. The `runar` mock package (`packages/runar-go`) provides type aliases, mock crypto functions, and real hash functions so contracts execute as plain Go.

### Project Setup

Go examples live in `examples/go/`, with one directory per contract. The module resolution relies on a `go.work` file at the project root:

```
go.work
├── compilers/go         # Go compiler
├── examples/go          # Go contract examples + tests
├── packages/runar-go     # Mock types, crypto, CompileCheck()
└── conformance          # Cross-compiler tests
```

This workspace allows `import runar "github.com/icellan/runar/packages/runar-go"` to resolve to the mock package everywhere. Within the monorepo, the `go.work` file provides local replacement; external consumers use the published module path directly.

### Basic Test Structure

```go
package contract

import (
	"testing"
	runar "github.com/icellan/runar/packages/runar-go"
)

func TestP2PKH_Unlock(t *testing.T) {
	pk := runar.MockPubKey()
	c := &P2PKH{PubKeyHash: runar.Hash160(pk)}
	c.Unlock(runar.MockSig(), pk)
}

func TestP2PKH_Unlock_WrongKey(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected assertion failure for wrong public key")
		}
	}()
	pk := runar.MockPubKey()
	wrongPk := runar.PubKey("\x03" + string(make([]byte, 32)))
	c := &P2PKH{PubKeyHash: runar.Hash160(pk)}
	c.Unlock(runar.MockSig(), wrongPk)
}

func TestP2PKH_Compile(t *testing.T) {
	if err := runar.CompileCheck("P2PKH.runar.go"); err != nil {
		t.Fatalf("Rúnar compile check failed: %v", err)
	}
}
```

Contracts call `runar.Assert()` which panics on failure. Tests that expect a failure use `defer/recover` to catch the panic.

### Testing Stateful Contracts

Stateful contracts mutate struct fields directly. After calling a method, inspect the fields:

```go
func TestCounter_Increment(t *testing.T) {
	c := &Counter{Count: 0}
	c.Increment()
	if c.Count != 1 {
		t.Errorf("expected Count=1, got %d", c.Count)
	}
}

func TestCounter_DecrementAtZero_Fails(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected assertion failure")
		}
	}()
	c := &Counter{Count: 0}
	c.Decrement()
}
```

### Multi-Output Contracts

Contracts that call `AddOutput()` track outputs via the embedded `StatefulSmartContract` base. Use `Outputs()` to inspect them:

```go
func TestFungibleToken_Transfer(t *testing.T) {
	c := newToken(alice, 100)
	c.Transfer(runar.MockSig(), bob, 30, 1000)
	out := c.Outputs()
	if len(out) != 2 {
		t.Fatalf("expected 2 outputs, got %d", len(out))
	}
	if out[0].Values[0] != bob {
		t.Error("output[0] owner should be bob")
	}
	if out[0].Values[1] != runar.Bigint(30) {
		t.Errorf("output[0] balance: expected 30, got %v", out[0].Values[1])
	}
}
```

The `OutputSnapshot` struct holds `Satoshis int64` and `Values []any` (mutable properties in declaration order).

### Mock Types and Functions

The `runar` package provides:

| Category | Functions |
|----------|-----------|
| **Types** | `Int`, `Bigint` (`int64`), `Bool` (`bool`), `PubKey`, `Sig`, `ByteString`, `Sha256`, `Addr` (all `string`-backed) |
| **Mock crypto** | `CheckSig`, `CheckMultiSig`, `CheckPreimage`, `VerifyRabinSig`, `VerifyWOTS` — always return `true` |
| **Real hashes** | `Hash160`, `Hash256`, `Sha256Hash`, `Ripemd160Func` — compute real values |
| **Math** | `Abs`, `Min`, `Max`, `Within`, `Safediv`, `Safemod`, `Clamp`, `Sign`, `Pow`, `MulDiv`, `PercentOf`, `Sqrt`, `Gcd`, `Log2`, `ToBool` |
| **Test helpers** | `MockSig()`, `MockPubKey()`, `MockPreimage()` |
| **Preimage extractors** | `ExtractLocktime`, `ExtractOutputHash`, `ExtractAmount`, etc. — return fixed test values |

Byte-backed types use `string` (not `[]byte`) so that `==` comparison works naturally in Go.

### CompileCheck

`runar.CompileCheck(filename)` runs the contract source through the Go compiler frontend (parse → validate → typecheck) and returns an error if anything fails. Always include a compile check test alongside your business logic tests:

```go
func TestMyContract_Compile(t *testing.T) {
	if err := runar.CompileCheck("MyContract.runar.go"); err != nil {
		t.Fatalf("Rúnar compile check failed: %v", err)
	}
}
```

### Running Go Tests

```bash
cd examples/go
go test ./...                    # Run all Go contract tests
go test ./p2pkh/...              # Run a specific contract
go test -v ./stateful-counter/   # Verbose output
```

---

## Testing Rust Contracts

Rust contracts are tested as native Rust code using `#[test]` attributes. The `runar` mock crate (`packages/runar-rs`) provides a prelude with type aliases, mock crypto, and real hash functions.

### Project Setup

Rust examples live in `examples/rust/`, with one directory per contract. A single `Cargo.toml` defines the workspace with `[[test]]` entries for each contract:

```toml
[package]
name = "runar-example-tests"
version = "0.1.0"
edition = "2021"
publish = false

[dependencies]
runar = { package = "runar-lang", version = "0.1.0" }

[[test]]
name = "p2pkh"
path = "p2pkh/P2PKH_test.rs"

[[test]]
name = "counter"
path = "stateful-counter/Counter_test.rs"

# ... one entry per contract
```

### Basic Test Structure

```rust
#[path = "P2PKH.runar.rs"]
mod contract;

use contract::*;
use runar::prelude::*;

#[test]
fn test_unlock() {
    let pk = mock_pub_key();
    let c = P2PKH { pub_key_hash: hash160(&pk) };
    c.unlock(&mock_sig(), &pk);
}

#[test]
#[should_panic]
fn test_unlock_wrong_key() {
    let pk = mock_pub_key();
    let wrong_pk = vec![0x03; 33];
    let c = P2PKH { pub_key_hash: hash160(&pk) };
    c.unlock(&mock_sig(), &wrong_pk);
}

#[test]
fn test_compile() {
    runar::compile_check(
        include_str!("P2PKH.runar.rs"),
        "P2PKH.runar.rs",
    ).unwrap();
}
```

Key patterns:
- **`#[path = "Contract.runar.rs"] mod contract;`** imports the contract source as a Rust module.
- **`use runar::prelude::*;`** brings all mock types and functions into scope.
- **`#[should_panic]`** cleanly asserts that a contract method panics (no need for `catch_unwind`).
- **`include_str!()`** embeds the contract source for `compile_check()`.

### Testing Stateful Contracts

Stateful contracts take `&mut self` and mutate fields directly:

```rust
#[test]
fn test_increment() {
    let mut c = Counter { count: 0 };
    c.increment();
    assert_eq!(c.count, 1);
}

#[test]
fn test_multiple_operations() {
    let mut c = Counter { count: 0 };
    c.increment();
    c.increment();
    c.increment();
    c.decrement();
    assert_eq!(c.count, 2);
}

#[test]
#[should_panic]
fn test_decrement_at_zero_fails() {
    Counter { count: 0 }.decrement();
}
```

### Multi-Output Contracts

Rust's borrow checker requires `.clone()` when passing owned fields to `add_output()`. Test files typically define a local output struct:

```rust
#[derive(Clone)]
struct FtOutput { satoshis: Bigint, owner: PubKey, balance: Bigint }

struct FungibleToken {
    owner: PubKey,
    balance: Bigint,
    token_id: ByteString,
    outputs: Vec<FtOutput>,
}

impl FungibleToken {
    fn add_output(&mut self, satoshis: Bigint, owner: PubKey, balance: Bigint) {
        self.outputs.push(FtOutput { satoshis, owner, balance });
    }
}

#[test]
fn test_transfer() {
    let mut c = new_token(alice(), 100);
    c.transfer(&mock_sig(), bob(), 30, 1000);
    assert_eq!(c.outputs.len(), 2);
    assert_eq!(c.outputs[0].owner, bob());
    assert_eq!(c.outputs[0].balance, 30);
}
```

Note: The `.runar.rs` contract file itself needs `.clone()` on owned values passed to `add_output()`. This is a no-op for Bitcoin Script compilation but satisfies the Rust borrow checker.

### Mock Types and Functions

The `runar::prelude` provides:

| Category | Functions |
|----------|-----------|
| **Types** | `Int`, `Bigint` (`i64`), `PubKey`, `Sig`, `ByteString`, `Sha256`, `Addr` (all `Vec<u8>`) |
| **Mock crypto** | `check_sig`, `check_multi_sig`, `check_preimage`, `verify_rabin_sig`, `verify_wots` — always return `true` |
| **Real hashes** | `hash160`, `hash256`, `sha256`, `ripemd160` — compute real values |
| **Math** | `safediv`, `safemod`, `clamp`, `sign`, `pow`, `mul_div`, `percent_of`, `sqrt`, `gcd`, `log2`, `bool_cast` |
| **Byte ops** | `num2bin`, `len`, `cat`, `substr` |
| **Test helpers** | `mock_sig()`, `mock_pub_key()`, `mock_preimage()` |
| **Preimage extractors** | `extract_locktime`, `extract_output_hash`, etc. — return fixed test values |

Byte-backed types use `Vec<u8>`, so equality comparisons with `==` work via `PartialEq`.

### compile_check

`runar::compile_check(source, filename)` runs the contract through the Rust compiler frontend (parse → validate → typecheck) and returns `Result<(), String>`:

```rust
#[test]
fn test_compile() {
    runar::compile_check(
        include_str!("Counter.runar.rs"),
        "Counter.runar.rs",
    ).unwrap();
}
```

Always include a compile check test. This catches Rúnar language errors (invalid types, unknown functions, recursion, etc.) that the Rust compiler itself would not flag.

### Running Rust Tests

```bash
cd examples/rust
cargo test                           # Run all Rust contract tests
cargo test --test p2pkh              # Run a specific contract
cargo test --test counter -- --nocapture  # Verbose output
```

---

## Cross-Language Testing Comparison

All seven tiers run native unit tests with their language's standard test runner, plus a `CompileCheck` / `compile_check` entry point that re-runs the contract through the frontend.

| Aspect | TypeScript | Go | Rust | Python | Zig | Ruby | Java |
|--------|-----------|----|------|--------|-----|------|------|
| **Test framework** | vitest | `testing.T` | `#[test]` | pytest | `zig build test` | rspec | JUnit 5 |
| **Failure assertion** | `expectScriptFailure(result)` (see note below) | `defer/recover` | `#[should_panic]` | `pytest.raises(AssertionError)` | `testing.expectError` | `expect { ... }.to raise_error` | `assertThrows(...)` |
| **Contract loading** | `TestContract.fromSource(source, state)` | Struct literal in same package | `#[path = "..."] mod contract;` | `load_contract("File.runar.py")` (conftest helper) | `@import("./contract.zig")` + struct literal | `require_relative` + class instantiation | Class instantiation in same package |
| **Type imports** | `import { ... } from 'runar-testing'` | `import runar "github.com/icellan/runar/packages/runar-go"` | `use runar::prelude::*;` | `from runar import ...` | `const runar = @import("runar");` | `require "runar"` | `import runar.lang.*;` |
| **Byte types** | Hex strings / `Uint8Array` | `string` (for `==`) | `Vec<u8>` (for `==` via `PartialEq`) | `bytes` | `[]const u8` | `String` (binary-encoded) | `byte[]` / `ByteString` wrapper |
| **Scalar types** | `bigint` | `int64` aliases | `i64` aliases | `int` (arbitrary precision) | `i64` aliases | `Integer` | `long` / `BigInteger` |
| **Output tracking** | `contract.state` after `call()` | `c.Outputs()` method | Manual `Vec<Output>` field | `c.outputs` list | `c.outputs` slice | `c.outputs` array | `c.outputs()` accessor |
| **Compile check** | Built into `fromArtifact` / `fromSource` | `runar.CompileCheck("file.runar.go")` | `runar::compile_check(include_str!("file"), "file")` | `runar.compile_check("file.runar.py")` | `runar.compileCheck("file.runar.zig")` | `Runar.compile_check("file.runar.rb")` | `CompileCheck.run(Path.of("File.runar.java"))` |
| **Borrow workarounds** | N/A | None needed | `.clone()` for owned fields in `add_output` | None needed | Explicit slice/allocator handling | None needed | None needed |
| **Off-chain real-crypto harness** | `ScriptVM` | `ScriptVM` | `ScriptVM` (execute-only) | `ScriptVM` (optional `bsv-sdk` dep) | None (regtest only) | None (regtest only) | `ContractSimulator` (real hashes + real secp256k1 + mocked sig-verify) |
| **Run command** | `npx vitest run` | `go test ./...` | `cargo test` | `python3 -m pytest` | `zig build test` | `bundle exec rspec` | `./gradlew test` |

Identifier-casing note: Python and Ruby contracts use snake_case in source; the parser converts to camelCase in the AST (`pub_key_hash` → `pubKeyHash`, `check_sig` → `checkSig`). Native tests in those tiers reference the snake_case names that the host language uses.

> **`expectScriptFailure`**: A convenience assertion exported from `runar-testing`. It takes a `VMResult` from `TestSmartContract.call()` or `ScriptVM.execute()` and throws if the script execution succeeded (i.e., it asserts that the script failed). Its counterpart is `expectScriptSuccess`. Both are imported from `runar-testing`:
>
> ```typescript
> import { expectScriptFailure, expectScriptSuccess } from 'runar-testing';
> ```

---

## Post-Quantum Signature Testing (Experimental)

Post-quantum signature verification (WOTS+ and SLH-DSA) has dedicated testing at three levels:

### Reference Implementation Tests

Pure TypeScript implementations in `packages/runar-testing/src/crypto/`:

- `wots.ts` — WOTS+ keygen, sign, verify (18 unit tests)
- `slh-dsa.ts` — SLH-DSA for all 6 SHA-256 parameter sets (9 unit tests)

```bash
npx vitest run packages/runar-testing/src/crypto/__tests__/
```

### Interpreter Tests

The interpreter performs real PQ verification (not mocked). Test contracts call `verifyWOTS` or `verifySLHDSA_SHA2_*` and the interpreter executes the actual algorithm:

```typescript
import { wotsKeygen, wotsSign } from '../crypto/wots.js';
const { sk, pk } = wotsKeygen(seed);
const sig = wotsSign(msg, sk);
const contract = TestContract.fromSource(source, { pubkey: toHex(pk) });
expect(contract.call('spend', { msg: toHex(msg), sig: toHex(sig) }).success).toBe(true);
```

### Dual-Oracle Tests

These validate that the compiled Bitcoin Script produces the same result as the interpreter:

- `post-quantum-dual-oracle.test.ts` — WOTS+ (10 KB script)
- `post-quantum-slh-dual-oracle.test.ts` — SLH-DSA-128s (203 KB script)

Both paths must agree on valid signatures (accept) and invalid signatures (reject).

### Conformance Golden Files

`conformance/tests/post-quantum-wots/` and `conformance/tests/post-quantum-slhdsa/` contain golden `expected-script.hex` files. WOTS+ and SLH-DSA codegen ship in **all 7 maintained compilers** (TS, Go, Rust, Python, Zig, Ruby, Java), and all 7 target byte-identical output against these goldens.

---

## Elliptic Curve Contract Testing

EC-based contracts (using `ecAdd`, `ecMul`, `ecMulGen`, etc.) are tested like any other Rúnar contract via `TestContract`, but require generating valid EC test vectors in the test harness.

### Generating EC Test Vectors

Since EC operations manipulate secp256k1 points, tests need to compute valid points and scalars. The test file typically includes JS helper functions for EC arithmetic:

```typescript
import { TestContract } from 'runar-testing';

// secp256k1 constants
const EC_P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2Fn;
const EC_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141n;
const GX = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798n;
const GY = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8n;

// JS helpers for test vector generation
function mod(a: bigint, m: bigint): bigint { return ((a % m) + m) % m; }
function modInv(a: bigint, m: bigint): bigint { /* extended Euclidean */ }
function pointAdd(x1: bigint, y1: bigint, x2: bigint, y2: bigint): [bigint, bigint] { /* ... */ }
function scalarMul(bx: bigint, by: bigint, k: bigint): [bigint, bigint] { /* ... */ }

// Encode a point as a 128-char hex string (64 bytes: x[32] || y[32])
function makePointHex(x: bigint, y: bigint): string {
  return x.toString(16).padStart(64, '0').toUpperCase()
       + y.toString(16).padStart(64, '0').toUpperCase();
}
```

### Example: Testing a Schnorr ZKP Contract

```typescript
describe('SchnorrZKP contract', () => {
  it('verifies a valid Schnorr ZKP proof', () => {
    const privKey = 42n;
    const [pubX, pubY] = scalarMul(GX, GY, privKey);
    const pubKeyHex = makePointHex(pubX, pubY);

    const r = 12345n;
    const [rX, rY] = scalarMul(GX, GY, r);
    const rHex = makePointHex(rX, rY);

    const e = 7n;
    const s = mod(r + e * privKey, EC_N);

    const c = TestContract.fromSource(source, { pubKey: pubKeyHex });
    const result = c.call('verify', { rPoint: rHex, s, e });
    expect(result.success).toBe(true);
  });

  it('rejects a proof with wrong s value', () => {
    // ... same setup but pass s + 1n ...
    const result = c.call('verify', { rPoint: rHex, s: s + 1n, e });
    expect(result.success).toBe(false);
  });
});
```

### Key Testing Considerations for EC Contracts

- **Point format**: Points are 64 bytes (128 hex chars), big-endian unsigned, no prefix. Use `makePointHex()` or equivalent to construct valid test points.
- **Modular arithmetic**: All scalar computations in tests must use `mod(value, EC_N)` to stay within the group order, matching what the on-chain contract does.
- **Interpreter-based**: `TestContract` uses the interpreter, which performs real EC arithmetic (not mocked). This means test results accurately reflect the contract's mathematical behavior.
- **Script size**: EC contracts generate large scripts (~50-100 KB per `ecMul`/`ecMulGen` call). Full Script VM execution of these contracts is feasible but slower than interpreter-based testing.

---

## Conformance Testing Across Compilers

The conformance suite in `conformance/` ensures the maintained Rúnar compilers produce identical output for the shared test corpus.

### Golden-File Tests

Each test case is a directory containing:

```
conformance/tests/basic-p2pkh/
  basic-p2pkh.runar.ts      # Source contract
  P2PKH.runar.zig           # Optional alternate-source frontend fixture
  expected-ir.json          # Expected ANF IR (canonical JSON)
  expected-script.hex       # Expected compiled script (hex)
```

### Running Conformance Tests

```bash
# Test the TypeScript reference compiler
pnpm run conformance:ts

# Test the Go compiler
pnpm run conformance:go

# Test the Rust compiler
pnpm run conformance:rust

# Test the Python compiler
pnpm run conformance:python

# Test the Zig compiler
pnpm run conformance:zig

# Test the Ruby compiler
pnpm run conformance:ruby

# Test the Java compiler
pnpm run conformance:java

# Run every conformance suite end-to-end (all 7 compilers + cross-tier + SDK + ANF parity)
pnpm run conformance:all
```

The runner compiles each source file, serializes the ANF IR using canonical JSON (RFC 8785), and compares the SHA-256 hash against the expected output. Byte-identical output is required.

### Adding a New Conformance Test

1. Create a directory under `conformance/tests/` with a descriptive name.
2. Write the source contract (`.runar.ts`).
3. Generate the expected IR using the reference compiler:

```bash
runar compile conformance/tests/my-test/my-test.runar.ts --ir --canonical
```

4. Copy the canonical ANF IR to `expected-ir.json`.
5. Optionally generate and save the expected script hex.
6. Run `pnpm run conformance:ts` to verify.

### Updating Golden Files

When the spec or compiler changes in a way that affects output:

```bash
pnpm run conformance:update-golden
```

Review the diffs carefully. An unexpected change in a golden file indicates either a compiler bug or an unintended spec change.

---

## Testing Strategy Summary

Rúnar employs a layered testing strategy:

| Layer | What It Tests | Tool |
|-------|--------------|------|
| **Unit tests per pass** | Each compiler pass in isolation | vitest |
| **End-to-end compilation** | Full pipeline: source to script | vitest + conformance golden files |
| **VM execution** | Compiled script with specific inputs | `TestSmartContract` / `ScriptVM` (execute compiled Bitcoin Script) |
| **Interpreter oracle** | ANF IR evaluation matches VM execution | `RunarInterpreter` vs `ScriptVM` |
| **Property-based fuzzing** | Random valid programs compile correctly | fast-check generators |
| **Differential fuzzing** | Compiler + VM agree with interpreter | `conformance/fuzzer` |
| **Cross-compiler conformance** | All compilers produce identical output | Golden-file SHA-256 comparison |
| **Post-quantum dual-oracle** | Compiled PQ script matches interpreter | `TestContract` vs `ScriptExecutionContract` |

The layers build on each other. Unit tests catch obvious regressions. VM tests verify that the compiled script actually works. The interpreter oracle catches subtle semantic bugs. Fuzzing searches for edge cases that hand-written tests miss. Conformance testing ensures the multi-compiler strategy holds together.

### Per-Pass Test Structure

Each compiler pass has its own test file. Tests provide specific input IR, run the pass, and assert properties of the output:

```
Pass 1 tests: source string      --> Rúnar AST assertions
Pass 2 tests: Rúnar AST           --> validation error/success
Pass 3 tests: Validated AST      --> type error/success assertions
Pass 4 tests: Validated AST      --> ANF IR structural assertions
Pass 5 tests: ANF IR             --> Stack IR depth assertions
Pass 6 tests: Stack IR           --> hex script assertions
```

This granularity makes it straightforward to isolate where a bug was introduced when a higher-level test fails.
