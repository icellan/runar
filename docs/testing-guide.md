# Testing Guide

This guide covers how to test TSOP smart contracts at every level, from unit tests of individual contracts to property-based fuzzing and cross-compiler conformance testing.

---

## Unit Testing with Vitest

TSOP uses vitest as its test runner. Contract tests compile a `.tsop.ts` file to an artifact, then execute methods against the built-in Script VM.

### Basic Test Structure

```typescript
import { describe, it, expect } from 'vitest';
import {
  TestSmartContract,
  expectScriptSuccess,
  expectScriptFailure,
} from 'tsop-testing';
import artifact from '../artifacts/P2PKH.json';

describe('P2PKH', () => {
  // Construct with the pubkey hash that was used at deploy time
  const pubKeyHash = '89abcdef01234567890abcdef01234567890abcd';
  const contract = TestSmartContract.fromArtifact(artifact, [pubKeyHash]);

  it('succeeds with valid signature and matching pubkey', () => {
    const sig = '3044022...'; // valid DER signature hex
    const pubKey = '02abc...'; // matching compressed pubkey hex

    const result = contract.call('unlock', [sig, pubKey]);
    expectScriptSuccess(result);
  });

  it('fails with wrong pubkey', () => {
    const sig = '3044022...';
    const wrongPubKey = '03def...'; // different pubkey

    const result = contract.call('unlock', [sig, wrongPubKey]);
    expectScriptFailure(result);
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

## Using TestSmartContract

`TestSmartContract` is the primary test helper. It loads a compiled artifact and executes methods against the Script VM.

### Creating an Instance

```typescript
import { TestSmartContract } from 'tsop-testing';

// From a JSON artifact object
const contract = TestSmartContract.fromArtifact(artifact, constructorArgs);

// With VM options (e.g., enable debug logging)
const contract = TestSmartContract.fromArtifact(artifact, constructorArgs, {
  maxOps: 10000,    // maximum opcodes before timeout
  debug: true,      // log each opcode execution
});
```

The `constructorArgs` array must match the artifact's ABI constructor parameters in order.

### Calling Methods

```typescript
const result = contract.call('methodName', [arg1, arg2, arg3]);
```

Arguments are encoded based on their ABI-declared types:

| ABI Type | Argument Format |
|----------|----------------|
| `bigint` | `bigint` value (e.g., `42n`) |
| `boolean` | `true` or `false` |
| `PubKey`, `Sig`, `ByteString`, etc. | Hex-encoded string |

The return value is a `VMResult` object:

```typescript
interface VMResult {
  success: boolean;          // true if stack top is truthy
  stack: Uint8Array[];       // final stack contents
  error?: string;            // error message if script failed
  opsExecuted: number;       // number of opcodes executed
}
```

### Assertion Helpers

```typescript
import {
  expectScriptSuccess,
  expectScriptFailure,
  expectStackTop,
  expectStackTopNum,
} from 'tsop-testing';

// Assert script execution succeeded
expectScriptSuccess(result);

// Assert script execution failed
expectScriptFailure(result);

// Assert the top of the stack equals specific bytes
expectStackTop(result, new Uint8Array([0x01]));

// Assert the top of the stack equals a specific number
expectStackTopNum(result, 42n);
```

Each helper throws a descriptive error on failure, including the actual stack contents and the number of opcodes executed.

---

## Script VM Testing

The `ScriptVM` class can be used directly for lower-level testing without the `TestSmartContract` wrapper.

```typescript
import { ScriptVM, hexToBytes, bytesToHex, disassemble } from 'tsop-testing';

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
} from 'tsop-testing';

// Encode/decode Script numbers
const encoded = encodeScriptNumber(42n);  // Uint8Array
const decoded = decodeScriptNumber(encoded); // 42n

// Check if a stack element is truthy
isTruthy(new Uint8Array([0x01])); // true
isTruthy(new Uint8Array([]));     // false (OP_FALSE)
```

---

## Reference Interpreter for Oracle Testing

The reference interpreter (`TSOPInterpreter`) evaluates ANF IR directly, without compiling to Bitcoin Script. It serves as an oracle: if the compiled script and the interpreter produce different results for the same inputs, there is a bug.

```typescript
import { TSOPInterpreter } from 'tsop-testing';
import type { ANFProgram } from 'tsop-ir-schema';

// Load the ANF IR (from a compiled artifact with --ir flag)
const anfProgram: ANFProgram = artifact.ir;

const interpreter = new TSOPInterpreter(anfProgram);

// Evaluate a method with arguments
const result = interpreter.evaluate('unlock', {
  sig: '3044022...',
  pubKey: '02abc...',
});

// result.success: boolean
// result.value: the final value (for private methods)
```

### Comparing Interpreter and VM Results

```typescript
it('compiler and interpreter agree', () => {
  const vmResult = contract.call('unlock', [sig, pubKey]);
  const interpResult = interpreter.evaluate('unlock', { sig, pubKey });

  // Both should agree on success/failure
  expect(vmResult.success).toBe(interpResult.success);
});
```

This pattern is the foundation of differential testing. If they ever disagree, you have found a compiler bug.

---

## Property-Based Fuzzing

TSOP includes property-based testing generators built on fast-check. These generate random valid TSOP contracts and verify compiler correctness.

### Built-in Generators

```typescript
import {
  arbContract,
  arbStatelessContract,
  arbArithmeticContract,
  arbCryptoContract,
} from 'tsop-testing';
```

| Generator | Produces |
|-----------|----------|
| `arbContract` | Random valid TSOP contract source |
| `arbStatelessContract` | Random contract with only `readonly` properties |
| `arbArithmeticContract` | Contract focusing on arithmetic operations |
| `arbCryptoContract` | Contract using cryptographic built-ins |

### Using with fast-check

```typescript
import { describe, it } from 'vitest';
import * as fc from 'fast-check';
import { arbStatelessContract } from 'tsop-testing';
import { compile } from 'tsop-compiler';

describe('compiler fuzzing', () => {
  it('never crashes on valid input', () => {
    fc.assert(
      fc.property(arbStatelessContract, (source) => {
        // The compiler should never throw on valid TSOP
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

The conformance fuzzer in `conformance/fuzzer/` generates random programs and checks that the compiler + VM produce the same result as the interpreter:

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
Generate random .tsop.ts --> Compile to ANF IR --> Compile to Script
                         |                    |
                         v                    v
                    Interpret ANF IR     Execute in VM
                         |                    |
                         v                    v
                    Compare results: must match
```

If the results disagree, the failing program is saved for reproduction. This is inspired by CSmith (Yang et al., PLDI 2011) and is the primary mechanism for finding compiler bugs.

---

## Conformance Testing Across Compilers

The conformance suite in `conformance/` ensures all TSOP compilers (TypeScript, Go, Rust) produce identical output.

### Golden-File Tests

Each test case is a directory containing:

```
conformance/tests/basic-p2pkh/
  basic-p2pkh.tsop.ts      # Source contract
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
```

The runner compiles each source file, serializes the ANF IR using canonical JSON (RFC 8785), and compares the SHA-256 hash against the expected output. Byte-identical output is required.

### Adding a New Conformance Test

1. Create a directory under `conformance/tests/` with a descriptive name.
2. Write the source contract (`.tsop.ts`).
3. Generate the expected IR using the reference compiler:

```bash
tsop compile conformance/tests/my-test/my-test.tsop.ts --ir --canonical
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

TSOP employs a layered testing strategy:

| Layer | What It Tests | Tool |
|-------|--------------|------|
| **Unit tests per pass** | Each compiler pass in isolation | vitest |
| **End-to-end compilation** | Full pipeline: source to script | vitest + conformance golden files |
| **VM execution** | Compiled script with specific inputs | `TestSmartContract` + `ScriptVM` |
| **Interpreter oracle** | ANF IR evaluation matches VM execution | `TSOPInterpreter` vs `ScriptVM` |
| **Property-based fuzzing** | Random valid programs compile correctly | fast-check generators |
| **Differential fuzzing** | Compiler + VM agree with interpreter | `conformance/fuzzer` |
| **Cross-compiler conformance** | All compilers produce identical output | Golden-file SHA-256 comparison |

The layers build on each other. Unit tests catch obvious regressions. VM tests verify that the compiled script actually works. The interpreter oracle catches subtle semantic bugs. Fuzzing searches for edge cases that hand-written tests miss. Conformance testing ensures the multi-compiler strategy holds together.

### Per-Pass Test Structure

Each compiler pass has its own test file. Tests provide specific input IR, run the pass, and assert properties of the output:

```
Pass 1 tests: source string      --> TSOP AST assertions
Pass 2 tests: TSOP AST           --> validation error/success
Pass 3 tests: Validated AST      --> type annotation assertions
Pass 4 tests: Typed AST          --> ANF IR structural assertions
Pass 5 tests: ANF IR             --> Stack IR depth assertions
Pass 6 tests: Stack IR           --> hex script assertions
```

This granularity makes it straightforward to isolate where a bug was introduced when a higher-level test fails.
