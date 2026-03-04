# runar-testing

**Test infrastructure for Rúnar: Bitcoin Script VM, reference interpreter, program fuzzer, and test helpers.**

This package provides everything needed to verify that compiled Rúnar contracts behave correctly. It contains four major components: a Bitcoin Script virtual machine, a definitional interpreter that serves as a correctness oracle, a program fuzzer for differential testing, and utility helpers for writing contract tests.

---

## Installation

```bash
pnpm add runar-testing
```

---

## Exports

The package exports the following from `runar-testing`:

| Export | Kind | Description |
|---|---|---|
| `ScriptVM` | class | Bitcoin Script virtual machine |
| `Opcode` | enum | Opcode constants |
| `opcodeName` | function | Opcode byte → name |
| `encodeScriptNumber` | function | BigInt → Script number bytes |
| `decodeScriptNumber` | function | Script number bytes → BigInt |
| `isTruthy` | function | Check if a stack element is truthy |
| `hexToBytes` | function | Hex string → Uint8Array |
| `bytesToHex` | function | Uint8Array → hex string |
| `disassemble` | function | Script hex → ASM string |
| `RunarInterpreter` | class | Reference definitional interpreter |
| `arbContract` | fast-check Arbitrary | Generate random valid Rúnar contracts |
| `arbStatelessContract` | fast-check Arbitrary | Generate random stateless contracts |
| `arbArithmeticContract` | fast-check Arbitrary | Generate random arithmetic-focused contracts |
| `arbCryptoContract` | fast-check Arbitrary | Generate random crypto-focused contracts |
| `TestSmartContract` | class | Test wrapper around compiled artifacts (VM-based) |
| `TestContract` | class | Test wrapper using the interpreter (no compilation needed) |
| `ScriptExecutionContract` | class | Script execution via BSV SDK |
| `expectScriptSuccess` | function | Assert script executes successfully |
| `expectScriptFailure` | function | Assert script fails |
| `expectStackTop` | function | Assert specific value on stack top |
| `expectStackTopNum` | function | Assert specific numeric value on stack top |
| `VMResult` | type | VM execution result (success, stack, altStack, error, opsExecuted, maxStackDepth) |
| `VMOptions` | type | VM configuration options (maxOps, maxStackSize, maxScriptSize, flags, checkSigCallback) |
| `VMFlags` | type | VM behavioural flags (enableSighashForkId, enableOpCodes, strictEncoding) |
| `RunarValue` | type | Interpreter value type |
| `InterpreterResult` | type | Interpreter execution result |
| `TestCallResult` | type | Result from `TestContract.call()` |
| `OutputSnapshot` | type | Snapshot of a transaction output |
| `MockPreimage` | type | Mock sighash preimage for testing |
| `ScriptExecResult` | type | Result from `ScriptExecutionContract` execution |

---

## Bitcoin Script VM

The `ScriptVM` executes raw Bitcoin Script bytecode. It implements the BSV instruction set including all re-enabled opcodes (post-Genesis).

### Basic Usage

```typescript
import { ScriptVM, hexToBytes } from 'runar-testing';

const vm = new ScriptVM();
const result = vm.execute(hexToBytes(unlockingScriptHex), hexToBytes(lockingScriptHex));

console.log(result.success);        // true if stack top is truthy
console.log(result.stack);          // stack state after execution (Uint8Array[])
console.log(result.error);          // error message if script failed
console.log(result.altStack);       // alt stack state after execution (Uint8Array[])
console.log(result.opsExecuted);    // number of non-push opcodes executed
console.log(result.maxStackDepth);  // peak stack depth during execution
```

### VM Options

```typescript
import { ScriptVM } from 'runar-testing';
import type { VMOptions, VMFlags } from 'runar-testing';

const vm = new ScriptVM({
  maxOps: 500_000,              // max non-push opcodes (default 500_000)
  maxStackSize: 800,            // max main + alt stack items (default 1_000)
  maxScriptSize: 10_000_000,   // max script size in bytes (default unlimited)
  flags: {                      // behavioural flags
    enableSighashForkId: false,
    enableOpCodes: true,        // BSV re-enabled opcodes (default true)
    strictEncoding: false,
  },
  checkSigCallback: (sig, pubkey) => true,  // optional; mock mode by default
});
```

---

## Reference Interpreter

The `RunarInterpreter` is a definitional interpreter that evaluates Rúnar contracts by walking the AST directly, without compiling to Bitcoin Script. It serves as a correctness oracle.

```typescript
import { RunarInterpreter } from 'runar-testing';

const interpreter = new RunarInterpreter(initialProperties);
interpreter.setContract(contractNode);

const result = interpreter.executeMethod(contractNode, 'unlock', {
  sig: { kind: 'bytes', value: sigBytes },
  pubKey: { kind: 'bytes', value: pubKeyBytes },
});

console.log(result.success);
```

---

## TestContract API

The recommended way to test contracts. Uses the interpreter (not the VM), with mocked crypto (`checkSig` always true, `checkPreimage` always true).

```typescript
import { TestContract } from 'runar-testing';

// From source string (TypeScript format by default)
const counter = TestContract.fromSource(source, { count: 0n });
counter.call('increment');
expect(counter.state.count).toBe(1n);

// Multi-format: pass fileName to select parser
const solCounter = TestContract.fromSource(solSource, { count: 0n }, 'Counter.runar.sol');

// From file path
const contract = TestContract.fromFile('./contracts/Counter.runar.ts', { count: 0n });
```

---

## Program Fuzzer

The fuzzer generates random valid Rúnar programs using fast-check `Arbitrary` combinators. Inspired by CSmith (Yang et al., PLDI 2011).

### Usage with fast-check

```typescript
import { arbContract, arbStatelessContract, arbArithmeticContract, arbCryptoContract } from 'runar-testing';
import fc from 'fast-check';
import { compile } from 'runar-compiler';

// Property test: every generated contract compiles without errors
fc.assert(
  fc.property(arbContract, (source) => {
    const result = compile(source);
    return result.success;
  }),
  { numRuns: 1000 },
);
```

### Available Arbitraries

| Arbitrary | Description |
|---|---|
| `arbContract` | Contracts with 1-3 properties of mixed types, 1-3 methods |
| `arbStatelessContract` | Contracts with no properties, methods use only parameters |
| `arbArithmeticContract` | Contracts focused on bigint arithmetic expressions |
| `arbCryptoContract` | Contracts using `checkSig` and `sha256` with PubKey/Sig types |

---

## Test Helpers

### TestSmartContract

A test wrapper around compiled artifacts that executes them in the Script VM:

```typescript
import { TestSmartContract } from 'runar-testing';

const contract = TestSmartContract.fromArtifact(artifact, constructorArgs);
const result = contract.call('unlock', [sigHex, pubKeyHex]);

expect(result.success).toBe(true);
```

### Assertion Utilities

All assertion helpers take a `VMResult` (as returned by `vm.execute()`) rather than raw script hex:

```typescript
import { ScriptVM, hexToBytes, encodeScriptNumber } from 'runar-testing';
import { expectScriptSuccess, expectScriptFailure, expectStackTop, expectStackTopNum } from 'runar-testing';

const vm = new ScriptVM();
const result = vm.execute(hexToBytes(unlockingHex), hexToBytes(lockingHex));

// Assert script succeeds (top of stack is truthy)
expectScriptSuccess(result);

// Assert script fails
expectScriptFailure(result);

// Assert specific bytes on stack top
expectStackTop(result, new Uint8Array([0x01, 0x02]));

// Assert specific numeric value on stack top
expectStackTopNum(result, 42n);
```
