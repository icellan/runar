# runar-testing

**Test infrastructure for Rúnar: Bitcoin Script VM, reference interpreter, program fuzzer, and test helpers.**

This package provides everything needed to verify that compiled Rúnar contracts behave correctly. It contains four major components: a Bitcoin Script virtual machine, a definitional interpreter that serves as a correctness oracle, a program fuzzer for differential testing, and utility helpers for writing contract tests.

---

## Installation

```bash
pnpm add runar-testing
```

---

## Bitcoin Script VM

The Script VM executes raw Bitcoin Script bytecode. It implements the BSV instruction set including all re-enabled opcodes (post-Genesis).

### Basic Usage

```typescript
import { ScriptVM, VMResult } from 'runar-testing';

// Create unlocking + locking script
const unlockingScript = Buffer.from('...', 'hex');
const lockingScript = Buffer.from('76a97c7e7e87a988ac', 'hex');

const vm = new ScriptVM();
const result: VMResult = vm.execute(unlockingScript, lockingScript);

console.log(result.success);     // true if stack top is truthy
console.log(result.finalStack);  // stack state after execution
console.log(result.error);       // error message if script failed
```

### Supported Opcodes

The VM supports the full BSV opcode set:

**Constants:** `OP_0` through `OP_16`, `OP_1NEGATE`, `OP_PUSHDATA1/2/4`

**Flow Control:** `OP_NOP`, `OP_IF`, `OP_NOTIF`, `OP_ELSE`, `OP_ENDIF`, `OP_VERIFY`, `OP_RETURN`

**Stack:** `OP_TOALTSTACK`, `OP_FROMALTSTACK`, `OP_DUP`, `OP_DROP`, `OP_NIP`, `OP_OVER`, `OP_PICK`, `OP_ROLL`, `OP_ROT`, `OP_SWAP`, `OP_TUCK`, `OP_2DROP`, `OP_2DUP`, `OP_3DUP`, `OP_2OVER`, `OP_2ROT`, `OP_2SWAP`, `OP_IFDUP`, `OP_DEPTH`, `OP_SIZE`

**Arithmetic:** `OP_ADD`, `OP_SUB`, `OP_MUL`, `OP_DIV`, `OP_MOD`, `OP_LSHIFT`, `OP_RSHIFT`, `OP_NEGATE`, `OP_ABS`, `OP_NOT`, `OP_0NOTEQUAL`, `OP_BOOLAND`, `OP_BOOLOR`, `OP_NUMEQUAL`, `OP_NUMEQUALVERIFY`, `OP_NUMNOTEQUAL`, `OP_LESSTHAN`, `OP_GREATERTHAN`, `OP_LESSTHANOREQUAL`, `OP_GREATERTHANOREQUAL`, `OP_MIN`, `OP_MAX`, `OP_WITHIN`, `OP_1ADD`, `OP_1SUB`

**Bitwise:** `OP_AND`, `OP_OR`, `OP_XOR`, `OP_INVERT`

**String/Splice:** `OP_CAT`, `OP_SPLIT`, `OP_NUM2BIN`, `OP_BIN2NUM`

**Crypto:** `OP_RIPEMD160`, `OP_SHA256`, `OP_HASH160`, `OP_HASH256`, `OP_CHECKSIG`, `OP_CHECKSIGVERIFY`, `OP_CHECKMULTISIG`, `OP_CHECKMULTISIGVERIFY`, `OP_CODESEPARATOR`

**Re-enabled (BSV Genesis):** `OP_MUL`, `OP_LSHIFT`, `OP_RSHIFT`, `OP_INVERT`, `OP_AND`, `OP_OR`, `OP_XOR`, `OP_CAT`, `OP_SPLIT`, `OP_NUM2BIN`, `OP_BIN2NUM`

### VM Options

```typescript
const vm = new ScriptVM({
  maxStackSize: 800,           // maximum stack depth (default: 800)
  maxScriptSize: 10_000_000,   // maximum script size in bytes
  maxOpcodeCount: 500_000,     // maximum opcodes executed
  requireMinimalPush: true,    // enforce minimal push encoding
  requireCleanStack: true,     // require exactly one item on stack at end
  genesisEnabled: true,        // enable post-Genesis opcodes
});
```

### Limitations vs Real BSV Node

The VM is designed for testing, not consensus. Known differences:

- **Signature verification** uses a mock implementation that checks against pre-registered key/sig pairs rather than performing actual ECDSA. This is intentional -- real signature verification requires a full transaction context.
- **OP_PUSH_TX / Sighash preimage** verification is simulated. The VM accepts a mock preimage context rather than computing real sighash digests.
- **Script size limits** are configurable and may not match the exact consensus rules of a specific BSV node version.

For production deployment, always test against a real BSV node (e.g., via the SDK's testnet deployment).

---

## Reference Interpreter

The reference interpreter is a **definitional interpreter** in the tradition of Reynolds (1972). It evaluates the ANF IR directly by recursive descent, without compiling to Bitcoin Script. It exists to serve as a correctness oracle.

### What is a Definitional Interpreter?

A definitional interpreter evaluates a program by walking its AST (or IR) and computing each node's result according to the language's operational semantics. It is the most direct implementation of "what this program means" -- no compilation, no optimization, no stack scheduling. If the interpreter says a program produces `42`, then `42` is the correct answer by definition.

### How it Serves as Oracle

The testing strategy is:

1. Compile a Rúnar source to Bitcoin Script (via the compiler).
2. Run the compiled script in the Script VM with specific inputs.
3. Independently evaluate the ANF IR in the reference interpreter with the same inputs.
4. Assert that the VM result matches the interpreter result.

If they disagree, there is a bug in either the compiler (passes 4-6), the VM, or the interpreter. Since the interpreter is intentionally simple (direct evaluation, no optimizations), bugs are far more likely in the compiler.

### Usage

```typescript
import { Interpreter, InterpreterResult } from 'runar-testing';

const anfIR = { ... };  // ANF IR from compiler

const interpreter = new Interpreter(anfIR);

const result: InterpreterResult = interpreter.evaluate('unlock', {
  sig: '3044...',
  pubKey: '02abc...',
});

console.log(result.success);  // true if all asserts passed
console.log(result.state);    // final contract state (for stateful contracts)
```

### Interpreter Internals

The interpreter maintains:

- An **environment** mapping parameter and temporary names to values.
- A **store** mapping property names to values (the contract state).

Each ANF binding is evaluated in sequence:

| Tag | Interpreter Action |
|---|---|
| `load_param` | Look up parameter in the environment |
| `load_prop` | Look up property in the store |
| `load_const` | Parse the constant value |
| `bin_op` | Evaluate the operation on the two operand values |
| `call` | Dispatch to the built-in function implementation |
| `if` | Evaluate condition, recurse into the appropriate branch |
| `assert` | Check condition; if false, halt with failure |
| `update_prop` | Update the property in the store |

---

## Program Fuzzer

The fuzzer generates random valid Rúnar programs for differential testing. It is inspired by CSmith (Yang et al., PLDI 2011), which found hundreds of bugs in production C compilers by generating random C programs and comparing the output of different compilers.

### CSmith-Inspired Approach

The fuzzer:

1. Generates a random contract with random properties (readonly and mutable).
2. Generates random method bodies using the allowed Rúnar expression and statement forms.
3. Ensures all generated programs are well-typed (the fuzzer tracks types as it generates).
4. Ensures all for-loop bounds are compile-time constants.
5. Ensures all public methods end with `assert(...)`.

The generated programs are intentionally diverse -- they exercise arithmetic, conditionals, loops, nested expressions, multiple methods, stateful updates, and various built-in functions.

### How to Run Differential Fuzzing

```typescript
import { Fuzzer, DifferentialTester } from 'runar-testing';

const fuzzer = new Fuzzer({ seed: 12345 });
const tester = new DifferentialTester();

for (let i = 0; i < 10000; i++) {
  const program = fuzzer.generate();
  const result = tester.test(program);

  if (!result.match) {
    console.error(`Mismatch on program ${i}:`);
    console.error(`Source: ${program.source}`);
    console.error(`VM result: ${result.vmResult}`);
    console.error(`Interpreter result: ${result.interpResult}`);
    break;
  }
}
```

### Fuzzer Configuration

```typescript
const fuzzer = new Fuzzer({
  seed: 42,                    // deterministic seed for reproducibility
  maxProperties: 5,            // max properties per contract
  maxMethods: 4,               // max methods per contract
  maxStatementsPerMethod: 10,  // max statements per method body
  maxLoopBound: 8,             // max for-loop iteration count
  maxNestingDepth: 3,          // max expression nesting depth
  includeStateful: true,       // generate stateful contracts
  includeArrays: true,         // generate FixedArray usage
});
```

---

## Test Helpers

### TestSmartContract

A utility for writing contract tests without the full compilation pipeline:

```typescript
import { TestSmartContract } from 'runar-testing';

const contract = new TestSmartContract('P2PKH', {
  properties: { pubKeyHash: Addr('a914...') },
});

// Test a public method call
const result = contract.call('unlock', {
  sig: Sig('3044...'),
  pubKey: PubKey('02abc...'),
});

expect(result.success).toBe(true);
```

### Assertion Utilities

```typescript
import { expectScriptSuccess, expectScriptFailure, expectStackTop } from 'runar-testing';

// Assert script succeeds
expectScriptSuccess(lockingScript, unlockingScript);

// Assert script fails
expectScriptFailure(lockingScript, unlockingScript);

// Assert specific value on stack top
expectStackTop(lockingScript, unlockingScript, expectedValue);
```

### Script Builder

```typescript
import { ScriptBuilder } from 'runar-testing';

const script = new ScriptBuilder()
  .pushData(Buffer.from('02abc...', 'hex'))
  .op('OP_DUP')
  .op('OP_HASH160')
  .pushData(Buffer.from('a914...', 'hex'))
  .op('OP_EQUALVERIFY')
  .op('OP_CHECKSIG')
  .build();
```
