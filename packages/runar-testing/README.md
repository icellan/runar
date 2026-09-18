# runar-testing

**Test infrastructure for Rúnar: Bitcoin Script VM, reference interpreter, program fuzzer, and test helpers.**

This package provides everything needed to verify that compiled Rúnar contracts behave correctly. It contains four major components: a Bitcoin Script virtual machine, a definitional interpreter that serves as a correctness oracle, a program fuzzer for differential testing, and utility helpers for writing contract tests.

---

## Read this first: interpreter tests ≠ spendability

`TestContract` and `RunarInterpreter` are **AST interpreters**. They walk the
parsed contract, never the compiled Bitcoin Script — so no opcode, script size
limit or sighash is exercised by them, whatever their crypto does. And their
crypto is a mixture, not a blanket mock: `checkSig` and `verifyRabinSig` verify
for real, `checkPreimage` is stubbed `true`, and `checkMultiSig` refuses to
answer at all (it throws). The per-builtin breakdown is in
[TestContract API](#testcontract-api) below.

> **An interpreter test proves business logic. It never proves the contract is
> spendable.** A green `TestContract` suite is silent about whether the
> compiled locking script can be spent on-chain at all — and about whether an
> accepted spend commits the *right* continuation state.

That is not a defect; it is what makes these tools usable without managing keys
and sighashes. It just means they cannot be the *only* evidence for a
fund-critical claim. The paths that do prove spendability:

| Path | What it proves | Where |
|---|---|---|
| `ScriptVM` | Compiled script bytes execute; **real** `OP_CHECKSIG` (real secp256k1, real BIP-143 sighash) | this package, `src/vm/script-vm.ts` |
| `runDifferentialExecution` | Interpreter and the `@bsv/sdk` engine agree — **on the verdict only** | `src/oracle/differential-execution.ts` |
| `runStatefulSpend` / `runStatelessSigned` | Real deploy→call→`Spend` with real signatures, **plus** a hand-authored post-spend state pin | `src/oracle/real-crypto-execution.ts`, driven by `conformance/witnesses/real-crypto/*.json` |
| `MockProvider` deploy/call | Whole-transaction acceptance through the real `Spend` engine | `runar-sdk` — **validation is ON by default** |
| Regtest integration | A real node | `integration/{ts,go,rust,python,ruby,zig,java}` |

**`MockProvider` now validates broadcasts by default.** Since the 2026-08
testing-gap remediation (Phase A1), `runar-sdk`'s `MockProvider` replays every
input it knows the UTXO for through `@bsv/sdk`'s production `Spend`
interpreter, fails closed when *no* input could be validated, and enforces a
fee floor. `broadcast()` throws rather than returning a fake txid. An SDK test
that deploys and calls is therefore an assertion that the script really runs.
Opting out (`{ validateBroadcasts: false }`, `disableBroadcastValidation()`,
`newAlwaysAckMockProvider()`) requires an entry in the machine-checked
`packages/runar-sdk/src/__tests__/always-ack-allowlist.json`.

Full context, including which gate catches which past fund-safety bug:
[`docs/testing-guide.md`](../../docs/testing-guide.md) ⇒ "Layers of assurance".

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
| `VMOptions` | type | VM configuration options (maxOps, maxStackSize, maxScriptSize, flags) |
| `VMFlags` | type | VM behavioural flags (`strictEncoding`) |
| `StepResult` | type | One opcode of step-mode execution (offset, opcode, mainStack, altStack, error, context) |
| `runDifferentialExecution` | function | Source-vs-script oracle: interpreter vs `ScriptVM`, **verdict only** |
| `runTriModalExecution` | function | Adds a strict full-consensus `Spend.validate()` leg |
| `runFoldEquivalence` | function | fold-ON vs fold-OFF execution equivalence |
| `runStatelessSigned` / `runStatefulSpend` | function | Real-crypto execution: real DER signatures, real BIP-143 preimage, post-spend state |
| `buildWitness` | function | Build an unlocking script from typed witness args |
| `testKey`, `TEST_KEYS`, `ALICE`…`JUDY` | function / const | Deterministic test keypairs |
| `signTestMessage`, `verifyTestMessageSig` | function | Real ECDSA over the fixed `TEST_MESSAGE` digest |
| `RunarValue` | type | Interpreter value type |
| `InterpreterResult` | type | Interpreter execution result |
| `TestCallResult` | type | Result from `TestContract.call()` |
| `OutputSnapshot` | type | Snapshot of a transaction output |
| `MockPreimage` | type | Mock sighash preimage for testing |
| `ScriptExecResult` | type | Result from `ScriptExecutionContract` execution |

---

## Bitcoin Script VM

`ScriptVM` executes raw Bitcoin Script bytecode. It is **not a custom VM**: the
execution core is the upstream `@bsv/sdk` `Spend` interpreter — the same
production engine that validates real BSV transactions — driven one opcode at a
time via `Spend.step()`. `ScriptVM` only builds a synthetic single-input
transaction context so bare scripts can run, applies the harness-level DoS
bounds, and shapes the result. Nothing here reimplements an opcode.

> **Signatures are real; there is no mock checksig.** `OP_CHECKSIG` /
> `OP_CHECKMULTISIG` perform real secp256k1 verification against the BIP-143
> sighash of that synthetic context. The old hand-rolled VM took a
> `checkSigCallback` that defaulted to `() => true` — fail-open — and it is
> **gone**. A script whose only guard is a signature check now only succeeds
> when the caller supplies a genuinely valid signature (see
> `src/oracle/real-crypto-execution.ts`, which builds exactly such witnesses).

`success` means "no evaluation error and a truthy top-of-stack", so bare opcode
fragments that legitimately leave several items on the stack remain runnable.
The three consensus rules `Spend.validate()` layers on top of evaluation —
push-only unlocking scripts, clean-stack, and minimal-push / low-S encoding —
are applied by `oracle/tri-modal-execution.ts` and
`oracle/real-crypto-execution.ts`, not here. Pass `flags.strictEncoding` to
turn the encoding rules back on for this VM.

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
  maxScriptSize: 10_000_000,    // max script size in bytes (default unlimited)
  flags: {
    // Apply the upstream engine's strict-encoding consensus rules: minimally
    // encoded pushes, minimally encoded script numbers, low-S signatures.
    // Default false (relaxed), so hand-written opcode fragments still run.
    strictEncoding: false,
  },
});
```

There is no `checkSigCallback` option, and no `enableSighashForkId` /
`enableOpCodes` flag — signature verification is real and non-overridable, and
the BSV post-Genesis opcode set is whatever the pinned `@bsv/sdk` implements.

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

The fastest way to test contract **business logic**. Uses the interpreter (not
the VM) — so it proves state transitions and assertion logic, and proves nothing
about spendability. See [Read this first](#read-this-first-interpreter-tests--spendability).

Its crypto is a MIXTURE, not a blanket mock (R-112 — this section used to say
"`checkSig` always true", which is the opposite of the truth):

| builtin | in the interpreter |
| --- | --- |
| `checkSig` | **real** ECDSA, over a fixed test message (`verifyTestMessageSig`) |
| `verifyRabinSig` | **real** Rabin verification |
| `checkPreimage` | stubbed `true` |
| `checkMultiSig` | **refuses** — throws, rather than answer without array values |

`checkMultiSig` threw away its old silent `false` for a reason: a test of a
multisig contract was asserting against a hardcoded failure, so it proved
nothing and would not have noticed a broken contract. Use `ScriptVM` for the
real `OP_CHECKMULTISIG`.

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

### Mock Preimage

For testing time-locked or amount-constrained stateful contracts, use `setMockPreimage` to override the sighash preimage fields seen by `checkPreimage`:

```typescript
import { TestContract } from 'runar-testing';

const contract = TestContract.fromSource(source, { deadline: 1000n });

// Override mock preimage fields (all fields are bigint)
contract.setMockPreimage({
  locktime: 500n,
  amount: 10000n,
});

// Subsequent calls will see the overridden preimage values
const result = contract.call('withdraw');
expect(result.success).toBe(true);
```

The `MockPreimage` type has four optional fields:

```typescript
interface MockPreimage {
  locktime: bigint;
  amount: bigint;
  version: bigint;
  sequence: bigint;
}
```

`setMockPreimage` accepts a `Partial<MockPreimage>` -- only the fields you provide are overridden; the rest keep their defaults.

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
| `arbContract` | Contracts extending `SmartContract` with 1-3 `readonly` properties of mixed types, 1-3 methods |
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

---

## Crypto Reference Implementations

The package includes reference implementations of post-quantum signature schemes, exported for use in tests and applications:

| Export | Description |
|--------|-------------|
| `wotsKeygen`, `wotsSign`, `wotsVerify`, `WOTS_PARAMS` | WOTS+ (Winternitz One-Time Signature) keygen, sign, verify |
| `WOTSKeyPair` | Type for WOTS+ key pairs |
| `slhKeygen`, `slhSign`, `slhVerify`, `slhVerifyVerbose` | SLH-DSA (SPHINCS+, FIPS 205) keygen, sign, verify |
| `SLH_SHA2_128s`, `SLH_SHA2_128f`, `SLH_SHA2_192s`, `SLH_SHA2_192f`, `SLH_SHA2_256s`, `SLH_SHA2_256f` | Parameter sets for all 6 FIPS 205 SHA-2 variants |
| `ALL_SHA2_PARAMS` | Array of all SHA-2 parameter sets |
| `SLHParams`, `SLHKeyPair` | Types for SLH-DSA parameters and key pairs |

```typescript
import { wotsKeygen, wotsSign, wotsVerify, WOTS_PARAMS } from 'runar-testing';
import { slhKeygen, slhSign, slhVerify, SLH_SHA2_128s } from 'runar-testing';
```
