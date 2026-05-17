# Cross-Covenant Output Reference Pattern

## Problem

A covenant needs to verify data from another covenant's transaction output.
OP_PUSH_TX only introspects the *current* spending transaction. Reading
another transaction's output requires a different approach.

## Solution

Pass the referenced output data as a method parameter. The covenant verifies
authenticity by hashing it and comparing against a known script hash.

```
Unlocking Script (provided by the spender):
  [referencedOutput] [other args...] [method selector]

Covenant Logic:
  1. hash256(referencedOutput) === this.expectedScriptHash  // verify authenticity
  2. stateRoot = substr(referencedOutput, offset, 32)       // extract data
  3. ... use stateRoot in business logic ...
```

## How It Works

### Step 1: Store the expected script hash

The covenant stores the hash of the source covenant's output script at
construction time (as a `readonly` property):

```typescript
class BridgeCovenant extends StatefulSmartContract {
  readonly stateCovenantScriptHash: Sha256;
  // ...
}
```

### Step 2: Accept referenced output as a parameter

Public methods receive the serialized output data from the spender:

```typescript
public withdraw(
  referencedOutput: ByteString,   // from the state covenant's tx
  amount: bigint,
  recipient: ByteString,
) {
  // ...
}
```

### Step 3: Verify and extract

```typescript
// Verify the output came from the expected covenant
const outputHash = hash256(referencedOutput);
assert(outputHash === this.stateCovenantScriptHash);

// Extract the state root (at a known offset in the output script)
const stateRoot = substr(referencedOutput, stateRootOffset, 32n);
```

## Security Properties

- **Authenticity**: The hash comparison proves the output data matches the
  expected covenant script. An attacker cannot forge output data without
  finding a hash collision.

- **Freshness**: This pattern does NOT guarantee the referenced output is
  from the latest transaction. For freshness, combine with a block height
  check or a nonce/sequence number stored in the state.

- **No new opcodes**: Uses only existing Rúnar primitives (`hash256`,
  `substr`, `===`). No compiler changes needed.

## Limitations

- The spender must provide the referenced output data in the unlocking
  script. This increases transaction size.

- The covenant must know the offset where data is located within the
  referenced output script. This is determined by the source covenant's
  script structure.

- This verifies a *specific output script hash*, not a *specific UTXO*.
  Multiple UTXOs with the same script would all pass verification.

## Example

See `examples/ts/cross-covenant/CrossCovenantRef.runar.ts` for a complete
working example with tests.

## Use in BSV-EVM

The bridge covenant uses this pattern to read the state covenant's latest
state root:

1. State covenant advances with each L2 batch, storing `stateRoot` in its
   output script
2. Bridge covenant receives the state covenant's output as a parameter
3. Bridge verifies the output hash, extracts the state root, and uses it
   to verify Merkle proofs of L2 withdrawal data

---

## Built-in Intrinsics (Phase 13)

Three built-ins formalise the hand-rolled witness-bridge pattern shown
above. They emit the same Stack-IR shape (`hash256` + `equalverify` +
re-push) but free the contract author from the bookkeeping and centralise
the unsafe-stub vs safe-binding distinction in the compiler.

### `runar.ExtractPrevOutputScript(inputIndex: int, expectedScriptHash: ByteString) -> ByteString`

Reads the previous-output locking script of input `inputIndex` via the
witness-bridge pattern, asserts its `hash256` matches
`expectedScriptHash`, and returns the script bytes on the stack for
caller substring extraction.

```go
intentScript := runar.ExtractPrevOutputScript(1, c.IntentCovenantScriptHash)
bClaimed := runar.Bin2Num(runar.ReverseBytes(runar.Substr(intentScript, 65, 4)))
```

Compiler-enforced constraints:

- `inputIndex` MUST be a compile-time integer literal. Variable indices
  are rejected at typecheck. Each distinct literal index used in one
  method auto-injects one hidden witness parameter
  `_prevOutScript_<inputIndex>` of type `ByteString` — the unlocker
  supplies the script bytes; the compiler emits the hash assertion.
- `expectedScriptHash` may be any `ByteString` expression, typically a
  `readonly` contract field pinned at construction time.

Equivalent hand-rolled form (what the compiler emits in spirit):

```go
public func CoSpendPrivileged(
    stateCovScript runar.ByteString,  // ← compiler auto-injects this
    ... // user params
) {
    runar.Assert(runar.Hash256(stateCovScript) == c.ExpectedStateCovScriptHash)
    // intentScript is `stateCovScript`, available for substring use
}
```

### `runar.RequireOutputP2PKH(outputIndex: int, pubkeyHash: ByteString, amount: Bigint)`

Asserts the spending tx's output at `outputIndex` is a standard P2PKH
script paying exactly `amount` satoshis to `pubkeyHash`. Side-effecting;
no return value. Failure rejects the spend.

```go
runar.RequireOutputP2PKH(0, runar.Hash160(c.PkP), c.B)
```

The compiler emits a `hash256(serialisedOutputs) ==
ExtractHashOutputs(preimage)` witness-bridge check once per method body
(idempotent across multiple `RequireOutputP2PKH` calls), then a
substring assertion at the computed byte offset against the constructed
34-byte P2PKH output.

Compiler-enforced constraints:

- `outputIndex` MUST be a compile-time integer literal. Variable indices
  are rejected at typecheck.
- v1 assumes every output in the tx's serialised output set is exactly
  34 bytes (8-byte LE amount ‖ 0x19 length ‖ 25-byte P2PKH script). The
  byte offset of output `i` is `i * 34`. Methods that also call
  `c.AddDataOutput(...)` (OP_RETURN) in the same body are rejected at
  typecheck — the variable-length OP_RETURN breaks the fixed-offset
  assumption. If BSVM needs mixed output sets later, a v2 will accept a
  literal `precedingOutputSizes [...]int64` argument.
- The serialised-outputs witness is auto-injected as a hidden method
  parameter `_serialisedOutputs` of type `ByteString` — supplied by the
  unlocker once per method, regardless of how many `RequireOutputP2PKH`
  calls reference it.

### `runar.CurrentBlockHeight() -> Bigint`

Returns the spending tx's `nLockTime` interpreted as a BSV block height.
Pure source-level sugar for `runar.ExtractLocktime(this.TxPreimage)`;
emits identical Stack-IR. Only callable inside stateful contracts
(needs the auto-injected `txPreimage`).

```go
if runar.CurrentBlockHeight() > c.TOpen + windowSecs {
    // expired branch
}
```

### Witness-binding contract for SDK consumers

Every `ExtractPrevOutputScript(i, ...)` call extends the method's ABI
with one extra positional parameter `_prevOutScript_<i>`. Every method
containing one or more `RequireOutputP2PKH(...)` calls extends the ABI
with one extra positional parameter `_serialisedOutputs`. Both follow
the existing `_`-prefixed auto-injected-param convention (see
`packages/runar-sdk/src/contract.ts` `prepareCall` filter for
`_changePKH`, `_changeAmount`, etc.). SDK consumers must:

1. Identify these params by name when filtering user-facing args.
2. Source the witness values from caller-supplied maps —
   `prevOutScripts: map[int64]ByteString` (keyed by input index) and a
   single `serialisedOutputs: ByteString` — set on the `RunarContract`
   instance before `BuildCallTransaction`.

The artifact format is **not** extended: the witness binding is encoded
in the ABI's existing positional param list, distinguished by the
`_`-prefix naming convention.
