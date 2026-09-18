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

- This verifies a *specific output script hash*, not a *specific UTXO*, and not
  even that any UTXO with that script is being spent by this transaction. All it
  proves is that the spender could produce bytes with that hash — and locking
  scripts are public, so that is free. Multiple UTXOs with the same script would
  all pass verification, and so would a transaction spending none of them.

## Example

See `examples/ts/cross-covenant/CrossCovenantRef.runar.ts` for a complete
working example with tests.

For the stronger form — verifying attributes of a *specific companion input*
of the current transaction by parsing its parent tx (hash-bound to the
spending tx via the BIP-143 preimage), with contract identity proven by a
slot-excised *template* hash instead of an exact script hash — see the
"Verified Companion Inputs" example pair in
`examples/ts/companion-verifier/` (`AttributedToken.runar.ts` +
`CompanionVerifier.runar.ts`). It addresses the third limitation above:
the parent tx binds a specific UTXO, not just a script shape, and
per-instance attribute values survive the identity check.

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

### `runar.ExtractPrevOutputScript(witnessSlot: int, expectedScriptHash: ByteString) -> ByteString`

Asserts that a caller-supplied byte string hashes to `expectedScriptHash` and
returns it on the stack for substring extraction. It is the hand-rolled
witness-bridge pattern above, packaged.

> **It does NOT read an input of the spending transaction (W6 / GhostInput).**
> The first argument is a compile-time LABEL used to name the hidden witness
> parameter `_prevOutScript_<witnessSlot>`, nothing more. The emitted script is
> `OP_HASH256 OP_EQUALVERIFY` over that witness: no vin lookup, no parent
> transaction, no outpoint comparison, no input-count check. A transaction with
> a SINGLE input satisfies a covenant calling `ExtractPrevOutputScript(1, ...)`,
> because nothing ever looks for a second input. And because locking scripts are
> public, "the spender knows these bytes" costs an attacker nothing. Use it for
> intent-TEMPLATE matching; never as evidence that a companion covenant is being
> spent alongside you. For that, see
> the "Verified Companion Inputs" pointer above — `examples/ts/companion-verifier/` — which
> binds a specific UTXO by parsing the companion input's parent transaction.
>
> **v1 decision.** The primitive keeps its behaviour and its name; what changed
> is every sentence that oversold it. Making it actually bind `vin[i]` means
> parsing the authenticated current transaction, selecting the input, fetching
> and hashing its parent tx, matching the outpoint txid, bounds-checking vout
> and extracting that output's script — a v2-sized change, and one this repo
> already ships as a hand-written, tested pattern in `companion-verifier`.
> Renaming the symbol at v1 would break every downstream caller and every
> surface parser without changing the emitted script by one byte.

```go
intentScript := runar.ExtractPrevOutputScript(1, c.IntentCovenantScriptHash)
bClaimed := runar.Bin2Num(runar.ReverseBytes(runar.Substr(intentScript, 65, 4)))
```

Compiler-enforced constraints:

- `witnessSlot` MUST be a compile-time integer literal. Variable indices
  are rejected at typecheck. Each distinct literal used in one
  method auto-injects one hidden witness parameter
  `_prevOutScript_<witnessSlot>` of type `ByteString` — the unlocker
  supplies the bytes; the compiler emits the hash assertion.
- `expectedScriptHash` may be any `ByteString` expression, typically a
  `readonly` contract field pinned at construction time.

Equivalent hand-rolled form (what the compiler emits, in full — there is
nothing else):

```go
public func WitnessMatchingHash(
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
- **`outputIndex` MUST be `0` in v1.** The byte offset of output `i` is
  `i * 34`, which is that output's START only if every earlier output is
  exactly 34 bytes — and a transaction guarantees no such thing. An
  output is `value[8] ‖ CompactSize(len) ‖ script[len]`, and the spender
  picks output 0's length: for `i = 1` an attacker builds output 0 as a
  78-byte OP_RETURN carrying the promised 34 P2PKH bytes at global offset
  34, and points the transaction's real output 1 at themselves. The
  witness still hashes to `hashOutputs` — it IS the real output set — so
  the assertion passes and the payment is not made (W2). Offset 0 is a
  genuine boundary, so index 0 is sound. Asserting a later output needs a
  CompactSize walk from byte 0, which the v1 codegen does not emit.
- The same 34-byte assumption is why methods that also call
  `c.AddDataOutput(...)` (OP_RETURN), `c.AddOutput(...)` or
  `c.AddRawOutput(...)` in the same body are rejected at typecheck
  (R-300). That is a ban on the CONTRACT's own outputs and was never a
  constraint on the transaction an attacker builds, which is what the
  index rule above adds. If BSVM needs mixed output sets later, a v2 will
  parse the CompactSize chain on chain.
- The serialised-outputs witness is auto-injected as a hidden method
  parameter `_serialisedOutputs` of type `ByteString` — supplied by the
  unlocker once per method, regardless of how many `RequireOutputP2PKH`
  calls reference it.

### `runar.CurrentBlockHeight() -> Bigint`

Returns the spending tx's `nLockTime`. Pure source-level sugar for
`runar.ExtractLocktime(this.TxPreimage)`; emits identical Stack-IR. Only
callable inside stateful contracts (needs the auto-injected `txPreimage`).

**The name is misleading and kept only for source compatibility: this is not
the chain height.** `nLockTime` is written by the spender and enforced by
consensus as a NOT-BEFORE, and only on a non-final transaction. So the
comparison below is sound — the spend cannot confirm before `TOpen +
windowSecs` — provided the covenant also asserts
`runar.ExtractSequence(c.TxPreimage) != 4294967295`, without which consensus
ignores `nLockTime` altogether. The reverse comparison (`<`, "still inside the
window") proves nothing at all: a spender past the window writes a stale
locktime and the node mines it.

```go
if runar.CurrentBlockHeight() > c.TOpen + windowSecs {
    // expired branch — sound only alongside the ExtractSequence finality guard
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
