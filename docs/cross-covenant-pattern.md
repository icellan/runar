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
