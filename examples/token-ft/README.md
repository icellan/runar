# Simple Fungible Token

A basic fungible token contract demonstrating ownership transfer with stateful on-chain tracking.

## What it does

Represents a fungible token with a fixed supply and a transferable owner. The current owner can transfer ownership to a new public key, and the contract state is updated on-chain.

- **Transfer** -- the current owner signs to transfer the token to a new owner. The contract state is updated in the output UTXO.

## Design pattern

**Stateful ownership transfer** -- combines signature-based authorization (`checkSig`) with the OP_PUSH_TX pattern to enforce state transitions. The `owner` field is mutable (non-`readonly`), while `supply` is immutable (`readonly`). Each transfer produces a new UTXO with the updated owner.

## TSOP features demonstrated

- Mix of `readonly` (immutable) and mutable (stateful) properties
- Owner-authorized state transitions via `checkSig()`
- OP_PUSH_TX pattern for state continuity
- `this.getStateScript()` for serializing updated contract state

## Compile and use

```bash
tsop compile FungibleTokenExample.tsop.ts
```

Deploy with an initial owner public key and a supply value. To transfer, the current owner signs the transaction and specifies the new owner's public key. The spending transaction must contain an output with the updated contract state.
