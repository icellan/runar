# Stateful Counter

A simple counter contract that maintains mutable state across transactions using the OP_PUSH_TX pattern.

## What it does

Maintains an on-chain counter that can be incremented or decremented. Each call produces a new UTXO containing the updated count value.

- **Increment** -- increases the count by 1
- **Decrement** -- decreases the count by 1 (requires count > 0)

## Design pattern

**Stateful contract (OP_PUSH_TX)** -- the `count` property is non-`readonly`, making it mutable state. The contract uses `checkPreimage()` to verify the sighash preimage of the spending transaction, then asserts that the transaction output contains the updated contract state via `hash256(this.getStateScript()) === extractOutputHash(txPreimage)`. This enforces that the contract persists in the next UTXO with its updated state.

## TSOP features demonstrated

- Non-`readonly` properties as mutable contract state
- `checkPreimage()` for OP_PUSH_TX transaction introspection
- `this.getStateScript()` to serialize the updated contract
- `hash256()` and `extractOutputHash()` for output covenant enforcement
- BigInt literals (`0n`) for script-level numeric operations

## Compile and use

```bash
tsop compile Counter.tsop.ts
```

Deploy with an initial count value. To interact, construct a transaction whose output contains the contract with the updated count, then provide the sighash preimage as the method argument. The contract self-verifies that the output matches the expected next state.
