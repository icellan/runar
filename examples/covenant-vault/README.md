# Covenant Vault

A covenant contract that enforces spending rules on transaction outputs, restricting how funds can be spent.

## What it does

Locks funds in a vault with enforced spending constraints. The owner can authorize spending, but the contract imposes a minimum output amount rule via transaction introspection.

- **Spend** -- the owner signs to authorize a spend, but the transaction must satisfy the covenant rule: the output amount must be at least `minAmount`.

This pattern is useful for implementing withdrawal limits, enforced savings, or rate-limited spending.

## Design pattern

**Covenant (output restriction)** -- uses `checkPreimage()` to introspect the spending transaction and enforce constraints on its outputs. Unlike simple signature-based contracts, a covenant examines the transaction itself to restrict where and how funds flow. The `readonly` properties define the immutable spending rules that persist for the lifetime of the contract.

## TSOP features demonstrated

- Transaction introspection via `checkPreimage()`
- Covenant-style output enforcement
- Combining signature authorization with structural transaction constraints
- `Addr` type for recipient addresses
- `readonly` properties as immutable covenant rules

## Compile and use

```bash
tsop compile CovenantVault.tsop.ts
```

Deploy with the owner's public key, a recipient address, and a minimum amount. To spend, the owner constructs a transaction that satisfies the minimum amount constraint and provides their signature along with the sighash preimage.
