# Escrow

A multi-party escrow contract involving three participants: a buyer, a seller, and an arbiter.

## What it does

Funds are locked in escrow and can be released in two ways:

- **Release** -- sends funds to the seller. Can be authorized by either the seller or the arbiter.
- **Refund** -- returns funds to the buyer. Can be authorized by either the buyer or the arbiter.

The arbiter acts as a trusted third party who can resolve disputes by authorizing either a release or a refund.

## Design pattern

**Stateless multi-method contract** -- each `public` method represents a distinct spending path compiled into the script. The contract uses `readonly` properties only, meaning no state is carried forward between transactions.

## TSOP features demonstrated

- Multiple `public` methods as separate spending paths
- Logical OR (`||`) conditions in assertions
- Three-party authorization logic
- `checkSig()` for per-party signature verification

## Compile and use

```bash
tsop compile Escrow.tsop.ts
```

Deploy by creating a transaction output with the compiled script, passing the three public keys as constructor arguments. To spend, invoke either the `release` or `refund` method with a valid signature from an authorized party.
