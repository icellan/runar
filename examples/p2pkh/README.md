# P2PKH (Pay-to-Public-Key-Hash)

The simplest and most fundamental Bitcoin smart contract. This is the standard spending condition used in most Bitcoin transactions.

## What it does

Locks funds to a public key hash (an address). To spend the funds, the spender must provide:

1. A valid signature (`sig`)
2. The public key (`pubKey`) whose hash matches the stored `pubKeyHash`

The contract verifies that `hash160(pubKey)` equals the stored address, then checks the signature against that public key.

## Design pattern

**Stateless contract** -- all properties are `readonly`. There is no state to carry forward; once the conditions are met, the funds are released.

## TSOP features demonstrated

- `readonly` properties for immutable contract parameters
- `hash160()` for public key hashing (SHA-256 followed by RIPEMD-160)
- `checkSig()` for ECDSA signature verification
- `assert()` for enforcing spending conditions

## Compile and use

```bash
tsop compile P2PKH.tsop.ts
```

This produces a Bitcoin Script locking script equivalent to:

```
OP_DUP OP_HASH160 <pubKeyHash> OP_EQUALVERIFY OP_CHECKSIG
```

To deploy, create a transaction with this script as the output. To spend, provide the signature and public key as the unlocking script.
