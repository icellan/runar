# Oracle Price Feed

A contract that uses a Rabin signature oracle to verify external data (a price feed) on-chain before releasing funds.

## What it does

Locks funds that can only be spent when an oracle-attested price exceeds a threshold. To settle the contract:

1. The oracle must have signed the price data with its Rabin private key.
2. The price must exceed the hardcoded threshold (50,000 in this example).
3. The designated receiver must also sign the transaction.

This pattern enables on-chain contracts to react to off-chain real-world data in a trust-minimized way.

## Design pattern

**Oracle-verified external data** -- uses Rabin signatures (a signature scheme efficient in Bitcoin Script) to verify that data was attested by a trusted oracle. The `verifyRabinSig()` function checks the oracle's signature over the price data. This is combined with standard `checkSig()` for receiver authorization, creating a two-factor spending condition: oracle attestation plus receiver consent.

## TSOP features demonstrated

- `RabinSig` and `RabinPubKey` types for oracle signature verification
- `verifyRabinSig()` for Rabin signature checking
- `num2bin()` for converting numeric values to byte strings
- Combining oracle verification with standard signature checks
- Threshold-based conditional logic

## Compile and use

```bash
tsop compile OraclePriceFeed.tsop.ts
```

Deploy with the oracle's Rabin public key and the receiver's public key. To spend, obtain a signed price from the oracle, then construct a transaction providing the price value, the Rabin signature, padding bytes, and the receiver's ECDSA signature.
