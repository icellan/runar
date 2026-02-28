# Simple NFT (Non-Fungible Token)

A non-fungible token contract with unique identity, metadata, transfer, and burn capabilities.

## What it does

Represents a unique, non-fungible token identified by a `tokenId` and associated `metadata`. The token has a single owner who can:

- **Transfer** -- transfer ownership to a new public key, updating the on-chain state.
- **Burn** -- permanently destroy the token. No state continuation occurs, meaning the UTXO is consumed without producing a successor contract output.

## Design pattern

**Stateful NFT with burn path** -- the `owner` is mutable state updated via OP_PUSH_TX on transfer, while `tokenId` and `metadata` are immutable (`readonly`). The burn method intentionally omits state continuation, which effectively destroys the token by not propagating the contract to a new UTXO.

## TSOP features demonstrated

- `ByteString` type for arbitrary binary data (token ID, metadata)
- Immutable identity fields (`readonly tokenId`, `readonly metadata`)
- Stateful ownership tracking
- Burn pattern: a public method with no state continuation
- OP_PUSH_TX for enforced state transitions on transfer

## Compile and use

```bash
tsop compile NFTExample.tsop.ts
```

Deploy with an initial owner, a unique token ID, and a metadata hash or URI. Transfer works like the fungible token example. To burn, the owner simply signs without requiring a state-carrying output.
