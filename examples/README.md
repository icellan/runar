# Rúnar Example Contracts

**A collection of example smart contracts demonstrating Rúnar patterns and features.**

Each example is a self-contained directory with a `.runar.ts` source file and its own README explaining the contract's logic.

---

## Contract Index

| Contract | Directory | Pattern | Complexity | Description |
|---|---|---|---|---|
| **P2PKH** | `p2pkh/` | Stateless | Beginner | Pay-to-Public-Key-Hash. The simplest possible contract: verify a signature against a hashed public key. |
| **Escrow** | `escrow/` | Stateless, Multi-method | Beginner | Three-party escrow with buyer, seller, and arbiter. Two spending paths: release to seller or refund to buyer. |
| **Counter** | `stateful-counter/` | Stateful (OP_PUSH_TX) | Intermediate | On-chain counter that persists across transactions. Uses `StatefulSmartContract` for automatic state management. |
| **Fungible Token** | `token-ft/` | Stateful, Token | Intermediate | Simple fungible token with transferable ownership. Owner signs to transfer; state tracks current owner. |
| **Non-Fungible Token** | `token-nft/` | Stateful, Token | Intermediate | NFT with transfer and burn operations. Immutable token ID and metadata, mutable owner. |
| **Oracle Price Feed** | `oracle-price/` | Oracle (Rabin) | Advanced | Contract that settles based on an oracle-signed price. Uses Rabin signatures for cheap on-chain verification. |
| **Auction** | `auction/` | Stateful, Multi-method | Advanced | On-chain auction with bidding and closing phases. Tracks highest bidder and bid amount. Enforces deadline via locktime. |
| **Covenant Vault** | `covenant-vault/` | Covenant | Advanced | Vault that restricts spending with covenant rules. Owner must authorize, and the output amount must exceed a minimum. |

---

## How to Compile Examples

### Single Contract

```bash
runar compile examples/p2pkh/P2PKH.runar.ts --outdir artifacts/
```

### All Contracts

```bash
runar compile examples/**/*.runar.ts --outdir artifacts/
```

---

## How to Test Examples

Each example can be tested using the `runar-testing` helpers:

```typescript
import { TestSmartContract, PubKey, Sig, Addr } from 'runar-testing';

describe('P2PKH', () => {
  it('should accept valid signature', () => {
    const contract = new TestSmartContract('P2PKH', {
      properties: { pubKeyHash: Addr('89abcdef0123456789abcdef0123456789abcdef') },
    });

    const result = contract.call('unlock', {
      sig: Sig('3044022055...'),
      pubKey: PubKey('02abc...'),
    });

    expect(result.success).toBe(true);
  });
});
```

Run tests:

```bash
runar test
```

---

## How to Deploy Examples to Testnet

1. Get testnet coins from a BSV faucet.

2. Deploy:

```bash
runar deploy ./artifacts/P2PKH.json \
  --network testnet \
  --key <your-testnet-WIF> \
  --satoshis 10000 \
  --params '{"pubKeyHash": "89abcdef0123456789abcdef0123456789abcdef"}'
```

3. Verify the deployment:

```bash
runar verify <txid> --artifact ./artifacts/P2PKH.json --network testnet
```

---

## Complexity Guide

### Beginner

Start with `p2pkh/` and `escrow/`. These are stateless contracts with straightforward spending conditions. They demonstrate:

- Basic contract structure (`SmartContract`, constructor, public methods)
- `readonly` properties
- `assert`, `checkSig`, `hash160`
- Multiple public methods (escrow has `release` and `refund`)

### Intermediate

Move to `stateful-counter/`, `token-ft/`, and `token-nft/`. These add state management:

- `StatefulSmartContract` for automatic preimage verification and state continuation
- Mutable properties for on-chain state
- `this.txPreimage` for accessing preimage fields (e.g. `extractLocktime`)
- State chaining across transactions

### Advanced

Tackle `oracle-price/`, `auction/`, and `covenant-vault/`. These combine multiple patterns:

- Rabin signature verification for oracle data
- Locktime-based deadlines
- Covenant rules constraining transaction outputs
- Complex state transitions with multiple spending paths
