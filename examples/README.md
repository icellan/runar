# Rúnar Example Contracts

**A collection of example smart contracts demonstrating Rúnar patterns and features.**

Examples are organized by input format under `ts/`, `sol/`, `move/`, `go/`, and `rust/`. Each format directory contains parallel implementations of the same contracts, plus format-specific extras.

---

## Contract Index

Contracts available across all five formats (TypeScript, Solidity-like, Move-style, Go, Rust):

| Contract | Directory | Pattern | Complexity | Description |
|---|---|---|---|---|
| **P2PKH** | `*/p2pkh/` | Stateless | Beginner | Pay-to-Public-Key-Hash. The simplest possible contract: verify a signature against a hashed public key. |
| **Escrow** | `*/escrow/` | Stateless, Multi-method | Beginner | Three-party escrow with buyer, seller, and arbiter. Four spending paths: release by seller, release by arbiter, refund to buyer, and refund by arbiter. |
| **Counter** | `*/stateful-counter/` | Stateful (OP_PUSH_TX) | Intermediate | On-chain counter that persists across transactions. Uses `StatefulSmartContract` for automatic state management. |
| **Fungible Token** | `*/token-ft/` | Stateful, Token | Intermediate | Simple fungible token with transferable ownership. Owner signs to transfer; state tracks current owner. |
| **Non-Fungible Token** | `*/token-nft/` | Stateful, Token | Intermediate | NFT with transfer and burn operations. Immutable token ID and metadata, mutable owner. |
| **Oracle Price Feed** | `*/oracle-price/` | Oracle (Rabin) | Advanced | Contract that settles based on an oracle-signed price. Uses Rabin signatures for cheap on-chain verification. |
| **Auction** | `*/auction/` | Stateful, Multi-method | Advanced | On-chain auction with bidding and closing phases. Tracks highest bidder and bid amount. Enforces deadline via locktime. |
| **Covenant Vault** | `*/covenant-vault/` | Covenant | Advanced | Vault that restricts spending with covenant rules. Owner must authorize, and the output amount must exceed a minimum. |
| **Math Demo** | `*/math-demo/` | Stateful (OP_PUSH_TX) | Beginner | Demonstrates built-in math functions (abs, min, max, sqrt, pow, etc.). |

Contracts available in TypeScript, Go, and Rust only:

| Contract | Directory | Pattern | Complexity | Description |
|---|---|---|---|---|
| **Function Patterns** | `{ts,go,rust}/function-patterns/` | Stateful (OP_PUSH_TX) | Intermediate | Demonstrates private helper methods and function call patterns. |

TypeScript-only contracts (post-quantum):

| Contract | Directory | Pattern | Complexity | Description |
|---|---|---|---|---|
| **Post-Quantum Wallet** | `ts/post-quantum-wallet/` | Stateless, PQ | Advanced | WOTS+ (Winternitz One-Time Signature) wallet for post-quantum security. |
| **SPHINCS+ Wallet** | `ts/sphincs-wallet/` | Stateless, PQ | Advanced | SLH-DSA-SHA2-128s (SPHINCS+) wallet for stateless post-quantum signatures. |

---

## How to Compile Examples

### Single Contract

```bash
runar compile examples/ts/p2pkh/P2PKH.runar.ts --outdir artifacts/
```

### All TypeScript Contracts

```bash
runar compile examples/ts/**/*.runar.ts --outdir artifacts/
```

---

## How to Test Examples

### TypeScript (vitest)

Each TypeScript example can be tested using `TestContract` from `runar-testing`:

```typescript
import { TestContract } from 'runar-testing';
import { readFileSync } from 'node:fs';

const source = readFileSync('P2PKH.runar.ts', 'utf8');

describe('P2PKH', () => {
  it('should accept valid signature', () => {
    const PUBKEY = '02' + 'ab'.repeat(32);
    const PUBKEY_HASH = 'ab'.repeat(20);
    const SIG = '30' + 'ff'.repeat(35);

    const contract = TestContract.fromSource(source, { pubKeyHash: PUBKEY_HASH });
    const result = contract.call('unlock', { sig: SIG, pubKey: PUBKEY });
    expect(typeof result.success).toBe('boolean');
  });
});
```

Stateful contracts track state across calls:

```typescript
const source = readFileSync('Counter.runar.ts', 'utf8');
const counter = TestContract.fromSource(source, { count: 0n });

counter.call('increment');
expect(counter.state.count).toBe(1n);
```

Run all TypeScript tests:

```bash
npx vitest run
```

### Go (go test)

Go examples are tested as native Go code with `runar.CompileCheck` for Runar validation:

```bash
cd examples/go && go test ./...
```

### Rust (cargo test)

Rust examples are tested as native Rust code with `runar::compile_check` for Runar validation:

```bash
cd examples/rust && cargo test
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

Start with `p2pkh/`, `escrow/`, and `math-demo/`. These contracts have straightforward spending conditions (`p2pkh/` and `escrow/` are stateless; `math-demo/` is stateful but focuses on demonstrating builtins). They demonstrate:

- Basic contract structure (`SmartContract`, constructor, public methods)
- `readonly` properties
- `assert`, `checkSig`, `hash160`
- Multiple public methods (escrow has `releaseBySeller`, `releaseByArbiter`, `refundToBuyer`, and `refundByArbiter`)
- Built-in math functions (`abs`, `min`, `max`, `sqrt`, `pow`, etc.)

### Intermediate

Move to `stateful-counter/`, `token-ft/`, `token-nft/`, and `function-patterns/`. These add state management and code organization:

- `StatefulSmartContract` for automatic preimage verification and state continuation
- Mutable properties for on-chain state
- `this.txPreimage` for accessing preimage fields (e.g. `extractLocktime`)
- State chaining across transactions
- Private helper methods

### Advanced

Tackle `oracle-price/`, `auction/`, `covenant-vault/`, `post-quantum-wallet/`, and `sphincs-wallet/`. These combine multiple patterns:

- Rabin signature verification for oracle data
- Locktime-based deadlines
- Covenant rules constraining transaction outputs
- Complex state transitions with multiple spending paths
- WOTS+ one-time post-quantum signatures
- SLH-DSA (SPHINCS+) stateless post-quantum signatures
