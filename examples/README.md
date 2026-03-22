# Rúnar Example Contracts

**A collection of example smart contracts demonstrating Rúnar patterns and features.**

Examples are organized by input format under `ts/`, `sol/`, `move/`, `go/`, `rust/`, `python/`, and `zig/`. Each directory contains the contract sources for that frontend, and the native-language frontends share the same 21-contract example set with adjacent native tests.

---

## Contract Index

Contracts available across the native-language frontends (`ts/`, `go/`, `rust/`, `python/`, `zig/`):

| Contract | Directory | Pattern | Complexity | Description |
|---|---|---|---|---|
| **P2PKH** | `*/p2pkh/` | Stateless | Beginner | Pay-to-Public-Key-Hash. The simplest possible contract: verify a signature against a hashed public key. |
| **Escrow** | `*/escrow/` | Stateless, Multi-method | Beginner | Three-party escrow with buyer, seller, and arbiter. Four spending paths: release by seller, release by arbiter, refund to buyer, and refund by arbiter. |
| **Counter** | `*/stateful-counter/` | Stateful (OP_PUSH_TX) | Intermediate | On-chain counter that persists across transactions. Uses `StatefulSmartContract` for automatic state management. |
| **Fungible Token** | `*/token-ft/` | Stateful, Token | Intermediate | Fungible token with UTXO splitting and merging. Three spending paths: transfer/split (1 input to 2 outputs), send (full balance transfer), and merge (N inputs to 1 output). State tracks owner and balance. |
| **Non-Fungible Token** | `*/token-nft/` | Stateful, Token | Intermediate | NFT with transfer and burn operations. Immutable token ID and metadata, mutable owner. |
| **Oracle Price Feed** | `*/oracle-price/` | Oracle (Rabin) | Advanced | Contract that settles based on an oracle-signed price. Uses Rabin signatures for cheap on-chain verification. |
| **Auction** | `*/auction/` | Stateful, Multi-method | Advanced | On-chain auction with bidding and closing phases. Tracks highest bidder and bid amount. Enforces deadline via locktime. |
| **Covenant Vault** | `*/covenant-vault/` | Covenant | Advanced | Vault that restricts spending with covenant rules. Owner must authorize, and the output amount must exceed a minimum. |
| **Math Demo** | `*/math-demo/` | Stateful (OP_PUSH_TX) | Beginner | Demonstrates built-in math functions (abs, min, max, sqrt, pow, etc.). |
| **EC Demo** | `*/ec-demo/` | Stateless, EC | Intermediate | Demonstrates EC point operations (ecAdd, ecMul, ecMulGen, etc.). |
| **Property Initializers** | `*/property-initializers/` | Stateful (OP_PUSH_TX) | Beginner | Demonstrates default values on contract properties. |
| **Function Patterns** | `{ts,go,rust,python,zig}/function-patterns/` | Stateful (OP_PUSH_TX) | Intermediate | Demonstrates private helper methods and function call patterns. |
| **Post-Quantum Wallet** | `{ts,go,rust,python,zig}/post-quantum-wallet/` | Stateless, PQ | Advanced | WOTS+ (Winternitz One-Time Signature) wallet for post-quantum security. |
| **SPHINCS+ Wallet** | `{ts,go,rust,python,zig}/sphincs-wallet/` | Stateless, PQ | Advanced | SLH-DSA-SHA2-128s (SPHINCS+) wallet for stateless post-quantum signatures. |
| **SchnorrZKP** | `{ts,go,rust,python,zig}/schnorr-zkp/` | Stateless, EC | Advanced | Schnorr zero-knowledge proof using EC point operations. |
| **Convergence Proof** | `{ts,go,rust,python,zig}/convergence-proof/` | Stateless | Advanced | Demonstrates convergence proof patterns. |
| **P2Blake3PKH** | `{ts,go,rust,python,zig}/p2blake3pkh/` | Stateless, BLAKE3 | Intermediate | Pay-to-public-key-hash variant using BLAKE3 instead of HASH160. |
| **Tic-Tac-Toe** | `{ts,go,rust,python,zig}/tic-tac-toe/` | Stateful game | Advanced | Two-player stateful game with turn tracking and board validation. |
| **BLAKE3 Test** | `{ts,go,rust,python,zig}/blake3/` | Stateless, BLAKE3 | Intermediate | Exercises `blake3Compress` and `blake3` codegen. |
| **SHA-256 Compress** | `{ts,go,rust,python,zig}/sha256-compress/` | Stateless, SHA-256 | Intermediate | Exercises the SHA-256 compression builtin directly. |
| **SHA-256 Finalize** | `{ts,go,rust,python,zig}/sha256-finalize/` | Stateless, SHA-256 | Intermediate | Exercises the SHA-256 finalize builtin directly. |

The Solidity-like and Move-style example trees currently cover a 16-contract subset: `auction`, `blake3`, `covenant-vault`, `ec-demo`, `escrow`, `math-demo`, `oracle-price`, `p2blake3pkh`, `p2pkh`, `property-initializers`, `sha256-compress`, `sha256-finalize`, `stateful-counter`, `tic-tac-toe`, `token-ft`, and `token-nft`.

---

## SDK Usage Reference

The `sdk-usage/` directory contains reference code snippets (not runnable) showing how to use the deployment SDK in TypeScript, Go, and Rust:

- `sdk-usage-typescript.ts` — TypeScript SDK usage patterns
- `sdk-usage-go.go` — Go SDK usage patterns
- `sdk-usage-rust.rs` — Rust SDK usage patterns

These are documentation files showing common SDK patterns (deploy, call, state management). They are not executable contracts.

---

## How to Compile Examples

### Single Contract

```bash
runar compile examples/ts/p2pkh/P2PKH.runar.ts --output artifacts/
```

### All TypeScript Contracts

```bash
runar compile examples/ts/**/*.runar.ts --output artifacts/
```

### Single Zig Contract

```bash
cd compilers/zig
zig build run -- compile ../../examples/zig/p2pkh/P2PKH.runar.zig
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

### Python (pytest)

Python examples are tested as native Python code with mock types from the `runar` package:

```bash
cd examples/python && PYTHONPATH=../../packages/runar-py python3 -m pytest
```

### Zig

Run the native Zig example suite:

```bash
cd examples/zig && zig build test
```

The Zig example runner imports `packages/runar-zig` as the `runar` module and executes the adjacent `*_test.zig` files under each example directory. Today that suite mixes compile checks, direct contract execution on the simpler examples, and helper/runtime-backed tests while the more complex Zig-native execution model continues to mature.

Compile a Zig example through the Zig compiler:

```bash
cd compilers/zig && zig build run -- compile ../../examples/zig/p2pkh/P2PKH.runar.zig
```

Run the Zig compiler verification suite:

```bash
cd compilers/zig && zig build test && zig build conformance
```

---

## How to Deploy Examples to Testnet

1. Get testnet coins from a BSV faucet.

2. Deploy:

```bash
runar deploy ./artifacts/P2PKH.json \
  --network testnet \
  --key <your-testnet-WIF> \
  --satoshis 10000
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
