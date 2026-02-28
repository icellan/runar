# Getting Started with TSOP

This guide walks you through installing TSOP, writing your first Bitcoin SV smart contract, compiling it, testing it, and deploying it to testnet.

---

## Prerequisites

Before you begin, make sure you have the following installed:

| Tool | Minimum Version | Purpose |
|------|----------------|---------|
| **Node.js** | 22.0.0+ | Runtime for the compiler and CLI |
| **pnpm** | 9.0.0+ | Package manager (workspace support required) |
| **Go** | 1.22+ | Only needed if you want to build/use the Go compiler |
| **Rust** | 1.75+ | Only needed if you want to build/use the Rust compiler |

Verify your installations:

```bash
node --version   # v22.x.x or higher
pnpm --version   # 9.x.x or higher
go version       # go1.22.x or higher (optional)
```

---

## Installation

### From Source (Monorepo)

```bash
git clone https://github.com/example/tsop.git
cd tsop
pnpm install
pnpm build
```

This builds all packages in the workspace: `tsop-lang`, `tsop-compiler`, `tsop-cli`, `tsop-sdk`, `tsop-testing`, and `tsop-ir-schema`.

### As npm Packages

If you only want to write and compile contracts without developing the toolchain itself:

```bash
pnpm add tsop-lang tsop-compiler tsop-cli
```

- **tsop-lang** -- Types and built-in function declarations you import in your contracts.
- **tsop-compiler** -- The reference TypeScript-to-Bitcoin-Script compiler.
- **tsop-cli** -- Command-line tool for compiling, testing, and deploying.

---

## Writing Your First Contract

Create a file named `P2PKH.tsop.ts`. TSOP contracts use the `.tsop.ts` extension so they remain valid TypeScript files with full IDE support.

```typescript
import { SmartContract, assert, PubKey, Sig, Addr, hash160, checkSig } from 'tsop-lang';

class P2PKH extends SmartContract {
  readonly pubKeyHash: Addr;

  constructor(pubKeyHash: Addr) {
    super(pubKeyHash);
    this.pubKeyHash = pubKeyHash;
  }

  public unlock(sig: Sig, pubKey: PubKey) {
    assert(hash160(pubKey) === this.pubKeyHash);
    assert(checkSig(sig, pubKey));
  }
}
```

### Step-by-Step Explanation

1. **Import from `tsop-lang`**: Every contract imports `SmartContract` (the base class), `assert` (the spending condition enforcer), and the types and built-in functions it needs.

2. **Class extends `SmartContract`**: TSOP contracts are classes. Exactly one class per file, and it must extend `SmartContract` directly.

3. **`readonly pubKeyHash: Addr`**: The `readonly` keyword marks this property as immutable. It is embedded in the locking script at deploy time. `Addr` is a 20-byte address type (the result of `hash160` on a public key).

4. **Constructor**: The constructor must call `super(...)` first, passing all properties in declaration order. Then it assigns each property with `this.x = x`.

5. **`public unlock(...)`**: Public methods are spending entry points. When someone wants to spend the UTXO locked by this contract, they provide arguments to `unlock` in the unlocking script (scriptSig).

6. **`assert(hash160(pubKey) === this.pubKeyHash)`**: Verifies the provided public key hashes to the expected address. If the assertion fails, the transaction is invalid.

7. **`assert(checkSig(sig, pubKey))`**: Verifies the ECDSA signature against the public key. This is the final assertion -- its result is left on the stack as the script's success indicator.

This contract compiles to the standard P2PKH script: `OP_DUP OP_HASH160 <pubKeyHash> OP_EQUALVERIFY OP_CHECKSIG`.

---

## Compiling Your Contract

Use the CLI to compile:

```bash
tsop compile P2PKH.tsop.ts
```

This produces `artifacts/P2PKH.json`, a JSON artifact containing:

- **`script`** -- The compiled locking script as hex.
- **`asm`** -- Human-readable assembly (`OP_DUP OP_HASH160 <pubKeyHash> OP_EQUALVERIFY OP_CHECKSIG`).
- **`abi`** -- The constructor and public method signatures.
- **`stateFields`** -- Empty array for this stateless contract.

### Compiler Options

```bash
# Specify output directory
tsop compile P2PKH.tsop.ts --output ./build

# Include the ANF IR in the artifact (for debugging)
tsop compile P2PKH.tsop.ts --ir

# Print the assembly to stdout
tsop compile P2PKH.tsop.ts --asm
```

---

## Testing Your Contract

Create a test file `P2PKH.test.ts` using vitest:

```typescript
import { describe, it, expect } from 'vitest';
import { TestSmartContract, expectScriptSuccess, expectScriptFailure } from 'tsop-testing';
import artifact from './artifacts/P2PKH.json';

describe('P2PKH', () => {
  const pubKeyHash = '89abcdef01234567890abcdef01234567890abcd';
  const contract = TestSmartContract.fromArtifact(artifact, [pubKeyHash]);

  it('should unlock with valid signature and public key', () => {
    const validSig = '3044...'; // DER-encoded signature hex
    const validPubKey = '02abc...'; // 33-byte compressed pubkey hex

    const result = contract.call('unlock', [validSig, validPubKey]);
    expectScriptSuccess(result);
  });

  it('should reject an invalid signature', () => {
    const invalidSig = '3044...'; // wrong signature
    const validPubKey = '02abc...';

    const result = contract.call('unlock', [invalidSig, validPubKey]);
    expectScriptFailure(result);
  });
});
```

Run tests:

```bash
tsop test
# or directly with vitest:
pnpm test
```

The `TestSmartContract` class loads your compiled artifact, builds unlocking scripts from the arguments you provide, and executes them against the locking script in TSOP's built-in Script VM.

---

## Deploying to Testnet

Once your contract compiles and passes tests, deploy it to the BSV testnet:

```bash
tsop deploy ./artifacts/P2PKH.json --network testnet --key <your-WIF-private-key> --satoshis 10000
```

This will:

1. Load the compiled artifact.
2. Connect to WhatsOnChain as the blockchain provider.
3. Create and sign a transaction that funds a UTXO with your contract's locking script.
4. Broadcast the transaction to testnet.
5. Print the transaction ID.

```
Deploying contract: P2PKH
  Network: testnet
  Satoshis: 10000
  Deployer address: mxyz...

Broadcasting...

Deployment successful!
  TXID: abc123def456...
  Explorer: https://whatsonchain.com/tx/abc123def456...
```

You need a testnet WIF private key with funded UTXOs. You can get testnet coins from a BSV testnet faucet.

---

## Next Steps

- Read the [Language Reference](./language-reference.md) for the complete set of types, operators, and built-in functions.
- Explore [Contract Patterns](./contract-patterns.md) for examples of escrow, stateful counters, tokens, oracles, and covenants.
- See the [Testing Guide](./testing-guide.md) for advanced testing techniques including property-based fuzzing.
- Review the [Compiler Architecture](./compiler-architecture.md) if you want to understand or contribute to the compiler.
- Check the [API Reference](./api-reference.md) for SDK and CLI documentation.
