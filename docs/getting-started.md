# Getting Started with Rúnar

This guide walks you through installing Rúnar, writing your first Bitcoin SV smart contract, compiling it, testing it, and deploying it to testnet.

---

## Prerequisites

Before you begin, make sure you have the following installed:

| Tool | Minimum Version | Purpose |
|------|-----------------|---------|
| **Node.js** | 20.0.0+         | Runtime for the compiler and CLI |
| **pnpm** | 9.0.0+          | Package manager (workspace support required) |
| **Go** | 1.26+           | Only needed if you want to build/use the Go compiler |
| **Rust** | 1.75+           | Only needed if you want to build/use the Rust compiler |
| **Zig** | 0.15.x           | Only needed if you want to build/use the Zig compiler |

Verify your installations:

```bash
node --version   # v20.x.x or higher
pnpm --version   # 9.x.x or higher
go version       # go1.26.x or higher (optional)
zig version      # 0.15.x (optional)
```

---

## Installation

### From Source (Monorepo)

```bash
git clone https://github.com/icellan/runar.git
cd runar
pnpm install
pnpm build
```

This installs the pnpm workspace packages and builds the JavaScript/TypeScript workspace packages such as `runar-lang`, `runar-compiler`, `runar-cli`, `runar-sdk`, `runar-testing`, and `runar-ir-schema`.

If you also want the Zig tooling, build and test it from source:

```bash
cd packages/runar-zig && zig build test
cd ../../examples/zig && zig build test
cd ../../compilers/zig && zig build
```

### As npm Packages

If you only want to write and compile contracts without developing the toolchain itself:

```bash
pnpm add runar-lang runar-compiler runar-cli
```

- **runar-lang** -- Types and built-in function declarations you import in your contracts.
- **runar-compiler** -- The reference TypeScript-to-Bitcoin-Script compiler.
- **runar-cli** -- Command-line tool for compiling, testing, and deploying.

---

## Writing Your First Contract

Create a file named `P2PKH.runar.ts`. Rúnar contracts use the `.runar.ts` extension so they remain valid TypeScript files with full IDE support.

```typescript
import { SmartContract, assert, PubKey, Sig, Addr, hash160, checkSig } from 'runar-lang';

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

1. **Import from `runar-lang`**: Every contract imports `SmartContract` (the base class), `assert` (the spending condition enforcer), and the types and built-in functions it needs.

2. **Class extends `SmartContract`**: Rúnar contracts are classes. Exactly one class per file, and it must extend `SmartContract` directly.

3. **`readonly pubKeyHash: Addr`**: The `readonly` keyword marks this property as immutable. It is embedded in the locking script at deploy time. `Addr` is a 20-byte address type (the result of `hash160` on a public key).

4. **Constructor**: The constructor must call `super(...)` first, passing all properties in declaration order. Then it assigns each property with `this.x = x`. Properties with initializers (`= value`) are excluded from the constructor — see the [Language Reference](./language-reference.md) for details.

5. **`public unlock(...)`**: Public methods are spending entry points. When someone wants to spend the UTXO locked by this contract, they provide arguments to `unlock` in the unlocking script (scriptSig).

6. **`assert(hash160(pubKey) === this.pubKeyHash)`**: Verifies the provided public key hashes to the expected address. If the assertion fails, the transaction is invalid.

7. **`assert(checkSig(sig, pubKey))`**: Verifies the ECDSA signature against the public key. This is the final assertion -- its result is left on the stack as the script's success indicator.

This contract compiles to the standard P2PKH script: `OP_DUP OP_HASH160 <pubKeyHash> OP_EQUALVERIFY OP_CHECKSIG`.

---

## Compiling Your Contract

Use the CLI to compile:

```bash
runar compile P2PKH.runar.ts
```

This produces `artifacts/P2PKH.json`, a JSON artifact containing:

- **`script`** -- The compiled locking script as hex.
- **`asm`** -- Human-readable assembly (`OP_DUP OP_HASH160 <pubKeyHash> OP_EQUALVERIFY OP_CHECKSIG`).
- **`abi`** -- The constructor and public method signatures.
- **`stateFields`** -- Empty array for this stateless contract.

### Compiler Options

```bash
# Specify output directory
runar compile P2PKH.runar.ts --output ./build

# Include the ANF IR in the artifact (for debugging)
runar compile P2PKH.runar.ts --ir

# Print the assembly to stdout
runar compile P2PKH.runar.ts --asm
```

---

## Testing Your Contract

Create a test file `P2PKH.test.ts` using vitest:

```typescript
import { describe, it, expect } from 'vitest';
import { readFileSync } from 'fs';
import { TestContract } from 'runar-testing';

const source = readFileSync('P2PKH.runar.ts', 'utf8');

describe('P2PKH', () => {
  const pubKeyHash = '89abcdef01234567890abcdef01234567890abcd';
  const contract = TestContract.fromSource(source, { pubKeyHash });

  it('should unlock with valid signature and public key', () => {
    const validSig = '3044...'; // DER-encoded signature hex
    const validPubKey = '02abc...'; // 33-byte compressed pubkey hex

    const result = contract.call('unlock', { sig: validSig, pubKey: validPubKey });
    expect(result.success).toBe(true);
  });

  it('should reject an invalid signature', () => {
    const invalidSig = '3044...'; // wrong signature
    const validPubKey = '02abc...';

    const result = contract.call('unlock', { sig: invalidSig, pubKey: validPubKey });
    expect(result.success).toBe(false);
  });
});
```

Run tests:

```bash
runar test
# or directly with vitest:
pnpm test
```

The `TestContract` class compiles your contract source, then uses the interpreter (with mocked crypto) to execute methods and verify business logic.

---

## Deploying to Testnet

Once your contract compiles and passes tests, deploy it to the BSV testnet:

```bash
runar deploy ./artifacts/P2PKH.json --network testnet --key <your-WIF-private-key> --satoshis 10000
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
