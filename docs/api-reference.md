# API Reference

This document covers the Rúnar CLI commands and the SDK classes for deploying, calling, and managing smart contracts programmatically.

---

## CLI Commands

The Rúnar CLI is provided by the `runar-cli` package. Install it globally or use via `npx`:

```bash
npx runar <command> [options]
```

### `runar init`

Initialize a new Rúnar project in the current directory.

```bash
runar init [project-name]
```

Creates a project scaffold with:
- `package.json` with Rúnar dependencies
- `tsconfig.json` configured for Rúnar
- `contracts/` directory with a sample contract
- `tests/` directory with a sample test
- `artifacts/` directory (gitignored)

### `runar compile`

Compile one or more Rúnar contract source files into artifact JSON.

```bash
runar compile <files...> [options]
```

**Options:**

| Flag | Default | Description |
|------|---------|-------------|
| `--output <dir>` | `./artifacts` | Output directory for compiled artifacts |
| `--ir` | `false` | Include the ANF IR in the artifact (for debugging) |
| `--asm` | `false` | Print the human-readable assembly to stdout |

**Example:**

```bash
runar compile contracts/P2PKH.runar.ts --output ./build --asm

# Output:
# Compiling: /path/to/contracts/P2PKH.runar.ts
#   Artifact written: /path/to/build/P2PKH.json
#
#   ASM (P2PKH):
#   OP_DUP OP_HASH160 <pubKeyHash> OP_EQUALVERIFY OP_CHECKSIG
```

### `runar test`

Run the project's test suite using vitest.

```bash
runar test [options]
```

Discovers and runs all `*.test.ts` files in the project. Under the hood this invokes vitest with Rúnar-appropriate configuration.

### `runar deploy`

Deploy a compiled contract to the BSV blockchain.

```bash
runar deploy <artifact-path> [options]
```

**Options:**

| Flag | Required | Description |
|------|----------|-------------|
| `--network <net>` | Yes | `mainnet` or `testnet` |
| `--key <wif>` | Yes | WIF-encoded private key for funding the deployment |
| `--satoshis <n>` | No (default: `10000`) | Amount of satoshis to lock in the contract UTXO |

**Example:**

```bash
runar deploy ./artifacts/P2PKH.json --network testnet --key cN1... --satoshis 10000

# Output:
# Deploying contract: P2PKH
#   Network: testnet
#   Satoshis: 10000
#   Deployer address: mxyz...
#
# Broadcasting...
#
# Deployment successful!
#   TXID: abc123...
#   Explorer: https://whatsonchain.com/tx/abc123...
```

### `runar verify`

Verify a deployed contract matches a compiled artifact. Fetches the transaction from the blockchain and compares the on-chain locking script against the artifact's expected script.

```bash
runar verify <txid> --artifact <path> --network <net>
```

---

## SDK Classes

The SDK is provided by the `runar-sdk` package. It gives you programmatic control over contract deployment, method invocation, and state management.

### RunarContract

The main runtime wrapper for a compiled Rúnar contract.

```typescript
import { RunarContract } from 'runar-sdk';
```

#### Constructor

```typescript
new RunarContract(artifact: RunarArtifact, constructorArgs: unknown[])
```

- **`artifact`** -- The compiled JSON artifact (loaded from the file produced by `runar compile`).
- **`constructorArgs`** -- Values for the contract's constructor parameters, matching the ABI in order.

Throws if the number of arguments does not match the ABI.

#### `deploy(...)`

Deploy the contract by creating a UTXO with the locking script. Has two overloads:

```typescript
// Overload 1: Use provider/signer stored via connect()
async deploy(options: DeployOptions): Promise<{ txid: string; tx: Transaction }>

// Overload 2: Pass provider and signer explicitly
async deploy(
  provider: Provider,
  signer: Signer,
  options: DeployOptions,
): Promise<{ txid: string; tx: Transaction }>
```

`DeployOptions` is `{ satoshis: number; changeAddress?: string }`.

1. Fetches the fee rate from the provider via `getFeeRate()`.
2. Fetches funding UTXOs from the provider.
3. Builds the deploy transaction with the locking script.
4. Signs all inputs with the signer.
5. Broadcasts via the provider.
6. Tracks the deployed UTXO internally.

#### `call(...)`

Call a public method on the contract (spend the UTXO). Has two overloads:

```typescript
// Overload 1: Use provider/signer stored via connect()
async call(
  methodName: string,
  args: unknown[],
  options?: CallOptions,
): Promise<{ txid: string; tx: Transaction }>

// Overload 2: Pass provider and signer explicitly
async call(
  methodName: string,
  args: unknown[],
  provider: Provider,
  signer: Signer,
  options?: CallOptions,
): Promise<{ txid: string; tx: Transaction }>
```

`CallOptions` is `{ satoshis?: number; changeAddress?: string; newState?: Record<string, unknown> }`.

For stateful contracts, a new UTXO is created with the updated state. For stateless contracts, the UTXO is consumed.

#### `state`

Read the current contract state (for stateful contracts).

```typescript
get state(): Record<string, unknown>
```

Returns a copy of the state object. Keys are property names, values are the current values.

#### `getLockingScript()`

Get the full locking script hex, including constructor parameters and serialized state.

```typescript
getLockingScript(): string
```

#### `RunarContract.fromTxId(artifact, txid, outputIndex, provider)`

Reconnect to an existing deployed contract from its on-chain UTXO.

```typescript
static async fromTxId(
  artifact: RunarArtifact,
  txid: string,
  outputIndex: number,
  provider: Provider
): Promise<RunarContract>
```

Fetches the transaction, extracts the UTXO, and if the contract is stateful, deserializes the current state from the locking script.

---

## Provider Interface

Providers give the SDK access to the blockchain. All providers implement the `Provider` interface:

```typescript
interface Provider {
  getTransaction(txid: string): Promise<Transaction>;
  broadcast(rawTx: string): Promise<string>;
  getUtxos(address: string): Promise<UTXO[]>;
  getContractUtxo(scriptHash: string): Promise<UTXO | null>;
  getNetwork(): 'mainnet' | 'testnet';
  getFeeRate(): Promise<number>;
}
```

#### `getFeeRate()`

Returns the current fee rate in satoshis per byte. Defaults to 1 sat/byte for BSV (the standard minimum relay fee). The SDK calls this internally during `deploy()` and `call()` for fee estimation.

### WhatsOnChainProvider

Production provider that connects to the WhatsOnChain API.

```typescript
import { WhatsOnChainProvider } from 'runar-sdk';

const provider = new WhatsOnChainProvider('testnet');
// or
const provider = new WhatsOnChainProvider('mainnet');
```

Uses the WhatsOnChain REST API for transaction lookups, UTXO queries, and broadcasting.

### MockProvider

In-memory provider for testing. Does not connect to any blockchain.

```typescript
import { MockProvider } from 'runar-sdk';

const provider = new MockProvider('testnet');
```

Useful for unit testing contract deployment and method calls without touching a real network. Stores transactions in memory and returns them from `getTransaction`.

---

## Signer Interface

Signers handle private key operations. All signers implement the `Signer` interface:

```typescript
interface Signer {
  getPublicKey(): Promise<string>;  // 33-byte compressed pubkey, hex
  getAddress(): Promise<string>;     // Base58Check BSV address
  sign(
    txHex: string,
    inputIndex: number,
    subscript: string,
    satoshis: number,
    sigHashType?: number             // defaults to ALL | FORKID (0x41)
  ): Promise<string>;               // DER signature + sighash byte, hex
}
```

### LocalSigner

Signs transactions using a local private key. Accepts either a hex-encoded raw key or a WIF-encoded key.

```typescript
import { LocalSigner } from 'runar-sdk';

// From a 64-char hex string (raw 32-byte private key)
const signer = new LocalSigner('abc123...def456...');

// From a WIF-encoded private key (Base58Check, starts with 5, K, or L)
const signerWif = new LocalSigner('KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFU73sVHnoWn');
```

Suitable for server-side applications, CLI tools, and testing.

### ExternalSigner

Delegates signing to an external service or hardware wallet.

```typescript
import { ExternalSigner } from 'runar-sdk';

const signer = new ExternalSigner(
  pubKeyHex,       // 33-byte compressed public key, hex
  addressStr,      // Base58Check BSV address
  async (txHex, inputIndex, subscript, satoshis, sigHashType?) => {
    // Sign the transaction and return DER signature + sighash byte, hex
    return await myHardwareWallet.sign(txHex, inputIndex, subscript, satoshis, sigHashType);
  },
);
```

The constructor takes three parameters: the public key hex, the BSV address, and a signing callback. The callback receives the raw transaction hex, input index, the locking script being spent (hex), the satoshi value of the UTXO, and optional sighash flags (defaults to ALL | FORKID = 0x41). It returns a DER-encoded signature with the sighash byte appended. This pattern supports integration with browser wallets, hardware security modules, or custodial APIs.

---

## State Management API

For stateful contracts, the SDK provides functions to serialize and deserialize contract state.

### `serializeState(fields, values)`

Serialize state values into hex-encoded Bitcoin Script push data.

```typescript
import { serializeState } from 'runar-sdk';

const hex = serializeState(
  artifact.stateFields,
  { counter: 42n, owner: '02abc...' }
);
```

Field order is determined by each `StateField`'s `index` property.

### `deserializeState(fields, scriptHex)`

Deserialize state values from a hex-encoded Script data section.

```typescript
import { deserializeState } from 'runar-sdk';

const state = deserializeState(artifact.stateFields, stateHex);
// state = { counter: 42n, owner: '02abc...' }
```

### `extractStateFromScript(artifact, scriptHex)`

Extract state from a full locking script. Finds the `OP_RETURN` delimiter and deserializes the state section.

```typescript
import { extractStateFromScript } from 'runar-sdk';

const state = extractStateFromScript(artifact, fullLockingScriptHex);
```

Returns `null` for stateless contracts or if no state section is found.

---

## Token Wallet API

The `TokenWallet` class is a higher-level convenience wrapper for managing fungible token UTXOs.

```typescript
import { TokenWallet } from 'runar-sdk';

const wallet = new TokenWallet(tokenArtifact, provider, signer);
```

### `getBalance()`

Get the total token balance across all UTXOs belonging to this wallet.

```typescript
const balance: bigint = await wallet.getBalance();
```

Iterates over all UTXOs, reconnects each as a `RunarContract`, reads the state's `balance` or `amount` field, and sums them.

### `transfer(recipientAddr, amount)`

Transfer tokens to a recipient address.

```typescript
const txid: string = await wallet.transfer('mxyz...', 1000n);
```

Finds a UTXO with sufficient balance and calls its `transfer` public method.

### `merge()`

Merge multiple token UTXOs into a single UTXO (assumes the contract has a `merge` method).

```typescript
const txid: string = await wallet.merge();
```

### `getUtxos()`

Get all token UTXOs associated with this wallet's signer address.

```typescript
const utxos: UTXO[] = await wallet.getUtxos();
```

Filters UTXOs by matching the token contract's locking script prefix.

---

## Types

### UTXO

```typescript
interface UTXO {
  txid: string;
  outputIndex: number;
  satoshis: number;
  script: string; // hex-encoded locking script
}
```

### Transaction

```typescript
interface Transaction {
  txid: string;
  version: number;
  inputs: TxInput[];
  outputs: TxOutput[];
  locktime: number;
  raw?: string; // hex-encoded raw transaction (optional)
}
```

### RunarArtifact

The compiled contract artifact. See `spec/artifact-format.md` for the full schema. Key fields:

- `contractName: string`
- `abi: { constructor: { params: ABIParam[] }, methods: ABIMethod[] }`
- `script: string` (hex template)
- `asm: string`
- `stateFields: StateField[]`
