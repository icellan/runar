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

### `runar codegen`

Generate typed wrapper classes from compiled artifact JSON files. The generated wrappers provide type-safe method signatures, automatic signature handling, and clean terminal output APIs — eliminating the need to use stringly-typed `contract.call()`.

```bash
runar codegen <artifacts...> [options]
```

**Arguments:**

The `<artifacts...>` argument accepts one or more artifact paths and supports shell globs.

**Options:**

| Flag | Default | Description |
|------|---------|-------------|
| `--output <dir>` | Same directory as artifact | Output directory for generated files |
| `--lang <lang>` | `ts` | Target language (`ts` supported) |

**Examples:**

```bash
# Single artifact
runar codegen artifacts/Auction.json -o src/generated/

# Multiple artifacts
runar codegen artifacts/Auction.json artifacts/Counter.json -o src/generated/

# Glob pattern
runar codegen artifacts/*.json -o src/generated/

# Combined with compile
runar compile contracts/*.runar.ts && runar codegen artifacts/*.json -o src/generated/
```

Each artifact produces a `<ContractName>Contract.ts` file in the output directory.

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

`DeployOptions` is `{ satoshis?: number; changeAddress?: string }`. `satoshis` defaults to 1 if omitted.

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

`CallOptions` fields:

| Field | Type | Description |
|-------|------|-------------|
| `satoshis` | `number?` | Satoshis for the continuation output (stateful). |
| `changeAddress` | `string?` | BSV address for the change output. |
| `changePubKey` | `string?` | Hex-encoded public key for the change output. Defaults to the signer's key. |
| `newState` | `Record<string, unknown>?` | New state values for the continuation output. |
| `outputs` | `Array<{ satoshis, state }>?` | Multiple continuation outputs for multi-output methods (e.g., token split). Replaces `newState` when provided. |
| `additionalContractInputs` | `UTXO[]?` | Additional contract UTXOs as inputs (e.g., for merge/swap patterns). Each gets its own OP_PUSH_TX and Sig. |
| `additionalContractInputArgs` | `unknown[][]?` | Per-input args for additional contract inputs. If omitted, all use the primary call's args. |
| `terminalOutputs` | `Array<{ scriptHex, satoshis }>?` | Terminal outputs for methods that verify `extractOutputHash()`. No change output; fee comes from the contract balance. |

For stateful contracts, a new UTXO is created with the updated state. For stateless contracts, the UTXO is consumed.

#### `connect(provider, signer)`

Store a provider and signer on the contract instance so they do not need to be passed to every `deploy()` and `call()` invocation.

```typescript
contract.connect(provider, signer);

// Now deploy/call without passing provider and signer explicitly:
await contract.deploy({ satoshis: 10000 });
await contract.call('increment', []);
```

#### `setState(newState)`

Directly update the contract's in-memory state (for stateful contracts). Merges the provided key-value pairs into the existing state. This is useful for testing or for manually correcting state before building a call transaction.

```typescript
contract.setState({ count: 42n });
// contract.state.count is now 42n
```

Does not broadcast anything -- it only modifies the local state representation. The updated state will be used the next time `getLockingScript()` is called (e.g., during `call()`).

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
  getRawTransaction(txid: string): Promise<string>;
  broadcast(rawTx: string): Promise<string>;
  getUtxos(address: string): Promise<UTXO[]>;
  getContractUtxo(scriptHash: string): Promise<UTXO | null>;
  getNetwork(): 'mainnet' | 'testnet';
  getFeeRate(): Promise<number>;
}
```

#### `getRawTransaction(txid)`

Returns the raw transaction hex for a given txid.

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

#### Test Data Injection

```typescript
// Inject a transaction (returned by getTransaction)
provider.addTransaction(tx);

// Inject a UTXO for an address (returned by getUtxos)
provider.addUtxo('mxyz...', { txid: '...', outputIndex: 0, satoshis: 50000, script: '...' });

// Inject a contract UTXO by script hash (returned by getContractUtxo)
provider.addContractUtxo('scripthash...', utxo);
```

#### `setFeeRate(rate)`

Set the fee rate (in satoshis per byte) returned by `getFeeRate()`. Defaults to 1. Useful for testing fee estimation logic with different fee environments.

```typescript
provider.setFeeRate(5); // 5 sat/byte
```

#### `getBroadcastedTxs()`

Returns a readonly array of all raw transaction hex strings that were broadcast through this provider. Useful for asserting that deploy/call operations produced the expected transactions.

```typescript
const txs = provider.getBroadcastedTxs();
expect(txs.length).toBe(1);
```

### RPCProvider

JSON-RPC provider that connects directly to a Bitcoin node. Suitable for regtest and testnet integration testing.

```typescript
import { RPCProvider } from 'runar-sdk';

const provider = new RPCProvider(url, user, pass, options?);
```

| Parameter | Type | Description |
|-----------|------|-------------|
| `url` | `string` | Node RPC URL (e.g., `http://localhost:18332`) |
| `user` | `string` | RPC username |
| `pass` | `string` | RPC password |
| `options.network` | `'mainnet' \| 'testnet'` | Network name (default: `'testnet'`) |
| `options.autoMine` | `boolean` | Auto-mine 1 block after broadcast (default: `false`) |
| `options.mineAddress` | `string` | Mining address for `generatetoaddress`. If empty, uses `generate`. |

Note: `getContractUtxo()` always returns `null` — use address-based UTXO tracking instead. `getFeeRate()` always returns 1.

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

### WalletSigner

Delegates signing to a BRC-100 compatible wallet via `@bsv/sdk`'s `WalletClient`. Computes BIP-143 sighash locally, then sends the pre-hashed digest to the wallet for ECDSA signing via `hashToDirectlySign`.

```typescript
import { WalletSigner } from 'runar-sdk';

const signer = new WalletSigner({
  protocolID: [2, 'my app'],  // BRC-100 protocol ID tuple
  keyID: '1',                 // Key derivation ID
  wallet: existingClient,     // Optional pre-existing WalletClient
});
```

| Option | Type | Description |
|--------|------|-------------|
| `protocolID` | `[SecurityLevel, string]` | BRC-100 protocol ID (required) |
| `keyID` | `string` | Key derivation ID (required) |
| `wallet` | `WalletClient?` | Pre-existing `WalletClient`. If not provided, a new one is created. |

---

## OP_PUSH_TX Helper

For contracts that use `checkPreimage()` (stateful and some stateless patterns), `computeOpPushTx` computes the BIP-143 sighash preimage and OP_PUSH_TX signature.

```typescript
import { computeOpPushTx } from 'runar-sdk';

const { sigHex, preimageHex } = computeOpPushTx(txHex, inputIndex, subscript, satoshis);
```

| Parameter | Type | Description |
|-----------|------|-------------|
| `txHex` | `string` | Raw transaction hex (with placeholder unlocking scripts) |
| `inputIndex` | `number` | The contract input index (usually 0) |
| `subscript` | `string` | Locking script of the UTXO being spent (hex) |
| `satoshis` | `number` | Satoshi value of the UTXO being spent |

Returns `{ sigHex: string; preimageHex: string }` — the DER signature (+ sighash byte) and raw BIP-143 preimage, both hex-encoded.

This is called internally by `RunarContract.call()` for stateful contracts. It is exposed for manual transaction building workflows. Uses private key k=1 (public key = generator point G) and enforces low-S.

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

Iterates over all UTXOs, reconnects each as a `RunarContract`, reads the state's `supply`, `balance`, or `amount` field (checked in that priority order), and sums them.

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
- `constructorSlots: ConstructorSlot[]` -- byte offsets for constructor parameter placeholders
- `codeSeparatorIndex?: number` -- byte offset of the last `OP_CODESEPARATOR` in the script (present for stateful contracts)
- `codeSeparatorIndices?: number[]` -- per-method `OP_CODESEPARATOR` byte offsets (for multi-method stateful contracts)

---

## Low-Level Transaction Building

These functions give you direct control over transaction construction, bypassing the `RunarContract` high-level API. Useful for custom workflows, batching, or integration with existing transaction pipelines.

### `buildDeployTransaction(...)`

Build a raw unsigned transaction that creates a UTXO with the given locking script.

```typescript
import { buildDeployTransaction } from 'runar-sdk';

function buildDeployTransaction(
  lockingScript: string,
  utxos: UTXO[],
  satoshis: number,
  changeAddress: string,
  changeScript: string,
  feeRate?: number,          // default: 1 sat/byte
): { txHex: string; inputCount: number }
```

- **`lockingScript`** -- The contract locking script hex (from `RunarContract.getLockingScript()`).
- **`utxos`** -- Funding UTXOs to consume as inputs.
- **`satoshis`** -- Amount to lock in the contract output.
- **`changeAddress`** -- BSV address (Base58Check) or 40-char hex pubkey hash for the change output.
- **`changeScript`** -- Pre-built change output locking script hex. If empty, a P2PKH script is built from `changeAddress`.
- **`feeRate`** -- Fee rate in satoshis per byte (default: 1).

Returns the unsigned transaction hex and the number of inputs (so the caller knows how many signatures are needed). The contract output is always output index 0; change (if any) is output index 1.

Throws if no UTXOs are provided or if the total input value is insufficient to cover `satoshis + fee`.

### `buildCallTransaction(...)`

Build a raw transaction that spends a contract UTXO (method call).

```typescript
import { buildCallTransaction } from 'runar-sdk';

function buildCallTransaction(
  currentUtxo: UTXO,
  unlockingScript: string,
  newLockingScript?: string,
  newSatoshis?: number,
  changeAddress?: string,
  changeScript?: string,
  additionalUtxos?: UTXO[],
  feeRate?: number,          // default: 1 sat/byte
): { txHex: string; inputCount: number }
```

- **`currentUtxo`** -- The contract UTXO being spent (input 0).
- **`unlockingScript`** -- The unlocking script hex for input 0 (from `RunarContract.buildUnlockingScript()`).
- **`newLockingScript`** -- For stateful contracts, the updated locking script for the continuation output. Omit for stateless contracts (the UTXO is consumed with no contract output).
- **`newSatoshis`** -- Satoshis for the new contract output. Defaults to the current UTXO's satoshis if omitted.
- **`changeAddress`** -- BSV address for the change output.
- **`changeScript`** -- Pre-built change output locking script hex.
- **`additionalUtxos`** -- Extra funding UTXOs (inputs 1..N, unsigned).
- **`feeRate`** -- Fee rate in satoshis per byte (default: 1).

Returns the transaction hex (with input 0's unlocking script already placed) and the total input count. Additional inputs (index 1+) have empty scriptSigs and need to be signed separately.

### `selectUtxos(...)`

Select the minimum set of UTXOs needed to fund a deployment, using a largest-first strategy.

```typescript
import { selectUtxos } from 'runar-sdk';

function selectUtxos(
  utxos: UTXO[],
  targetSatoshis: number,
  lockingScriptByteLen: number,
  feeRate?: number,          // default: 1 sat/byte
): UTXO[]
```

- **`utxos`** -- Available UTXOs to select from.
- **`targetSatoshis`** -- The amount that needs to be funded (contract output value).
- **`lockingScriptByteLen`** -- Byte length of the contract locking script (used for fee estimation).
- **`feeRate`** -- Fee rate in satoshis per byte (default: 1).

Returns the selected subset of UTXOs. If the total is still insufficient, returns all UTXOs (the caller should check or let `buildDeployTransaction` throw).

### `estimateDeployFee(...)`

Estimate the fee for a deployment transaction.

```typescript
import { estimateDeployFee } from 'runar-sdk';

function estimateDeployFee(
  numInputs: number,
  lockingScriptByteLen: number,
  feeRate?: number,          // default: 1 sat/byte
): number
```

- **`numInputs`** -- Number of P2PKH funding inputs.
- **`lockingScriptByteLen`** -- Byte length of the contract locking script.
- **`feeRate`** -- Fee rate in satoshis per byte (default: 1).

Returns the estimated fee in satoshis. Assumes P2PKH inputs (148 bytes each), includes the contract output (8 bytes + varint + script) and a P2PKH change output (34 bytes), plus 10 bytes of transaction overhead.

### `RunarContract.buildUnlockingScript(...)`

Build the unlocking script for a contract method call.

```typescript
buildUnlockingScript(methodName: string, args: unknown[]): string
```

- **`methodName`** -- The name of the public method to call.
- **`args`** -- The method arguments, matching the ABI parameter types in order.

Returns the unlocking script hex. Each argument is encoded as a Bitcoin Script push data element. If the contract has multiple public methods, a method selector (the method's index among public methods) is appended.

This is called internally by `RunarContract.call()`, but is exposed for use with `buildCallTransaction()` when building transactions manually.

### `SignCallback` Type

The callback type used by `ExternalSigner` for delegated signing.

```typescript
import type { SignCallback } from 'runar-sdk';

type SignCallback = (
  txHex: string,
  inputIndex: number,
  subscript: string,
  satoshis: number,
  sigHashType?: number,
) => Promise<string>;
```

- **`txHex`** -- The raw transaction hex to sign.
- **`inputIndex`** -- The index of the input being signed.
- **`subscript`** -- The locking script hex of the UTXO being spent (used for BIP-143 sighash computation).
- **`satoshis`** -- The satoshi value of the UTXO being spent (used for BIP-143 sighash computation).
- **`sigHashType`** -- Optional sighash flags. Defaults to `SIGHASH_ALL | SIGHASH_FORKID` (0x41).

Returns a hex-encoded DER signature with the sighash byte appended.

---

## Code Generation

The `generateTypescript` function produces a typed wrapper class from a compiled artifact. The generated class wraps `RunarContract` and provides:

- **Typed constructor** with named parameters instead of positional `unknown[]`
- **Typed methods** for each public contract method
- **Auto-computed signatures** — `Sig` and `SigHashPreimage` params are hidden; the SDK handles them via the connected signer
- **Terminal vs state-mutating** distinction — terminal methods accept `TerminalOutput[]` directly; state-mutating methods accept `StatefulCallOptions`
- **Address-based outputs** — terminal methods accept `{ address, satoshis }` (converted to P2PKH) instead of raw `{ scriptHex, satoshis }`

### `generateTypescript(artifact)`

```typescript
import { generateTypescript } from 'runar-sdk';

const code: string = generateTypescript(artifact);
```

Takes a `RunarArtifact` and returns a string of TypeScript source code containing the generated wrapper class.

### Generated Class Structure

For a stateful contract `Auction` with a state-mutating `bid` method and a terminal `close` method:

```typescript
// Generated by: runar codegen
import { RunarContract, buildP2PKHScript } from 'runar-sdk';
import type { RunarArtifact } from 'runar-sdk';

export interface TerminalOutput {
  satoshis: number;
  address?: string;   // converted to P2PKH script
  scriptHex?: string; // raw locking script hex (fallback)
}

export interface AuctionStatefulCallOptions {
  satoshis?: number;
  changeAddress?: string;
  changePubKey?: string;
  newState?: Record<string, unknown>;
  outputs?: Array<{ satoshis: number; state: Record<string, unknown> }>;
}

export class AuctionContract {
  constructor(artifact: RunarArtifact, args: {
    auctioneer: string | null;
    highestBidder: string | null;
    highestBid: bigint;
    deadline: bigint;
  });

  connect(provider: Provider, signer: Signer): void;
  deploy(options?: DeployOptions): Promise<CallResult>;
  deploy(provider: Provider, signer: Signer, options?: DeployOptions): Promise<CallResult>;
  get contract(): RunarContract; // escape hatch for advanced usage

  /** State-mutating method */
  bid(bidder: string | null, bidAmount: bigint, options?: AuctionStatefulCallOptions): Promise<CallResult>;

  /** Terminal method */
  close(outputs: TerminalOutput[]): Promise<CallResult>;
}
```

### Usage Example

```typescript
import { AuctionContract } from './generated/AuctionContract.js';

const auction = new AuctionContract(artifact, {
  auctioneer: myPubKey,
  highestBidder: myPubKey,
  highestBid: 0n,
  deadline: 1000n,
});
auction.connect(provider, signer);
await auction.deploy({ satoshis: 10000 });

// State-mutating call
await auction.bid(bidderPubKey, 5000n, { satoshis: 10000 });

// Terminal call — sends funds to an address
await auction.close([{ address: winnerAddress, satoshis: 9000 }]);
```

### Parameter Handling

| ABI Param Type | Generated Signature | Passed to `call()` |
|---|---|---|
| `Sig` | Hidden | `null` (auto-signed) |
| `SigHashPreimage` | Hidden | `null` (auto-computed) |
| `_changePKH` | Hidden | `null` (auto-computed) |
| `_changeAmount` | Hidden | `null` (auto-computed) |
| `PubKey` | `string \| null` | Value or `null` (auto from signer) |
| `bigint` | `bigint` | Value |
| `boolean` | `boolean` | Value |
| `ByteString`, `Addr`, `Ripemd160`, `Sha256`, `Point` | `string` | Value |

Pass `null` for a `PubKey` parameter to auto-resolve it from the connected signer's public key.

### Escape Hatch

For advanced use cases not covered by the generated wrapper, access the underlying `RunarContract` via the `.contract` getter:

```typescript
const result = await auction.contract.call('bid', [null, bidder, amount], {
  additionalContractInputs: [...],
});
```
