# runar-sdk

**Deploy, call, and interact with compiled Runar smart contracts on BSV.**

The SDK provides the runtime layer between compiled contract artifacts and the BSV blockchain. It handles transaction construction, signing, broadcasting, state management for stateful contracts, and UTXO tracking.

---

## Installation

```bash
pnpm add runar-sdk
```

---

## Contract Lifecycle

A Rúnar contract goes through four stages:

```
  [1. Instantiate]     Load the compiled artifact and set constructor parameters.
         |
         v
  [2. Deploy]          Build a transaction with the locking script, sign, and broadcast.
         |
         v
  [3. Call]            Build an unlocking transaction to invoke a public method.
         |
         v
  [4. Read State]      (Stateful only) Read state from the contract's current UTXO.
```

### Full Example

```typescript
import { RunarContract, WhatsOnChainProvider, LocalSigner } from 'runar-sdk';
import P2PKHArtifact from './artifacts/P2PKH.json';

// 1. Instantiate
const provider = new WhatsOnChainProvider('testnet');
const signer = new LocalSigner('a1b2c3...');  // 32-byte hex private key or WIF

const contract = new RunarContract(P2PKHArtifact, [
  '89abcdef0123456789abcdef0123456789abcdef',  // pubKeyHash constructor arg
]);

// 2. Connect provider and signer (optional — avoids passing them on every call)
contract.connect(provider, signer);

// 3. Deploy (uses connected provider/signer)
const { txid } = await contract.deploy({ satoshis: 10000 });
console.log('Deployed:', txid);

// 4. Call a public method
const pubKey = await signer.getPublicKey();
const result = await contract.call('unlock', [sig, pubKey]);
console.log('Spent:', result.txid);

// You can also pass provider/signer explicitly (overrides connected ones):
// await contract.deploy(provider, signer, { satoshis: 10000 });
// await contract.call('unlock', [sig, pubKey], provider, signer);
```

### Stateful Contract Example

```typescript
import { RunarContract, WhatsOnChainProvider, LocalSigner } from 'runar-sdk';
import CounterArtifact from './artifacts/Counter.json';

const provider = new WhatsOnChainProvider('testnet');
const signer = new LocalSigner('KwDiBf89QgGbjEhKnhX...');  // WIF key also accepted

const counter = new RunarContract(CounterArtifact, [0n]);  // initial count
counter.connect(provider, signer);

// Deploy with initial state
const { txid } = await counter.deploy({ satoshis: 10000 });

// Read current state (synchronous)
console.log('Count:', counter.state.count);  // 0n

// Call increment (uses connected provider/signer)
await counter.call('increment', [], {
  satoshis: 9500,
  newState: { count: 1n },
});
console.log('Count after increment:', counter.state.count);  // 1n

// Call again
await counter.call('increment', [], {
  satoshis: 9000,
  newState: { count: 2n },
});
console.log('Count:', counter.state.count);  // 2n
```

### Reconnecting to a Deployed Contract

```typescript
// Reconnect to an existing on-chain contract by txid
const contract = await RunarContract.fromTxId(
  CounterArtifact,
  'abc123...',    // txid
  0,              // output index
  provider,
);

console.log('Current state:', contract.state);
```

---

## Providers

Providers handle communication with the BSV network: fetching UTXOs, broadcasting transactions, and querying transaction data.

### WhatsOnChainProvider

Connects to the WhatsOnChain API for mainnet or testnet:

```typescript
import { WhatsOnChainProvider } from 'runar-sdk';

const mainnet = new WhatsOnChainProvider('mainnet');
const testnet = new WhatsOnChainProvider('testnet');

// Fetch UTXOs for an address
const utxos = await testnet.getUtxos('1A1zP1...');

// Broadcast a raw transaction
const txid = await testnet.broadcast(rawTxHex);

// Fetch transaction details
const tx = await testnet.getTransaction(txid);

// Get the network name
const network = testnet.getNetwork();  // 'testnet'

// Get the current fee rate (sat/byte)
const feeRate = await testnet.getFeeRate();  // 1 (BSV standard)
```

### MockProvider

For unit testing without network access:

```typescript
import { MockProvider } from 'runar-sdk';

const mock = new MockProvider();

// Pre-register UTXOs (keyed by address)
mock.addUtxo('1A1zP1...', {
  txid: 'abc123...',
  outputIndex: 0,
  satoshis: 10000,
  script: '76a914...88ac',
});

// Pre-register transactions
mock.addTransaction({
  txid: 'abc123...',
  version: 1,
  inputs: [],
  outputs: [{ satoshis: 10000, script: '76a914...88ac' }],
  locktime: 0,
});

// Transactions are stored in memory
const txid = await mock.broadcast(rawTx);
const tx = await mock.getTransaction(txid);

// Inspect what was broadcast
const broadcastedTxs = mock.getBroadcastedTxs();

// Override the fee rate (default is 1 sat/byte)
mock.setFeeRate(2);
```

### Custom Provider

Implement the `Provider` interface for other network APIs:

```typescript
import { Provider, UTXO, Transaction } from 'runar-sdk';

class MyProvider implements Provider {
  async getUtxos(address: string): Promise<UTXO[]> {
    // Your implementation
  }

  async broadcast(rawTx: string): Promise<string> {
    // Your implementation -- returns txid
  }

  async getTransaction(txid: string): Promise<Transaction> {
    // Your implementation
  }

  async getContractUtxo(scriptHash: string): Promise<UTXO | null> {
    // Find UTXO by script hash (for stateful contract lookup)
  }

  getNetwork(): 'mainnet' | 'testnet' {
    // Return the network
  }

  async getFeeRate(): Promise<number> {
    return 1;  // BSV standard: 1 sat/byte
  }
}
```

---

## Signers

Signers handle private key operations: signing transactions and deriving public keys.

### LocalSigner

Holds a private key in memory. Uses `@bsv/sdk` for secp256k1 key derivation and ECDSA signing with BIP-143 sighash preimage computation. Accepts either a 64-char hex string or a WIF-encoded key:

```typescript
import { LocalSigner } from 'runar-sdk';

// From hex
const signer = new LocalSigner('a1b2c3...');  // 32-byte hex private key

// From WIF (Base58Check, starts with 5/K/L)
const signerWif = new LocalSigner('KwDiBf89QgGbjEhKnhX...');

const pubKey = await signer.getPublicKey();    // compressed public key hex
const address = await signer.getAddress();     // P2PKH address

// Sign a transaction input
const signature = await signer.sign(
  txHex,          // raw transaction hex
  inputIndex,     // which input to sign
  subscript,      // locking script of the UTXO being spent
  satoshis,       // value of the UTXO being spent
  sigHashType,    // optional, defaults to SIGHASH_ALL | SIGHASH_FORKID (0x41)
);
```

### ExternalSigner

Delegates signing to a caller-provided callback. Useful for hardware wallets and browser extensions:

```typescript
import { ExternalSigner, SignCallback } from 'runar-sdk';

const signFn: SignCallback = async (txHex, inputIndex, subscript, satoshis, sigHashType?) => {
  // Request signature from hardware wallet / browser extension
  return derSignatureHex;
};

const signer = new ExternalSigner(
  pubKeyHex,    // 33-byte compressed public key (66 hex chars)
  addressStr,   // Base58Check BSV address
  signFn,
);
```

### Custom Signer

Implement the `Signer` interface:

```typescript
import { Signer } from 'runar-sdk';

class MySigner implements Signer {
  async getPublicKey(): Promise<string> {
    // Return compressed public key hex (66 chars)
  }

  async getAddress(): Promise<string> {
    // Return Base58Check P2PKH address
  }

  async sign(
    txHex: string,
    inputIndex: number,
    subscript: string,
    satoshis: number,
    sigHashType?: number,
  ): Promise<string> {
    // Return DER-encoded signature + sighash byte, hex-encoded
  }
}
```

---

## Stateful Contract Support

### State Chaining

Stateful contracts maintain state across transactions using the OP_PUSH_TX pattern. The SDK manages this automatically:

1. **Deploy:** The initial state is serialized and appended after an OP_RETURN separator in the locking script.
2. **Call:** The SDK reads the current state from the existing UTXO, builds the unlocking script, and creates a new output with the updated locking script containing the new state.
3. **Read:** The SDK deserializes state from the UTXO's locking script.

### State Serialization Format

The SDK knows the contract's state schema from the artifact's `stateFields` array. State is stored as a suffix of the locking script:

```
<code_part> OP_RETURN <field_0_bytes> <field_1_bytes> ... <field_n_bytes>
```

Each field is encoded as Bitcoin Script push data, ordered by the field's `index` property. Type-specific encoding:

- `int`/`bigint`: minimally-encoded Script integers (with sign byte)
- `bool`: OP_0 for false, OP_1 for true
- `bytes`/`ByteString`/`PubKey`/`Ripemd160`/`Addr`/`Sha256`: direct pushdata

Deserialization reverses this: the SDK finds the last OP_RETURN at an opcode boundary (skipping push data), extracts the suffix, and decodes each field.

### UTXO Management

For stateful contracts, the SDK tracks the "current" UTXO internally. After each `call`, the SDK updates its pointer to the new UTXO created by the transaction.

```typescript
// The SDK tracks the current UTXO automatically
const tx1 = await counter.call('increment', [], provider, signer, {
  satoshis: 9500,
  newState: { count: 1n },
});
// counter now points to the new UTXO created by tx1

const tx2 = await counter.call('increment', [], provider, signer, {
  satoshis: 9000,
  newState: { count: 2n },
});
// counter now points to the new UTXO created by tx2
```

---

## Token Support

The SDK provides a `TokenWallet` utility for managing fungible token contracts:

```typescript
import { TokenWallet, WhatsOnChainProvider, LocalSigner } from 'runar-sdk';

const provider = new WhatsOnChainProvider('testnet');
const signer = new LocalSigner('a1b2c3...');

const wallet = new TokenWallet(FungibleTokenArtifact, provider, signer);

// Get total balance across all token UTXOs
const balance = await wallet.getBalance();
console.log('Balance:', balance);

// Transfer tokens to a recipient
const txid = await wallet.transfer(recipientAddress, 500n);

// Merge two UTXOs into one (calls the contract's merge() method)
const mergeTxid = await wallet.merge();

// List all token UTXOs
const utxos = await wallet.getUtxos();
```

---

## Transaction Building Utilities

The SDK exports lower-level functions for custom transaction construction:

```typescript
import {
  buildDeployTransaction,
  buildCallTransaction,
  selectUtxos,
  estimateDeployFee,
  serializeState,
  deserializeState,
  extractStateFromScript,
} from 'runar-sdk';

// Select UTXOs (largest-first strategy)
const selected = selectUtxos(utxos, targetSatoshis, lockingScriptByteLen, feeRate);

// Estimate deployment fee (default 1 sat/byte)
const fee = estimateDeployFee(numInputs, lockingScriptByteLen, feeRate);

// Build an unsigned deploy transaction
const { txHex, inputCount } = buildDeployTransaction(
  lockingScript, utxos, satoshis, changeAddress, changeScript, feeRate,
);

// Build a method call transaction
const { txHex: callTxHex, inputCount: callInputCount } = buildCallTransaction(
  currentUtxo, unlockingScript, newLockingScript, newSatoshis,
  changeAddress, changeScript, additionalUtxos, feeRate,
);

// State serialization
const stateHex = serializeState(stateFields, { count: 5n });
const stateObj = deserializeState(stateFields, stateHex);
const extracted = extractStateFromScript(artifact, fullLockingScriptHex);
```

---

## Types

```typescript
interface Transaction {
  txid: string;
  version: number;
  inputs: TxInput[];
  outputs: TxOutput[];
  locktime: number;
  raw?: string;
}

interface TxInput {
  txid: string;
  outputIndex: number;
  script: string;     // hex
  sequence: number;
}

interface TxOutput {
  satoshis: number;
  script: string;     // hex
}

interface UTXO {
  txid: string;
  outputIndex: number;
  satoshis: number;
  script: string;     // hex
}

interface DeployOptions {
  satoshis: number;
  changeAddress?: string;
}

interface CallOptions {
  satoshis?: number;
  changeAddress?: string;
  newState?: Record<string, unknown>;
}
```

---

## Design Decision: Provider/Signer Abstraction

The provider and signer are separate abstractions because they serve different trust boundaries:

- **Provider** handles read operations (fetching UTXOs, querying transactions) and write operations (broadcasting). It does NOT hold private keys. A provider can be swapped between mainnet, testnet, and mocks without changing any contract logic.

- **Signer** handles private key operations only. It never touches the network directly. This separation means you can use a `LocalSigner` for development and swap in an `ExternalSigner` for production without changing your provider configuration.

This pattern enables:

- Testing with `MockProvider` + `LocalSigner` (no network, fast).
- Staging with `WhatsOnChainProvider('testnet')` + `LocalSigner` (real network, test keys).
- Production with `WhatsOnChainProvider('mainnet')` + `ExternalSigner` (real network, hardware wallet).
