# runar-sdk

**Deploy, call, and interact with compiled Rúnar smart contracts on BSV.**

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
  [4. Read State]      (Stateful only) Deserialize state from the UTXO.
```

### Full Example

```typescript
import { ContractInstance, WhatsOnChainProvider, LocalSigner } from 'runar-sdk';
import P2PKHArtifact from './artifacts/P2PKH.json';

// 1. Instantiate
const provider = new WhatsOnChainProvider('testnet');
const signer = new LocalSigner('cRkL4...');  // WIF private key

const contract = new ContractInstance(P2PKHArtifact, {
  pubKeyHash: Addr('89abcdef0123456789abcdef0123456789abcdef'),
});

contract.connect(provider, signer);

// 2. Deploy
const deployTx = await contract.deploy({ satoshis: 10000n });
console.log('Deployed:', deployTx.txid);

// 3. Call a public method
const callTx = await contract.call('unlock', {
  sig: await signer.sign(deployTx.txid),
  pubKey: signer.publicKey,
});
console.log('Spent:', callTx.txid);
```

### Stateful Contract Example

```typescript
import { ContractInstance, WhatsOnChainProvider, LocalSigner } from 'runar-sdk';
import CounterArtifact from './artifacts/Counter.json';

const provider = new WhatsOnChainProvider('testnet');
const signer = new LocalSigner('cRkL4...');

const counter = new ContractInstance(CounterArtifact, {
  count: 0n,
});

counter.connect(provider, signer);

// Deploy with initial state
const deployTx = await counter.deploy({ satoshis: 10000n });

// Read current state
const state = await counter.getState();
console.log('Count:', state.count);  // 0n

// Call increment -- builds the preimage automatically
const tx1 = await counter.call('increment', {});
const newState = await counter.getState();
console.log('Count after increment:', newState.count);  // 1n

// Call again
const tx2 = await counter.call('increment', {});
console.log('Count:', (await counter.getState()).count);  // 2n
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
const utxos = await testnet.getUTXOs('1A1zP1...');

// Broadcast a raw transaction
const txid = await testnet.broadcast(rawTxHex);

// Fetch transaction details
const tx = await testnet.getTransaction(txid);
```

### MockProvider

For unit testing without network access:

```typescript
import { MockProvider } from 'runar-sdk';

const mock = new MockProvider();

// Pre-register UTXOs
mock.addUTXO({
  txid: 'abc123...',
  outputIndex: 0,
  satoshis: 10000n,
  script: '76a914...88ac',
});

// Transactions are stored in memory
const txid = await mock.broadcast(rawTx);
const tx = await mock.getTransaction(txid);
```

### Custom Provider

Implement the `Provider` interface for other network APIs:

```typescript
import { Provider, UTXO, Transaction } from 'runar-sdk';

class MyProvider implements Provider {
  async getUTXOs(address: string): Promise<UTXO[]> {
    // Your implementation
  }

  async broadcast(rawTx: string): Promise<string> {
    // Your implementation -- returns txid
  }

  async getTransaction(txid: string): Promise<Transaction> {
    // Your implementation
  }

  async getFeeRate(): Promise<bigint> {
    // Satoshis per byte
  }
}
```

---

## Signers

Signers handle private key operations: signing transactions and deriving public keys.

### LocalSigner

Holds a private key in memory. Suitable for development, testing, and server-side deployment:

```typescript
import { LocalSigner } from 'runar-sdk';

const signer = new LocalSigner('cRkL4...');  // WIF-encoded private key

console.log(signer.publicKey);   // compressed public key hex
console.log(signer.address);     // P2PKH address

// Sign a transaction
const signature = await signer.sign(txid, inputIndex, lockingScript, amount, sigHashType);
```

### ExternalSigner

Interface for hardware wallets and external signing services:

```typescript
import { ExternalSigner } from 'runar-sdk';

class LedgerSigner implements ExternalSigner {
  async getPublicKey(): Promise<string> {
    // Request public key from hardware wallet
  }

  async sign(
    txid: string,
    inputIndex: number,
    lockingScript: string,
    amount: bigint,
    sigHashType: bigint,
  ): Promise<string> {
    // Request signature from hardware wallet
  }
}
```

### Custom Signer

Implement the `Signer` interface:

```typescript
import { Signer } from 'runar-sdk';

class MySigner implements Signer {
  get publicKey(): string { ... }
  get address(): string { ... }

  async sign(
    txid: string,
    inputIndex: number,
    lockingScript: string,
    amount: bigint,
    sigHashType: bigint,
  ): Promise<string> {
    // Return DER-encoded signature + sighash byte, hex-encoded
  }
}
```

---

## Stateful Contract Support

### State Chaining

Stateful contracts maintain state across transactions using the OP_PUSH_TX pattern. The SDK manages this automatically:

1. **Deploy:** The initial state is serialized and prepended to the locking script.
2. **Call:** The SDK reads the current state from the existing UTXO, constructs the preimage, computes the new state, and builds the output with the updated locking script.
3. **Read:** The SDK deserializes state from the UTXO's locking script.

### State Serialization/Deserialization

The SDK knows the contract's state schema from the artifact's `properties` array. Each mutable property is serialized in declaration order:

```
<prop_1_bytes> <prop_2_bytes> ... <prop_n_bytes> OP_DROP^n <code_part>
```

Deserialization reverses this: the SDK strips the state prefix, decodes each property according to its type, and returns a typed state object.

### UTXO Management

For stateful contracts, the SDK tracks the "current" UTXO -- the one containing the latest state. After each `call`, the SDK updates its internal pointer to the new UTXO created by the transaction.

```typescript
// The SDK tracks the current UTXO automatically
const tx1 = await counter.call('increment', {});
// counter now points to the new UTXO created by tx1

const tx2 = await counter.call('increment', {});
// counter now points to the new UTXO created by tx2

// You can also manually set the UTXO
counter.setUTXO({
  txid: 'abc...',
  outputIndex: 0,
  satoshis: 9500n,
});
```

---

## Token Support

The SDK provides a `TokenWallet` utility for managing token contracts:

```typescript
import { TokenWallet, WhatsOnChainProvider, LocalSigner } from 'runar-sdk';

const wallet = new TokenWallet(FungibleTokenArtifact, {
  provider: new WhatsOnChainProvider('testnet'),
  signer: new LocalSigner('cRkL4...'),
});

// Deploy a new token
const deployTx = await wallet.deploy({
  owner: signer.publicKey,
  supply: 1000000n,
});

// Transfer ownership
const transferTx = await wallet.transfer(recipientPubKey);

// Get current token state
const state = await wallet.getState();
console.log('Owner:', state.owner);
console.log('Supply:', state.supply);
```

---

## Design Decision: Provider/Signer Abstraction

The provider and signer are separate abstractions because they serve different trust boundaries:

- **Provider** handles read operations (fetching UTXOs, querying transactions) and write operations (broadcasting). It does NOT hold private keys. A provider can be swapped between mainnet, testnet, and mocks without changing any contract logic.

- **Signer** handles private key operations only. It never touches the network directly. This separation means you can use a `LocalSigner` for development and swap in a `LedgerSigner` for production without changing your provider configuration.

This pattern is common in blockchain SDKs (ethers.js uses the same separation) and enables:

- Testing with `MockProvider` + `LocalSigner` (no network, fast).
- Staging with `WhatsOnChainProvider('testnet')` + `LocalSigner` (real network, test keys).
- Production with `WhatsOnChainProvider('mainnet')` + `ExternalSigner` (real network, hardware wallet).
