# Integration Guide

This guide walks through the full lifecycle of Rúnar smart contracts: writing, testing locally, compiling, deploying on-chain, and interacting with deployed contracts. It focuses on stateful contracts since they're the most interesting and the least obvious.

---

## Local Development (No Blockchain Needed)

Most development happens locally with `TestContract`, which compiles a contract and runs methods through the reference interpreter. No blockchain connection, no real keys, no fees.

### Stateless Contract

A stateless contract (like P2PKH) has only `readonly` properties. Spending is a single transaction that consumes the UTXO.

```typescript
import { readFileSync } from 'node:fs';
import { TestContract } from 'runar-testing';

// Load the contract source
const source = readFileSync('P2PKH.runar.ts', 'utf8');

// Create with constructor args (property values baked into the locking script)
const contract = TestContract.fromSource(source, {
  pubKeyHash: 'ab'.repeat(20),  // hex-encoded 20-byte address
});

// Call the unlock method — checkSig is mocked to return true
const result = contract.call('unlock', {
  sig: '30' + 'ff'.repeat(35),
  pubKey: '02' + 'ab'.repeat(32),
});

console.log(result.success);  // true or false
console.log(result.error);    // error message if false
```

### Stateful Contract (Counter)

A stateful contract has mutable properties. The state persists across transactions — each `call()` mutates the contract's state, and you can inspect it after each call.

```typescript
const source = readFileSync('Counter.runar.ts', 'utf8');

// Deploy with initial state: count = 0
const counter = TestContract.fromSource(source, { count: 0n });
console.log(counter.state.count);  // 0n

// Call increment — state updates in place
counter.call('increment');
console.log(counter.state.count);  // 1n

counter.call('increment');
counter.call('increment');
console.log(counter.state.count);  // 3n

// Call decrement
counter.call('decrement');
console.log(counter.state.count);  // 2n

// Decrement at zero fails
const zeroCounter = TestContract.fromSource(source, { count: 0n });
const result = zeroCounter.call('decrement');
console.log(result.success);  // false — assert(this.count > 0n) failed
```

This is the primary development loop: write contract, run `TestContract`, inspect state, iterate.

### Multi-Output Contract (Fungible Token)

Contracts that call `this.addOutput()` create multiple transaction outputs. This is how tokens split and merge.

```typescript
const source = readFileSync('FungibleTokenExample.runar.ts', 'utf8');

const token = TestContract.fromSource(source, {
  owner: '02' + 'aa'.repeat(32),   // Alice
  balance: 100n,
  tokenId: 'deadbeef',
});

// Transfer 30 tokens from Alice to Bob — creates 2 outputs
const result = token.call('transfer', {
  sig: '30' + 'ff'.repeat(35),
  to: '02' + 'bb'.repeat(32),       // Bob
  amount: 30n,
  outputSatoshis: 1000n,
});

console.log(result.success);          // true
console.log(result.outputs.length);   // 2

// Output 0: Bob gets 30 tokens
console.log(result.outputs[0].owner);    // Bob's pubkey
console.log(result.outputs[0].balance);  // 30n
console.log(result.outputs[0].satoshis); // 1000n

// Output 1: Alice keeps 70 tokens (change)
console.log(result.outputs[1].owner);    // Alice's pubkey
console.log(result.outputs[1].balance);  // 70n
```

Each output becomes a separate UTXO on-chain, each carrying its own copy of the contract code with updated state values.

### How `addOutput` Works

In the contract source:

```typescript
class FungibleToken extends StatefulSmartContract {
  owner: PubKey;           // mutable state field (index 0)
  balance: bigint;         // mutable state field (index 1)
  readonly tokenId: ByteString;

  public transfer(sig: Sig, to: PubKey, amount: bigint, outputSatoshis: bigint) {
    assert(checkSig(sig, this.owner));
    assert(amount > 0n && amount <= this.balance);

    // addOutput(satoshis, <state fields in declaration order>)
    this.addOutput(outputSatoshis, to, amount);                      // recipient
    this.addOutput(outputSatoshis, this.owner, this.balance - amount); // change
  }
}
```

The arguments after `satoshis` correspond to the mutable properties in declaration order (`owner`, `balance`). The compiler verifies this at typecheck time.

---

## Compiling to Artifacts

### CLI

```bash
runar compile Counter.runar.ts                   # => artifacts/Counter.json
runar compile Counter.runar.ts --output ./build  # Custom output directory
runar compile Counter.runar.ts --ir              # Include ANF IR in artifact
```

### Programmatic

```typescript
import { compile } from 'runar-compiler';

const source = readFileSync('Counter.runar.ts', 'utf8');
const result = compile(source, { fileName: 'Counter.runar.ts' });

if (!result.success) {
  throw new Error(result.diagnostics.filter(d => d.severity === 'error').map(d => d.message).join('\n'));
}

const artifact = result.artifact!;
console.log(artifact.contractName);   // "Counter"
console.log(artifact.script);         // hex-encoded Bitcoin Script
console.log(artifact.stateFields);    // [{ name: "count", type: "bigint", index: 0 }]
```

### Artifact Structure

```json
{
  "version": "runar-v0.1.0",
  "contractName": "Counter",
  "abi": {
    "constructor": { "params": [{ "name": "count", "type": "bigint" }] },
    "methods": [
      { "name": "increment", "params": [], "isPublic": true },
      { "name": "decrement", "params": [], "isPublic": true }
    ]
  },
  "script": "5179...",
  "asm": "OP_1 OP_PICK ...",
  "stateFields": [
    { "name": "count", "type": "bigint", "index": 0 }
  ]
}
```

The `stateFields` array is present only for `StatefulSmartContract`. It tells the SDK which fields are mutable and their serialization order.

---

## On-Chain Lifecycle: Stateful Counter

This is the complete lifecycle of a stateful contract from deployment through multiple state transitions.

### Step 1: Compile

```typescript
import { compile } from 'runar-compiler';
import { RunarContract, LocalSigner, WhatsOnChainProvider } from 'runar-sdk';

const source = readFileSync('Counter.runar.ts', 'utf8');
const { artifact } = compile(source, { fileName: 'Counter.runar.ts' });
```

### Step 2: Deploy (count = 0)

```typescript
const provider = new WhatsOnChainProvider('mainnet');
const signer = new LocalSigner(privateKey);

// Instantiate with initial state
const counter = new RunarContract(artifact, [0n]);

// Deploy: creates a UTXO with the locking script + state
const { txid } = await counter.deploy(provider, signer, { satoshis: 10_000 });
console.log('Deployed:', txid);
// The UTXO now contains: <compiled code> OP_RETURN <count=0>
```

### Step 3: Call increment (count → 1)

```typescript
const { txid: tx2 } = await counter.call('increment', [], provider, signer);
console.log('Incremented:', tx2);
console.log('State:', counter.state);  // { count: 1n }
// The old UTXO is spent. A new UTXO is created with: <code> OP_RETURN <count=1>
```

### Step 4: Call increment again (count → 2)

```typescript
const { txid: tx3 } = await counter.call('increment', [], provider, signer);
console.log('State:', counter.state);  // { count: 2n }
```

### Step 5: Reconnect to an existing contract

```typescript
// On a different machine, reconnect to the deployed contract
const existing = await RunarContract.fromTxId(artifact, tx3, 0, provider);
console.log('Reconnected state:', existing.state);  // { count: 2n }
```

### What Happens On-Chain

Each state transition is a Bitcoin transaction:

```
TX1 (deploy):
  Input:  funding UTXO
  Output: Counter locking script with count=0, 10000 sats

TX2 (increment):
  Input:  TX1 output 0 (unlocking script proves method call)
  Output: Counter locking script with count=1, 10000 sats

TX3 (increment):
  Input:  TX2 output 0
  Output: Counter locking script with count=2, 10000 sats
```

The contract code is identical in every output. Only the state suffix changes. The OP_PUSH_TX pattern (automatic preimage verification) ensures that the spending transaction actually contains the correct updated state.

---

## On-Chain Lifecycle: Token Split

Multi-output contracts create multiple UTXOs per transaction, enabling token splitting and merging.

### Deploy with 100 tokens

```typescript
const tokenArtifact = compile(tokenSource, { fileName: 'FungibleToken.runar.ts' }).artifact!;
const token = new RunarContract(tokenArtifact, [alicePubKey, 100n, tokenIdHex]);
const { txid } = await token.deploy(provider, signer, { satoshis: 10_000 });
```

### Transfer 30 tokens to Bob (split)

```typescript
const { txid: splitTx } = await token.call(
  'transfer',
  [aliceSig, bobPubKey, 30n, 5000n],
  provider,
  signer,
);
```

This creates a single transaction with **two outputs**:

```
TX (transfer):
  Input:  deploy UTXO (Alice owns 100 tokens)
  Output 0: FungibleToken { owner: Bob,   balance: 30 }, 5000 sats
  Output 1: FungibleToken { owner: Alice, balance: 70 }, 5000 sats
```

Each output is an independent UTXO that can be spent separately. Bob can now transfer his 30 tokens, and Alice can transfer her 70.

---

## State Management

### Serialization

The SDK serializes state values into the locking script suffix:

```typescript
import { serializeState, deserializeState, extractStateFromScript } from 'runar-sdk';

// Serialize state to hex (for embedding in custom transactions)
const stateHex = serializeState(artifact.stateFields!, { count: 42n });

// Deserialize from a data section
const state = deserializeState(artifact.stateFields!, stateHex);
console.log(state.count);  // 42n

// Extract state directly from a full locking script
const state = extractStateFromScript(artifact, scriptHex);
```

### State Encoding

State fields are encoded as Bitcoin Script push data in the order specified by `stateFields[].index`:

| Type | Encoding |
|------|----------|
| `bigint` | 8-byte OP_NUM2BIN (little-endian, sign-magnitude) |
| `boolean` | 1-byte OP_NUM2BIN |
| `ByteString` | Raw push data |
| `PubKey` | 33-byte push data (compressed) |

---

## Script VM Testing (Advanced)

For testing that the compiled Bitcoin Script actually executes correctly (not just the interpreter), use `ScriptExecutionContract`:

```typescript
import { ScriptExecutionContract } from 'runar-testing';

const compiled = ScriptExecutionContract.fromSource(source, { count: 0n });
const result = compiled.execute('increment', []);
console.log(result.success);  // true
```

This compiles the contract with baked constructor args, then executes the locking + unlocking scripts through the BSV SDK's production script interpreter. Use this for validation that the compiled Bitcoin Script matches the interpreter.

---

## Production Integration: TypeScript (@bsv/sdk)

For production deployments with full control over transaction construction, use `@bsv/sdk` directly with the compiled locking script.

### Deploy a Contract

```typescript
import { readFileSync } from 'node:fs';
import { PrivateKey, Transaction, P2PKH, ARC, LockingScript } from '@bsv/sdk';
import { RunarContract } from 'runar-sdk';

// Load compiled artifact
const artifact = JSON.parse(readFileSync('artifacts/Counter.json', 'utf8'));
const contract = new RunarContract(artifact, [0n]); // count = 0

// The locking script is the contract bytecode + embedded constructor args
// For stateful contracts, it also includes the OP_RETURN-delimited state suffix
const lockingScript = LockingScript.fromHex(contract.getLockingScript());

// Build deployment transaction
const privKey = PrivateKey.fromWIF('...');
const deployTx = new Transaction();
deployTx.addInput({
  sourceTransaction: fundingTx,
  sourceOutputIndex: 0,
  unlockingScriptTemplate: new P2PKH().unlock(privKey),
});
deployTx.addOutput({ lockingScript, satoshis: 10_000 });
deployTx.addOutput({
  lockingScript: new P2PKH().lock(privKey.toAddress()),
  change: true,
});
await deployTx.fee();
await deployTx.sign();

// Broadcast via ARC
const broadcaster = new ARC('https://arc.taal.com');
const { txid } = await deployTx.broadcast(broadcaster);
```

### Call a Stateless Method (Spend)

For stateless contracts (P2PKH, Escrow), spending consumes the UTXO with no continuation:

```typescript
import { UnlockingScript } from '@bsv/sdk';

// Build the unlocking script: method arguments + method selector
const unlockHex = contract.buildUnlockingScript('unlock', [sigHex, pubKeyHex]);

const spendTx = new Transaction();
spendTx.addInput({
  sourceTransaction: deployTx,
  sourceOutputIndex: 0,
  unlockingScript: UnlockingScript.fromHex(unlockHex),
});
// Add outputs (payment, change, etc.)
spendTx.addOutput({ ... });
await spendTx.fee();
await spendTx.sign();
await spendTx.broadcast(broadcaster);
```

### Call a Stateful Method (State Transition)

Stateful contracts (Counter, FungibleToken) spend the current UTXO and create a new one with updated state. The OP_PUSH_TX pattern ensures the spending transaction contains the correct updated output.

```typescript
import { Hash, TransactionSignature } from '@bsv/sdk';

// 1. Build the NEW locking script with updated state
//    (same contract code, but state suffix changes)
const newLockingScript = LockingScript.fromHex(
  contract.getLockingScript() // reflects updated state after call()
);

// 2. Build transaction: old contract input → new contract output
const callTx = new Transaction();
callTx.addInput({
  sourceTransaction: deployTx,
  sourceOutputIndex: 0,
  sequenceNumber: 0xffffffff,
});
// Output 0: new contract UTXO with updated state
callTx.addOutput({ lockingScript: newLockingScript, satoshis: 10_000 });
// Output 1: change
callTx.addOutput({
  lockingScript: new P2PKH().lock(privKey.toAddress()),
  change: true,
});
await callTx.fee();

// 3. Compute BIP-143 sighash preimage for OP_PUSH_TX
const scope = TransactionSignature.SIGHASH_ALL | TransactionSignature.SIGHASH_FORKID;
const preimageBytes = TransactionSignature.formatBytes({
  sourceTXID: deployTx.id('hex'),
  sourceOutputIndex: 0,
  sourceSatoshis: 10_000,
  transactionVersion: callTx.version,
  otherInputs: [],
  outputs: callTx.outputs,
  inputIndex: 0,
  subscript: oldLockingScript,
  inputSequence: 0xffffffff,
  lockTime: callTx.lockTime,
  scope,
});

// 4. Sign the preimage (OP_PUSH_TX uses a well-known key)
const singleHash = Hash.sha256(Array.from(preimageBytes));
const sig = privKey.sign(singleHash);
const txSig = new TransactionSignature(sig.r, sig.s, scope);
const sigDer = txSig.toChecksigFormat();

// 5. Build unlocking script: <sig> <preimage> [method args] [method index]
const unlockHex = contract.buildUnlockingScript('increment', [
  bytesToHex(new Uint8Array(sigDer)),
  bytesToHex(new Uint8Array(preimageBytes)),
]);
callTx.inputs[0].unlockingScript = UnlockingScript.fromHex(unlockHex);

await callTx.broadcast(broadcaster);
```

### Multi-Method Dispatch

For contracts with multiple public methods, the unlocking script includes a method selector index:

```typescript
// Escrow has 4 methods: releaseBySeller(0), releaseByArbiter(1), refundToBuyer(2), refundByArbiter(3)
const unlock = contract.buildUnlockingScript('releaseByArbiter', [sigHex]);
// Internally appends OP_1 (method index 1) after the arguments
```

### Read State from an Existing UTXO

```typescript
import { extractStateFromScript } from 'runar-sdk';

// Fetch the UTXO's locking script from the blockchain
const utxo = await provider.getTransaction(txid);
const scriptHex = utxo.outputs[0].script;

// Extract the state fields
const state = extractStateFromScript(artifact, scriptHex);
console.log(state.count);  // 2n
```

---

## Production Integration: Go (go-sdk)

The Go BSV SDK (`github.com/bsv-blockchain/go-sdk`) provides the same capabilities for transaction construction.

### Deploy a Contract

```go
package main

import (
    "encoding/hex"
    "log"

    "github.com/bsv-blockchain/go-sdk/primitives/ec"
    "github.com/bsv-blockchain/go-sdk/script"
    "github.com/bsv-blockchain/go-sdk/transaction"
    "github.com/bsv-blockchain/go-sdk/transaction/sighash"
)

func main() {
    // Load the compiled locking script hex from the artifact
    lockingScriptHex := artifact.Script // from JSON artifact

    // Generate or load a keypair
    privKey, _ := ec.NewPrivateKey()
    pubKey := privKey.PubKey()
    address, _ := script.NewAddressFromPublicKey(pubKey, true)

    // Build deployment transaction
    deployTx := transaction.NewTransaction()

    // Add funding input (P2PKH UTXO you control)
    _ = deployTx.AddInputFrom(
        fundingTxID,   // hex txid of the funding UTXO
        0,             // output index
        fundingScript, // P2PKH locking script of the funding UTXO
        100_000,       // satoshis in the funding UTXO
        nil,           // unlocking script (will be signed below)
    )

    // Output 0: contract UTXO
    lockScript, _ := script.NewFromHex(lockingScriptHex)
    deployTx.AddOutput(&transaction.TransactionOutput{
        Satoshis:      10_000,
        LockingScript: lockScript,
    })

    // Output 1: change back to sender
    changeScript, _ := script.NewP2PKHFromAddress(address)
    deployTx.AddOutput(&transaction.TransactionOutput{
        Satoshis:      89_000, // 100k - 10k - ~1k fee
        LockingScript: changeScript,
    })

    // Sign the funding input
    sigHash, _ := deployTx.CalcInputSignatureHash(0, sighash.AllForkID)
    sig, _ := privKey.Sign(sigHash)
    sigBytes := append(sig.Serialize(), byte(sighash.AllForkID))

    unlockScript := &script.Script{}
    _ = unlockScript.AppendPushData(sigBytes)
    _ = unlockScript.AppendPushData(pubKey.Compressed())
    deployTx.Inputs[0].UnlockingScript = unlockScript

    // Broadcast (use your preferred provider)
    rawTx := hex.EncodeToString(deployTx.Bytes())
    log.Printf("Deploy txid: %s", deployTx.TxID())
}
```

### Call a Stateful Method

```go
// Build the spending transaction
spendTx := transaction.NewTransaction()

// Input: the contract UTXO
spendTx.AddInputWithOutput(
    &transaction.TransactionInput{
        SourceTXID:       deployTxID,
        SourceTxOutIndex: 0,
        SequenceNumber:   0xffffffff,
    },
    &transaction.TransactionOutput{
        Satoshis:      10_000,
        LockingScript: lockScript, // the current locking script
    },
)

// Output 0: new contract UTXO with updated state
newLockScript, _ := script.NewFromHex(newLockingScriptHex) // updated state
spendTx.AddOutput(&transaction.TransactionOutput{
    Satoshis:      10_000,
    LockingScript: newLockScript,
})

// Output 1: change
spendTx.AddOutput(&transaction.TransactionOutput{
    Satoshis:      changeAmount,
    LockingScript: changeScript,
})

// OP_PUSH_TX: compute preimage and sign
preimage, _ := spendTx.CalcInputPreimage(0, sighash.AllForkID)
preimageHash := sha256d(preimage) // double SHA-256

sig, _ := privKey.Sign(preimageHash)
sigBytes := append(sig.Serialize(), byte(sighash.AllForkID))

// Build unlocking script: <sig> <preimage> [method args] [method index]
unlockScript := &script.Script{}
_ = unlockScript.AppendPushData(sigBytes)
_ = unlockScript.AppendPushData(preimage)
// For method index (if multi-method): unlockScript.AppendPushDataByte(0x00)
spendTx.Inputs[0].UnlockingScript = unlockScript

rawTx := hex.EncodeToString(spendTx.Bytes())
log.Printf("Call txid: %s", spendTx.TxID())
```

### Script Execution (Local Verification)

Verify that a spending transaction is valid before broadcasting:

```go
import "github.com/bsv-blockchain/go-sdk/script/interpreter"

eng := interpreter.NewEngine()
err := eng.Execute(
    interpreter.WithScripts(lockingScript, unlockingScript),
    interpreter.WithAfterGenesis(),  // enable BSV Genesis opcodes
    interpreter.WithForkID(),        // enable BIP-143 sighash
)
if err != nil {
    log.Fatalf("Script execution failed: %v", err)
}
```

---

## Provider & Signer Interfaces

The SDK abstracts blockchain access and key management:

### Provider

```typescript
interface Provider {
  getTransaction(txid: string): Promise<Transaction>;
  broadcast(rawTx: string): Promise<string>;  // returns txid
  getUtxos(address: string): Promise<UTXO[]>;
  getContractUtxo(scriptHash: string): Promise<UTXO | null>;
  getNetwork(): 'mainnet' | 'testnet';
  getFeeRate(): Promise<number>;  // satoshis per byte (default: 1 for BSV)
}
```

Built-in implementations: `WhatsOnChainProvider` (production), `MockProvider` (testing).

### Signer

```typescript
interface Signer {
  getPublicKey(): Promise<string>;
  getAddress(): Promise<string>;
  sign(txHex: string, inputIndex: number, subscript: string, satoshis: number, sigHashType?: number): Promise<string>;
}
```

Built-in implementations: `LocalSigner` (in-memory key, testing/CLI), `ExternalSigner` (hardware wallet callback).

---

## Cross-Compiler Workflow

All three compilers (TypeScript, Go, Rust) produce byte-identical Bitcoin Script for the same contract. You can:

1. **Write** in any format (`.runar.ts`, `.runar.go`, `.runar.rs`, `.runar.sol`, `.runar.move`)
2. **Test** with the native test runner (`vitest`, `go test`, `cargo test`)
3. **Compile** with any compiler
4. **Deploy** the same artifact from any language

The ANF IR is the portable interchange format:

```bash
runar compile Counter.runar.ts --ir          # generates Counter-anf.json
runar-go --ir Counter-anf.json -o Counter.json
runar-rust --ir Counter-anf.json -o Counter.json
```

All three produce identical `script` hex. The conformance test suite validates this.

---

## Deployment SDKs

Deployment SDKs are available in all three languages. Each provides the same API surface: `RunarContract` for lifecycle management, `Provider` for blockchain access, and `Signer` for key operations.

### Go SDK (`packages/runar-go/`)

```go
import "runar"

// Load artifact
artifact := runar.RunarArtifact{}
json.Unmarshal(data, &artifact)

// Create contract
contract := runar.NewRunarContract(&artifact, []interface{}{pubKeyHash})

// Deploy
provider := runar.NewMockProvider("testnet")
signer := runar.NewExternalSigner(pubKeyHex, address, signFunc)
txid, tx, err := contract.Deploy(provider, signer, runar.DeployOptions{Satoshis: 50000})

// Call
txid, tx, err = contract.Call("unlock", []interface{}{sig, pubKey}, provider, signer, nil)
```

Signing is delegated via the `ExternalSigner` callback pattern. For real ECDSA signing, wrap `github.com/bsv-blockchain/go-sdk` in an `ExternalSigner`.

### Rust SDK (`packages/runar-rs/src/sdk/`)

```rust
use runar::sdk::*;

// Load artifact
let artifact: RunarArtifact = serde_json::from_str(&data)?;

// Create contract
let mut contract = RunarContract::new(artifact, vec![SdkValue::Bytes(pub_key_hash)]);

// Deploy
let mut provider = MockProvider::new("testnet");
let signer = MockSigner::new();
let txid = contract.deploy(&mut provider, &signer, &DeployOptions {
    satoshis: 50000,
    change_address: None,
})?;

// Call
let txid = contract.call("unlock", &[sig, pub_key], &mut provider, &signer, None)?;
```

Signing is delegated via the `ExternalSigner` closure pattern. For real ECDSA signing, wrap `rust-sv` in an `ExternalSigner`.
