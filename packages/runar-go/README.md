# runar-go

**Deploy, call, and interact with compiled Runar smart contracts on BSV from Go.**

The Go SDK provides the runtime layer between compiled contract artifacts and the BSV blockchain. It handles transaction construction, signing, broadcasting, state management for stateful contracts, and UTXO tracking.

---

## Installation

```bash
go get github.com/icellan/runar/packages/runar-go
```

The module name is `runar`. If using the go.work workspace, `import "runar"` resolves directly.

---

## Contract Lifecycle

A Runar contract goes through four stages:

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

```go
import "runar"

// 1. Load the artifact (compiled contract JSON)
artifact := &runar.RunarArtifact{ /* loaded from JSON */ }

// 2. Create the contract with constructor arguments
contract := runar.NewRunarContract(artifact, []interface{}{pubKeyHash})

// 3. Set up provider and signer
//    Use ExternalSigner to wrap a real signing library (e.g. go-sdk)
signer := runar.NewExternalSigner(pubKeyHex, address,
    func(txHex string, inputIndex int, subscript string, satoshis int64, sigHashType *int) (string, error) {
        // Delegate to your signing library here
        return signWithGoSDK(txHex, inputIndex, subscript, satoshis, sigHashType)
    },
)
provider := runar.NewMockProvider("testnet")

// 4. Connect provider and signer (optional -- avoids passing them on every call)
contract.Connect(provider, signer)

// 5. Deploy
txid, tx, err := contract.Deploy(nil, nil, runar.DeployOptions{Satoshis: 10000})

// 6. Call a public method
txid2, tx2, err := contract.Call("unlock", []interface{}{sig, pubKey}, nil, nil, nil)
```

### Stateful Contract Example

```go
// Create with initial state
artifact := &runar.RunarArtifact{ /* Counter artifact with stateFields */ }
contract := runar.NewRunarContract(artifact, []interface{}{int64(0)}) // initial count

// Deploy
contract.Connect(provider, signer)
txid, _, err := contract.Deploy(nil, nil, runar.DeployOptions{Satoshis: 10000})

// Read current state
state := contract.GetState()
fmt.Println("Count:", state["count"]) // 0

// Call increment with updated state
txid2, _, err := contract.Call("increment", nil, nil, nil, &runar.CallOptions{
    Satoshis: 9500,
    NewState: map[string]interface{}{"count": int64(1)},
})
fmt.Println("Count:", contract.GetState()["count"]) // 1
```

### Reconnecting to a Deployed Contract

```go
// Reconnect to an existing on-chain contract by txid
contract, err := runar.FromTxId(artifact, txid, 0, provider)
fmt.Println("Current state:", contract.GetState())
```

---

## Providers

Providers handle communication with the BSV network: fetching UTXOs, broadcasting transactions, and querying transaction data.

### MockProvider

For unit testing without network access:

```go
provider := runar.NewMockProvider("testnet")

// Pre-register UTXOs
provider.AddUtxo("myAddress", runar.UTXO{
    Txid:        "abc123...",
    OutputIndex: 0,
    Satoshis:    10000,
    Script:      "76a914...88ac",
})

// Pre-register transactions
provider.AddTransaction(&runar.Transaction{
    Txid:    "abc123...",
    Version: 1,
    Outputs: []runar.TxOutput{{Satoshis: 10000, Script: "76a914...88ac"}},
})

// Pre-register contract UTXOs for stateful lookup
provider.AddContractUtxo("scripthash...", &runar.UTXO{...})

// Inspect broadcasts
broadcastedTxs := provider.GetBroadcastedTxs()

// Override the fee rate (default 1 sat/byte)
provider.SetFeeRate(2)
```

### Custom Provider

Implement the `Provider` interface for other network APIs:

```go
type Provider interface {
    GetTransaction(txid string) (*Transaction, error)
    Broadcast(rawTx string) (string, error)
    GetUtxos(address string) ([]UTXO, error)
    GetContractUtxo(scriptHash string) (*UTXO, error)
    GetNetwork() string
    GetFeeRate() (int64, error)
}
```

Production providers (e.g. WhatsOnChain) are not included in this package -- implement the interface using your preferred HTTP client or use a community adapter.

---

## Signers

Signers handle private key operations: signing transactions and deriving public keys.

### MockSignerImpl

For unit testing without real crypto:

```go
signer := runar.NewMockSigner("", "") // uses deterministic defaults
pubKey, _ := signer.GetPublicKey()     // 66-char hex
address, _ := signer.GetAddress()
sig, _ := signer.Sign(txHex, 0, subscript, satoshis, nil)
```

### ExternalSigner

Delegates signing to a caller-provided callback. Use this to wrap real signing libraries (e.g. `github.com/bsv-blockchain/go-sdk`):

```go
signer := runar.NewExternalSigner(pubKeyHex, address,
    func(txHex string, inputIndex int, subscript string, satoshis int64, sigHashType *int) (string, error) {
        // Your signing logic here
        return derSignatureHex, nil
    },
)
```

### Custom Signer

Implement the `Signer` interface:

```go
type Signer interface {
    GetPublicKey() (string, error)
    GetAddress() (string, error)
    Sign(txHex string, inputIndex int, subscript string, satoshis int64, sigHashType *int) (string, error)
}
```

---

## Stateful Contract Support

### State Chaining

Stateful contracts maintain state across transactions using the OP_PUSH_TX pattern. The SDK manages this automatically:

1. **Deploy:** The initial state is serialized and appended after an OP_RETURN separator in the locking script.
2. **Call:** The SDK reads the current state from the existing UTXO, builds the unlocking script, and creates a new output with the updated locking script containing the new state.
3. **Read:** `GetState()` returns the deserialized state from the UTXO's locking script.

### State Serialization Format

State is stored as a suffix of the locking script:

```
<code_part> OP_RETURN <field_0> <field_1> ... <field_n>
```

Type-specific encoding:
- `int`/`bigint`: OP_0 for zero, otherwise minimally-encoded Script integers (with sign byte)
- `bool`: OP_0 (`00`) for false, OP_1 (`51`) for true
- `bytes`/`ByteString`/`PubKey`/`Addr`/`Sha256`: direct pushdata

---

## Transaction Building Utilities

The SDK exports lower-level functions for custom transaction construction:

```go
// Select UTXOs (largest-first strategy, optional feeRate in sat/byte)
selected := runar.SelectUtxos(utxos, targetSatoshis, lockingScriptByteLen, feeRate)

// Estimate deployment fee (optional feeRate in sat/byte, default 1)
fee := runar.EstimateDeployFee(numInputs, lockingScriptByteLen, feeRate)

// Build an unsigned deploy transaction (optional feeRate in sat/byte)
txHex, inputCount, err := runar.BuildDeployTransaction(
    lockingScript, utxos, satoshis, changeAddress, changeScript, feeRate,
)

// Build a method call transaction (optional feeRate in sat/byte)
txHex, inputCount := runar.BuildCallTransaction(
    currentUtxo, unlockingScript, newLockingScript, newSatoshis,
    changeAddress, changeScript, additionalUtxos, feeRate,
)

// State serialization
stateHex := runar.SerializeState(stateFields, values)
state := runar.DeserializeState(stateFields, stateHex)
state := runar.ExtractStateFromScript(artifact, fullLockingScriptHex)
```

---

## Types

```go
type Transaction struct {
    Txid     string
    Version  int
    Inputs   []TxInput
    Outputs  []TxOutput
    Locktime int
    Raw      string
}

type UTXO struct {
    Txid        string
    OutputIndex int
    Satoshis    int64
    Script      string // hex
}

type DeployOptions struct {
    Satoshis      int64
    ChangeAddress string
}

type CallOptions struct {
    Satoshis      int64
    ChangeAddress string
    NewState      map[string]interface{}
}
```

---

## Design Decisions

- **No built-in network provider:** Go applications typically have their own HTTP client preferences and middleware. Implement the `Provider` interface with your stack.
- **No built-in crypto signer:** Go applications should use established libraries like `github.com/bsv-blockchain/go-sdk` for secp256k1 operations. The `ExternalSigner` callback pattern makes integration straightforward.
- **`interface{}` for state values:** Go lacks sum types, so state values use `interface{}` (int64 for bigint, bool for bool, string for hex bytes).
- **Synchronous API:** All methods are synchronous. Use goroutines for concurrent operations.
