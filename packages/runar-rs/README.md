# runar-rs

**Deploy, call, and interact with compiled Runar smart contracts on BSV from Rust.**

The Rust SDK provides the runtime layer between compiled contract artifacts and the BSV blockchain. It handles transaction construction, signing, broadcasting, state management for stateful contracts, and UTXO tracking.

---

## Installation

Add to your `Cargo.toml`:

```toml
[dependencies]
runar = { package = "runar-lang", version = "0.1.0" }
```

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

```rust
use runar::sdk::*;

// 1. Load the artifact (compiled contract JSON)
let artifact: RunarArtifact = serde_json::from_str(&json)?;

// 2. Create the contract with constructor arguments
//    Panics if the number of args does not match the artifact's constructor params.
let mut contract = RunarContract::new(artifact, vec![
    SdkValue::Bytes(pub_key_hash),
]);

// 3. Set up provider and signer
//    Use ExternalSigner to wrap a real signing library
let signer = ExternalSigner::new(
    || Ok(pub_key_hex.clone()),
    || Ok(address.clone()),
    |tx_hex, input_index, subscript, satoshis, sig_hash_type| {
        // Delegate to your signing library here
        sign_with_rust_sv(tx_hex, input_index, subscript, satoshis, sig_hash_type)
    },
);
let mut provider = MockProvider::testnet();

// 4. Deploy
let (txid, tx) = contract.deploy(&mut provider, &signer, &DeployOptions {
    satoshis: 10_000,
    change_address: None,
})?;

// 5. Call a public method
let (txid2, tx2) = contract.call("unlock", &[
    SdkValue::Bytes(sig),
    SdkValue::Bytes(pub_key),
], &mut provider, &signer, None)?;
```

### Connected API

Instead of passing the provider and signer to every `deploy()` and `call()` invocation, you can store them on the contract with `connect()` and then use `deploy_connected()` / `call_connected()`:

```rust
use runar::sdk::*;

let mut contract = RunarContract::new(artifact, vec![SdkValue::Int(0)]);

// Store provider and signer on the contract
contract.connect(
    Box::new(MockProvider::testnet()),
    Box::new(MockSigner::new()),
);

// Deploy without passing provider/signer
let (txid, tx) = contract.deploy_connected(&DeployOptions {
    satoshis: 10_000,
    change_address: None,
})?;

// Call without passing provider/signer
let (txid2, tx2) = contract.call_connected("increment", &[], None)?;
```

If `connect()` has not been called, `deploy_connected()` and `call_connected()` return an error.

### Stateful Contract Example

```rust
use std::collections::HashMap;

// Create with initial state
let mut contract = RunarContract::new(counter_artifact, vec![SdkValue::Int(0)]);

// Deploy
let (txid, _) = contract.deploy(&mut provider, &signer, &DeployOptions {
    satoshis: 10_000,
    change_address: None,
})?;

// Read current state
println!("Count: {:?}", contract.state().get("count")); // Some(Int(0))

// Call increment with updated state
let mut new_state = HashMap::new();
new_state.insert("count".to_string(), SdkValue::Int(1));
let (txid2, _) = contract.call("increment", &[], &mut provider, &signer, Some(&CallOptions {
    satoshis: Some(9_500),
    change_address: None,
    new_state: Some(new_state),
}))?;
println!("Count: {:?}", contract.state().get("count")); // Some(Int(1))

// Update state directly (without a call)
let mut override_state = HashMap::new();
override_state.insert("count".to_string(), SdkValue::Int(99));
contract.set_state(override_state);
```

### Reconnecting to a Deployed Contract

```rust
// Reconnect to an existing on-chain contract by txid
let contract = RunarContract::from_txid(artifact, &txid, 0, &provider)?;
println!("Current state: {:?}", contract.state());
```

### Script Access

```rust
// Get the full locking script hex (code + OP_RETURN + state for stateful contracts)
let locking_script = contract.get_locking_script();

// Build an unlocking script for a method call
let unlock = contract.build_unlocking_script("transfer", &[
    SdkValue::Bytes(sig_hex),
    SdkValue::Bytes(pubkey_hex),
])?;
```

---

## Providers

Providers handle communication with the BSV network: fetching UTXOs, broadcasting transactions, and querying transaction data.

### MockProvider

For unit testing without network access:

```rust
// Create with a specific network name
let mut provider = MockProvider::new("mainnet");
// Or use the testnet shorthand
let mut provider = MockProvider::testnet();

// Pre-register UTXOs
provider.add_utxo("myAddress", Utxo {
    txid: "abc123...".to_string(),
    output_index: 0,
    satoshis: 10_000,
    script: "76a914...88ac".to_string(),
});

// Pre-register transactions
provider.add_transaction(Transaction { /* ... */ });

// Pre-register contract UTXOs for stateful lookup
provider.add_contract_utxo("scripthash...", Utxo { /* ... */ });

// Inspect broadcasts after deploying/calling
let broadcasted: &[String] = provider.get_broadcasted_txs();

// Override the fee rate (default 1 sat/byte)
provider.set_fee_rate(2);
```

### Custom Provider

Implement the `Provider` trait for other network APIs:

```rust
pub trait Provider {
    fn get_transaction(&self, txid: &str) -> Result<Transaction, String>;
    fn get_raw_transaction(&self, txid: &str) -> Result<String, String>;
    fn broadcast(&mut self, raw_tx: &str) -> Result<String, String>;
    fn get_utxos(&self, address: &str) -> Result<Vec<Utxo>, String>;
    fn get_contract_utxo(&self, script_hash: &str) -> Result<Option<Utxo>, String>;
    fn get_network(&self) -> &str;
    fn get_fee_rate(&self) -> Result<i64, String>;
}
```

Production providers are not included in this crate -- implement the trait using your preferred HTTP client.

---

## Signers

Signers handle private key operations: signing transactions and deriving public keys.

### MockSigner

For unit testing without real crypto. Returns deterministic dummy values (a fixed 66-char hex public key, a fixed 40-char hex address, and a fixed mock DER signature):

```rust
let signer = MockSigner::new();
let pub_key = signer.get_public_key()?;  // "0200...00" (66-char hex)
let address = signer.get_address()?;     // "0000...00" (40-char hex)
let sig = signer.sign(tx_hex, 0, subscript, satoshis, None)?;

// Fields are public for customization in tests
let custom = MockSigner {
    public_key: "02aabb...".to_string(),
    address: "myaddr".to_string(),
};
```

`MockSigner` also implements `Default` (equivalent to `MockSigner::new()`).

### LocalSigner

Holds a private key in memory and performs real secp256k1 ECDSA signing with BIP-143 sighash computation. Uses the `k256` crate for ECDSA and manual BIP-143 preimage construction. Accepts hex or WIF private keys:

```rust
// From hex
let signer = LocalSigner::new("0000...0001")?;

// From WIF
let signer = LocalSigner::new("KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFU73sVHnoWn")?;

let pub_key = signer.get_public_key()?;  // 66-char compressed pubkey hex
let address = signer.get_address()?;     // mainnet P2PKH address (starts with "1")
let sig = signer.sign(tx_hex, 0, subscript, satoshis, None)?;  // DER + sighash byte
```

Suitable for CLI tooling and testing. For production wallets, use ExternalSigner with hardware wallet callbacks.

### ExternalSigner

Delegates signing to caller-provided closures. Use this to wrap real signing libraries (e.g., `rust-sv`, `secp256k1`):

```rust
let signer = ExternalSigner::new(
    || Ok("02aabb...".to_string()),           // get_public_key
    || Ok("1Address...".to_string()),          // get_address
    |tx_hex, idx, sub, sats, sht| {            // sign
        Ok(your_sign_fn(tx_hex, idx, sub, sats, sht))
    },
);
```

### Custom Signer

Implement the `Signer` trait:

```rust
pub trait Signer {
    fn get_public_key(&self) -> Result<String, String>;
    fn get_address(&self) -> Result<String, String>;
    fn sign(
        &self,
        tx_hex: &str,
        input_index: usize,
        subscript: &str,
        satoshis: i64,
        sig_hash_type: Option<u32>,
    ) -> Result<String, String>;
}
```

---

## Stateful Contract Support

### State Chaining

Stateful contracts maintain state across transactions using the OP_PUSH_TX pattern. The SDK manages this automatically:

1. **Deploy:** The initial state is serialized and appended after an OP_RETURN separator in the locking script.
2. **Call:** The SDK reads the current state from the existing UTXO, builds the unlocking script, and creates a new output with the updated locking script containing the new state.
3. **Read:** `contract.state()` returns the deserialized state as `&HashMap<String, SdkValue>`.

### State Serialization Format

State is stored as a suffix of the locking script:

```
<code_part> OP_RETURN <field_0> <field_1> ... <field_n>
```

Type-specific encoding:
- `int`/`bigint`: OP_0 for zero, otherwise minimally-encoded Script integers (with sign byte)
- `bool`: OP_0 (`00`) for false, OP_1 (`51`) for true
- `bytes`/`ByteString`/`PubKey`/`Addr`/`Sha256`/`Ripemd160`: direct pushdata

The `find_last_op_return()` function uses opcode-aware walking to locate the real OP_RETURN boundary, properly skipping `0x6a` bytes inside push data payloads.

---

## Value Types

The `SdkValue` enum represents typed contract values:

```rust
pub enum SdkValue {
    Int(i64),
    Bool(bool),
    Bytes(String),  // hex-encoded
    Auto,           // placeholder for auto-computed Sig/PubKey parameters
}
```

Convenience accessors are available. They panic if called on the wrong variant:

```rust
let n: i64 = value.as_int();    // panics if not Int
let b: bool = value.as_bool();  // panics if not Bool
let s: &str = value.as_bytes(); // panics if not Bytes
```

---

## Transaction Building Utilities

The SDK exports lower-level functions for custom transaction construction:

```rust
use runar::sdk::deployment::*;
use runar::sdk::calling::*;
use runar::sdk::state::*;

// Select UTXOs (largest-first strategy)
let selected = select_utxos(&utxos, target_satoshis, locking_script_byte_len, Some(fee_rate));

// Estimate the fee for a deploy transaction
let fee = estimate_deploy_fee(num_inputs, locking_script_byte_len, Some(fee_rate));

// Build an unsigned deploy transaction
// Panics if utxos is empty or if total funds are insufficient.
let (tx_hex, input_count) = build_deploy_transaction(
    &locking_script, &utxos, satoshis, change_address, &change_script, Some(fee_rate),
);

// Build a method call transaction
let (tx_hex, input_count) = build_call_transaction(
    &current_utxo, &unlocking_script, Some(new_locking_script), Some(new_satoshis),
    Some(change_address), Some(&change_script), Some(&additional_utxos), Some(fee_rate),
);

// State serialization
let state_hex = serialize_state(&state_fields, &values);
let state: HashMap<String, SdkValue> = deserialize_state(&state_fields, &state_hex);
let state: Option<HashMap<String, SdkValue>> = extract_state_from_script(&artifact, &full_script);

// Opcode-aware OP_RETURN finder (returns hex-char offset or None)
let pos: Option<usize> = find_last_op_return(&script_hex);
```

---

## Panics

Several functions panic instead of returning `Result` for programmer errors:

| Function | Panic condition |
|---|---|
| `RunarContract::new()` | Constructor arg count does not match artifact ABI |
| `build_deploy_transaction()` | Empty UTXO slice, or insufficient funds |
| `SdkValue::as_int()` | Called on a non-`Int` variant |
| `SdkValue::as_bool()` | Called on a non-`Bool` variant |
| `SdkValue::as_bytes()` | Called on a non-`Bytes` variant |

All other error conditions return `Result<T, String>`.

---

## Design Decisions

- **No built-in network provider:** Rust applications typically use specific async runtimes (tokio, async-std) and HTTP clients. Implement the `Provider` trait with your stack.
- **Built-in LocalSigner:** `LocalSigner::new()` provides real secp256k1 signing via the `k256` crate with manual BIP-143 sighash computation. For custom signing flows, use `ExternalSigner` with closure callbacks.
- **Synchronous API:** All methods are synchronous (`fn`, not `async fn`). This makes the SDK usable with any async runtime without imposing `Send`/`Sync` constraints.
- **`SdkValue` enum:** Unlike Go's `interface{}`, Rust uses a typed enum for state values, providing exhaustive matching and type safety.
