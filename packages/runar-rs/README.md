# Rúnar Rust SDK

`runar-lang` — write, compile, deploy, and call Rúnar smart contracts on Bitcoin SV from Rust.

The crate ships in two layers:

- **Contract authoring** — the `runar::prelude::*` module plus the proc-macro
  attributes from `runar-lang-macros` give you the types, intrinsics, and
  decorators needed to write a `.runar.rs` source file that the Rúnar compiler
  can translate to Bitcoin Script.
- **Deployment SDK** — `runar::sdk::*` is the runtime layer between a compiled
  artifact and the chain. It builds, signs, and broadcasts deploy/call
  transactions, tracks state for stateful contracts, and ships a BRC-100 wallet
  bridge for browser-style key custody.

The same Rust source compiles to byte-identical Bitcoin Script as the six other
Rúnar compilers (TS, Go, Python, Zig, Ruby, Java) and the SDKs produce
byte-identical deploy outputs (verified by
[`conformance/sdk-output/tests/stateful-counter`](../../conformance/sdk-output/tests/stateful-counter)).

---

## Table of Contents

1. [Installation](#1-installation)
2. [Quick Start](#2-quick-start)
3. [Core Concepts](#3-core-concepts)
4. [Writing a Contract](#4-writing-a-contract)
5. [Compiling](#5-compiling)
6. [Deploying Contracts](#6-deploying-contracts)
7. [Calling Contract Methods](#7-calling-contract-methods)
   - [7a. Single-signer (`call` / `call_connected`)](#7a-single-signer-call--call_connected)
   - [7b. Multi-signer (`prepare_call` / `finalize_call`)](#7b-multi-signer-prepare_call--finalize_call)
   - [7c. BRC-100 wallet signing (`WalletProvider<W>` + `WalletSigner<W>`)](#7c-brc-100-wallet-signing-walletproviderw--walletsignerw)
8. [Stateful Contracts](#8-stateful-contracts)
9. [UTXO and Fee Management](#9-utxo-and-fee-management)
10. [Typed Contract Bindings (`generate_rust`)](#10-typed-contract-bindings-generate_rust)
11. [Testing](#11-testing)
    - [11a. Off-chain testing](#11a-off-chain-testing)
    - [11b. Integration testing against a regtest node](#11b-integration-testing-against-a-regtest-node)
12. [Provider Configuration](#12-provider-configuration)
13. [Full API Reference](#13-full-api-reference)
14. [Error Handling](#14-error-handling)
15. [Troubleshooting / FAQ](#15-troubleshooting--faq)
16. [Versioning and Stability](#16-versioning-and-stability)
17. [Links](#17-links)

> Section numbering follows the canonical 19-section README layout used across
> all seven Rúnar SDKs. Sections 9a/9b/9c, 13a/13b are addressed inside their
> parent sections (8a/8b/8c, 11a/11b here) to keep the table of contents flat
> in the rendered crates.io view.

---

## 1. Installation

Add to your `Cargo.toml`:

```toml
[dependencies]
runar = { package = "runar-lang", version = "0.4" }
```

The crate is **published as `runar-lang`** and conventionally renamed to
`runar` via Cargo's `package = ...` field — every example and integration test
in this repository imports it as `runar`. If you keep the published name, all
paths in this README reduce to `runar_lang::…` instead of `runar::…`.

The proc-macro crate `runar-lang-macros` is pulled in transitively; you do not
need to declare it explicitly.

Minimum supported Rust version: **1.70** (the SDK uses `let-else`, GATs in trait
return types, and standard `?` propagation).

The SDK has no compile-time feature flags — every provider, signer, and codegen
helper compiles by default. The transitive dependency surface is documented in
[`Cargo.toml`](Cargo.toml).

---

## 2. Quick Start

Compile a `Counter` contract, deploy it, increment it twice, and read the new
state. Counter is the simplest stateful contract in the language —
[`examples/rust/stateful-counter/Counter.runar.rs`](../../examples/rust/stateful-counter/Counter.runar.rs):

```rust
// examples/rust/stateful-counter/Counter.runar.rs
use runar::prelude::*;

#[runar::contract]
pub struct Counter {
    pub count: Bigint,
}

#[runar::methods(Counter)]
impl Counter {
    #[public]
    pub fn increment(&mut self) {
        self.count += 1;
    }

    #[public]
    pub fn decrement(&mut self) {
        assert!(self.count > 0);
        self.count -= 1;
    }
}
```

End-to-end deploy + call against a `MockProvider`:

```rust
use std::collections::HashMap;
use runar::sdk::{
    DeployOptions, MockProvider, MockSigner,
    RunarArtifact, RunarContract, SdkValue, Signer, Utxo,
};

fn main() -> Result<(), String> {
    // 1. Load the artifact (produced by the compiler — see Section 5).
    let artifact_json = std::fs::read_to_string("Counter.artifact.json")
        .map_err(|e| format!("read artifact: {}", e))?;
    let artifact: RunarArtifact = serde_json::from_str(&artifact_json)
        .map_err(|e| format!("parse artifact: {}", e))?;

    // 2. Construct the contract with `count = 0`.
    let mut contract = RunarContract::new(artifact, vec![SdkValue::Int(0)]);

    // 3. Wire up provider + signer (use real ones in production).
    let mut provider = MockProvider::testnet();
    let signer = MockSigner::new();
    provider.add_utxo(&signer.get_address()?, Utxo {
        txid: "aa".repeat(32),
        output_index: 0,
        satoshis: 50_000,
        script: format!("76a914{}88ac", "00".repeat(20)),
    });

    // 4. Deploy.
    let (deploy_txid, _tx) = contract.deploy(
        &mut provider,
        &signer,
        &DeployOptions { satoshis: 5_000, change_address: None },
    )?;
    println!("deployed at {}", deploy_txid);

    // 5. Call increment twice (0 -> 1 -> 2). State is tracked automatically.
    contract.call("increment", &[], &mut provider, &signer, None)?;
    contract.call("increment", &[], &mut provider, &signer, None)?;

    // 6. Read state.
    let count = contract.state().get("count").unwrap().as_int();
    assert_eq!(count, 2);
    println!("count = {}", count);
    Ok(())
}
```

The `MockProvider` records broadcast hex but does not exercise the on-chain VM.
For a real chain, swap `MockProvider` → `RPCProvider`, `WhatsOnChainProvider`,
or `WalletProvider<W>` (Section 12), and `MockSigner` → `LocalSigner` or
`WalletSigner<W>` (Section 13). The reference end-to-end flow against a
regtest node lives in
[`integration/rust/tests/counter.rs`](../../integration/rust/tests/counter.rs).

---

## 3. Core Concepts

The SDK is built around a small set of orthogonal types that compose into the
deploy → call → call lifecycle. Each concept appears as a Rust type in
`runar::sdk` and is defined here only — Sections 4 onward refer back without
re-introducing them.

| Concept | Rust type | Where |
|---------|-----------|-------|
| **Provider** | trait `Provider` | [`src/sdk/provider.rs`](src/sdk/provider.rs) |
| **Signer** | trait `Signer` | [`src/sdk/signer.rs`](src/sdk/signer.rs) |
| **Contract** | `RunarContract` | [`src/sdk/contract.rs`](src/sdk/contract.rs) |
| **Artifact** | `RunarArtifact` (deserialized from JSON) | [`src/sdk/types.rs`](src/sdk/types.rs) |
| **Call** | `RunarContract::call` / `call_connected` | [`src/sdk/contract.rs`](src/sdk/contract.rs) |
| **PreparedCall** | `PreparedCall` | [`src/sdk/types.rs`](src/sdk/types.rs) |
| **State** | `HashMap<String, SdkValue>` returned by `RunarContract::state()` | [`src/sdk/state.rs`](src/sdk/state.rs) |
| **UTXO** | `Utxo` | [`src/sdk/types.rs`](src/sdk/types.rs) |
| **SdkValue** | enum `SdkValue` (the wire type for every contract argument and state field) | [`src/sdk/types.rs`](src/sdk/types.rs) |
| **Inscription** | `Inscription` (1sat ordinals envelope) | [`src/sdk/ordinals.rs`](src/sdk/ordinals.rs) |
| **Wallet** | trait `WalletClient` (BRC-100 backend) | [`src/sdk/wallet.rs`](src/sdk/wallet.rs) |

### `SdkValue` — the wire type

Every contract argument and every state-field value crosses the SDK boundary as
an `SdkValue`. Pick the variant that matches the param type in the artifact's
ABI (`int` → `Int`, `bigint` → `Int` for ≤ i64 or `BigInt` for larger,
`bool` → `Bool`, byte-string types like `Sig`, `PubKey`, `Addr`,
`Ripemd160`, `Sha256`, `ByteString`, `Point`, `SigHashPreimage` →
`Bytes(hex_string)`):

```rust
use num_bigint::BigInt;
use runar::sdk::SdkValue;

let int_arg     = SdkValue::Int(42);
let big_arg     = SdkValue::BigInt(BigInt::from(10).pow(30));
let bool_arg    = SdkValue::Bool(true);
let bytes_arg   = SdkValue::Bytes("18f5bdad6dac9a0a5044a970edf2897d67a7562d".to_string());
let array_arg   = SdkValue::Array(vec![SdkValue::Int(1), SdkValue::Int(2), SdkValue::Int(3)]);

// Auto = "let the SDK fill this in" — used for Sig, PubKey,
// SigHashPreimage, and ByteString allPrevouts params (Section 7a).
let auto_sig    = SdkValue::Auto;
```

`SdkValue::Array` is the carrier for `FixedArray<T, N>` state fields and gets
flattened into positional scalar slots according to the artifact's
`fixed_array.synthetic_names`.

`as_int()`, `as_bool()`, and `as_bytes()` are convenience accessors — they
panic if the variant doesn't match (this matches the cross-SDK behaviour for
"value of unexpected type"; see Section 14 for typed alternatives).

---

## 4. Writing a Contract

Rúnar Rust contracts live in `*.runar.rs` files. They use plain Rust syntax
plus four proc-macro attributes from `runar-lang-macros` (re-exported under
`runar::` and inside `runar::prelude::*`):

| Attribute | Where it goes | What it does |
|-----------|---------------|--------------|
| `#[runar::contract]` | the contract `struct` | Strips `#[readonly]` field annotations so `rustc` accepts the struct, then passes the struct through unchanged. Used for both stateless and stateful contracts. |
| `#[runar::stateful_contract]` | the contract `struct` | Alias for `#[runar::contract]` — kept for parity with other SDKs. |
| `#[runar::methods(ContractName)]` | the `impl` block | Identity macro that validates it wraps an `impl` block. Required so the parser knows where the method body lives. |
| `#[public]` | each public spending entry point | Identity macro that marks a method as a callable spending path in the compiled artifact. |
| `#[readonly]` | a struct field | (No-op at the Rust level — the proc-macro strips it.) The Rúnar parser uses it to mark stateless / immutable properties. |

Minimal stateless P2PKH:

```rust
use runar::prelude::*;

#[runar::contract]
pub struct P2PKH {
    #[readonly]
    pub pub_key_hash: Addr,
}

#[runar::methods(P2PKH)]
impl P2PKH {
    #[public]
    pub fn unlock(&self, sig: Sig, pub_key: PubKey) {
        assert!(hash160(&pub_key) == self.pub_key_hash);
        assert!(check_sig(&sig, &pub_key));
    }
}
```

The `prelude` exports every type alias (`Bigint`, `Sig`, `PubKey`, `Addr`,
`Ripemd160`, `Sha256`, `Sha256Digest`, `Point`, `ByteString`,
`SigHashPreimage`, `RabinSig`, `RabinPubKey`), every real-crypto verification
helper (`check_sig`, `check_multi_sig`, `check_preimage`, `verify_rabin_sig`,
`verify_wots`, `verify_slh_dsa_sha2_*`), every hash function (`hash160`,
`hash256`, `sha256`, `sha256_hash`, `ripemd160`, `sha256_compress`,
`sha256_finalize`), the EC primitives (`ec_add`, `ec_mul`, `ec_mul_gen`,
`ec_negate`, `ec_on_curve`, `ec_mod_reduce`, `ec_encode_compressed`,
`ec_make_point`, `ec_point_x`, `ec_point_y`), the math intrinsics (`safediv`,
`safemod`, `clamp`, `sign`, `pow`, `mul_div`, `percent_of`, `sqrt`, `gcd`,
`divmod`, `log2`, `bool_cast`), the BabyBear field helpers (`bb_field_*`,
`bb_ext4_*`), the Merkle helpers (`merkle_root_sha256`, `merkle_root_hash256`),
the test mocks (`mock_sig`, `mock_pub_key`, `mock_preimage`), and the
deterministic test keys (`ALICE`, `BOB`, `CHARLIE`).

For the full language guide — assignment vs. reassignment, allowed control
flow, the `addOutput`/`addRawOutput`/`addDataOutput` intrinsics, and which
operators map to which opcodes — see [`docs/formats/rust.md`](../../docs/formats/rust.md).

---

## 5. Compiling

Compile a `.runar.rs` source file from Rust by calling the compiler crate
directly. The compiled artifact is a JSON-serializable struct that the SDK
deserializes into [`RunarArtifact`](src/sdk/types.rs).

```rust
fn compile_to_sdk_artifact(
    source_path: &str,
) -> Result<runar::sdk::RunarArtifact, String> {
    let source = std::fs::read_to_string(source_path)
        .map_err(|e| format!("read source: {}", e))?;
    let file_name = std::path::Path::new(source_path)
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_else(|| "contract.rs".to_string());

    let compiler_artifact = runar_compiler_rust::compile_from_source_str(
        &source,
        Some(&file_name),
    ).map_err(|e| format!("compile: {}", e))?;

    let json = serde_json::to_string(&compiler_artifact)
        .map_err(|e| format!("serialize artifact: {}", e))?;
    serde_json::from_str::<runar::sdk::RunarArtifact>(&json)
        .map_err(|e| format!("deserialize SDK artifact: {}", e))
}
```

If you want to run **only the frontend** (parse → validate → typecheck →
expand-fixed-arrays) — for example inside a `#[test]` that asserts a contract
compiles without producing the full artifact — use [`runar::compile_check`](src/lib.rs):

```rust
#[test]
fn counter_compiles() {
    let source = include_str!("Counter.runar.rs");
    runar::compile_check(source, "Counter.runar.rs").unwrap();
}
```

`compile_check` returns `Ok(())` when the contract is valid Rúnar and an
`Err(String)` describing the first failing pass otherwise. It's the equivalent
of `CompileCheck.run(...)` in the Java SDK and `runar.CompileCheck(...)` in
Go.

---

## 6. Deploying Contracts

Deployment creates a UTXO whose locking script is the contract's compiled
template with the constructor arguments spliced into the slots that the
compiler reserved (see `RunarArtifact::constructor_slots`).

There are two surfaces:

1. **Explicit** — pass `&mut Provider` and `&dyn Signer` on every call. This
   is the idiomatic Rust pattern: ownership is visible and the borrow checker
   keeps you honest.
2. **Connected** — call `contract.connect(provider, signer)` once and then
   use the `*_connected` variants. This is mostly there for parity with the
   TS/Go/Python SDKs; in Rust the explicit form is preferred.

```rust
use runar::sdk::{DeployOptions, LocalSigner, RPCProvider, RunarContract, SdkValue};

fn deploy_counter(
    artifact: runar::sdk::RunarArtifact,
) -> Result<(String, runar::sdk::TransactionData), String> {
    let mut provider = RPCProvider::new_regtest("http://localhost:18332", "bitcoin", "bitcoin");
    let signer = LocalSigner::new("KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFU73sVHnoWn")?;

    let mut contract = RunarContract::new(artifact, vec![SdkValue::Int(0)]);

    let result = contract.deploy(
        &mut provider,
        &signer,
        &DeployOptions {
            satoshis: 5_000,
            change_address: None, // None = use signer's own P2PKH address
        },
    )?;

    assert_eq!(contract.get_utxo().unwrap().txid, result.0);
    Ok(result)
}
```

Connected form (after `contract.connect(...)`):

```rust
use runar::sdk::{DeployOptions, LocalSigner, RPCProvider, RunarContract};

fn deploy_connected(mut contract: RunarContract) -> Result<String, String> {
    let provider = RPCProvider::new_regtest("http://localhost:18332", "bitcoin", "bitcoin");
    let signer = LocalSigner::new("KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFU73sVHnoWn")?;

    contract.connect(Box::new(provider), Box::new(signer));
    let (txid, _tx) = contract.deploy_connected(&DeployOptions {
        satoshis: 5_000,
        change_address: None,
    })?;
    Ok(txid)
}
```

Reconnect later from a known txid+vout:

```rust
use runar::sdk::{Provider, RunarArtifact, RunarContract, Utxo};

fn reconnect(
    artifact: RunarArtifact,
    txid: &str,
    provider: &dyn Provider,
    existing_utxo: &Utxo,
) -> Result<RunarContract, String> {
    let from_txid = RunarContract::from_txid(artifact.clone(), txid, 0, provider)?;
    let _from_utxo = RunarContract::from_utxo(artifact, existing_utxo);
    Ok(from_txid)
}
```

Both helpers parse the on-chain script: the code portion (including any
inscription envelope) is stored verbatim, and stateful contracts have their
state extracted from the section after the last `OP_RETURN` and dropped into
`contract.state()`.

`DeployOptions::change_address` accepts a Base58 BSV address. When `None`, the
signer's own address (from `signer.get_address()`) is used.

---

## 7. Calling Contract Methods

A "call" spends the contract UTXO. For stateful contracts the SDK
automatically produces a continuation output with the updated state so the
contract keeps living at a new outpoint.

`CallOptions` is the sole tunable; all fields are optional and `Default` is
sensible:

```rust
use runar::sdk::CallOptions;

let opts = CallOptions {
    // For stateful contracts, override the satoshi value of the continuation output.
    satoshis: Some(5_000),
    // Override the change address. Default = signer's own P2PKH address.
    change_address: None,
    // Force-overwrite specific state fields after the call (test-only — bypasses
    // the auto-state computation; useful for negative tests like the "wrong
    // state" rejection cases below).
    new_state: None,
    // For multi-output methods (e.g. transfer that splits a UTXO):
    outputs: None,                        // Vec<OutputSpec>
    // For methods that consume additional contract UTXOs as inputs (e.g. merge):
    additional_contract_inputs: None,     // Vec<Utxo>
    additional_contract_input_args: None, // Vec<Vec<SdkValue>>
    // Override the change pubkey (hex). Default = signer's own pubkey.
    change_pub_key: None,
    // Terminal outputs (no continuation, no change — the contract balance pays the fee):
    terminal_outputs: None,               // Vec<TerminalOutput>
    // Override addDataOutput emissions. Default = run the ANF interpreter.
    data_outputs: None,                   // Vec<ContractDataOutput>
};
let _ = opts;
```

### 7a. Single-signer (`call` / `call_connected`)

For the common case — one signer, no off-line coordination — `RunarContract::call`
prepares, signs, and broadcasts the call in one step. Pass `SdkValue::Auto` for
any `Sig`, `PubKey`, `SigHashPreimage`, or `ByteString` (`allPrevouts`) param
that the SDK should fill in:

```rust
use runar::sdk::{Provider, RunarContract, SdkValue, Signer, TransactionData};

fn call_p2pkh_unlock(
    contract: &mut RunarContract,
    provider: &mut dyn Provider,
    signer: &dyn Signer,
) -> Result<(String, TransactionData), String> {
    // Stateless P2PKH unlock: let the SDK auto-resolve sig + pubkey from the signer.
    contract.call(
        "unlock",
        &[SdkValue::Auto, SdkValue::Auto],
        provider,
        signer,
        None,
    )
}
```

Stateful Counter increment — no user-visible args:

```rust
use runar::sdk::{Provider, RunarContract, Signer};

fn increment_once(
    contract: &mut RunarContract,
    provider: &mut dyn Provider,
    signer: &dyn Signer,
) -> Result<(), String> {
    contract.call("increment", &[], provider, signer, None)?;
    // contract.state() now reflects the post-increment value automatically:
    assert_eq!(contract.state().get("count").unwrap().as_int(), 1);
    Ok(())
}
```

Connected variant:

```rust
use runar::sdk::{Provider, RunarContract, Signer};

fn increment_connected(
    mut contract: RunarContract,
    provider: Box<dyn Provider>,
    signer: Box<dyn Signer>,
) -> Result<(), String> {
    contract.connect(provider, signer);
    contract.call_connected("increment", &[], None)?;
    Ok(())
}
```

### 7b. Multi-signer (`prepare_call` / `finalize_call`)

For hardware wallets, multi-party signing, or any flow where the signature is
produced asynchronously, split the call into two phases.

`prepare_call` builds the transaction with **placeholder** sigs at every
`SdkValue::Auto` position and returns a [`PreparedCall`](src/sdk/types.rs)
containing the BIP-143 sighash that an external signer must sign over.
P2PKH funding inputs and any `additional_contract_inputs` are signed by the
attached `signer` during preparation; only the **primary** contract input's
`Sig` params are left as 72-byte zero placeholders.

```rust
use std::collections::HashMap;
use runar::sdk::{PreparedCall, Provider, RunarContract, SdkValue, Signer, TransactionData};

fn external_sign_each(_prepared: &PreparedCall) -> Result<HashMap<usize, String>, String> {
    // Hand `_prepared.sighash` to the hardware wallet, get back DER+sighash sigs
    // keyed by the user-visible arg index. Stub implementation:
    Ok(HashMap::new())
}

fn unlock_with_external_signer(
    contract: &mut RunarContract,
    provider: &mut dyn Provider,
    signer: &dyn Signer,
    pub_key_hex: String,
) -> Result<(String, TransactionData), String> {
    let prepared = contract.prepare_call(
        "unlock",
        &[SdkValue::Auto /* sig */, SdkValue::Bytes(pub_key_hex)],
        provider,
        signer,
        None,
    )?;

    println!("ask hardware wallet to sign sighash: {}", prepared.sighash);
    println!("preimage (full BIP-143):             {}", prepared.preimage);
    let signatures = external_sign_each(&prepared)?;

    // Inject the real sigs and broadcast.
    contract.finalize_call(&prepared, &signatures, provider)
}
```

Connected variants exist as well: `prepare_call_connected` and
`finalize_call_connected`. The key fields on `PreparedCall` for external
signing are `sighash`, `preimage`, `op_push_tx_sig`, `tx_hex`, and
`sig_indices`. The remaining fields are opaque — `finalize_call` consumes them.

### 7c. BRC-100 wallet signing (`WalletProvider<W>` + `WalletSigner<W>`)

When the SDK cannot hold raw private keys — browser extension wallets, MetaNet
Client, mobile wallets — implement [`WalletClient`](src/sdk/wallet.rs) and
plug it into `WalletProvider<W>` (UTXO + broadcast) and `WalletSigner<W>`
(BIP-143 sighash → wallet → DER signature).

The trait surface is:

```rust
use runar::sdk::{WalletActionOutput, WalletActionResult, WalletOutput};

pub trait WalletClient {
    fn get_public_key(
        &self,
        protocol_id: &(u32, &str),
        key_id: &str,
    ) -> Result<String, String>;

    fn create_signature(
        &self,
        hash_to_sign: &[u8],
        protocol_id: &(u32, &str),
        key_id: &str,
    ) -> Result<Vec<u8>, String>;

    fn create_action(
        &self,
        description: &str,
        outputs: &[WalletActionOutput],
    ) -> Result<WalletActionResult, String>;

    fn list_outputs(
        &self,
        basket: &str,
        tags: &[&str],
        limit: usize,
    ) -> Result<Vec<WalletOutput>, String>;
}
```

A minimal in-memory `WalletClient` for tests:

```rust
use runar::sdk::{
    WalletActionOutput, WalletActionResult, WalletClient, WalletOutput,
    WalletProvider, WalletSigner,
};

#[derive(Clone)]
pub struct MyWallet { /* keys, basket store, ... */ }

impl WalletClient for MyWallet {
    fn get_public_key(&self, _proto: &(u32, &str), _key_id: &str) -> Result<String, String> {
        Ok("0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798".to_string())
    }
    fn create_signature(
        &self,
        _hash: &[u8],
        _proto: &(u32, &str),
        _key_id: &str,
    ) -> Result<Vec<u8>, String> {
        // sign `_hash` with the user's key and return DER bytes
        Ok(vec![0u8; 71])
    }
    fn create_action(
        &self,
        _description: &str,
        _outputs: &[WalletActionOutput],
    ) -> Result<WalletActionResult, String> {
        Ok(WalletActionResult { txid: "00".repeat(32), tx: None })
    }
    fn list_outputs(
        &self,
        _basket: &str,
        _tags: &[&str],
        _limit: usize,
    ) -> Result<Vec<WalletOutput>, String> {
        Ok(vec![])
    }
}

// WalletProvider holds one wallet client; WalletSigner holds another (or a
// clone). They are deliberately separate so the same wallet can be used as a
// pure signer without exposing UTXO listing, and vice versa.
fn build_wallet_pair() -> (WalletProvider<MyWallet>, WalletSigner<MyWallet>) {
    let provider = WalletProvider::new(
        MyWallet {},
        (2, "my app".to_string()),
        "1".to_string(),
        "runar-funding".to_string(),
        Some("funding".to_string()),
        None,           // arc_url — defaults to https://arc.gorillapool.io
        None,           // overlay_url
        Some("mainnet".to_string()),
        Some(100),      // fee rate, sat/KB
    );
    let signer = WalletSigner::new(
        MyWallet {},
        (2, "my app".to_string()),
        "1".to_string(),
    );
    (provider, signer)
}
```

Both types are generic over `W: WalletClient`, so the wallet trait object
machinery is monomorphized away — there's no allocation overhead and the
borrow rules of your concrete wallet are preserved.

For one-shot deploys via the wallet — bypassing the full
`RunarContract::deploy` flow when you just need to land the locking script as
a wallet action — call [`deploy_with_wallet`](src/sdk/wallet.rs).

---

## 8. Stateful Contracts

Stateful contracts (any contract whose `state_fields` is non-empty) embed
their state in the locking script as a suffix of raw bytes after the last
`OP_RETURN`:

```text
<code> [<inscription envelope>] OP_RETURN <field0> <field1> ... <fieldN>
```

Each field is fixed-width (the compiler emits `OP_NUM2BIN`-based
serialization): `int`/`bigint` → 8 bytes LE sign-magnitude, `bool` → 1 byte,
`PubKey` → 33 bytes, `Addr`/`Ripemd160` → 20 bytes, `Sha256` → 32 bytes,
`Point` → 64 bytes. The exact layout is implemented by
[`serialize_state`](src/sdk/state.rs) and verified by the on-chain script
itself via `OP_CODESEPARATOR` + `checkPreimage`.

### State chaining and OP_PUSH_TX

For every `#[public]` method on a stateful contract, the compiler injects:

1. An implicit `SigHashPreimage` parameter (the BIP-143 preimage of the
   spending transaction).
2. An implicit `_changePKH` and `_changeAmount` (hash160 + satoshi amount of
   the funding-change output) for methods that need to verify a P2PKH change
   output exists.
3. An implicit `_newAmount` for methods that need to assert the continuation
   output's value.
4. An OP_CODESEPARATOR after these implicit args, so the user-visible
   `checkSig` only commits to the post-separator subscript.

The SDK fills all of these in automatically — you only ever pass the
user-visible arguments to `call()`. The OP_PUSH_TX signature (computed against
private key `k=1` so the script can derive the corresponding pubkey on its
own) is also auto-computed; see
[`compute_op_push_tx_with_code_sep`](src/sdk/oppushtx.rs).

### ANF auto-state

Every artifact compiled by Rúnar carries an `anf` (A-Normal Form) IR
representation of each method body. Before broadcasting a stateful call, the
SDK runs the ANF interpreter
([`compute_new_state_and_data_outputs`](src/sdk/anf_interpreter.rs)) over the
method body using the current state + provided args, producing the next
state and any `addDataOutput` emissions. This means **you do not have to
specify the new state** — `contract.state()` updates itself based on the
contract's own logic.

You can override this with `CallOptions { new_state: Some(...) }` for
negative tests (e.g. assert that "wrong state" is rejected by the on-chain
preimage check):

```rust
use std::collections::HashMap;
use runar::sdk::{CallOptions, Provider, RunarContract, SdkValue, Signer};

fn negative_test_wrong_state(
    contract: &mut RunarContract,
    provider: &mut dyn Provider,
    signer: &dyn Signer,
) {
    let mut wrong_state = HashMap::new();
    wrong_state.insert("count".to_string(), SdkValue::Int(99));

    let result = contract.call(
        "increment",
        &[],
        provider,
        signer,
        Some(&CallOptions {
            new_state: Some(wrong_state),
            ..Default::default()
        }),
    );
    assert!(result.is_err(), "expected on-chain preimage check to reject wrong state");
}
```

### Multi-output and terminal methods

`addOutput(satoshis, ...values)` in a contract method produces an additional
continuation output with its own state values. The SDK reflects this in
`CallOptions::outputs` — pass a `Vec<OutputSpec>` and the SDK builds one
locking script per entry, all rooted at the same code prefix.

`addRawOutput(satoshis, scriptBytes)` and `addDataOutput(satoshis, scriptBytes)`
produce non-state outputs (raw scripts and `OP_RETURN`-style data outputs
respectively). The compiler verifies them on chain via the auto-injected
hashOutputs check; the SDK either auto-resolves them through the ANF
interpreter or accepts an explicit override via `CallOptions::data_outputs`.

A **terminal** method (`AbiMethod::is_terminal == true`) consumes the
contract's balance entirely — no continuation, no change, no funding inputs.
The contract is fully spent. Pass `CallOptions::terminal_outputs` with the
exact output set the on-chain script verifies.

---

## 9. UTXO and Fee Management

The SDK uses **largest-first** UTXO selection
([`select_utxos`](src/sdk/deployment.rs)), iterating until the selection
covers `target + estimated_fee`. Fee estimation uses real script sizes (not
hardcoded P2PKH assumptions) — see
[`estimate_deploy_fee`](src/sdk/deployment.rs) and
[`estimate_call_fee`](src/sdk/calling.rs).

The fee rate comes from `Provider::get_fee_rate()` — `MockProvider` defaults
to **100 sat/KB** (BSV standard), which is overridable via
`MockProvider::set_fee_rate`. `RPCProvider` and the HTTP providers query their
backend; if no rate is reported they fall back to the same 100 sat/KB.

You can drive the math directly:

```rust
use runar::sdk::{estimate_deploy_fee, estimate_call_fee};

let deploy_fee = estimate_deploy_fee(
    /* num_inputs */ 1,
    /* locking_script_byte_len */ 240,
    /* fee_rate */ Some(100),
);

let call_fee = estimate_call_fee(
    /* locking_script_byte_len */ 240,
    /* unlocking_script_byte_len */ 320,
    /* num_funding_inputs */ 1,
    /* fee_rate */ Some(100),
);

let _ = (deploy_fee, call_fee);
```

For the contract UTXO itself, the SDK tracks the current outpoint
automatically. After `deploy` it points at the deploy output (vout 0). After
each stateful `call` it advances to the new continuation output (also vout 0
on the call tx). Inspect the current value with `contract.get_utxo()` —
`None` after a terminal call or before the first deploy.

For stateful contracts that use `addOutput` to fan out into multiple
continuation UTXOs, the tracked UTXO is the **first** continuation. To track
the others you must reconnect with `RunarContract::from_txid`.

---

## 10. Typed Contract Bindings (`generate_rust`)

[`generate_rust`](src/sdk/codegen.rs) turns a `RunarArtifact` into a typed
Rust wrapper around `RunarContract`. The wrapper hides the untyped
`call("methodName", &[SdkValue::…, …], …)` surface behind one Rust
function per public contract method, elides compiler-injected params
(`Sig`, `SigHashPreimage`, `_changePKH`, `_changeAmount`, `_newAmount`),
and produces a typed constructor-args struct so `new()` checks at compile
time. The generated file has no runtime overhead and depends only on
`runar::sdk` types. Per artifact it emits `<Name>Contract` (wrapper),
`<Name>ConstructorArgs` (typed fields), `<Name>StatefulCallOptions`
(stateful non-terminal contracts), `TerminalOutput` (terminal methods),
and one `pub fn <method>` per public method — plus
`prepare_<method>` / `finalize_<method>` companions for any method that
takes a `Sig`.

### Generating the wrapper

Programmatically from a build script or a one-off binary:

```rust
use std::fs;
use runar::sdk::{generate_rust, RunarArtifact};

fn main() -> Result<(), String> {
    let json = fs::read_to_string("artifacts/Counter.json")
        .map_err(|e| format!("read artifact: {}", e))?;
    let artifact: RunarArtifact = serde_json::from_str(&json)
        .map_err(|e| format!("parse artifact: {}", e))?;

    fs::write("src/generated/counter_contract.rs", generate_rust(&artifact))
        .map_err(|e| format!("write generated: {}", e))?;
    Ok(())
}
```

From the `runar` CLI (the TS-based CLI dispatches to the same Rust
template via the cross-target codegen — output is byte-identical):

```bash
pnpm exec runar codegen artifacts/Counter.json -o src/generated/ --lang rust
# Generated: src/generated/counter_contract.rs
```

For a build-time pattern, call `generate_rust` from `build.rs`, write to
`OUT_DIR`, then `include!` the file in your module tree. Most projects
prefer the one-shot CLI invocation and check the generated `.rs` into
git so it shows up in code review.

### Generated wrapper for `Counter` (abridged)

The `Counter` artifact in
`conformance/sdk-output/tests/stateful-counter/input.json` declares a
single `count: bigint` constructor param and two stateful non-terminal
methods (`increment`, `decrement`). Each method's ABI lists four
synthetic params (`_changePKH`, `_changeAmount`, `_newAmount`,
`txPreimage`) which the wrapper hides. Running
`cargo run --example codegen_counter` against this artifact produces:

```rust
// Generated by: runar codegen
// Source: Counter
// Do not edit manually.

use std::collections::HashMap;
use num_bigint::BigInt;
use runar::sdk::{
    RunarContract, RunarArtifact, SdkValue, Provider, Signer,
    TransactionData, DeployOptions, CallOptions, PreparedCall,
};
use runar::sdk::deployment::build_p2pkh_script_from_address;

pub struct CounterStatefulCallOptions {
    pub satoshis: Option<i64>,
    pub change_address: Option<String>,
    pub change_pub_key: Option<String>,
    pub new_state: Option<HashMap<String, SdkValue>>,
}

impl CounterStatefulCallOptions {
    fn to_call_options(&self) -> CallOptions { /* ... */ }
}

pub struct CounterConstructorArgs {
    pub count: BigInt,
}

pub struct CounterContract { inner: RunarContract }

impl CounterContract {
    pub fn new(artifact: RunarArtifact, args: CounterConstructorArgs) -> Self {
        let ctor_args = vec![SdkValue::BigInt(args.count)];
        Self { inner: RunarContract::new(artifact, ctor_args) }
    }

    pub fn from_txid(
        artifact: RunarArtifact, txid: &str, output_index: usize,
        provider: &dyn Provider,
    ) -> Result<Self, String> { /* ... */ }

    pub fn connect(&mut self, provider: Box<dyn Provider>, signer: Box<dyn Signer>) { /* ... */ }

    pub fn deploy(
        &mut self, provider: &mut dyn Provider, signer: &dyn Signer,
        options: &DeployOptions,
    ) -> Result<(String, TransactionData), String> { /* ... */ }

    pub fn get_locking_script(&self) -> String { /* ... */ }
    pub fn contract(&self) -> &RunarContract { &self.inner }
    pub fn contract_mut(&mut self) -> &mut RunarContract { &mut self.inner }

    /// Call the increment method.
    pub fn increment(
        &mut self,
        provider: &mut dyn Provider,
        signer: &dyn Signer,
        options: Option<&CounterStatefulCallOptions>,
    ) -> Result<(String, TransactionData), String> {
        let args = vec![];
        let opts = options.map(|o| o.to_call_options());
        self.inner.call("increment", &args, provider, signer, opts.as_ref())
    }

    /// Call the decrement method.
    pub fn decrement(
        &mut self,
        provider: &mut dyn Provider,
        signer: &dyn Signer,
        options: Option<&CounterStatefulCallOptions>,
    ) -> Result<(String, TransactionData), String> {
        let args = vec![];
        let opts = options.map(|o| o.to_call_options());
        self.inner.call("decrement", &args, provider, signer, opts.as_ref())
    }
}
```

`Counter` has no `Sig` parameters, so no `prepare_*`/`finalize_*` pair is
emitted. Stateless contracts that take a `Sig` (the `P2PKH` artifact, for
example) gain `prepare_unlock` and `finalize_unlock` companions for the
external-signer flow described in section 7b.

State accessors are not generated — read state via
`counter.contract().state().get("count")` or
`extract_state_from_script(...)` (section 13).

### Usage

```rust
use std::fs;
use num_bigint::BigInt;
use runar::sdk::{DeployOptions, MockProvider, RunarArtifact, MockSigner};

mod generated { include!("generated/counter_contract.rs"); }
use generated::{CounterConstructorArgs, CounterContract, CounterStatefulCallOptions};

let artifact: RunarArtifact = serde_json::from_str(&fs::read_to_string("Counter.json")?)?;
let mut provider = MockProvider::new("testnet");
let signer = MockSigner::new();
provider.add_utxo(&signer.get_address()?, /* utxo */ utxo);

let mut counter = CounterContract::new(artifact, CounterConstructorArgs { count: BigInt::from(0) });

counter.deploy(&mut provider, &signer, &DeployOptions::default())?;
counter.increment(&mut provider, &signer, None)?;
counter.increment(&mut provider, &signer, None)?;

assert_eq!(counter.contract().state().get("count"),
           Some(&runar::sdk::SdkValue::BigInt(BigInt::from(2))));
```

Equivalent code without the wrapper — every call site repeats the method
name as a string, splices `SdkValue` enum variants by hand, and loses
constructor-arg type checking:

```rust
let mut contract = RunarContract::new(artifact, vec![SdkValue::BigInt(BigInt::from(0))]);
contract.deploy(&mut provider, &signer, &DeployOptions::default())?;
contract.call("increment", &[], &mut provider, &signer, None)?;
contract.call("increment", &[], &mut provider, &signer, None)?;
```

### Type mapping

Derived from `map_type_to_rust` in `src/sdk/codegen.rs`:

| ABI type                                                                                | Generated Rust type | `SdkValue` wrapping     |
|-----------------------------------------------------------------------------------------|---------------------|-------------------------|
| `bigint`                                                                                | `BigInt`            | `SdkValue::BigInt(_)`   |
| `boolean`                                                                               | `bool`              | `SdkValue::Bool(_)`     |
| `Sig`, `PubKey`                                                                         | `String` (elided)   | `SdkValue::Auto`        |
| `ByteString`, `Addr`, `Ripemd160`, `Sha256`, `Point`, `SigHashPreimage`                 | `String` (hex)      | `SdkValue::Bytes(_)`    |
| anything else                                                                           | `SdkValue`          | passed through verbatim |

Method names that would shadow the wrapper's own surface (`connect`,
`deploy`, `contract`, `get_locking_script`) are emitted with a `call_`
prefix — so a contract method named `connect` is generated as
`call_connect`, matching the cross-target `safe_method_name` helper.

---

## 11. Testing

### 11a. Off-chain testing

The fastest test loop is to exercise the contract as native Rust code using
mock crypto.

**Compile-only check** — assert a contract is valid Rúnar without producing
the full artifact (matches `CompileCheck.run` in Java, `compile_check` in
Python, etc.):

```rust
#[test]
fn counter_compiles() {
    let source = include_str!("Counter.runar.rs");
    runar::compile_check(source, "Counter.runar.rs").unwrap();
}
```

**Business-logic check** — instantiate the contract as a plain Rust struct.
This bypasses every Bitcoin Script intrinsic so it asserts only on the
arithmetic / control flow, but it's free, runs in milliseconds, and catches
the vast majority of bugs:

```rust
#[path = "Counter.runar.rs"]
mod contract;
use contract::Counter;

#[test]
fn test_increment() {
    let mut c = Counter { count: 0 };
    c.increment();
    assert_eq!(c.count, 1);
}

#[test]
#[should_panic]
fn test_decrement_at_zero_fails() {
    Counter { count: 0 }.decrement();
}
```

The `runar::prelude::*` mocks behave consistently: `mock_sig()` returns a
72-byte zero placeholder, `mock_pub_key()` returns a 33-byte compressed
placeholder starting `0x02`, `check_preimage(...)` always returns `true`,
`extract_locktime(...)` returns `0`, `extract_outpoint(...)` returns 36 zero
bytes. The verification helpers (`check_sig`, `verify_rabin_sig`,
`verify_wots`, `verify_slh_dsa_sha2_*`, `merkle_root_*`) **do** run real math
against the canonical `TEST_MESSAGE` so signature tests still catch real
bugs. See [`src/prelude.rs`](src/prelude.rs) for the full list and
[`src/test_keys.rs`](src/test_keys.rs) for the deterministic `ALICE`,
`BOB`, `CHARLIE` test keys.

**SDK smoke test** — drive the deploy/call flow against `MockProvider`:

```rust
use runar::sdk::{
    DeployOptions, MockProvider, MockSigner, RunarContract, SdkValue, Signer, Utxo,
};

fn smoke_test_counter(artifact: runar::sdk::RunarArtifact) -> Result<(), String> {
    let mut contract = RunarContract::new(artifact, vec![SdkValue::Int(0)]);
    let mut provider = MockProvider::testnet();
    let signer = MockSigner::new();

    // Inject a funding UTXO at the signer's mock address.
    provider.add_utxo(&signer.get_address()?, Utxo {
        txid: "aa".repeat(32),
        output_index: 0,
        satoshis: 50_000,
        script: format!("76a914{}88ac", "00".repeat(20)),
    });

    let (deploy_txid, _tx) = contract.deploy(
        &mut provider,
        &signer,
        &DeployOptions { satoshis: 5_000, change_address: None },
    )?;
    assert!(!deploy_txid.is_empty());
    Ok(())
}
```

Note the `Signer` import — `MockSigner::get_address()` is on the trait.

### 11b. Integration testing against a regtest node

For end-to-end confidence — the on-chain VM actually executing your script —
point an `RPCProvider` at a local Bitcoin SV regtest node. The reference
harness lives in
[`integration/rust/`](../../integration/rust/) and is gated behind a
`regtest` cargo feature so it doesn't slow down `cargo test`:

```bash
# 1. Start a regtest node (helper script in repo root):
./integration/regtest.sh start

# 2. Run the gated tests:
cd integration/rust
cargo test --features regtest
```

The harness pattern (see
[`integration/rust/tests/helpers/mod.rs`](../../integration/rust/tests/helpers/mod.rs))
is:

```rust
#[cfg(test)]
mod fake_helpers {
    use runar::sdk::{RPCProvider, RunarArtifact, Signer};
    pub fn skip_if_no_node() {}
    pub fn compile_contract(_path: &str) -> RunarArtifact { unimplemented!() }
    pub fn create_provider() -> RPCProvider {
        RPCProvider::new_regtest("http://localhost:18332", "bitcoin", "bitcoin")
    }
    pub fn create_funded_wallet(_p: &mut RPCProvider) -> (Box<dyn Signer>, ()) {
        unimplemented!()
    }
}

#[cfg(test)]
mod counter_integration_example {
    use super::fake_helpers::*;
    use runar::sdk::{DeployOptions, RunarContract, SdkValue};

    #[test]
    #[cfg_attr(not(feature = "regtest"), ignore)]
    fn test_counter_increment() {
        skip_if_no_node();

        let artifact = compile_contract("examples/rust/stateful-counter/Counter.runar.rs");
        let mut contract = RunarContract::new(artifact, vec![SdkValue::Int(0)]);
        let mut provider = create_provider();
        let (signer, _wallet) = create_funded_wallet(&mut provider);

        contract
            .deploy(&mut provider, &*signer, &DeployOptions {
                satoshis: 5000,
                change_address: None,
            })
            .expect("deploy failed");

        contract
            .call("increment", &[], &mut provider, &*signer, None)
            .expect("call increment failed");
    }
}
```

[`conformance/sdk-output/`](../../conformance/sdk-output/) cross-validates
that this SDK emits **byte-identical deployed locking scripts** as every
other Rúnar SDK (TS, Go, Python, Zig, Ruby, Java) for the same artifact +
constructor args. The Counter contract is one of the 27 fixtures.

---

## 12. Provider Configuration

| Provider | Use it for | Network | HTTP backend |
|----------|-----------|---------|--------------|
| `MockProvider` | unit tests, deterministic txids, manual UTXO injection | any (string label) | none |
| `RPCProvider` | full Bitcoin node JSON-RPC (regtest, custom mainnet/testnet nodes) | `regtest` (auto-mines after broadcast), or general-purpose | stdlib TCP |
| `WhatsOnChainProvider` | hosted public mainnet/testnet API | `mainnet` / `testnet` | `ureq` |
| `GorillaPoolProvider` | 1sat ordinals API + standard Provider methods | `mainnet` / `testnet` | `ureq` |
| `WalletProvider<W>` | BRC-100 wallet integration; UTXOs come from a wallet basket | configurable | `ureq` (for ARC broadcast) |

All providers implement the [`Provider`](src/sdk/provider.rs) trait, so any
of them can be passed to `RunarContract::deploy`, `::call`, `::prepare_call`,
or `::finalize_call`. Construction patterns:

```rust
use runar::sdk::{
    GorillaPoolProvider, MockProvider, RPCProvider, WhatsOnChainProvider,
};

// 1. MockProvider — for tests:
let mut mock = MockProvider::testnet();
mock.set_fee_rate(50);  // override default 100 sat/KB

// 2. RPCProvider — full node JSON-RPC:
let mut _rpc = RPCProvider::new("http://localhost:8332", "user", "pass");
let mut _regtest = RPCProvider::new_regtest("http://localhost:18332", "bitcoin", "bitcoin");
// regtest auto-mines 1 block after each broadcast so the tx confirms immediately.

// 3. WhatsOnChainProvider — hosted public API:
let _woc_main = WhatsOnChainProvider::new("mainnet");
let _woc_test = WhatsOnChainProvider::new("testnet");

// 4. GorillaPoolProvider — 1sat ordinals + Provider:
let _gp_main = GorillaPoolProvider::new("mainnet");
```

`MockProvider` exposes test-only setters: `add_transaction`, `add_utxo`,
`add_contract_utxo`, `set_fee_rate`, and `get_broadcasted_txs` for
post-broadcast assertions.

---

## 13. Full API Reference

Alphabetized list of every symbol in the public surface. All paths are
relative to the crate root (`runar_lang::…`, conventionally aliased to
`runar::…`). The proc-macros from `runar-lang-macros` are documented in
Section 4.

### Crate-root items

#### `pub fn compile_check(source: &str, file_name: &str) -> Result<(), String>`

Run the Rúnar frontend (parse → validate → typecheck → expand-fixed-arrays)
against a contract source string. Returns `Ok(())` if the contract is valid
Rúnar; `Err(String)` describes the first failing pass.

```rust
runar::compile_check(include_str!("Counter.runar.rs"), "Counter.runar.rs").unwrap();
```

Source: [`src/lib.rs`](src/lib.rs).

### `runar::prelude` — contract-author surface

Re-exports the proc macros (`contract`, `methods`, `public`,
`stateful_contract`), every type alias (`Int`, `Bigint`, `PubKey`, `Sig`,
`Addr`, `ByteString`, `Sha256`, `Sha256Digest`, `Ripemd160`,
`SigHashPreimage`, `RabinSig`, `RabinPubKey`, `Point`), every real-crypto
helper (`check_sig`, `check_multi_sig`, `check_preimage`,
`verify_rabin_sig`, `verify_wots`, `verify_slh_dsa_sha2_{128s,128f,192s,192f,256s,256f}`),
every hash function (`hash160`, `hash256`, `sha256`, `sha256_hash`,
`ripemd160`, `sha256_compress`, `sha256_finalize`, `blake3_hash`,
`blake3_compress`), the EC primitives (`ec_add`, `ec_mul`, `ec_mul_gen`,
`ec_negate`, `ec_on_curve`, `ec_mod_reduce`, `ec_encode_compressed`,
`ec_make_point`, `ec_point_x`, `ec_point_y`), the math intrinsics (`safediv`,
`safemod`, `clamp`, `sign`, `pow`, `mul_div`, `percent_of`, `sqrt`, `gcd`,
`divmod`, `log2`, `bool_cast`), the BabyBear field helpers
(`bb_field_{add,sub,mul,inv}`, `bb_ext4_{mul0,mul1,mul2,mul3,inv0,inv1,inv2,inv3}`),
the Merkle helpers (`merkle_root_sha256`, `merkle_root_hash256`),
the test mocks (`mock_sig`, `mock_pub_key`, `mock_preimage`,
`extract_locktime`, `extract_output_hash`, `extract_hash_prevouts`,
`extract_outpoint`, `get_state_script`), the deterministic test keys
(`ALICE`, `BOB`, `CHARLIE`, `TestKeyPair`, `sign_test_message`,
`pub_key_from_priv_key`, `TEST_MESSAGE`, `TEST_MESSAGE_DIGEST`,
`ecdsa_verify`), and the per-curve key generation / signing helpers
(`p256_keygen`, `p256_sign`, `verify_ecdsa_p256`, `P256KeyPair`;
`p384_keygen`, `p384_sign`, `verify_ecdsa_p384`, `P384KeyPair`;
`wots_keygen`, `wots_sign`, `WotsKeyPair`;
`slh_keygen`, `slh_sign`, `slh_verify`, `SlhKeyPair`, `SlhParams`,
`SLH_SHA2_128S`/`128F`/`192S`/`192F`/`256S`/`256F`;
`rabin_sign_trivial`).

Source: [`src/prelude.rs`](src/prelude.rs).

### `runar::sdk` — deployment SDK

#### `pub struct AbiConstructor`
Constructor portion of an ABI. Field: `params: Vec<AbiParam>`.

#### `pub struct AbiMethod`
A method in the ABI. Fields: `name: String`, `params: Vec<AbiParam>`,
`is_public: bool`, `is_terminal: Option<bool>`.

#### `pub struct AbiParam`
A parameter in the ABI. Fields: `name: String`, `param_type: String`,
`fixed_array: Option<FixedArrayInfo>`.

#### `pub struct AdditionalContractInput`
Auxiliary contract input for merge-style calls. Fields: `utxo: Utxo`,
`unlocking_script: String`.

#### `pub struct ANFProgram`
Deserialized A-Normal Form IR carried in `RunarArtifact::anf`. Used by the
SDK's auto-state computation. Fields/structure: see
[`src/sdk/anf_interpreter.rs`](src/sdk/anf_interpreter.rs).

#### `pub fn build_call_transaction(...) -> (String, usize, i64)`
Build a raw call transaction (txid is unsigned at this layer; sigs are
inserted later). Returns `(tx_hex, input_count, change_amount)`. Most
callers should use `RunarContract::call` instead.

```rust
fn build_call_transaction(
    current_utxo: &runar::sdk::Utxo,
    unlocking_script: &str,
    new_locking_script: Option<&str>,
    new_satoshis: Option<i64>,
    change_address: Option<&str>,
    change_script: Option<&str>,
    additional_utxos: Option<&[runar::sdk::Utxo]>,
    fee_rate: Option<i64>,
) -> (String, usize, i64) { unimplemented!() }
```

#### `pub fn build_call_transaction_ext(..., options: Option<&CallTxOptions>) -> (String, usize, i64)`
Extended `build_call_transaction` with multi-output, additional contract
inputs, and explicit data outputs. See [`src/sdk/calling.rs`](src/sdk/calling.rs).

#### `pub fn build_deploy_transaction(...) -> (String, usize)`
Build an unsigned deploy transaction. Returns `(tx_hex, input_count)`.

```rust
fn build_deploy_transaction(
    locking_script: &str,
    utxos: &[runar::sdk::Utxo],
    satoshis: i64,
    change_address: &str,
    change_script: &str,
    fee_rate: Option<i64>,
) -> (String, usize) { unimplemented!() }
```

#### `pub fn build_inscription_envelope(content_type: &str, data: &str) -> String`
Build a 1sat ordinals envelope hex (`OP_FALSE OP_IF "ord" OP_1 <content-type>
OP_0 <data> OP_ENDIF`). `data` is hex-encoded raw inscription bytes.

#### `pub fn bsv20_deploy(tick: &str, max: &str, lim: Option<&str>, dec: Option<&str>) -> Inscription`
Build a BSV-20 deploy inscription.

#### `pub fn bsv20_mint(tick: &str, amt: &str) -> Inscription`
Build a BSV-20 mint inscription.

#### `pub fn bsv20_transfer(tick: &str, amt: &str) -> Inscription`
Build a BSV-20 transfer inscription.

#### `pub fn bsv21_deploy_mint(...) -> Inscription`
Build a BSV-21 combined deploy+mint inscription.

#### `pub fn bsv21_transfer(id: &str, amt: &str) -> Inscription`
Build a BSV-21 transfer inscription.

#### `pub struct CallOptions`
Tunables for `RunarContract::call`/`prepare_call`. All fields are `Option<…>`
and the type derives `Default`. See Section 7 for field-by-field semantics.

#### `pub struct CallTxOptions`
Low-level extended options for `build_call_transaction_ext`. Fields:
`contract_outputs: Option<Vec<ContractOutput>>`,
`additional_contract_inputs: Option<Vec<AdditionalContractInput>>`,
`data_outputs: Option<Vec<ContractOutput>>`.

#### `pub struct CodeSepIndexSlot`
Template-time slot describing where an `OP_CODESEPARATOR` index placeholder
lives. Internal — used by the SDK during script splicing.

#### `pub fn compute_op_push_tx(tx_hex, input_index, subscript, satoshis) -> Result<(String, String), String>`
Compute the OP_PUSH_TX DER signature + BIP-143 preimage for a contract input.
Returns `(sig_hex_with_sighash_byte, preimage_hex)`. See
[`src/sdk/oppushtx.rs`](src/sdk/oppushtx.rs).

#### `pub struct ConstructorSlot`
Maps a constructor parameter index to a byte offset in the script template.
Fields: `param_index: usize`, `byte_offset: usize`.

#### `pub struct ContractDataOutput`
Hex-encoded script + satoshis, used as the value type in
`CallOptions::data_outputs`.

#### `pub struct ContractOutput`
Internal contract output specification (script + satoshis), used by
`CallTxOptions`.

#### `pub fn deploy_with_wallet<W: WalletClient>(wallet, basket, locking_script, contract_name, options) -> Result<(String, usize), String>`
One-shot deploy via a BRC-100 wallet — bypasses `RunarContract::deploy` and
uses `WalletClient::create_action` directly. Returns `(txid, output_index)`.

#### `pub struct DeployOptions`
Fields: `satoshis: i64`, `change_address: Option<String>`.

#### `pub struct DeployWithWalletOptions`
Optional knobs for `deploy_with_wallet`. Fields: `satoshis: Option<i64>`,
`description: Option<String>`. Implements `Default` (1 sat, generic
description).

#### `pub fn deserialize_state(fields: &[StateField], script_hex: &str) -> HashMap<String, SdkValue>`
Parse a state byte section back into a `HashMap`. Inverse of
`serialize_state`. Used by `RunarContract::from_utxo`.

#### `pub struct EnvelopeBounds`
Hex-char offsets bounding an inscription envelope within a script. Fields:
`start_hex: usize`, `end_hex: usize`.

#### `pub fn estimate_call_fee(locking_script_byte_len, unlocking_script_byte_len, num_funding_inputs, fee_rate: Option<i64>) -> i64`
Estimate fee for a call transaction.

#### `pub fn estimate_deploy_fee(num_inputs, locking_script_byte_len, fee_rate: Option<i64>) -> i64`
Estimate fee for a deploy transaction.

#### `pub struct ExternalSigner`
Signer that delegates to user-provided closures. Constructor:

```rust
use runar::sdk::ExternalSigner;

let _signer = ExternalSigner::new(
    || Ok::<_, String>("02aabb".to_string()),
    || Ok::<_, String>("myaddr".to_string()),
    |_tx: &str, _idx: usize, _sub: &str, _sats: i64, _sht: Option<u32>|
        Ok::<_, String>("sig_hex".to_string()),
);
```

The closures must be `'static` (no captured borrows from the enclosing scope
that don't outlive the signer). For a hardware wallet, `sign_fn` typically
forwards to a thread that talks to the device.

#### `pub fn extract_constructor_args(artifact: &RunarArtifact, script_hex: &str) -> Vec<SdkValue>`
Extract constructor argument values from an on-chain locking script using the
artifact's `constructor_slots`. Useful when reconnecting to a contract whose
constructor args you've forgotten.

#### `pub fn extract_state_from_script(artifact: &RunarArtifact, script_hex: &str) -> Option<HashMap<String, SdkValue>>`
Extract the state map from a full locking script. Returns `None` if the
artifact has no state fields or no recognizable state section.

#### `pub fn find_inscription_envelope(script_hex: &str) -> Option<EnvelopeBounds>`
Find the bounds of an inscription envelope inside a script.

#### `pub fn find_last_op_return(script_hex: &str) -> Option<usize>`
Walk the script as opcodes and return the hex-char offset of the last real
`OP_RETURN` (skipping push-data 0x6a bytes). Used for state extraction.

#### `pub struct FixedArrayInfo`
Metadata for expanded `FixedArray<T, N>` state fields. Fields:
`element_type: String`, `length: usize`, `synthetic_names: Vec<String>`.

#### `pub fn flatten_fixed_array_state(...) -> ...`
Helper for flattening nested `SdkValue::Array` into the synthetic leaf order
used by the script. Internal but `pub` for codegen integration.

#### `pub fn generate_rust(artifact: &RunarArtifact) -> String`
Generate a typed Rust wrapper module from a compiled artifact. See
Section 10.

#### `pub struct GorillaPoolProvider`
HTTP provider for the GorillaPool 1sat Ordinals API. Constructor:
`GorillaPoolProvider::new(network: &str)` (`"mainnet"` or `"testnet"`).
Implements `Provider`. Adds ordinal-specific methods for inscriptions,
BSV-20/BSV-21 balances, and token UTXOs — see
[`src/sdk/gorillapool.rs`](src/sdk/gorillapool.rs).

#### `pub struct Inscription`
Fields: `content_type: String`, `data: String` (hex-encoded payload).
Equatable + cloneable. Use `RunarContract::with_inscription(insc)` to attach
to a contract before deploy.

#### `pub struct InscriptionDetail` / `pub struct InscriptionInfo`
Returned by `GorillaPoolProvider` methods. See
[`src/sdk/gorillapool.rs`](src/sdk/gorillapool.rs).

#### `pub struct LocalSigner`
In-memory ECDSA signer using `k256`. Constructor:

```rust
use runar::sdk::LocalSigner;

let _signer = LocalSigner::new("KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFU73sVHnoWn")
    .expect("valid WIF");
```

`key_input` is either a 64-char hex private key or a WIF-encoded key (starts
with `5`, `K`, or `L`). Implements `Signer`. Suitable for CLI tooling and
testing; for production wallets prefer `ExternalSigner` or
`WalletSigner<W>`.

#### `pub fn matches_artifact(artifact: &RunarArtifact, script_hex: &str) -> bool`
Test whether a script's code prefix matches a given artifact's template.
Useful when scanning a chunk of UTXOs for "is this one of my contracts".

#### `pub struct MockProvider`
In-memory provider for tests. Constructors: `MockProvider::new(network: &str)`,
`MockProvider::testnet()`. Test helpers:

```rust
use runar::sdk::{MockProvider, TransactionData, Utxo};

let mut p = MockProvider::testnet();
p.add_transaction(TransactionData {
    txid: "aa".repeat(32),
    version: 1,
    inputs: vec![],
    outputs: vec![],
    locktime: 0,
    raw: None,
});
p.add_utxo("myaddr", Utxo {
    txid: "aa".repeat(32),
    output_index: 0,
    satoshis: 50_000,
    script: "51".to_string(),
});
p.add_contract_utxo("scripthash", Utxo {
    txid: "bb".repeat(32),
    output_index: 0,
    satoshis: 1_000,
    script: "76a914".to_string(),
});
let _broadcasts: &[String] = p.get_broadcasted_txs();
p.set_fee_rate(50);
```

Generated txids on `broadcast` are deterministic (derived from broadcast
count + first 16 chars of raw hex), so tests across processes produce the
same txid for the same call sequence.

#### `pub struct MockSigner`
Signer that returns deterministic mock values (33-byte zero pubkey, 20-byte
zero address, 72-byte zero DER signature with sighash byte `0x41`).
Constructor: `MockSigner::new()`. Implements `Default`.

#### `pub struct OutputSnapshot`
Recorded output from `addOutput` — used by mock-mode tests. Fields:
`satoshis: Bigint`, `values: Vec<Vec<u8>>`. (Re-exported through
`runar::prelude::*`.)

#### `pub struct OutputSpec`
Specification for a single continuation output in multi-output stateful
calls. Fields: `satoshis: i64`, `state: HashMap<String, SdkValue>`.

#### `pub fn parse_inscription_envelope(script_hex: &str) -> Option<Inscription>`
Parse the first inscription envelope found in a script.

#### `pub struct PreparedCall`
Output of `RunarContract::prepare_call`. See Section 7b for the public field
semantics. The `pub(crate)` fields are opaque internals for `finalize_call`.

#### `pub trait Provider`
Blockchain abstraction. Required methods:

```rust
use runar::sdk::{TransactionData, Utxo};

pub trait Provider {
    fn get_transaction(&self, txid: &str) -> Result<TransactionData, String>;
    fn broadcast(&mut self, tx: &bsv::transaction::Transaction) -> Result<String, String>;
    fn get_utxos(&self, address: &str) -> Result<Vec<Utxo>, String>;
    fn get_contract_utxo(&self, script_hash: &str) -> Result<Option<Utxo>, String>;
    fn get_network(&self) -> &str;
    fn get_fee_rate(&self) -> Result<i64, String>;
    fn get_raw_transaction(&self, txid: &str) -> Result<String, String>;
}
```

Implementations: `MockProvider`, `RPCProvider`, `WhatsOnChainProvider`,
`GorillaPoolProvider`, `WalletProvider<W>`. The `bsv::…::Transaction` type
comes from the `bsv-sdk` dependency.

#### `pub struct RPCProvider`
JSON-RPC provider for full Bitcoin nodes. Constructors:

```rust
use runar::sdk::RPCProvider;

let _generic = RPCProvider::new("http://localhost:8332", "user", "pass");
let _regtest = RPCProvider::new_regtest("http://localhost:18332", "bitcoin", "bitcoin");
```

The regtest variant auto-mines 1 block after each broadcast so the
transaction confirms immediately. Uses stdlib TCP + manual HTTP — no extra
HTTP dependencies.

#### `pub fn regroup_fixed_array_state(...) -> SdkValue`
Inverse of `flatten_fixed_array_state`. Used internally for state
deserialization.

#### `pub struct RunarArtifact`
The compiled contract. Deserialized from the JSON output of the Rúnar
compiler. Fields:

```rust
use runar::sdk::{Abi, ANFProgram, CodeSepIndexSlot, ConstructorSlot, StateField};

pub struct RunarArtifact {
    pub version: String,
    pub contract_name: String,
    pub abi: Abi,
    pub script: String,                        // template hex
    pub state_fields: Option<Vec<StateField>>,
    pub constructor_slots: Option<Vec<ConstructorSlot>>,
    pub code_sep_index_slots: Option<Vec<CodeSepIndexSlot>>,
    pub code_separator_index: Option<usize>,
    pub code_separator_indices: Option<Vec<usize>>,
    pub anf: Option<ANFProgram>,
}
```

Use `serde_json::from_str` to deserialize a JSON artifact into this struct.

#### `pub struct RunarContract`
The runtime wrapper. Methods:

```rust
use std::collections::HashMap;
use runar::sdk::{
    CallOptions, DeployOptions, Inscription, PreparedCall, Provider,
    RunarArtifact, SdkValue, Signer, TransactionData, Utxo,
};

pub struct RunarContract { /* private */ }

impl RunarContract {
    // Construction
    pub fn new(artifact: RunarArtifact, constructor_args: Vec<SdkValue>) -> Self
    { unimplemented!() }
    pub fn from_txid(
        artifact: RunarArtifact,
        txid: &str,
        output_index: usize,
        provider: &dyn Provider,
    ) -> Result<Self, String> { unimplemented!() }
    pub fn from_utxo(artifact: RunarArtifact, utxo: &Utxo) -> Self
    { unimplemented!() }

    // State / UTXO access
    pub fn state(&self) -> &HashMap<String, SdkValue> { unimplemented!() }
    pub fn set_state(&mut self, _new_state: HashMap<String, SdkValue>) {}
    pub fn get_utxo(&self) -> Option<&Utxo> { None }

    // Inscription
    pub fn with_inscription(&mut self, _i: Inscription) -> &mut Self { self }
    pub fn inscription(&self) -> Option<&Inscription> { None }

    // Script construction
    pub fn get_locking_script(&self) -> String { String::new() }
    pub fn build_unlocking_script(
        &self,
        _method_name: &str,
        _args: &[SdkValue],
    ) -> Result<String, String> { Ok(String::new()) }

    // Deploy / Call
    pub fn deploy(
        &mut self,
        _provider: &mut dyn Provider,
        _signer: &dyn Signer,
        _options: &DeployOptions,
    ) -> Result<(String, TransactionData), String> { unimplemented!() }
    pub fn call(
        &mut self,
        _method_name: &str,
        _args: &[SdkValue],
        _provider: &mut dyn Provider,
        _signer: &dyn Signer,
        _options: Option<&CallOptions>,
    ) -> Result<(String, TransactionData), String> { unimplemented!() }
    pub fn prepare_call(
        &mut self,
        _method_name: &str,
        _args: &[SdkValue],
        _provider: &mut dyn Provider,
        _signer: &dyn Signer,
        _options: Option<&CallOptions>,
    ) -> Result<PreparedCall, String> { unimplemented!() }
    pub fn finalize_call(
        &mut self,
        _prepared: &PreparedCall,
        _signatures: &HashMap<usize, String>,
        _provider: &mut dyn Provider,
    ) -> Result<(String, TransactionData), String> { unimplemented!() }

    // Connected variants (after .connect()):
    pub fn connect(&mut self, _p: Box<dyn Provider>, _s: Box<dyn Signer>) {}
    pub fn deploy_connected(
        &mut self,
        _options: &DeployOptions,
    ) -> Result<(String, TransactionData), String> { unimplemented!() }
    pub fn call_connected(
        &mut self,
        _method_name: &str,
        _args: &[SdkValue],
        _options: Option<&CallOptions>,
    ) -> Result<(String, TransactionData), String> { unimplemented!() }
    pub fn prepare_call_connected(
        &mut self,
        _method_name: &str,
        _args: &[SdkValue],
        _options: Option<&CallOptions>,
    ) -> Result<PreparedCall, String> { unimplemented!() }
    pub fn finalize_call_connected(
        &mut self,
        _prepared: &PreparedCall,
        _signatures: &HashMap<usize, String>,
    ) -> Result<(String, TransactionData), String> { unimplemented!() }
}
```

Construction `new` panics if `constructor_args.len()` doesn't match the
artifact's declared constructor parameter count. This is the only public
panic in normal flow — it indicates a hard programmer error. Other failure
modes (network errors, missing UTXOs, wrong sig type) return `Err(String)`.

#### `pub enum SdkValue`
Wire type for every cross-boundary value. See Section 3.

```rust
pub enum SdkValue {
    Int(i64),
    BigInt(num_bigint::BigInt),
    Bool(bool),
    Bytes(String),       // hex-encoded
    Auto,
    Array(Vec<SdkValue>),
}

impl SdkValue {
    pub fn as_int(&self) -> i64 { unimplemented!() }    // panics on non-numeric or BigInt > i64::MAX
    pub fn as_bool(&self) -> bool { unimplemented!() }  // panics on non-Bool
    pub fn as_bytes(&self) -> &str { unimplemented!() } // panics on non-Bytes
}
```

#### `pub fn select_utxos(utxos: &[Utxo], target_satoshis: i64, locking_script_byte_len: usize, fee_rate: Option<i64>) -> Vec<Utxo>`
Largest-first UTXO selection.

#### `pub fn serialize_state(fields: &[StateField], values: &HashMap<String, SdkValue>) -> String`
Serialize a state map to the hex-encoded raw byte section that lives after
`OP_RETURN` in a stateful contract's locking script.

#### `pub trait Signer`
Signer abstraction. Required methods:

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
        sig_hash_type: Option<u32>, // defaults to SIGHASH_ALL | SIGHASH_FORKID = 0x41
    ) -> Result<String, String>;
}
```

Implementations: `LocalSigner`, `ExternalSigner`, `MockSigner`,
`WalletSigner<W>`.

#### `pub struct StateField`
A state field definition. Fields: `name: String`, `field_type: String`,
`index: usize`, `initial_value: Option<serde_json::Value>`,
`fixed_array: Option<FixedArrayInfo>`.

#### `pub fn strip_inscription_envelope(script_hex: &str) -> String`
Return a copy of the script with the inscription envelope removed. Used
when comparing script templates that may or may not have ordinals attached.

#### `pub struct TerminalOutput`
Specification for an exact output in a terminal-method call. Fields:
`script_hex: String`, `satoshis: i64`.

#### `pub struct TokenWallet`
Higher-level wrapper for fungible-token contracts. Constructor:

```rust
use runar::sdk::{Provider, RunarArtifact, Signer, TokenWallet};

fn make_wallet(
    artifact: RunarArtifact,
    provider: Box<dyn Provider>,
    signer:   Box<dyn Signer>,
) -> TokenWallet {
    TokenWallet::new(artifact, provider, signer)
}
```

Methods include `get_balance() -> Result<i64, String>` and
`transfer(recipient_addr: &str, amount: i64) -> Result<String, String>`. Use
when the artifact's state field is named `balance`, `supply`, or `amount`
and the contract has a `transfer` method.

#### `pub struct Transaction = TransactionData`
Backward-compat alias.

#### `pub struct TransactionData`
Parsed transaction. Fields: `txid: String`, `version: u32`,
`inputs: Vec<TxInput>`, `outputs: Vec<TxOutput>`, `locktime: u32`,
`raw: Option<String>`.

#### `pub struct TxInput` / `pub struct TxOutput`
Standard tx-component records. `TxOutput { satoshis: i64, script: String }`,
`TxInput { txid: String, output_index: u32, script: String, sequence: u32 }`.

#### `pub struct Utxo`
Unspent output. Fields: `txid: String`, `output_index: u32`,
`satoshis: i64`, `script: String`.

#### `pub struct WalletActionOutput` / `WalletActionResult` / `WalletOutput`
Data carriers for the `WalletClient` trait. See Section 7c and
[`src/sdk/wallet.rs`](src/sdk/wallet.rs).

#### `pub trait WalletClient`
BRC-100 wallet abstraction. See Section 7c.

#### `pub struct WalletProvider<W: WalletClient>`
Provider backed by a wallet basket. Constructor takes nine arguments:
`(wallet, protocol_id, key_id, basket, funding_tag, arc_url, overlay_url,
network, fee_rate)`. Methods:
`cache_tx(&mut self, txid, raw_hex)`,
`ensure_funding(&mut self, min_satoshis: i64) -> Result<(), String>`. Implements
`Provider`. The generic parameter `W` is monomorphized — there's no `dyn`
indirection. See Section 7c for a full constructor example.

#### `pub struct WalletProviderOptions<W: WalletClient>`
Bundle of constructor parameters for `WalletProvider`. Fields: `wallet: W`,
`signer: WalletSigner<W>`, `basket: String`,
`funding_tag: Option<String>`, `arc_url: Option<String>`,
`overlay_url: Option<String>`, `network: Option<String>`,
`fee_rate: Option<i64>`. Provided as a convenience for callers who'd rather
populate a struct than pass nine positional args.

#### `pub struct WalletSigner<W: WalletClient>`
Signer that computes BIP-143 sighash locally then delegates ECDSA to the
wallet. Constructor:

```rust
// Pseudocode shape — instantiate with your concrete WalletClient `W`:
//
//   WalletSigner::new(
//       wallet:      W,
//       protocol_id: (u32, String),
//       key_id:      String,
//   ) -> WalletSigner<W>
```

Method: `sign_hash(&self, sighash: &[u8]) -> Result<String, String>` — sign a
pre-computed hash directly. Implements `Signer`.

#### `pub struct WhatsOnChainProvider`
HTTP provider for the WhatsOnChain API. Constructor:
`WhatsOnChainProvider::new(network: &str)` — `"mainnet"` or anything else
(testnet). Implements `Provider`.

---

## 14. Error Handling

Every fallible SDK function returns `Result<T, String>` — error messages are
descriptive strings, not typed enums. This is a deliberate choice mirrored in
the TypeScript and Python SDKs (where errors are also stringly typed). The
upside: simple cross-call propagation with `?` and easy logging. The
downside: you cannot pattern-match on error kinds, so if you need to react to
a specific failure (e.g. "insufficient funds"), substring-match the message:

```rust
use runar::sdk::{DeployOptions, Provider, RunarContract, Signer, TransactionData};

fn try_deploy(
    contract: &mut RunarContract,
    provider: &mut dyn Provider,
    signer:   &dyn Signer,
) -> Result<(String, TransactionData), String> {
    match contract.deploy(provider, signer, &DeployOptions { satoshis: 5_000, change_address: None }) {
        Ok(ok) => Ok(ok),
        Err(e) if e.contains("no UTXOs found") => {
            eprintln!("wallet is empty: {}", e);
            Err(e)
        }
        Err(e) if e.contains("insufficient funds") => {
            eprintln!("need to top up: {}", e);
            Err(e)
        }
        Err(e) => Err(e),
    }
}
```

`?`-propagation just works because every fallible SDK method has `String` as
its error type:

```rust
use runar::sdk::{
    DeployOptions, MockProvider, MockSigner, RunarArtifact, RunarContract, SdkValue,
};

fn run(artifact: RunarArtifact) -> Result<(), String> {
    let mut contract = RunarContract::new(artifact, vec![SdkValue::Int(0)]);
    let mut provider = MockProvider::testnet();
    let signer = MockSigner::new();
    let (txid, _) = contract.deploy(&mut provider, &signer, &DeployOptions {
        satoshis: 5_000, change_address: None,
    })?;
    contract.call("increment", &[], &mut provider, &signer, None)?;
    println!("deployed: {}", txid);
    Ok(())
}
```

Mixing `Result<_, String>` with other error types is straightforward via
`.map_err(|e| e.to_string())`:

```rust
fn load_artifact() -> Result<runar::sdk::RunarArtifact, String> {
    let json = std::fs::read_to_string("artifact.json")
        .map_err(|e| format!("read artifact: {}", e))?;
    let artifact: runar::sdk::RunarArtifact = serde_json::from_str(&json)
        .map_err(|e| format!("parse artifact: {}", e))?;
    Ok(artifact)
}
```

A handful of conditions panic instead of returning an error — they signal
**hard programmer errors** that no amount of retry will fix:

- `RunarContract::new` panics if `constructor_args.len()` doesn't match the
  artifact's declared constructor param count.
- `SdkValue::as_int` / `as_bool` / `as_bytes` panic if the variant doesn't
  match (use a manual `match` if you need a fallible converter).
- `build_p2pkh_script` panics on a malformed Base58 address.
- `build_deploy_transaction` panics if no UTXOs are passed (the caller
  controls UTXO selection — passing zero is a bug, not a runtime condition).
- `pow`, `mul_div`, `percent_of`, `sqrt`, `gcd` in the prelude panic on
  i64 overflow (Bitcoin Script supports arbitrary precision; Rust tests use
  i64 for ergonomics).

There are no exported error variants — the SDK does not ship custom error
types. The closest equivalent to typed errors in this surface is the
prelude's panic messages, which all start with the function name (e.g.
`"safediv: division by zero"`) for easy grep-based test assertions.

---

## 15. Troubleshooting / FAQ

**`thread '...' panicked at 'expected N constructor args for M, got K'`** —
You called `RunarContract::new` with the wrong number of `SdkValue`s. Check
the artifact's `abi.constructor.params.len()` — it must equal
`constructor_args.len()`.

**`SdkValue::as_int called on non-numeric variant`** — You're reading a
state field that the artifact declares as `bool` or `ByteString`. Use
`as_bool()` / `as_bytes()` instead, or pattern-match on `SdkValue` directly.

**Deploy succeeds but `call` returns `"contract is not deployed"`** — You
constructed a fresh `RunarContract` after deploying (e.g. via
`RunarContract::new`) instead of reusing the contract object that owns the
tracked UTXO. Either keep the same instance, or reconnect via
`RunarContract::from_txid` / `::from_utxo`.

**Stateful call fails on chain with "preimage mismatch"** — The new state
the SDK serialized doesn't match what the on-chain script expected. This is
usually one of: (a) you overrode `CallOptions::new_state` with a value that
doesn't match the contract's logic, (b) the artifact you deployed isn't the
one you're calling against (check `RunarArtifact::contract_name` and
`script` template), or (c) the contract has an `addOutput` / `addRawOutput`
the SDK is unaware of (provide it explicitly via `CallOptions::outputs` /
`::data_outputs`).

**`MockProvider: no UTXOs found for address`** — `MockProvider` is
in-memory; you have to `provider.add_utxo(&signer.get_address()?, utxo)`
before deploying. The reference test in
[`integration/rust/tests/helpers/mod.rs`](../../integration/rust/tests/helpers/mod.rs)
shows the regtest equivalent.

**`LocalSigner: invalid private key`** — `LocalSigner::new` accepts either
a 64-char hex private key or a WIF-encoded key (starting with `5`, `K`, or
`L`). Anything else is rejected. Check for stray whitespace.

**Compile errors about missing `runar::contract` macro** — You wrote
`use runar::*;` instead of `use runar::prelude::*;` (the former does not
re-export the proc-macros). Either fix the import or use the fully-qualified
form `#[runar::contract]` and `#[runar::methods(Foo)]`.

**Wallet provider: `"public key not cached"`** — `WalletProvider::get_utxos`
needs a cached pubkey to derive the funding script. Call
`provider.ensure_funding(min_sats)?` once before the first deploy/call;
that warms the cache.

**Mainnet broadcast fails with "missing inputs"** — your funding UTXO is
already spent (probably by a competing tx). Re-fetch UTXOs from the
provider; the SDK doesn't poll.

---

## 16. Versioning and Stability

The Rúnar Rust SDK follows semantic versioning. As of this README the crate
version is `0.4.x`; the `0.x` line carries the **unstable** marker — minor
bumps may break public APIs. We do however commit to the following:

- `RunarContract::deploy` / `::call` / `::prepare_call` / `::finalize_call`
  signatures are frozen for the `0.4.x` line. Optional `CallOptions` fields
  may be added in patch releases (additive change, default value preserves
  behaviour).
- `Provider` and `Signer` trait methods are frozen for the `0.4.x` line.
- Wire formats (artifact JSON, `SdkValue`'s mapping to script bytes) are
  governed by the `version` field on the artifact and validated by the
  cross-SDK conformance suite — they will not change incompatibly within a
  language version.

**Cross-SDK byte identity** — every `0.4.x` release of the seven Rúnar SDKs
(TS, Go, Rust, Python, Zig, Ruby, Java) produces byte-identical deployed
locking scripts for the same artifact + constructor args. This is verified
by [`conformance/sdk-output/`](../../conformance/sdk-output/) on every CI
run. If you observe a divergence, please file an issue.

When the language reaches `1.0` the SDK will follow with the same
guarantees, locking the trait surface for the entire `1.x` line.

---

## 17. Links

- **Repository** — <https://github.com/icellan/runar>
- **Crates.io** — <https://crates.io/crates/runar-lang>
- **Compiler crate** — <https://crates.io/crates/runar-compiler-rust>
- **Macros crate** — <https://crates.io/crates/runar-lang-macros>
- **Language guide (Rust format)** — [`docs/formats/rust.md`](../../docs/formats/rust.md)
- **Counter end-to-end (integration)** — [`integration/rust/tests/counter.rs`](../../integration/rust/tests/counter.rs)
- **Counter end-to-end (Go reference flow)** — [`integration/go/counter_test.go`](../../integration/go/counter_test.go)
- **SDK output conformance** — [`conformance/sdk-output/`](../../conformance/sdk-output/)
- **Issue tracker** — <https://github.com/icellan/runar/issues>
- **License** — MIT
