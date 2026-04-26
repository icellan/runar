# runar-lang

Ruby runtime and SDK for writing, compiling, deploying, and interacting with Rúnar Bitcoin Script smart contracts on BSV.

`runar-lang` is the Ruby implementation of the Rúnar language and deployment SDK. It ships base classes for writing contracts directly in Ruby, real cryptographic primitives (SHA-256, RIPEMD-160, secp256k1, BLAKE3, Rabin, WOTS+, SLH-DSA), an off-chain interpreter for testing business logic, and a transaction-building SDK for deploying and calling contracts on the BSV mainnet, testnet, and regtest.

The compiled output is byte-identical to the output of the six peer SDKs (TypeScript, Go, Rust, Python, Zig, Java). Contracts written in any host language can be deployed by any SDK; contracts deployed by any SDK can be called from any other SDK.

---

## Table of Contents

1. [Installation](#1-installation)
2. [Quick Start](#2-quick-start)
3. [Core Concepts](#3-core-concepts)
4. [Writing a Contract](#4-writing-a-contract)
5. [Compiling](#5-compiling)
6. [Deploying Contracts](#6-deploying-contracts)
7. [Calling Contract Methods](#7-calling-contract-methods)
   - [7a. Single-signer (`call`)](#7a-single-signer-call)
   - [7b. Multi-signer (`prepare_call` / `finalize_call`)](#7b-multi-signer-prepare_call--finalize_call)
   - [7c. BRC-100 wallet signing](#7c-brc-100-wallet-signing)
8. [Stateful Contracts](#8-stateful-contracts)
9. [UTXO and Fee Management](#9-utxo-and-fee-management)
10. [Typed Contract Bindings (`Runar::SDK::CodeGen`)](#10-typed-contract-bindings-runarsdkcodegen)
11. [Testing](#11-testing)
    - [11a. Off-chain testing](#11a-off-chain-testing)
    - [11b. Integration testing against a regtest node](#11b-integration-testing-against-a-regtest-node)
12. [Provider Configuration](#12-provider-configuration)
13. [Full API Reference](#13-full-api-reference)
14. [Error Handling](#14-error-handling)
15. [Troubleshooting / FAQ](#15-troubleshooting--faq)
16. [Versioning and Stability](#16-versioning-and-stability)
17. [Links](#17-links)

> Note on numbering: this README uses 17 top-level sections; sections 7, 11, and the in-section anchors expand the structure described in the project plan.

---

## 1. Installation

Add the gem to your Gemfile:

```ruby
# Gemfile
source 'https://rubygems.org'

gem 'runar-lang'
```

Then:

```bash
bundle install
```

Or install it directly:

```bash
gem install runar-lang
```

**Required Ruby version:** `>= 3.0`.

**Hard dependencies:** none. The core gem uses only Ruby's standard library (`digest`, `openssl`, `net/http`, `json`, `securerandom`).

**Optional dependencies:**

| Gem               | Required for                                                                                    |
|-------------------|-------------------------------------------------------------------------------------------------|
| `bsv-sdk`         | `Runar::SDK::LocalSigner` — real ECDSA signing with a hot key                                   |
| `runar_compiler`  | `Runar.compile_check` — running the Rúnar frontend (parse → validate → typecheck) from Ruby     |

If you only intend to write contracts, test them off-chain, and have someone else compile + deploy them, no optional gems are needed.

To use the deployment SDK in production with a hot key:

```ruby
gem 'runar-lang'
gem 'bsv-sdk'
```

---

## 2. Quick Start

End-to-end deploy → call → verify cycle for a stateful counter, using the in-memory `MockProvider` so it runs without a node:

```ruby
require 'json'
require 'runar/sdk'

# 1. Load the compiled artifact (produced by any Rúnar compiler).
artifact = Runar::SDK::RunarArtifact.from_json(File.read('Counter.json'))

# 2. Wire up provider + signer.
provider = Runar::SDK::MockProvider.new
signer   = Runar::SDK::MockSigner.new

# Pre-fund the signer's address so deploy has a UTXO to spend from.
provider.add_utxo(
  signer.get_address,
  Runar::SDK::Utxo.new(
    txid:         'a' * 64,
    output_index: 0,
    satoshis:     1_000_000,
    script:       Runar::SDK.build_p2pkh_script(signer.get_address)
  )
)

# 3. Construct the contract with constructor args (count = 0).
contract = Runar::SDK::RunarContract.new(artifact, [0])
contract.connect(provider, signer)

# 4. Deploy.
deploy_txid, _tx = contract.deploy(
  provider, signer,
  Runar::SDK::DeployOptions.new(satoshis: 5_000)
)
puts "deployed: #{deploy_txid}"

# 5. Call increment.
call_txid, _tx = contract.call('increment', [])
puts "incremented: #{call_txid}"

# 6. Read the new state.
puts "count = #{contract.get_state['count']}"   # => count = 1
```

The same flow works against a real node by swapping `MockProvider` for `RPCProvider` (regtest/local node), `WhatsOnChainProvider` (mainnet/testnet REST), or `GorillaPoolProvider` (1Sat ordinals overlay). The same flow works against a BRC-100 wallet by swapping `MockSigner` for `WalletSigner` and `MockProvider` for `WalletProvider`. See [Section 12](#12-provider-configuration).

The `Counter` contract source is at [`examples/ruby/stateful-counter/Counter.runar.rb`](../../examples/ruby/stateful-counter/Counter.runar.rb). See also [`integration/ruby/spec/counter_spec.rb`](../../integration/ruby/spec/counter_spec.rb) for the regtest version of the same flow.

---

## 3. Core Concepts

The Ruby SDK is built around eight concepts that are common to every Rúnar SDK:

| Concept            | Ruby type                                              | Role                                                                                                                |
|--------------------|---------------------------------------------------------|---------------------------------------------------------------------------------------------------------------------|
| **Artifact**       | `Runar::SDK::RunarArtifact`                            | The compiled contract — locking-script template, ABI, state schema, constructor slots, ANF IR. Loaded from JSON.    |
| **Contract**       | `Runar::SDK::RunarContract`                            | Runtime wrapper for an artifact + constructor args + state + current UTXO. Knows how to deploy, call, and serialize. |
| **Provider**       | `Runar::SDK::Provider` (abstract base)                  | Read/write blockchain interface. Fetches UTXOs and transactions; broadcasts signed txs. Pluggable.                  |
| **Signer**         | `Runar::SDK::Signer` (abstract base)                    | Key-management interface. Returns compressed pubkey + P2PKH address; signs BIP-143 sighashes. Pluggable.            |
| **Wallet**         | `Runar::SDK::WalletClient` (abstract base)              | BRC-100 wallet client (browser/extension wallet). Backs `WalletProvider` + `WalletSigner` when raw keys aren't held. |
| **Call**           | `RunarContract#call`, `#prepare_call`, `#finalize_call` | A single method invocation: spend the contract UTXO, optionally produce a continuation, optionally produce data outputs, broadcast. |
| **PreparedCall**   | `Runar::SDK::PreparedCall`                              | Result of the two-pass calling flow — built-but-unsigned tx + per-Sig sighashes for an external signer.             |
| **State**          | `Hash` returned by `RunarContract#get_state`            | Mutable Bitcoin-Script-encoded payload after the contract's last `OP_RETURN`. Stateful contracts only.              |
| **UTXO**           | `Runar::SDK::Utxo`                                      | The contract's current on-chain output (`txid`, `output_index`, `satoshis`, `script`). Tracked across deploy → call → call. |
| **Inscription**    | `Runar::SDK::Inscription`                               | A 1Sat ordinals envelope spliced between code and state in the locking script. Immutable across state transitions.  |

**Cross-SDK type-name mapping.** The Ruby type names follow Ruby conventions (snake_case methods, `Runar::SDK::` namespace) but map one-to-one to the equivalents in the other six SDKs:

| Concept          | Ruby                            | Other SDKs                       |
|------------------|---------------------------------|----------------------------------|
| Contract         | `Runar::SDK::RunarContract`     | `RunarContract`                  |
| Artifact         | `Runar::SDK::RunarArtifact`     | `RunarArtifact`                  |
| Provider         | `Runar::SDK::Provider`          | `Provider` (interface/trait/ABC) |
| Signer           | `Runar::SDK::Signer`            | `Signer` (interface/trait/ABC)   |
| Mainnet provider | `Runar::SDK::WhatsOnChainProvider` | `WhatsOnChainProvider` everywhere except: the Ruby file is named `lib/runar/sdk/woc_provider.rb` (historical) but the class itself is `WhatsOnChainProvider`. |
| BRC-100 wallet provider | `Runar::SDK::WalletProvider` | `WalletProvider`                 |

`Runar::SDK` is a Ruby module, not a class — every public name is reached through it (`Runar::SDK::RunarContract`, `Runar::SDK::Utxo`, `Runar::SDK.build_p2pkh_script`, etc.).

---

## 4. Writing a Contract

A Rúnar contract is a Ruby class that extends `Runar::SmartContract` (stateless) or `Runar::StatefulSmartContract` (stateful), declares its properties with the `prop` DSL, and marks public spending entry points with `runar_public`.

### 4.1 The DSL

Three class methods make a Ruby class a Rúnar contract:

| Method                                    | Purpose                                                                                                                            |
|-------------------------------------------|------------------------------------------------------------------------------------------------------------------------------------|
| `prop :name, Type [, readonly: true] [, default: value]` | Declare a typed property. `readonly:` generates only a reader. `default:` sets an initial value and excludes the prop from the auto-generated constructor. |
| `runar_public [**param_types]`            | Mark the next method as a public spending entry point. Optional keyword args declare ABI param types.                              |
| `params **param_types`                    | Declare parameter types for the next private method (helper).                                                                      |

The DSL is implemented in [`lib/runar/dsl.rb`](lib/runar/dsl.rb). Type names are Ruby constants (`Bigint`, `PubKey`, `Sig`, `Addr`, `Sha256`, `Ripemd160`, `Point`, `ByteString`, `Boolean`, etc.) defined in [`lib/runar/types.rb`](lib/runar/types.rb) and re-exported at the top level so a typo raises `NameError` immediately at class load.

### 4.2 Stateless contracts (`Runar::SmartContract`)

A stateless contract carries no on-chain state; all properties are `readonly`. The developer writes the full unlocking logic.

```ruby
require 'runar'

class P2PKH < Runar::SmartContract
  prop :pub_key_hash, Addr

  def initialize(pub_key_hash)
    super(pub_key_hash)
    @pub_key_hash = pub_key_hash
  end

  runar_public sig: Sig, pub_key: PubKey
  def unlock(sig, pub_key)
    assert hash160(pub_key) == @pub_key_hash
    assert check_sig(sig, pub_key)
  end
end
```

Source: [`examples/ruby/p2pkh/P2PKH.runar.rb`](../../examples/ruby/p2pkh/P2PKH.runar.rb).

The constructor must call `super(...)` first, passing all properties. `assert` is the primary control-flow mechanism — when any assertion is false, the script fails.

### 4.3 Stateful contracts (`Runar::StatefulSmartContract`)

A stateful contract has mutable properties carried in the UTXO state. The compiler auto-injects `check_preimage` at method entry and the state continuation at exit, so the developer only writes the state transition itself.

```ruby
require 'runar'

class Counter < Runar::StatefulSmartContract
  prop :count, Bigint

  def initialize(count)
    super(count)
    @count = count
  end

  runar_public
  def increment
    @count += 1
  end

  runar_public
  def decrement
    assert @count > 0
    @count -= 1
  end
end
```

Source: [`examples/ruby/stateful-counter/Counter.runar.rb`](../../examples/ruby/stateful-counter/Counter.runar.rb).

### 4.4 Built-in functions

Rúnar built-ins are mixed into `Kernel` so they can be called from anywhere — both inside a contract method and inside a test:

```ruby
hash160(mock_pub_key)        # => 40-char hex
check_sig(mock_sig, mock_pub_key)  # => true (mock crypto)
num2bin(42, 8)               # => "2a00000000000000"
```

The full set is defined in [`lib/runar/builtins.rb`](lib/runar/builtins.rb):

- **Hashes (real):** `sha256`, `hash256`, `ripemd160`, `hash160`, `sha256_compress`, `sha256_finalize`, `blake3_compress`, `blake3_hash`
- **Crypto verification:** `check_sig` (real ECDSA over a fixed test digest), `check_multi_sig`, `check_preimage` (always true off-chain), `verify_rabin_sig`, `verify_wots`, `verify_slh_dsa_sha2_{128,192,256}{s,f}` (real verification)
- **Math:** `assert`, `abs`, `min`, `max`, `within`, `safediv`, `safemod`, `clamp`, `sign`, `pow`, `mul_div`, `percent_of`, `sqrt`, `gcd`, `divmod`, `log2`, `bool`
- **EC (secp256k1, real):** `ec_add`, `ec_mul`, `ec_mul_gen`, `ec_negate`, `ec_on_curve`, `ec_mod_reduce`, `ec_encode_compressed`, `ec_make_point`, `ec_point_x`, `ec_point_y`
- **Binary utilities:** `num2bin`, `bin2num`, `cat`, `substr`, `left`, `right`, `reverse_bytes`, `len`
- **Preimage extraction (mocked off-chain):** `extract_locktime`, `extract_output_hash`, `extract_amount`, `extract_version`, `extract_sequence`, `extract_hash_prevouts`, `extract_outpoint`
- **Test helpers:** `mock_sig`, `mock_pub_key`, `mock_preimage`

### 4.5 Stateful intrinsics

`Runar::StatefulSmartContract` exposes three output-emission helpers used inside method bodies:

```ruby
add_output(satoshis, *state_values)      # contract-state continuation output
add_raw_output(satoshis, script_bytes)   # raw script bytes — included in continuation hash
add_data_output(satoshis, script_bytes)  # OP_RETURN data — between state and change
```

- `add_output(satoshis, *state_values)` writes a continuation output with `state_values` matching mutable properties in declaration order.
- `add_raw_output(satoshis, script_bytes)` writes an output whose script is caller-defined (not the contract's own codePart). Hashed into the continuation alongside state outputs.
- `add_data_output(satoshis, script_bytes)` writes an arbitrary script (e.g. `OP_RETURN <data>`) between state outputs and the change output. Preserves declaration order in the continuation hash.

Implementation: [`lib/runar/base.rb`](lib/runar/base.rb).

---

## 5. Compiling

Rúnar contracts must be compiled to a JSON artifact before they can be deployed or called. Compilation runs Parse → Validate → TypeCheck → ANF lowering → Stack lowering → Emit, producing the locking-script template that all 7 SDKs share.

The Ruby gem itself does **not** ship the full compiler. Two complementary tools handle compilation from Ruby:

### 5.1 `Runar.compile_check` — frontend validation only

`Runar.compile_check(source_or_path, file_name = nil)` runs the frontend pipeline (Parse → Validate → TypeCheck) on a contract source and raises if the contract is not valid Rúnar. It does not produce a compiled artifact — use it from RSpec to keep contracts honest as you edit them.

```ruby
require 'runar'

# By path:
Runar.compile_check('Counter.runar.rb')

# Or by source string:
source = File.read('Counter.runar.rb')
Runar.compile_check(source, 'Counter.runar.rb')
```

`compile_check` requires the `runar_compiler` gem to be installed. If it isn't, `compile_check` raises `LoadError` with an install hint:

```
LoadError: compile_check requires the runar_compiler gem.
Install it with: gem install runar_compiler, or add gem 'runar_compiler' to your Gemfile
```

Implementation: [`lib/runar/compile_check.rb`](lib/runar/compile_check.rb).

### 5.2 Producing a JSON artifact

To produce the JSON artifact a `RunarContract` consumes, run any of the seven compilers as a CLI:

```bash
# TypeScript reference compiler
npx runar compile path/to/Counter.runar.rb -o Counter.json

# Ruby compiler (in this repo)
ruby compilers/ruby/bin/runar-compiler-ruby --source Counter.runar.rb > Counter.json

# Go compiler
runar-go compile Counter.runar.rb -o Counter.json
```

All seven compilers parse all nine `.runar.{ts,sol,move,go,rs,py,zig,rb,java}` extensions and produce byte-identical output. The conformance suite at [`conformance/sdk-output/`](../../conformance/sdk-output/) verifies that the seven SDKs produce byte-identical deployed locking scripts for the same artifact + constructor args (27 test cases including [`stateful-counter`](../../conformance/sdk-output/tests/stateful-counter/)).

---

## 6. Deploying Contracts

Construct a `RunarContract` from an artifact + constructor args, attach a provider + signer, and call `deploy`. The SDK selects funding UTXOs, builds and signs the funding transaction, broadcasts it, and starts tracking the contract UTXO.

```ruby
require 'runar/sdk'
require 'runar/sdk/local_signer'

artifact = Runar::SDK::RunarArtifact.from_json(File.read('Counter.json'))
contract = Runar::SDK::RunarContract.new(artifact, [0])

provider = Runar::SDK::WhatsOnChainProvider.new(network: 'testnet')
signer   = Runar::SDK::LocalSigner.new(ENV.fetch('RUNAR_PRIV_KEY_HEX'))
contract.connect(provider, signer)

txid, tx = contract.deploy(
  provider, signer,
  Runar::SDK::DeployOptions.new(satoshis: 5_000)
)

puts "deployed: #{txid}"
puts "contract UTXO: #{contract.get_utxo.inspect}"
```

`deploy` accepts either positional or already-stored provider/signer:

```ruby
contract.connect(provider, signer)
contract.deploy                                     # uses connected provider/signer
contract.deploy(other_provider, other_signer)       # one-off override
```

`DeployOptions` fields:

| Field            | Type    | Default     | Meaning                                                    |
|------------------|---------|-------------|------------------------------------------------------------|
| `satoshis`       | Integer | `10_000`    | Value to lock in the contract output.                      |
| `change_address` | String  | `''`        | Override change address. Empty → uses signer's address.    |

`deploy` returns `[txid, transaction_data]` where `transaction_data` is a `Runar::SDK::TransactionData` (alias `Runar::SDK::Transaction`). Implementation: [`lib/runar/sdk/contract.rb`](lib/runar/sdk/contract.rb).

After deployment, the contract instance owns the contract UTXO. Call `contract.get_utxo` to inspect it. To reconnect to an already-deployed contract from another process, see `RunarContract.from_txid` and `RunarContract.from_utxo` in [Section 13](#13-full-api-reference).

---

## 7. Calling Contract Methods

A call on a deployed contract spends the contract UTXO and produces (a) a continuation UTXO if the contract is stateful, plus (b) any optional data outputs the method declares, plus (c) a P2PKH change output to the signer's address. The Ruby SDK supports three calling styles:

- **`call`** — single signer holds all keys; one round trip.
- **`prepare_call` / `finalize_call`** — two-pass flow for hardware wallets, multi-party signing, or any external signer that can sign a sighash but doesn't hold raw keys in process.
- **BRC-100 wallet** — `WalletProvider` + `WalletSigner` delegate funding and signing to a browser/extension wallet that talks the BRC-100 protocol.

### 7a. Single-signer (`call`)

```ruby
contract.connect(provider, signer)
txid, _tx = contract.call('increment', [])
```

For a method with arguments:

```ruby
# Stateful contract: increment with no args.
contract.call('increment', [])

# Stateless P2PKH: pass the user-visible args; SDK injects Sig placeholder
# and replaces it with a real signature signed by the connected signer.
contract.call('unlock', [signer.get_public_key])
```

`call` resolves the method's user-visible parameters (anything that isn't `SigHashPreimage`, `_changePKH`, `_changeAmount`, `_newAmount`):

| Param type | Behaviour when arg is `nil`                                     |
|------------|------------------------------------------------------------------|
| `Sig`      | 72-byte placeholder; replaced with a real signature in `call`.   |
| `PubKey`   | Filled in from `signer.get_public_key`.                          |
| `SigHashPreimage` | Computed automatically from BIP-143 + the call transaction.  |
| `ByteString` (with name `allPrevouts`) | Filled in from the actual transaction's input outpoints. |
| anything else | Caller must supply the value.                                 |

For stateful contracts, the SDK auto-computes the new state via the bundled ANF interpreter ([`Runar::SDK::ANFInterpreter`](lib/runar/sdk/anf_interpreter.rb)) using the artifact's ANF IR, the current state, and the user-supplied args — so callers don't need to duplicate contract logic.

`CallOptions` fields:

| Field                               | Type                | Default | Meaning                                                                |
|-------------------------------------|---------------------|---------|------------------------------------------------------------------------|
| `satoshis`                          | Integer             | `0`     | Override continuation output value. `0` carries the current value forward. |
| `change_address`                    | String              | `''`    | Override change address.                                              |
| `change_pub_key`                    | String              | `''`    | Optional pubkey hint for `_changePKH` substitution.                    |
| `new_state`                         | Hash                | `nil`   | Override the auto-computed state. Useful for testing rejection paths.  |
| `outputs`                           | Array<OutputSpec>   | `nil`   | Multi-output continuation (e.g. token splits).                         |
| `additional_contract_inputs`        | Array<Utxo or Hash> | `nil`   | Extra contract UTXOs to include as inputs (multi-UTXO calls).         |
| `additional_contract_input_args`    | Array<Array>        | `nil`   | Per-input args for the extra contract inputs.                          |
| `terminal_outputs`                  | Array<TerminalOutput> | `nil` | For terminal methods: exact output set (no change, no funding inputs). |
| `funding_utxos`                     | Array<Utxo>         | `nil`   | Override which P2PKH UTXOs to use for fees.                            |
| `data_outputs`                      | Array<Hash>         | `nil`   | Extra data outputs (e.g. `OP_RETURN <data>`) emitted between state and change. |

`call` returns `[txid, transaction_data]`. After the call returns, `contract.get_utxo` points at the new continuation UTXO (for stateful contracts) or `nil` (for terminal calls or stateless calls).

### 7b. Multi-signer (`prepare_call` / `finalize_call`)

When the signer that controls the contract input lives outside the SDK process — a hardware wallet, a multi-party signing setup, or an offline cold-storage box — split the call into two phases.

`prepare_call(method_name, args, provider, signer, options)` builds the transaction, signs all P2PKH funding inputs, computes the BIP-143 sighash for each `Sig` parameter on the contract input, and returns a `Runar::SDK::PreparedCall`:

```ruby
prepared = contract.prepare_call(
  'unlock', [signer.get_public_key],
  provider, signer
)

prepared.sighash         # 64-char hex sighash for external signing
prepared.preimage        # full BIP-143 preimage
prepared.tx_hex          # built transaction with placeholder sigs
prepared.sig_indices     # arg indices that need external signatures
```

The external signer signs `prepared.sighash` (or computes its own preimage from the tx) and produces a DER signature with the sighash flag byte appended.

`finalize_call(prepared, signatures, provider)` injects the signatures, computes the OP_PUSH_TX prefix if needed, broadcasts the transaction, and updates the tracked UTXO:

```ruby
external_signatures = {
  prepared.sig_indices[0] => external_wallet.sign(prepared.sighash)
}

txid, tx = contract.finalize_call(prepared, external_signatures, provider)
```

The `signatures` hash maps user-arg index → hex DER-with-sighash signature.

`Runar::SDK::PreparedCall` is the canonical multi-signer hand-off shape — mirrors the `PreparedCall` types in the Go, Rust, Python, and Java SDKs. Public fields (`sighash`, `preimage`, `op_push_tx_sig`, `tx_hex`, `sig_indices`) are stable across SDKs; the rest are internal to `finalize_call`.

#### Sig parameter substitution at a glance

When you call a stateless contract with a `Sig`-typed parameter, the SDK performs a two-pass dance:

1. First pass: build a transaction with a 72-byte zero placeholder where the signature will go. Use it to compute the BIP-143 sighash.
2. Sign the sighash with the connected signer.
3. Second pass: replace the placeholder with the real signature, broadcast.

You don't see steps 1–3 — `call` does it for you, taking the user-visible args you pass and the `signer` from `connect` (or the override you passed). For multi-signer flows, `prepare_call` exposes the sighash so you can sign elsewhere; `finalize_call` injects the result.

#### Per-method ABI parameter handling

| ABI param          | Stateless contract                              | Stateful contract (compiler-injected: skipped)    |
|--------------------|--------------------------------------------------|----------------------------------------------------|
| `Sig`              | Placeholder, replaced with real sig             | Same                                              |
| `PubKey`           | If `nil`, filled from signer                    | Same                                              |
| `SigHashPreimage`  | Computed from BIP-143                           | Implicit — never user-visible                     |
| `Ripemd160` named `_changePKH` | User must pass                      | Computed from `signer.get_address`'s pubkey hash; never user-visible |
| `bigint` named `_changeAmount` | User must pass                      | Computed by fee estimator; never user-visible    |
| `bigint` named `_newAmount`    | User must pass                      | Carried from the contract UTXO; never user-visible |
| `ByteString` named `allPrevouts` | User must pass                    | Computed from the actual transaction's input outpoints |
| Anything else      | User must pass                                  | User must pass                                    |

If a method takes a `ByteString allPrevouts` parameter, the SDK rebuilds the transaction once it knows the final input layout, then re-signs with the real `allPrevouts` value. This is why stateful calls go through two preimage passes inside `prepare_call`.

### 7c. BRC-100 wallet signing

A BRC-100 wallet (browser extension, mobile wallet, or any wallet implementing the BRC-100 spec) handles its own keys, builds its own transactions, and broadcasts them. The Ruby SDK adapts a BRC-100 wallet via two helpers:

- `Runar::SDK::WalletProvider` — implements the `Provider` interface, fetching UTXOs from the wallet's basket via `list_outputs`.
- `Runar::SDK::WalletSigner` — implements the `Signer` interface, computing BIP-143 sighashes locally and delegating ECDSA signing to the wallet via `create_signature`.

Both are constructed from a `Runar::SDK::WalletClient` subclass that wraps the four BRC-100 operations:

```ruby
require 'runar/sdk/wallet'

class MyAppWallet < Runar::SDK::WalletClient
  def get_public_key(protocol_id:, key_id:)
    # ...call into your BRC-100 wallet (HTTP, browser bridge, in-process SDK)
  end

  def create_signature(hash_to_sign:, protocol_id:, key_id:)
    # ...wallet signs the digest directly
  end

  def create_action(description:, outputs:)
    # ...wallet builds, funds, signs, and broadcasts the transaction
  end

  def list_outputs(basket:, tags: [], limit: 100)
    # ...wallet enumerates spendable UTXOs in the basket
  end
end

wallet  = MyAppWallet.new
signer  = Runar::SDK::WalletSigner.new(
  wallet:      wallet,
  protocol_id: [2, 'my app'],
  key_id:      '1'
)
provider = Runar::SDK::WalletProvider.new(
  wallet:  wallet,
  signer:  signer,
  basket:  'my-app',
  network: 'mainnet'
)

contract = Runar::SDK::RunarContract.new(artifact, [0])
contract.connect(provider, signer)

# Wallet-funded deploy: the wallet selects inputs, builds, and broadcasts.
result = contract.deploy_with_wallet(satoshis: 1, description: 'My Counter')
# => { txid: "abc...", output_index: 0 }

# Subsequent calls go through the standard call path; signatures come from
# the wallet via WalletSigner.
contract.call('increment', [])
```

`WalletSigner#sign_hash(sighash_hex)` is also exposed for the prepare/finalize flow. Implementation: [`lib/runar/sdk/wallet.rb`](lib/runar/sdk/wallet.rb). A live-endpoint smoke test lives at [`integration/ruby/spec/wallet_client_spec.rb`](../../integration/ruby/spec/wallet_client_spec.rb).

---

## 8. Stateful Contracts

A stateful contract carries mutable state in its UTXO. The SDK chains state across calls by building a continuation output that contains the same code script, an optional inscription envelope, an `OP_RETURN`, and the new state-encoded payload.

### 8.1 State chaining

After every call on a stateful contract, the SDK:

1. Reads the current state from `contract.@state`.
2. Computes the new state via the ANF interpreter (or uses the caller-supplied `new_state` override).
3. Builds the continuation locking script: `code_script || optional_inscription || OP_RETURN || serialised_state`.
4. Builds the call transaction with that continuation as output 0.
5. Computes the BIP-143 preimage in two passes (first pass sizes the unlocking script, second pass produces the stable preimage with the final tx layout).
6. Computes the OP_PUSH_TX signature via the k=1 trick (private key d=1, nonce k=1) so the contract can verify the preimage on-chain without a real ECDSA signature.
7. Broadcasts the transaction.
8. Updates `contract.@current_utxo` to point at output 0 of the new transaction.

State is read with `contract.get_state` (returns a `Hash`) and overridden with `contract.set_state(hash)` (mostly useful for tests).

### 8.2 OP_PUSH_TX

Stateful contracts use the OP_PUSH_TX technique: the unlocking script pushes the BIP-143 preimage and a deterministic ECDSA signature with `d = k = 1`. The on-chain script verifies that `(preimage_hash, sig)` is consistent with the secp256k1 generator point, which is true iff the preimage matches the actual sighash of the spending transaction. The Ruby SDK implements OP_PUSH_TX in [`lib/runar/sdk/oppushtx.rb`](lib/runar/sdk/oppushtx.rb) (see `Runar::SDK.compute_op_push_tx`).

### 8.3 ANF interpreter

To save callers from duplicating contract logic, the SDK ships a lightweight off-chain interpreter for the contract's ANF IR: `Runar::SDK::ANFInterpreter`. Given the ANF (from `artifact.anf`), the method name, the current state, and the named args, it computes the new state without running Bitcoin Script. The interpreter handles:

- `bin_op`, `unary_op`, `if`, `loop`, `assert` (no-op), `update_prop`, `add_output`, `add_data_output`
- Built-in calls: real hashes (`sha256`, `hash160`, `hash256`, `ripemd160`), real math (`abs`, `min`, `max`, `safediv`, `safemod`, `pow`, `sqrt`, `gcd`, `log2`, …), real binary utilities (`num2bin`, `bin2num`, `cat`, `substr`, `len`)
- Mock crypto: `check_sig`, `check_multi_sig`, `check_preimage` always return true off-chain
- `add_raw_output`, `check_preimage`, `deserialize_state`, `get_state_script`: skipped (on-chain only)
- Private method calls: looked up in the ANF IR, evaluated in a child env, state mutations propagated back

Loop iteration is bounded by `MAX_LOOP_ITERATIONS = 65_536` to prevent unbounded simulation of malformed artifacts. Override per-call with the `max_loop_iterations:` keyword. Implementation: [`lib/runar/sdk/anf_interpreter.rb`](lib/runar/sdk/anf_interpreter.rb).

### 8.4 Reading state from chain

```ruby
contract = Runar::SDK::RunarContract.from_txid(artifact, txid, vout, provider)
contract.get_state                  # => { 'count' => 42 }
contract.get_utxo                   # => Utxo(...)
contract.inscription                # => Inscription(...) or nil
```

`from_utxo` is the synchronous variant when a `Utxo` (or `Hash` in the same shape) is already on hand and no `Provider` lookup is needed.

State serialisation lives in [`lib/runar/sdk/state.rb`](lib/runar/sdk/state.rb): integers are 8-byte little-endian sign-magnitude (`num2bin`), booleans are a single byte, and known fixed-width types (`PubKey`, `Addr`, `Sha256`, `Ripemd160`, `Point`) are written as raw hex. Everything else is push-data encoded. `FixedArray<T, N>` fields are flattened across N scalar slots and re-grouped on read.

### 8.5 Inscriptions

Attach a 1Sat ordinals inscription to a contract before deployment with `with_inscription`:

```ruby
insc = Runar::SDK::Inscription.new(
  content_type: 'image/png',
  data:         File.binread('logo.png').unpack1('H*')
)
contract.with_inscription(insc)
```

The envelope is a no-op (`OP_FALSE OP_IF … OP_ENDIF`) spliced between the code script and the state section. Once deployed, the inscription is immutable — it persists identically across all state transitions. BSV-20 / BSV-21 helpers live in [`Runar::SDK::Ordinals`](lib/runar/sdk/ordinals.rb).

---

## 9. UTXO and Fee Management

### 9.1 UTXO selection

The SDK uses **largest-first selection with fee-aware iteration**: UTXOs are sorted by `satoshis` descending, then added one-by-one until `total >= target_satoshis + estimated_fee`. The fee is recomputed on each iteration to account for the additional input. If the available UTXOs can't cover both the target and the fee, `select_utxos` raises `ArgumentError` with a clear message.

Implementation: `Runar::SDK.select_utxos(utxos, target_satoshis, locking_script_byte_len, fee_rate:)` in [`lib/runar/sdk/deployment.rb`](lib/runar/sdk/deployment.rb).

### 9.2 Fee estimation

Fees are computed from actual script sizes — not hardcoded P2PKH assumptions. Two helpers:

```ruby
Runar::SDK.estimate_deploy_fee(num_inputs, locking_script_byte_len, fee_rate)
Runar::SDK.estimate_call_fee(locking_script_byte_len, unlocking_script_byte_len, num_funding_inputs, fee_rate)
```

The size model accounts for: 10-byte tx overhead, 148-byte P2PKH inputs, the contract input's actual unlocking script, the contract output's actual locking script (with varint), data outputs, and one P2PKH change output. `fee_rate` is in satoshis per kilobyte (minimum 1).

### 9.3 Change output

If the change amount is positive and either `change_address` or `change_script` is provided, a P2PKH change output is appended. If the change amount is zero (or negative after fees), no change output is emitted — the entire surplus is consumed by the fee.

### 9.4 P2PKH script construction

`Runar::SDK.build_p2pkh_script(address)` accepts either:

- A 40-character hex pubkey hash (e.g. `'9a1c78a507689f6f54b847ad1cef1e614ee23f1e'`), or
- A Base58Check-encoded P2PKH address (mainnet `1...`, testnet `m.../n...`, regtest matching).

It returns the standard 25-byte locking script `76a914{20-byte-hash}88ac` as a hex string. The Base58 decoder is bundled — no external gems are needed.

### 9.5 Tracking the contract UTXO

`RunarContract` maintains `@current_utxo` automatically:

| After…                       | `get_utxo` returns…                             |
|------------------------------|-------------------------------------------------|
| `new(artifact, args)`        | `nil`                                           |
| `deploy`                     | output 0 of the deploy tx                       |
| `call` (stateful)            | output 0 of the call tx                         |
| `call` (multi-output)        | output 0 of the call tx (first continuation)    |
| `call` (stateless)           | `nil`                                           |
| `call` with `terminal_outputs:` | `nil`                                        |
| `from_txid` / `from_utxo`    | the UTXO at `(txid, vout)`                      |

---

## 10. Typed Contract Bindings (`Runar::SDK::CodeGen`)

`Runar::SDK::CodeGen` generates a typed Ruby wrapper class from a compiled artifact. The wrapper exposes a method per contract method, with idiomatic keyword arguments matching the ABI, and hides the SDK plumbing (placeholder Sig args, preimage params, change-PKH params, etc.) behind a clean signature.

```ruby
require 'runar/sdk'

artifact = Runar::SDK::RunarArtifact.from_json(File.read('Counter.json'))
File.write(
  'counter_binding.rb',
  Runar::SDK::CodeGen.generate_ruby(artifact)
)
```

The generated file defines `Runar::Contracts::CounterContract` (or `<ContractName>Contract`) with:

- A typed constructor: `CounterContract.new(artifact, count: 0)`.
- One method per public contract method: `counter.increment(provider:, signer:)`.
- For stateful methods, a `<ContractName>StatefulCallOptions` struct accepting `satoshis:`, `change_address:`, `change_pub_key:`, `new_state:`, and `outputs:`.
- For terminal methods, a `Runar::Contracts::TerminalOutput` struct accepting `satoshis:`, `address:`, `script_hex:`.
- For methods with `Sig` parameters, a `prepare_<method>` / `finalize_<method>` pair for the multi-signer flow.
- A `from_txid(artifact, txid, output_index, provider)` class method that returns a typed wrapper around an existing on-chain UTXO.

The generator currently exposes `generate_ruby(artifact) -> String`. At parity with the other six SDKs, the planned cross-target surface is:

| Target    | Method                              |
|-----------|-------------------------------------|
| Ruby      | `Runar::SDK::CodeGen.generate_ruby(artifact)`       |
| TypeScript| `Runar::SDK::CodeGen.generate_typescript(artifact)` |
| Go        | `Runar::SDK::CodeGen.generate_go(artifact)`         |
| Rust      | `Runar::SDK::CodeGen.generate_rust(artifact)`       |
| Python    | `Runar::SDK::CodeGen.generate_python(artifact)`     |
| Zig       | `Runar::SDK::CodeGen.generate_zig(artifact)`        |
| Java      | `Runar::SDK::CodeGen.generate_java(artifact)`       |

Mustache-style template rendering is bundled (no external dependencies). Implementation: [`lib/runar/sdk/codegen.rb`](lib/runar/sdk/codegen.rb).

> Note: the Ruby file uses `Runar::SDK::Codegen` (lower-case `g`) today; the canonical name in this README and across the Rúnar tree is `Runar::SDK::CodeGen`. Both spellings will resolve once the parity work in [`RUNAR-SDK-PARITY.md`](../../RUNAR-SDK-PARITY.md) lands; until then, prefer `Runar::SDK::Codegen.generate_ruby(artifact)`.

---

## 11. Testing

Rúnar's testing story has two layers: off-chain RSpec tests that exercise contract business logic with mocked crypto, and on-chain integration tests that compile and broadcast against a live regtest node.

### 11a. Off-chain testing

A `.runar.rb` source file is itself valid Ruby. Require it from RSpec and instantiate the contract directly — `mock_pub_key` returns ALICE's real test pubkey, `mock_sig` returns a real ECDSA signature over the fixed test digest, and `check_sig` verifies it. Other crypto primitives (`check_preimage`) are stubbed to true so tests focus on business logic; hashes (`hash160`, `sha256`) use real `digest`/`openssl`.

#### Mock crypto consistency across SDKs

The Ruby SDK ships the same set of intrinsic mock helpers as the other six SDKs, with the same semantics:

| Helper                                  | Behaviour off-chain                                                            |
|-----------------------------------------|--------------------------------------------------------------------------------|
| `mock_sig`                              | Returns ALICE's real DER-encoded ECDSA signature over the fixed test digest    |
| `mock_pub_key`                          | Returns ALICE's real 33-byte compressed secp256k1 public key                   |
| `mock_preimage`                         | 181 zero bytes (matches the BIP-143 preimage size for a single-input transaction) |
| `check_sig(sig, pk)`                    | Real ECDSA verification against `SHA256("runar-test-message-v1")`              |
| `check_multi_sig(sigs, pks)`            | Real Bitcoin-style ordered multi-sig verification                              |
| `check_preimage(preimage)`              | Always returns true                                                            |
| `verify_rabin_sig(...)`                 | Real Rabin verification math                                                   |
| `verify_wots(...)`, `verify_slh_dsa_*` | Real verification math                                                         |
| `hash160`, `hash256`, `sha256`, `ripemd160` | Real hashes (Ruby `digest` / `openssl`)                                    |

#### Setup: spec_helper

A minimal `spec_helper.rb` for an `examples/ruby/` style layout:

```ruby
# spec/spec_helper.rb
require 'rspec'
require 'runar'

RSpec.configure do |config|
  config.expect_with :rspec do |c|
    c.syntax = :expect
  end
end
```

#### Pattern: idempotent setup with `let`

```ruby
require 'spec_helper'
require_relative '../P2PKH.runar'

RSpec.describe P2PKH do
  let(:pk)    { mock_pub_key }
  let(:wrong) { '03' + ('00' * 32) }
  let(:c)     { P2PKH.new(hash160(pk)) }

  it 'unlocks with the right key' do
    expect { c.unlock(mock_sig, pk) }.not_to raise_error
  end

  it 'rejects a wrong key' do
    expect { c.unlock(mock_sig, wrong) }.to raise_error(RuntimeError, /assertion failed/)
  end
end
```

#### Pattern: stateful chains

```ruby
require 'spec_helper'
require_relative '../Counter.runar'

RSpec.describe Counter do
  it 'chains 0 -> 1 -> 2 -> 1' do
    c = Counter.new(0)
    c.increment
    c.increment
    c.decrement
    expect(c.count).to eq(1)
  end
end
```

```ruby
# spec/p2pkh_spec.rb
require_relative '../P2PKH.runar'

RSpec.describe P2PKH do
  it 'unlocks with a valid signature over the test digest' do
    pk = mock_pub_key
    c  = P2PKH.new(hash160(pk))
    expect { c.unlock(mock_sig, pk) }.not_to raise_error
  end

  it 'rejects a wrong public key' do
    pk       = mock_pub_key
    wrong_pk = '03' + ('00' * 32)
    c        = P2PKH.new(hash160(pk))
    expect { c.unlock(mock_sig, wrong_pk) }.to raise_error(RuntimeError)
  end
end
```

A stateful counter test:

```ruby
# spec/counter_spec.rb
require_relative '../Counter.runar'

RSpec.describe Counter do
  it 'increments' do
    c = Counter.new(0)
    c.increment
    expect(c.count).to eq(1)
  end

  it 'fails to decrement at zero' do
    c = Counter.new(0)
    expect { c.decrement }.to raise_error(RuntimeError)
  end
end
```

Run with:

```bash
cd examples/ruby && bundle exec rspec
```

To additionally guard that the contract still type-checks under the Rúnar frontend, add a compile-check spec:

```ruby
require 'runar'

RSpec.describe 'Counter compile-check' do
  it 'parses, validates, and type-checks' do
    expect(Runar.compile_check('Counter.runar.rb')).to be true
  end
end
```

`compile_check` requires the `runar_compiler` gem (see [Section 5](#5-compiling)).

The full set of off-chain testing patterns is shown across the `examples/ruby/` directory: stateful (`stateful-counter`, `auction`, `tic-tac-toe`), stateless (`p2pkh`, `escrow`), and post-quantum (`post-quantum-wots`, `post-quantum-wallet`).

### 11b. Integration testing against a regtest node

For end-to-end validation against a real node, [`integration/ruby/`](../../integration/ruby/) ships an RSpec suite that compiles each contract, deploys it through the Ruby SDK, calls each method, and verifies the on-chain state.

Prerequisites:

- A BSV regtest node listening on `localhost:18332` (user `bitcoin` / pass `bitcoin`). Override with `RPC_URL`, `RPC_USER`, `RPC_PASS`.
- The `bsv-sdk` gem (for real ECDSA signing).

```bash
cd integration && ./regtest.sh start
cd ruby && bundle exec rspec spec/counter_spec.rb
```

A representative test flow ([`integration/ruby/spec/counter_spec.rb`](../../integration/ruby/spec/counter_spec.rb)):

```ruby
require 'spec_helper'

RSpec.describe 'Counter' do
  it 'increments then decrements: 0 -> 1 -> 0' do
    artifact = compile_contract('examples/ts/stateful-counter/Counter.runar.ts')
    contract = Runar::SDK::RunarContract.new(artifact, [0])

    provider = create_provider
    wallet   = create_funded_wallet(provider)

    contract.deploy(provider, wallet[:signer], Runar::SDK::DeployOptions.new(satoshis: 5_000))
    contract.call('increment', [], provider, wallet[:signer], Runar::SDK::CallOptions.new(new_state: { 'count' => 1 }))
    contract.call('decrement', [], provider, wallet[:signer], Runar::SDK::CallOptions.new(new_state: { 'count' => 0 }))
  end
end
```

The `compile_contract`, `create_provider`, and `create_funded_wallet` helpers live in [`integration/ruby/spec/spec_helper.rb`](../../integration/ruby/spec/spec_helper.rb).

**Cross-SDK parity.** The conformance suite [`conformance/sdk-output/`](../../conformance/sdk-output/) verifies that all 7 SDKs produce byte-identical deployed locking scripts for the same artifact + constructor args, including [`stateful-counter`](../../conformance/sdk-output/tests/stateful-counter/). If your contract works under the Ruby SDK, it works under the other six.

---

## 12. Provider Configuration

Five concrete `Provider` implementations ship with the gem. They all live under `Runar::SDK::` and all extend `Runar::SDK::Provider`.

### 12.1 `MockProvider`

In-memory provider for unit tests and local development. Pre-populate with UTXOs and transactions, then inspect what the SDK broadcasts.

```ruby
provider = Runar::SDK::MockProvider.new(network: 'testnet')

provider.add_utxo(address, Runar::SDK::Utxo.new(txid: 'aa'*32, output_index: 0, satoshis: 1_000_000, script: '76a914...88ac'))
provider.add_transaction(Runar::SDK::TransactionData.new(txid: 'bb'*32, outputs: [...]))
provider.set_fee_rate(100)

provider.get_broadcasted_txs   # => Array<String> of every raw tx the SDK pushed
```

Implementation: [`lib/runar/sdk/provider.rb`](lib/runar/sdk/provider.rb).

### 12.2 `RPCProvider`

JSON-RPC provider for a Bitcoin node (BSV or compatible). Uses `net/http` + `json` from stdlib.

```ruby
provider = Runar::SDK::RPCProvider.new(
  host:     'localhost',
  port:     18_332,
  username: 'bitcoin',
  password: 'bitcoin',
  network:  'regtest'
)

# Or use the regtest factory shortcut:
provider = Runar::SDK::RPCProvider.regtest

# Mine N blocks (regtest only):
provider.mine(5)
```

`get_contract_utxo(script_hash)` uses `scantxoutset` — functional for regtest/testnet but slow on mainnet. For mainnet, use an electrum-style indexer or track UTXOs manually with `RunarContract.from_txid`. Implementation: [`lib/runar/sdk/rpc_provider.rb`](lib/runar/sdk/rpc_provider.rb).

### 12.3 `WhatsOnChainProvider`

HTTP REST provider for the WhatsOnChain BSV API. Uses stdlib only.

```ruby
provider = Runar::SDK::WhatsOnChainProvider.new(network: 'mainnet')
# or:
provider = Runar::SDK::WhatsOnChainProvider.new(network: 'testnet')

provider.get_utxos('1A1zP1eP...')
provider.broadcast(raw_tx_hex)
```

Note: WhatsOnChain does not return locking scripts in UTXO lists, so `get_utxos` returns `Utxo` rows with `script: ''`. Implementation: [`lib/runar/sdk/woc_provider.rb`](lib/runar/sdk/woc_provider.rb). The other six SDKs use the same class name, `WhatsOnChainProvider`; the Ruby file is named `woc_provider.rb` for historical reasons but the public class name matches.

### 12.4 `GorillaPoolProvider`

HTTP REST provider for the GorillaPool 1Sat ordinals overlay. Implements `Provider` plus ordinal-specific helpers for inscriptions and BSV-20/BSV-21 token UTXOs.

```ruby
provider = Runar::SDK::GorillaPoolProvider.new(network: 'mainnet')

provider.get_inscriptions_by_address('1A1zP1eP...')
provider.get_bsv20_balance('1A1zP1eP...', 'TICK')
provider.get_bsv21_utxos('1A1zP1eP...', 'token-id')
```

Implementation: [`lib/runar/sdk/gorillapool_provider.rb`](lib/runar/sdk/gorillapool_provider.rb).

### 12.5 `WalletProvider`

BRC-100 wallet-backed provider. Pairs with `WalletSigner`. See [Section 7c](#7c-brc-100-wallet-signing) for full usage. Constructor:

```ruby
Runar::SDK::WalletProvider.new(
  wallet:      wallet_client,
  signer:      wallet_signer,
  basket:      'my-app',
  funding_tag: 'funding',
  arc_url:     'https://arc.gorillapool.io',
  overlay_url: nil,
  network:     'mainnet',
  fee_rate:    100
)
```

Implementation: [`lib/runar/sdk/wallet.rb`](lib/runar/sdk/wallet.rb).

### 12.6 Implementing a custom provider

Subclass `Runar::SDK::Provider` and implement seven methods:

```ruby
class MyProvider < Runar::SDK::Provider
  def get_transaction(txid);            end  # => TransactionData
  def get_raw_transaction(txid);        end  # => String (hex)
  def broadcast(raw_tx);                end  # => String (txid)
  def get_utxos(address);               end  # => Array<Utxo>
  def get_contract_utxo(script_hash);   end  # => Utxo or nil
  def get_network;                      end  # => 'mainnet' | 'testnet' | 'regtest'
  def get_fee_rate;                     end  # => Integer (sat/KB)
end
```

The default base-class implementations raise `NotImplementedError`, so it's an error to forget a method.

---

## 13. Full API Reference

Every public class, module, and method exported by `runar-lang`. Methods are listed in alphabetical order within each class.

### 13.1 Top-level: `Runar`

#### `Runar::SmartContract`

Base class for stateless contracts. Includes `Runar::DSL`, `Runar::Builtins`, and `Runar::ECMixin` so contract methods can call `assert`, `check_sig`, `hash160`, `ec_add`, etc. directly.

- `initialize(*args)` — applies `default:` initializers declared with `prop :name, Type, default: value`, then yields to the subclass's `initialize`.

#### `Runar::StatefulSmartContract < Runar::SmartContract`

Base class for stateful contracts.

- `initialize(*args)` — initializes `@_outputs`, `@_data_outputs`, `@_raw_outputs`, `@tx_preimage`.
- `add_output(satoshis, *state_values)` — emit a continuation output; `state_values` map to mutable properties in declaration order.
- `add_raw_output(satoshis, script_bytes)` — emit a raw-script output included in the continuation hash.
- `add_data_output(satoshis, script_bytes)` — emit a data output between state outputs and the change output.
- `outputs`, `raw_outputs`, `data_outputs` — accessors for the recorded outputs (used by tests).
- `reset_outputs` — clear all output buffers.
- `get_state_script` — returns the empty string off-chain; on-chain it returns the encoded state.
- `tx_preimage` (`attr_accessor`) — preimage available to the method body.

#### `Runar::DSL` (mixed into `SmartContract` via `included`)

Adds class methods:

- `prop(name, type, readonly: false, default: :__no_default__)` — declare a typed property. `readonly:` (default `true` for stateless) generates only a reader.
- `runar_public(**param_types)` — mark the next method as public; optionally declare ABI param types.
- `params(**param_types)` — declare ABI param types for the next method (without changing visibility).
- `runar_properties` — returns the property descriptors `[{ name:, type:, readonly:, default: }, ...]`.
- `runar_methods` — returns method metadata `{ name => { visibility:, param_types: } }`.
- `runar_defaults` — returns `{ name => default_value }` for properties with `default:`.

#### `Runar::Builtins` (mixed into `Kernel` and `Runar::SmartContract`)

See [Section 4.4](#44-built-in-functions) for the full list of built-in functions (`assert`, `check_sig`, `hash160`, `num2bin`, `safediv`, …). Implementation: [`lib/runar/builtins.rb`](lib/runar/builtins.rb).

#### `Runar.compile_check(source_or_path, file_name = nil)`

Run the Rúnar frontend pipeline (Parse → Validate → TypeCheck) on a contract source.

- **Params:** `source_or_path` (String — either a path or inline source); `file_name` (optional, used in error messages).
- **Returns:** `true` on success.
- **Raises:** `LoadError` if the `runar_compiler` gem is not installed; `RuntimeError` with descriptive message on parse, validation, or type-check errors.
- **Example:**
  ```ruby
  Runar.compile_check('Counter.runar.rb')   # => true
  ```

### 13.2 SDK: `Runar::SDK::*`

Require the SDK explicitly — it is not auto-loaded by `require 'runar'`:

```ruby
require 'runar/sdk'                  # all of the below
require 'runar/sdk/local_signer'     # opt-in: requires bsv-sdk
```

#### `Runar::SDK::ABI`

`Struct` with `:constructor_params` (`Array<ABIParam>`) and `:methods` (`Array<ABIMethod>`).

#### `Runar::SDK::ABIMethod`

`Struct` with `:name`, `:params`, `:is_public`, `:is_terminal`.

#### `Runar::SDK::ABIParam`

`Struct` with `:name`, `:type`, `:fixed_array`.

#### `Runar::SDK::ANFInterpreter` (module)

- `compute_new_state(anf, method_name, current_state, args, constructor_args: [], max_loop_iterations: 65_536)` — simulate a method call, returning the new state hash.
- `compute_new_state_and_data_outputs(...)` — same, but also returns `Array<{satoshis:, script:}>` of `add_data_output` calls in declaration order.
- **Raises:** `ArgumentError` if `method_name` is not a public method in the ANF IR.

#### `Runar::SDK::CallOptions`

Keyword-init struct for `RunarContract#call` / `#prepare_call`. See [Section 7a](#7a-single-signer-call) for the field table.

#### `Runar::SDK::CodeGen` (module)

- `generate_ruby(artifact) -> String` — return Ruby source code for a typed wrapper class. See [Section 10](#10-typed-contract-bindings-runarsdkcodegen).
- `generate_typescript(artifact)`, `generate_go(artifact)`, `generate_rust(artifact)`, `generate_python(artifact)`, `generate_zig(artifact)`, `generate_java(artifact)` — cross-target generators (parity with the other six SDKs; see Section 10's note on the parity plan).

#### `Runar::SDK::CodeSepIndexSlot`

`Struct` with `:byte_offset`, `:code_sep_index`. Used by `RunarArtifact` to locate `OP_CODESEPARATOR` placeholders in the script.

#### `Runar::SDK::ConstructorSlot`

`Struct` with `:param_index`, `:byte_offset`. Used by `RunarArtifact` to locate constructor-arg placeholders in the script.

#### `Runar::SDK::DeployOptions`

Keyword-init struct: `satoshis: 10_000`, `change_address: ''`. See [Section 6](#6-deploying-contracts).

#### `Runar::SDK::ExternalSigner < Runar::SDK::Signer`

Callback-based signer.

- `new(pub_key_hex:, address:, sign_fn:)` — `sign_fn` is any callable taking `(tx_hex, input_index, subscript, satoshis, sighash_type)` and returning a hex DER+sighash signature.
- `get_public_key`, `get_address`, `sign(...)` — delegate to the wrapped fields / callable.

#### `Runar::SDK::GorillaPoolProvider < Runar::SDK::Provider`

See [Section 12.4](#124-gorillapoolprovider).

- `new(network: 'mainnet')`
- Standard `Provider` interface: `get_transaction`, `get_raw_transaction`, `broadcast`, `get_utxos`, `get_contract_utxo`, `get_network`, `get_fee_rate`.
- Ordinal helpers: `get_inscriptions_by_address(addr)`, `get_inscription(id)`, `get_bsv20_balance(addr, tick)`, `get_bsv20_utxos(addr, tick)`, `get_bsv21_balance(addr, id)`, `get_bsv21_utxos(addr, id)`.

#### `Runar::SDK::Inscription`

Keyword-init struct: `:content_type`, `:data`. Used with `RunarContract#with_inscription`.

#### `Runar::SDK::LocalSigner < Runar::SDK::Signer`

Hot-key signer using the `bsv-sdk` gem.

- `new(key_hex)` — accepts a 64-char hex private key.
- `get_public_key` — 66-char hex compressed public key.
- `get_address` — Base58Check P2PKH address.
- `sign(tx_hex, input_index, subscript, satoshis, sighash_type = nil)` — DER + sighash byte, hex-encoded. Defaults to `SIGHASH_ALL | SIGHASH_FORKID` (0x41).
- **Raises:** `RuntimeError` from `new` if the `bsv-sdk` gem is not installed.

#### `Runar::SDK::MockProvider < Runar::SDK::Provider`

See [Section 12.1](#121-mockprovider).

- `new(network: 'testnet')`
- Mutation: `add_utxo(address, utxo)`, `add_transaction(tx)`, `add_contract_utxo(script_hash, utxo)`, `set_fee_rate(rate)`, `get_broadcasted_txs`.
- Provider interface: `get_transaction`, `get_raw_transaction`, `broadcast`, `get_utxos`, `get_contract_utxo`, `get_network`, `get_fee_rate`.

#### `Runar::SDK::MockSigner < Runar::SDK::Signer`

Deterministic signer — does not perform real cryptography.

- `new(pub_key_hex: '', address: '')` — defaults to `02` + 32 zero bytes / 20 zero bytes.
- `sign(...)` — returns a deterministic 72-byte mock signature (`30 + 70 zero bytes + 41`).

#### `Runar::SDK::Ordinals` (module)

- `build_inscription_envelope(content_type, data) -> String` — hex-encoded envelope.
- `find_inscription_envelope(script_hex) -> EnvelopeBounds | nil`
- `parse_inscription_envelope(script_hex) -> Inscription | nil`
- `strip_inscription_envelope(script_hex) -> String`
- BSV-20 helpers: `bsv20_deploy(tick:, max:, lim: nil, dec: nil)`, `bsv20_mint(tick:, amt:)`, `bsv20_transfer(tick:, amt:)`.
- BSV-21 helpers: `bsv21_deploy_mint(amt:, dec: nil, sym: nil, icon: nil)`, `bsv21_transfer(id:, amt:)`.

#### `Runar::SDK::OutputSpec`

Keyword-init struct: `:satoshis`, `:state` (a `Hash`). Used in `CallOptions#outputs` for multi-output continuations.

#### `Runar::SDK::PreparedCall`

Keyword-init struct returned by `RunarContract#prepare_call`. Public fields: `:sighash`, `:preimage`, `:op_push_tx_sig`, `:tx_hex`, `:sig_indices`. Internal fields (consumed by `finalize_call`): `:method_name`, `:resolved_args`, `:method_selector_hex`, `:is_stateful`, `:is_terminal`, `:needs_op_push_tx`, `:method_needs_change`, `:change_pkh_hex`, `:change_amount`, `:method_needs_new_amount`, `:new_amount`, `:preimage_index`, `:contract_utxo`, `:new_locking_script`, `:new_satoshis`, `:has_multi_output`, `:contract_outputs`, `:code_sep_idx`.

#### `Runar::SDK::Provider`

Abstract base class. Subclasses must implement: `get_transaction(txid)`, `get_raw_transaction(txid)`, `broadcast(raw_tx)`, `get_utxos(address)`, `get_contract_utxo(script_hash)`, `get_network`, `get_fee_rate`. Defaults raise `NotImplementedError`.

#### `Runar::SDK::RPCProvider < Runar::SDK::Provider`

See [Section 12.2](#122-rpcprovider).

- `new(host: 'localhost', port: 18_332, username: 'bitcoin', password: 'bitcoin', network: 'regtest')`
- `RPCProvider.regtest(host: 'localhost', port: 18_332, username: 'bitcoin', password: 'bitcoin')` — factory.
- Standard `Provider` interface plus `mine(n_blocks = 1)` and `rpc_call(method, *params)` for direct RPC access.

#### `Runar::SDK::RunarArtifact`

Compiled artifact. `attr_reader :version, :compiler_version, :contract_name, :abi, :script, :asm, :state_fields, :constructor_slots, :code_sep_index_slots, :build_timestamp, :code_separator_index, :code_separator_indices, :anf`.

- `RunarArtifact.from_json(json_string) -> RunarArtifact`
- `RunarArtifact.from_hash(hash) -> RunarArtifact` — the camelCase keys produced by every Rúnar compiler.
- `new(...)` — keyword-init. Rarely called directly.

#### `Runar::SDK::RunarContract`

Runtime contract wrapper. `attr_reader :artifact, :inscription`.

- `new(artifact, constructor_args)` — **Raises** `ArgumentError` if `constructor_args.length != artifact.abi.constructor_params.length`.
- `RunarContract.from_txid(artifact, txid, output_index, provider) -> RunarContract` — load an existing on-chain contract via the provider. **Raises** `ArgumentError` if `output_index` is out of range.
- `RunarContract.from_utxo(artifact, utxo) -> RunarContract` — synchronous variant when the UTXO is already in hand. `utxo` may be a `Utxo` struct or a `Hash` with `:txid`, `:output_index`, `:satoshis`, `:script` keys.
- `with_inscription(inscription) -> self` — attach a 1Sat ordinals envelope.
- `connect(provider, signer)` — store provider + signer for later calls.
- `deploy(provider = nil, signer = nil, options = nil) -> [String, TransactionData]`
- `deploy_with_wallet(satoshis: 1, description: nil) -> { txid:, output_index: }` — wallet-funded deploy via a connected `WalletProvider`.
- `call(method_name, args = [], provider = nil, signer = nil, options = nil) -> [String, TransactionData]`
- `prepare_call(method_name, args = [], provider = nil, signer = nil, options = nil) -> PreparedCall`
- `finalize_call(prepared, signatures, provider = nil) -> [String, TransactionData]`
- `build_unlocking_script(method_name, args) -> String` — hex unlocking script (no broadcast).
- `build_code_script -> String` — hex code script with constructor args spliced in.
- `get_locking_script -> String` — full locking script (code + envelope + state).
- `get_utxo -> Utxo | nil` — current contract UTXO.
- `get_state -> Hash` — copy of the current state.
- `set_state(new_state)` — merge `new_state` into the current state (mostly for tests).

Implementation: [`lib/runar/sdk/contract.rb`](lib/runar/sdk/contract.rb).

#### `Runar::SDK::ScriptUtils` (module, also extended onto `Runar::SDK`)

- `extract_constructor_args(artifact, script_hex) -> Hash` — recover constructor arg values from an on-chain script.
- `matches_artifact(artifact, script_hex) -> Boolean` — returns true iff the script was produced by the given artifact (regardless of constructor args).
- `read_script_element(hex, offset) -> Hash` — parse a single push opcode.
- `decode_script_number(data_hex) -> Integer`
- `interpret_script_element(opcode, data_hex, type) -> Object`

#### `Runar::SDK::Signer`

Abstract base class. Subclasses must implement: `get_public_key`, `get_address`, `sign(tx_hex, input_index, subscript, satoshis, sighash_type = nil)`.

#### `Runar::SDK::State` (module, also extended onto `Runar::SDK`)

State serialisation / deserialisation. Methods are also reachable as `Runar::SDK.encode_push_data(...)`, etc.

- `encode_push_data(data_hex) -> String` — minimal push-data wrapper (1 / `OP_PUSHDATA1` / `OP_PUSHDATA2` / `OP_PUSHDATA4`).
- `encode_script_int(n) -> String` — minimal script-number push (`OP_0`, `OP_1..OP_16`, sign-magnitude LE).
- `find_last_op_return(script_hex) -> Integer` — hex-char offset of the last opcode-boundary `OP_RETURN`, or `-1`.
- `serialize_state(state_fields, values) -> String` — encode a state `Hash` to raw hex bytes.
- `deserialize_state(state_fields, state_hex) -> Hash` — inverse of `serialize_state`.
- `extract_state_from_script(artifact, locking_script_hex) -> Hash | nil`
- `parse_fixed_array_dims(type) -> Array<Integer>`
- `unwrap_fixed_array_leaf(type) -> String`

#### `Runar::SDK::StateField`

Keyword-init struct: `:name`, `:type`, `:index`, `:initial_value`, `:fixed_array`. Used by `RunarArtifact`.

#### `Runar::SDK::TerminalOutput`

Keyword-init struct: `:script_hex`, `:satoshis`. Used in `CallOptions#terminal_outputs` for terminal methods.

#### `Runar::SDK::TokenWallet`

Higher-level wrapper for fungible-token contracts (artifacts with a `transfer` public method and a `balance`/`supply`/`amount` state field).

- `new(artifact, provider, signer)`
- `get_balance -> Integer` — sum of token balance across all wallet UTXOs.
- `transfer(recipient_addr, amount) -> String` (txid)
- `merge -> String` (txid) — combine two token UTXOs.
- `get_utxos -> Array<Utxo>` — token UTXOs belonging to the signer's address.

Implementation: [`lib/runar/sdk/token_wallet.rb`](lib/runar/sdk/token_wallet.rb).

#### `Runar::SDK::TransactionData` / `Runar::SDK::Transaction`

`Transaction` is an alias for `TransactionData`. Keyword-init struct: `:txid`, `:version`, `:inputs`, `:outputs`, `:locktime`, `:raw`.

#### `Runar::SDK::TxInput`

Keyword-init struct: `:txid`, `:output_index`, `:script`, `:sequence` (default `0xFFFFFFFF`).

#### `Runar::SDK::TxOutput`

Keyword-init struct: `:script`, `:satoshis`.

#### `Runar::SDK::Utxo`

Keyword-init struct: `:txid`, `:output_index`, `:satoshis`, `:script`.

#### `Runar::SDK::WalletClient`

Abstract BRC-100 wallet client. Subclasses must implement: `get_public_key(protocol_id:, key_id:)`, `create_signature(hash_to_sign:, protocol_id:, key_id:)`, `create_action(description:, outputs:)`, `list_outputs(basket:, tags: [], limit: 100)`.

#### `Runar::SDK::WalletProvider < Runar::SDK::Provider`

See [Section 7c](#7c-brc-100-wallet-signing) and [Section 12.5](#125-walletprovider).

- `new(wallet:, signer:, basket:, funding_tag: 'funding', arc_url: 'https://arc.gorillapool.io', overlay_url: nil, network: 'mainnet', fee_rate: 100)`
- `cache_tx(txid, raw_hex)` — pre-populate the in-memory tx cache.
- Standard `Provider` interface.

#### `Runar::SDK::WalletSigner < Runar::SDK::Signer`

- `new(wallet:, protocol_id:, key_id:)`
- Standard `Signer` interface.
- `sign_hash(sighash_hex) -> String` — sign a pre-computed sighash directly (multi-signer flow).

#### `Runar::SDK::WhatsOnChainProvider < Runar::SDK::Provider`

See [Section 12.3](#123-whatsonchainprovider).

- `new(network: 'mainnet' | 'testnet')`
- Standard `Provider` interface.

### 13.3 Module-level helpers on `Runar::SDK`

The following helpers are mixed into the `Runar::SDK` module via `extend State` and `extend ScriptUtils`, and are also defined directly as `module_function` methods in `lib/runar/sdk/{deployment,calling,oppushtx}.rb`:

#### Deployment / call building

- `build_deploy_transaction(locking_script, utxos, satoshis, change_address, change_script = '', fee_rate: 100) -> [tx_hex, input_count]`
- `build_call_transaction(current_utxo, unlocking_script, new_locking_script, new_satoshis, change_address, change_script = '', additional_utxos = nil, fee_rate: 100, options: nil) -> [tx_hex, input_count, change_amount]`
- `select_utxos(utxos, target_satoshis, locking_script_byte_len, fee_rate: 100) -> Array<Utxo>`
- `estimate_deploy_fee(num_inputs, locking_script_byte_len, fee_rate = 100) -> Integer`
- `estimate_call_fee(locking_script_byte_len, unlocking_script_byte_len, num_funding_inputs, fee_rate = 100) -> Integer`
- `build_p2pkh_script(address) -> String` — hex `76a914{20-byte-hash}88ac`. Accepts a 40-char hex pubkey hash or a Base58Check address.
- `insert_unlocking_script(tx_hex, input_index, unlock_script) -> String`
- `read_varint_hex(hex_str, pos) -> [Integer, Integer]`

#### OP_PUSH_TX / BIP-143

- `compute_preimage(tx_hex, input_index, subscript_hex, satoshis, sighash_type = SIGHASH_ALL_FORKID) -> String`
- `sign_preimage_k1(preimage_hex) -> String`
- `compute_op_push_tx(tx_hex, input_index, subscript_hex, satoshis, code_separator_index = -1) -> [sig_hex, preimage_hex]`
- `get_subscript(script_hex, code_separator_index) -> String`
- `double_sha256(hex) -> String`

#### Constants

- `Runar::SDK::SIGHASH_ALL_FORKID = 0x41` — default sighash type for all signers.

### 13.4 Top-level constants (re-exported by `require 'runar'`)

Defined in [`lib/runar.rb`](lib/runar.rb) so contracts can write `prop :balance, Bigint` without a namespace:

- Types: `Bigint`, `Int`, `ByteString`, `PubKey`, `Sig`, `Addr`, `Sha256`, `Ripemd160`, `SigHashPreimage`, `RabinSig`, `RabinPubKey`, `Point`, `P256Point`, `P384Point`, `OpCodeType`, `Boolean`.
- EC constants (secp256k1): `EC_P`, `EC_N`, `EC_G`.
- Test keys: `ALICE`, `BOB`, `CHARLIE`, `DAVE`, `EVE`, `FRANK`, `GRACE`, `HEIDI`, `IVAN`, `JUDY` — each a `Runar::TestKeys::TestKeyPair` with `priv_key`, `pub_key`, `pub_key_hash`, `test_sig`. **Test-only material — never use these on mainnet.**

---

## 14. Error Handling

The Ruby SDK uses standard Ruby exception classes throughout — no custom hierarchy. Three are common:

| Class                  | Raised when                                                                         |
|------------------------|--------------------------------------------------------------------------------------|
| `ArgumentError`        | API misuse: wrong constructor-arg count, unknown method name, out-of-range UTXO index, insufficient funds in `select_utxos`, malformed `Utxo`. |
| `RuntimeError`         | Runtime failures: provider returned no UTXOs, missing transaction, BIP-143 sighash with no provider/signer, `assert` failed inside a contract method. |
| `NotImplementedError`  | An abstract base method was called without being overridden (e.g. a custom `Provider` forgot to implement `broadcast`). |
| `LoadError`            | An optional dependency is missing — `compile_check` requires `runar_compiler`; `LocalSigner` requires `bsv-sdk`. |

The SDK does not export typed error classes — programmer errors and protocol errors both use plain `RuntimeError` with descriptive messages. To pattern-match, use `e.message`:

```ruby
begin
  contract.deploy
rescue RuntimeError => e
  case e.message
  when /no UTXOs/        then handle_unfunded
  when /insufficient funds/ then handle_insufficient
  else raise
  end
end
```

For contract-level assertions:

```ruby
begin
  counter.decrement
rescue RuntimeError => e
  raise unless e.message.include?('runar: assertion failed')
  # contract rejected the call
end
```

For comparison: TypeScript/JavaScript SDK throws `Error`, Go returns `(value, error)`, Rust returns `Result<T, String>`, Python uses standard exceptions, Java uses checked + runtime exceptions, Zig uses typed error sets. The Ruby SDK mirrors Python's pattern: lean on stdlib exception classes, communicate intent through messages.

---

## 15. Troubleshooting / FAQ

**Q: `LoadError: cannot load such file -- bsv-sdk` when constructing a `LocalSigner`.**
A: `LocalSigner` requires the `bsv-sdk` gem. Add `gem 'bsv-sdk'` to your Gemfile, or use `MockSigner` / `ExternalSigner` instead. Core SDK functionality (offline transaction building, state encoding, ANF interpretation) does not require `bsv-sdk`.

**Q: `LoadError: compile_check requires the runar_compiler gem`.**
A: Run `gem install runar_compiler`, or add it to your Gemfile. `compile_check` is the only feature in the runtime gem that needs the compiler.

**Q: `RuntimeError: RunarContract.deploy: no UTXOs found for <address>`.**
A: The address has no spendable UTXOs. With `MockProvider`, use `provider.add_utxo(address, utxo)`. With `RPCProvider`, fund the address (e.g. `bitcoin-cli sendtoaddress <addr> 1.0` then mine a block on regtest). With `WhatsOnChainProvider`, the address must have confirmed UTXOs on the chosen network.

**Q: `RuntimeError: build_deploy_transaction: insufficient funds. Need N sats, have M`.**
A: Increase the funding UTXOs, lower `DeployOptions.satoshis`, or lower the `fee_rate` returned by your provider.

**Q: `ArgumentError: RunarContract.from_txid: output index N out of range`.**
A: The transaction has fewer outputs than `output_index + 1`. Check `provider.get_transaction(txid).outputs.length`.

**Q: My stateful contract call fails on chain with "wrong state hash".**
A: The new state computed off-chain doesn't match what the contract expects. Likely the ANF interpreter doesn't handle a primitive your contract uses; pass an explicit `new_state:` in `CallOptions` to override the auto-computed value, and verify against the contract logic.

**Q: I deployed from the Ruby SDK and want to call from the TypeScript SDK. Will it work?**
A: Yes — the seven SDKs produce byte-identical locking scripts and use the same on-chain protocol. The conformance suite verifies this. Load the same artifact JSON in the TS SDK, point it at the same `(txid, vout)` via `RunarContract.fromTxId`, and call.

**Q: How do I sign with a hardware wallet?**
A: Use `prepare_call` to get a `PreparedCall`, send `prepared.sighash` (or the raw `prepared.preimage`) to the wallet for signing, then pass the resulting hex DER+sighash signature to `finalize_call`. See [Section 7b](#7b-multi-signer-prepare_call--finalize_call).

**Q: Can I mix Ruby contracts with contracts written in other formats?**
A: Yes — every Rúnar compiler parses all nine formats. A `.runar.ts` source compiles to the same artifact whether you compile it with the TypeScript or Ruby compiler. Choose the host language that fits each contract; deploy them all from the same Ruby app.

**Q: Where do `mock_sig` and `mock_pub_key` come from?**
A: `mock_pub_key` returns ALICE's compressed public key; `mock_sig` returns ALICE's pre-computed real ECDSA signature over the fixed test digest (`SHA256("runar-test-message-v1")`). Together they pass `check_sig`. Source: [`lib/runar/test_keys.rb`](lib/runar/test_keys.rb).

**Q: `WalletProvider` says "raw transaction not found in cache or overlay" after a wallet broadcast.**
A: After a wallet-funded deploy or call, cache the raw hex with `provider.cache_tx(txid, raw_hex)` so subsequent `get_raw_transaction` lookups resolve. Alternatively, configure `overlay_url:` so the provider can fetch raw hex from an overlay service.

**Q: My `runar_public` method takes more arguments than I declared in the source.**
A: Stateful contracts have implicit compiler-injected params (`_changePKH`, `_changeAmount`, `_newAmount`, `txPreimage`). The SDK hides these from `call(method_name, args)` — pass only the user-visible args. The codegen wrappers in [Section 10](#10-typed-contract-bindings-runarsdkcodegen) make this explicit.

---

## 16. Versioning and Stability

`runar-lang` follows semantic versioning. The current version is `0.4.4` (see [`runar.gemspec`](runar.gemspec)), part of the broader Rúnar `0.4.x` line.

**Pre-1.0 stability promise:** within a `0.x.y` series, patch releases (`0.x.y → 0.x.(y+1)`) are bug-fix-only and do not change the public API. Minor releases (`0.x.y → 0.(x+1).0`) may introduce breaking changes; check the release notes.

The artifact JSON format is the canonical cross-SDK contract: any change to the schema bumps the minor version and is coordinated across all seven SDKs. The on-chain script-emission rules are stabilised by the conformance suite at [`conformance/sdk-output/`](../../conformance/sdk-output/) — a change to `RunarContract#get_locking_script` that breaks one of those tests will not be released.

The following are not yet stable and may evolve before 1.0:

- The exact constructor signature of `WalletProvider` (`arc_url:`, `overlay_url:`, `funding_tag:`).
- The cross-target codegen API (`generate_typescript`, `generate_go`, etc.) is being unified across the seven SDKs.
- The `additional_contract_inputs` / `additional_contract_input_args` shape in `CallOptions`.

The following are stable:

- The base classes `Runar::SmartContract` and `Runar::StatefulSmartContract`.
- The DSL methods `prop`, `runar_public`, `params`.
- The full set of built-in functions in `Runar::Builtins`.
- The lifecycle methods on `RunarContract`: `new`, `connect`, `deploy`, `call`, `prepare_call`, `finalize_call`, `from_txid`, `from_utxo`, `get_state`, `set_state`, `get_utxo`, `with_inscription`.
- The `Provider` and `Signer` abstract interfaces (method names, signatures, return shapes).
- The `Utxo`, `TransactionData`, `TxInput`, `TxOutput`, `Inscription`, `DeployOptions`, `PreparedCall` struct field names.

---

## 17. Example contracts

Each `examples/ruby/<name>/` directory contains a `.runar.rb` source plus an RSpec spec exercising it off-chain. A few worth reading:

| Example                                                                                | Demonstrates                                                                  |
|----------------------------------------------------------------------------------------|-------------------------------------------------------------------------------|
| [`p2pkh/`](../../examples/ruby/p2pkh/)                                                 | Stateless P2PKH — `hash160`, `check_sig`, single-method unlock                |
| [`escrow/`](../../examples/ruby/escrow/)                                               | Stateless multi-party — release vs. refund methods                            |
| [`stateful-counter/`](../../examples/ruby/stateful-counter/)                           | Minimal stateful — `prop`, `runar_public`, ANF interpreter integration        |
| [`auction/`](../../examples/ruby/auction/)                                             | Stateful with monetary continuation outputs and `add_output`                  |
| [`tic-tac-toe/`](../../examples/ruby/tic-tac-toe/)                                     | Stateful with `FixedArray`, complex state transitions                         |
| [`token-ft/`](../../examples/ruby/token-ft/)                                           | Fungible-token contract — pairs with `Runar::SDK::TokenWallet`                |
| [`schnorr-zkp/`](../../examples/ruby/schnorr-zkp/)                                     | EC primitives — `ec_mul_gen`, `ec_add`, `ec_encode_compressed`                |
| [`merkle-proof/`](../../examples/ruby/merkle-proof/)                                   | `merkle_root_sha256` / `merkle_root_hash256`, on-chain proof verification     |
| [`p2blake3pkh/`](../../examples/ruby/p2blake3pkh/)                                     | BLAKE3 hash — `blake3_compress`, `blake3_hash`                                |
| [`post-quantum-wots/`](../../examples/ruby/post-quantum-wots/)                         | WOTS+ one-time signatures — `verify_wots`                                     |
| [`post-quantum-wallet/`](../../examples/ruby/post-quantum-wallet/)                     | SLH-DSA (FIPS 205) — `verify_slh_dsa_sha2_*`                                  |
| [`add-raw-output/`](../../examples/ruby/add-raw-output/)                               | `add_raw_output` — output with caller-specified script bytes                  |
| [`state-covenant/`](../../examples/ruby/state-covenant/)                               | Covenant pattern — restricts how the contract can be spent                    |

Run all of them:

```bash
cd examples/ruby && bundle exec rspec
```

---

## 18. Links

- Rúnar repository: <https://github.com/icellan/runar>
- Ruby SDK source: [`packages/runar-rb/`](.) (this directory)
- Examples: [`examples/ruby/`](../../examples/ruby/)
- Integration tests: [`integration/ruby/`](../../integration/ruby/)
- Cross-SDK conformance: [`conformance/sdk-output/`](../../conformance/sdk-output/)
- Language specification: [`spec/`](../../spec/)
- Format-specific docs: [`docs/formats/`](../../docs/formats/)
- DSL design rationale: [`DESIGN.md`](DESIGN.md)
- Ruby compiler: [`compilers/ruby/`](../../compilers/ruby/)
- Issue tracker: <https://github.com/icellan/runar/issues>
- License: MIT
