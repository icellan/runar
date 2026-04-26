# runar-go

Deploy, call, and interact with compiled Rúnar smart contracts on Bitcoin SV from Go.

The Rúnar Go SDK is the runtime layer that sits between a compiled contract artifact (the JSON output of the Go compiler in `compilers/go`) and the Bitcoin SV blockchain. It owns transaction construction, BIP-143 signing, broadcast, OP_PUSH_TX assembly, contract-state serialization, UTXO selection, and fee estimation. It also exposes the type universe (`runar.Bigint`, `runar.PubKey`, `runar.Sig`, `runar.SmartContract`, `runar.StatefulSmartContract`, etc.) that `.runar.go` source files import so they double as runnable Go code under `go test`.

## Table of Contents

1. [Installation](#1-installation)
2. [Quick start](#2-quick-start)
3. [Core concepts](#3-core-concepts)
4. [Writing a contract](#4-writing-a-contract)
5. [Compiling](#5-compiling)
6. [Deploying contracts](#6-deploying-contracts)
7. [Calling contract methods](#7-calling-contract-methods)
   1. [Single-signer (`Call`)](#71-single-signer-call)
   2. [Multi-signer (`PrepareCall` / `FinalizeCall`)](#72-multi-signer-preparecall--finalizecall)
   3. [BRC-100 wallet signing (`WalletProvider` + `WalletSigner`)](#73-brc-100-wallet-signing-walletprovider--walletsigner)
8. [Stateful contracts](#8-stateful-contracts)
9. [UTXO and fee management](#9-utxo-and-fee-management)
10. [Typed contract bindings (`GenerateGo`)](#10-typed-contract-bindings-generatego)
11. [Testing](#11-testing)
    1. [Off-chain testing](#111-off-chain-testing)
    2. [Integration testing against a regtest node](#112-integration-testing-against-a-regtest-node)
12. [Provider configuration](#12-provider-configuration)
13. [Full API reference](#13-full-api-reference)
14. [Error handling](#14-error-handling)
15. [Troubleshooting / FAQ](#15-troubleshooting--faq)
16. [Versioning and stability](#16-versioning-and-stability)
17. [Links](#17-links)

---

## 1. Installation

```bash
go get github.com/icellan/runar/packages/runar-go
```

The package name on disk is `runar`; the canonical import alias is also `runar`:

```go
import runar "github.com/icellan/runar/packages/runar-go"
```

Requires Go 1.26+. The SDK depends on `github.com/bsv-blockchain/go-sdk` for ECDSA, BIP-143 sighash, and transaction primitives, on `golang.org/x/crypto/ripemd160` for hash160, and on `github.com/icellan/runar/compilers/go` for the frontend wrapper used by `CompileCheck`. The exact dependency list is in [go.mod](go.mod).

> Note on terminology used throughout this README: the canonical concepts (Artifact, Contract, Provider, Signer, Wallet, Call, PreparedCall, State, UTXO, Inscription) are defined once in [Section 3](#3-core-concepts) and referred to thereafter.

---

## 2. Quick start

The minimal contract used here is `Counter` — a stateful contract with one `Bigint` field and two methods (`Increment`, `Decrement`). The full contract source is in [`examples/go/stateful-counter/Counter.runar.go`](../../examples/go/stateful-counter/Counter.runar.go); the conformance fixture proving every SDK in the project produces a byte-identical locking script for it lives at [`conformance/sdk-output/tests/stateful-counter/`](../../conformance/sdk-output/tests/stateful-counter).

```go
package main

import (
	"encoding/json"
	"fmt"
	"os"

	runar "github.com/icellan/runar/packages/runar-go"
)

func main() {
	// 1. Load the compiled artifact (JSON produced by the Rúnar Go compiler).
	raw, err := os.ReadFile("Counter.artifact.json")
	if err != nil {
		panic(err)
	}
	var artifact runar.RunarArtifact
	if err := json.Unmarshal(raw, &artifact); err != nil {
		panic(err)
	}

	// 2. Bind constructor args. Counter has one bigint field: count.
	contract := runar.NewRunarContract(&artifact, []interface{}{int64(0)})

	// 3. Provider + signer (mock for local exploration).
	provider := runar.NewMockProvider("regtest")
	provider.AddUtxo("mock-address", runar.UTXO{
		Txid:        "ab" + "00000000000000000000000000000000000000000000000000000000000000",
		OutputIndex: 0,
		Satoshis:    1_000_000,
		Script:      "76a914" + "0000000000000000000000000000000000000000" + "88ac",
	})
	signer := runar.NewMockSigner("", "mock-address")
	contract.Connect(provider, signer)

	// 4. Deploy.
	deployTxid, _, err := contract.Deploy(nil, nil, runar.DeployOptions{Satoshis: 5000})
	if err != nil {
		panic(err)
	}
	fmt.Println("deployed:", deployTxid)

	// 5. Call the increment method (no user args; SDK injects the preimage).
	callTxid, _, err := contract.Call("increment", []interface{}{}, nil, nil, nil)
	if err != nil {
		panic(err)
	}
	fmt.Println("incremented:", callTxid)

	// 6. Read state after the call. (count is the auto-computed new value.)
	fmt.Println("count after call:", contract.GetState()["count"])
}
```

Replace `MockProvider` + `MockSigner` with `RPCProvider` + `LocalSigner` to talk to a real BSV node and a real key. The end-to-end regtest version of this exact flow is in [`integration/go/counter_test.go`](../../integration/go/counter_test.go) and ships with five test cases (increment, chain, decrement, wrong-state rejection, underflow rejection).

---

## 3. Core concepts

These names are used consistently across all seven Rúnar SDKs (TypeScript, Go, Rust, Python, Zig, Ruby, Java).

| Concept | Definition | Go type |
|---|---|---|
| **Artifact** | The compiled contract: locking-script template, ABI, state schema, constructor and code-separator slots, ANF IR. Loaded once from JSON, immutable. | [`RunarArtifact`](sdk_types.go) |
| **Contract** | The runtime object that wraps an artifact + constructor args + state + current UTXO. Knows how to deploy, call, prepare/finalize, and serialize state. | [`RunarContract`](sdk_contract.go) |
| **Provider** | Read/write blockchain interface. Fetches transactions / UTXOs and broadcasts new ones. Pluggable. | [`Provider`](sdk_provider.go) (interface) |
| **Signer** | Key-management interface. Produces compressed pubkey, P2PKH address, and BIP-143 ECDSA signatures over given subscripts. Pluggable. | [`Signer`](sdk_signer.go) (interface) |
| **Wallet** | BRC-100 wallet client (browser/extension wallet) backing a `WalletProvider` + `WalletSigner` pair when the SDK can't hold raw keys. | [`WalletClient`](sdk_wallet.go) (interface) |
| **Call** | A method invocation on a deployed contract: spend the contract UTXO, optionally produce a continuation UTXO, optionally produce data outputs, broadcast. | `RunarContract.Call(...)` |
| **PreparedCall** | The output of the two-pass calling flow: a built-but-unsigned tx hex + per-Sig sighashes that an external signer (hardware wallet, multi-party) can sign offline. | [`PreparedCall`](sdk_types.go) |
| **State** | The mutable Bitcoin-Script-encoded payload after the contract's last `OP_RETURN`. Stateful-contract-only. Encoded with `SerializeState`, decoded with `DeserializeState`. | `map[string]interface{}` |
| **UTXO** | The contract's current on-chain output (txid, vout, satoshis, script). Tracked across deploy → call → call. | [`UTXO`](sdk_types.go) |
| **Inscription** | A 1sat ordinals envelope spliced between the code part and the state section in the locking script. Immutable across state transitions. | [`Inscription`](sdk_ordinals.go) |

A few Go-specific notes that matter for the rest of this README:

- The SDK is **synchronous**. Provider methods make blocking HTTP / RPC calls; signer methods are CPU-bound. Compose them with goroutines + channels if you need concurrency.
- Errors are **Go errors**, never panics — except for a small set of programmer-error panics in `NewRunarContract`, `BuildUnlockingScript`, `InsertUnlockingScript`, and `BuildP2PKHScript`. See [Section 14](#14-error-handling).
- State values are typed as `map[string]interface{}` because Go has no sum type. The conventional Go runtime encoding is `int64` for `bigint`, `bool` for `bool`, and a hex string for byte types (`PubKey`, `Addr`, `Sha256`, `Ripemd160`, `Point`, `ByteString`).

---

## 4. Writing a contract

A Rúnar contract is a Go struct that embeds either `runar.SmartContract` (stateless) or `runar.StatefulSmartContract` (stateful) and exposes one or more public methods (capitalized Go method names). Public methods are spending entry points; private methods are inlined helpers. The Go compiler (in `compilers/go`) parses the `.runar.go` source, validates the Rúnar subset, type-checks, lowers to ANF and Stack IR, and emits a `RunarArtifact`. Each compiler in the project (TypeScript, Go, Rust, Python, Zig, Ruby, Java) accepts every `.runar.{ts,sol,move,go,rs,py,zig,rb,java}` extension and produces a byte-identical artifact for the same source.

The full Quick Start contract is just 12 effective lines:

```go
package contract

import runar "github.com/icellan/runar/packages/runar-go"

type Counter struct {
	runar.StatefulSmartContract
	Count runar.Bigint
}

func (c *Counter) Increment() {
	c.Count++
}

func (c *Counter) Decrement() {
	runar.Assert(c.Count > 0)
	c.Count--
}
```

`runar.Assert(cond)` is the primary control mechanism — Bitcoin Script `OP_VERIFY` semantics. The compiler auto-injects `checkPreimage` at each public method entry on stateful contracts, and a state-continuation output at exit, so the contract author never writes either by hand. The full language specification is in [`spec/`](../../spec/) and the playground at <https://runar.build> compiles snippets to Bitcoin Script in the browser.

---

## 5. Compiling

The Go compiler lives in `compilers/go`. The Go SDK exposes a thin **frontend wrapper** that runs `parse → validate → typecheck` against a `.runar.go` source file — useful in unit tests to catch contract-level errors before deployment:

```go
import runar "github.com/icellan/runar/packages/runar-go"

func TestCounter_Compile(t *testing.T) {
	if err := runar.CompileCheck("Counter.runar.go"); err != nil {
		t.Fatalf("Rúnar compile check failed: %v", err)
	}
}
```

`CompileCheck` only verifies the contract is **valid Rúnar** (i.e. that it would compile). To produce a `RunarArtifact` for deployment, drive the full pipeline through `compilers/go`'s public packages — see [`compilers/go/compiler`](../../compilers/go/compiler) and the integration helper [`integration/go/helpers/compiler.go`](../../integration/go/helpers/compiler.go) for the canonical invocation. The conformance suite in [`conformance/sdk-output/`](../../conformance/sdk-output) verifies that all seven SDK implementations agree byte-for-byte on the deployed locking script for the same artifact + constructor args.

---

## 6. Deploying contracts

Deployment creates a UTXO whose locking script is the contract's full code (with constructor args spliced in at byte offsets specified by `artifact.ConstructorSlots`) followed by `OP_RETURN <serialized state>` for stateful contracts.

```go
contract := runar.NewRunarContract(artifact, []interface{}{int64(0)})

// Connect once; subsequent Deploy/Call calls can pass nil for provider/signer.
contract.Connect(provider, signer)

txid, txData, err := contract.Deploy(nil, nil, runar.DeployOptions{
	Satoshis:      5000,             // value locked in the contract output
	ChangeAddress: "",               // empty = signer.GetAddress()
})
if err != nil {
	return err
}
fmt.Println("contract UTXO at", txid+":0")
```

`Deploy` performs the full sequence: fetch fee rate, fetch funding UTXOs for the signer's address, run the largest-first UTXO selector, build the unsigned deploy transaction, sign every P2PKH input, broadcast, and track the resulting contract UTXO so subsequent `Call`s find it via `c.GetCurrentUtxo()`. If you only want the unsigned tx — for example to stage a hardware-wallet flow — call [`BuildDeployTransaction`](#13-full-api-reference) directly.

The constructor args slice must contain one entry per **grouped** ABI parameter (see `artifact.ABI.Constructor.Params`). Grouped `FixedArray<...>` parameters accept a nested Go slice; the SDK flattens them into the underlying scalar slots before splicing.

---

## 7. Calling contract methods

### 7.1. Single-signer (`Call`)

`Call` is the all-in-one helper for the common case where one signer holds all the keys:

```go
txid, _, err := contract.Call(
	"increment",         // method name (case-sensitive, matches ABI)
	[]interface{}{},     // user-visible args (the SDK injects checkPreimage etc.)
	nil, nil,            // provider/signer; nil falls back to Connect()
	&runar.CallOptions{  // optional per-call overrides
		Satoshis: 4500,
	},
)
```

For each `Sig` user-visible parameter the caller may pass `nil` — the SDK will compute it for the connected signer. The same convention works for `PubKey` (resolves from the signer), `SigHashPreimage` (computed from the BIP-143 preimage), and `ByteString` parameters that look like an `allPrevouts` placeholder.

For stateful contracts the SDK also auto-injects three internal parameters (`_changePKH`, `_changeAmount`, `_newAmount`) and the `SigHashPreimage`. None of these appear in the user-visible args slice — `args` only contains what the original method declared after stripping those four slots.

The set of overrides you can drop into `CallOptions` is in [Section 8](#8-stateful-contracts) and in the API reference; the most common are `Satoshis` (continuation-output value), `ChangeAddress` (override for non-signer change), `NewState` (override the auto-computed new state map for testing), `Outputs` (multi-output continuation), `AdditionalContractInputs` (merge-style multi-input spends), `TerminalOutputs` (final spend with no continuation), and `FundingUtxos` (extra P2PKH inputs for terminal calls).

### 7.2. Multi-signer (`PrepareCall` / `FinalizeCall`)

When the signing key lives outside the SDK process (hardware wallet, M-of-N quorum, browser extension), `Call` is split into two halves:

```go
prepared, err := contract.PrepareCall(
	"transfer",
	[]interface{}{nil /* sig */, recipientAddr},
	provider, signer, // signer is still needed for funding-input P2PKH signs and for the pubkey
	nil,
)
if err != nil {
	return err
}

// prepared.Sighash is the 32-byte BIP-143 hash the external signer must sign.
// prepared.Preimage is the full preimage if the caller wants to recompute.
// prepared.SigIndices lists the args positions that need an external Sig.
sigHex := externalSign(prepared.Sighash) // your hardware wallet etc.

txid, _, err := contract.FinalizeCall(prepared, map[int]string{
	0: sigHex, // arg index 0 was the Sig param
}, provider)
```

Important details:

- `PrepareCall` already signs the **funding** P2PKH inputs and the **additional contract inputs** (when present) using the provided signer. Only the primary contract input's `Sig` parameters are left as 72-byte placeholders — those are the slots in `prepared.SigIndices`.
- `Sighash` is the SHA-256 of the BIP-143 preimage; `Preimage` is the full preimage. External signers usually sign `Sighash` directly.
- `OpPushTxSig` is the OP_PUSH_TX DER signature over the same preimage, signed with the well-known `k=1` private key. The SDK computes this for stateful contracts; it is exposed on `PreparedCall` for inspection.
- `FinalizeCall` re-injects the real signatures, broadcasts, and returns the same `(txid, *TransactionData, error)` tuple as `Call`.

### 7.3. BRC-100 wallet signing (`WalletProvider` + `WalletSigner`)

For browser-extension wallets that implement BRC-100, the SDK ships a paired `WalletProvider` + `WalletSigner`. The user's wallet holds the private key; the SDK never sees it.

```go
type myBRC100Wallet struct{ /* implements runar.WalletClient */ }

wallet := &myBRC100Wallet{}

signer := runar.NewWalletSigner(runar.WalletSignerOptions{
	ProtocolID: [2]interface{}{2, "my-app"},
	KeyID:      "1",
	Wallet:     wallet,
})

provider := runar.NewWalletProvider(runar.WalletProviderOptions{
	Wallet:     wallet,
	Signer:     signer,
	Basket:     "my-app-utxos",
	FundingTag: "funding",        // defaults to "funding"
	ArcUrl:     "https://arc.gorillapool.io", // defaults to this
	Network:    "mainnet",
})

contract := runar.NewRunarContract(artifact, []interface{}{...})
contract.Connect(provider, signer)

// Standard Deploy / Call flow now uses the wallet for signing:
contract.Deploy(nil, nil, runar.DeployOptions{Satoshis: 5000})
```

The `WalletClient` interface that wallets implement is small (`GetPublicKey`, `CreateSignature`, `CreateAction`, `ListOutputs`); see the full signature in the [API reference](#13-full-api-reference). For wallet-driven deployments where the wallet builds the funding transaction itself, use `RunarContract.DeployWithWallet`:

```go
result, err := contract.DeployWithWallet(&runar.DeployWithWalletOptions{
	Satoshis:    5000,
	Description: "deploy Counter v1",
	Basket:      "my-app",
	Tags:        []string{"contract", "counter"},
})
```

The provider must be a `*WalletProvider` for `DeployWithWallet` to work; otherwise it returns an error.

---

## 8. Stateful contracts

Stateful contracts maintain mutable fields across spends using the OP_PUSH_TX pattern. The SDK manages the chain end-to-end:

1. **Deploy.** The initial state (built from the constructor args plus any `InitialValue` annotations on `StateField` entries) is serialized and appended after `OP_RETURN` in the locking script.
2. **Call.** The SDK computes the new state by running the artifact's ANF IR interpreter on the method body (`anf_interpreter.go`), serializes it, builds a continuation output with the same code part + new state, appends an OP_PUSH_TX preimage push to the unlocking script, and signs.
3. **Read.** `contract.GetState()` returns a copy of the current state map; `ExtractStateFromScript(artifact, scriptHex)` parses state from any locking script directly.

### State auto-computation

For stateful contracts whose method bodies the ANF interpreter can resolve (the vast majority of real-world contracts), the SDK runs the body during `PrepareCall` to derive both the new state and any `this.addDataOutput(...)` outputs. You don't need to pass `NewState` — it's there only as an escape hatch for tests that want to fail-on-purpose by claiming a wrong state, as in [`integration/go/counter_test.go::TestCounter_WrongStateHash_Rejected`](../../integration/go/counter_test.go).

```go
// Auto path: state computed from method body.
contract.Call("increment", []interface{}{}, provider, signer, nil)

// Override path: pin a deliberate state value (will be rejected by the chain
// if it doesn't match what checkPreimage expects).
contract.Call("increment", []interface{}{}, provider, signer, &runar.CallOptions{
	NewState: map[string]interface{}{"count": int64(99)},
})
```

### Multi-output state continuations

Methods that emit multiple state outputs (e.g. `transfer` on a token contract that splits a UTXO) use `CallOptions.Outputs`:

```go
contract.Call("transfer", []interface{}{recipient, amount, sig}, provider, signer, &runar.CallOptions{
	Outputs: []runar.OutputSpec{
		{Satoshis: 1, State: map[string]interface{}{"holder": recipient, "supply": amount}},
		{Satoshis: 1, State: map[string]interface{}{"holder": sender, "supply": remaining}},
	},
})
```

Each `OutputSpec` becomes one continuation output with the contract's code part followed by `OP_RETURN <serialized state>`.

### Additional contract inputs (merge / swap)

For multi-contract-input spends like merge/swap patterns, drop the extra UTXOs into `CallOptions.AdditionalContractInputs`. Each extra input is unlocked with the same method name and (by default) the same arg vector as the primary input, with `OP_PUSH_TX` and `Sig` parameters auto-computed per input. To pass per-input arg overrides, fill `AdditionalContractInputArgs` parallel to `AdditionalContractInputs`.

### Terminal methods

When a contract method burns its UTXO instead of producing a continuation (e.g. an auction settlement that sends value to the winner and seller), use `CallOptions.TerminalOutputs`. With `TerminalOutputs` set, the SDK builds a transaction with **only** the contract UTXO as input (no funding inputs, no change output) — fees come from the contract balance. Pass `FundingUtxos` to add P2PKH funding when the contract balance can't cover the outputs + fee.

### OP_CODESEPARATOR

Stateful contracts have OP_CODESEPARATOR auto-inserted by the compiler. The SDK reads `artifact.CodeSeparatorIndex` (single index, post-constructor-arg-substitution) and `artifact.CodeSeparatorIndices` (the full list, used by some advanced patterns) and computes the BIP-143 sub-script accordingly. `ComputeOpPushTxWithCodeSep` exposes the underlying primitive if you need to drive sighash computation outside the contract path.

---

## 9. UTXO and fee management

The SDK uses a **largest-first** UTXO selector and an **actual-byte-size** fee estimator. Fee rates are in satoshis per KB; the BSV standard relay fee is 100 sat/KB (0.1 sat/byte).

```go
// Pick UTXOs to fund a target output value, accounting for the contract output's size.
selected := runar.SelectUtxos(allUtxos, /*target*/ 5000, /*lockingScriptByteLen*/ 800, /*feeRate*/ 100)

// Estimate deploy fee (P2PKH inputs + contract output + P2PKH change).
fee := runar.EstimateDeployFee(/*numInputs*/ 1, /*lockingScriptByteLen*/ 800, /*feeRate*/ 100)

// Estimate call fee (1 contract input + N P2PKH funding inputs + contract output + change).
fee = runar.EstimateCallFee(/*lockingScriptByteLen*/ 800, /*unlockingScriptByteLen*/ 250, /*numFundingInputs*/ 1, /*feeRate*/ 100)
```

`feeRate` is variadic on all three helpers — omit it to use the default 100 sat/KB.

The provider determines the live fee rate. `MockProvider.SetFeeRate` overrides it for tests; `WhatsOnChainProvider` and `GorillaPoolProvider` both return a hardcoded 100. `WalletProvider.GetFeeRate` returns the value passed to `WalletProviderOptions.FeeRate` (defaults to 100).

For a step-by-step look at how `Call` builds a transaction, see [`BuildCallTransaction` in sdk_calling.go](sdk_calling.go) — it is the single function that lays out inputs, contract outputs, data outputs, and the change output, and it returns the parsed `*transaction.Transaction` from `go-sdk` so you can inspect or modify before signing.

---

## 10. Typed contract bindings (`GenerateGo`)

`GenerateGo` produces a typed wrapper class for a `RunarArtifact` so callers don't have to remember method names, arg types, or arg orders:

```go
artifact := loadArtifact("Counter.json")
generated := runar.GenerateGo(artifact)
os.WriteFile("counter_wrapper.go", []byte(generated), 0644)
```

The generated wrapper exposes a `<ContractName>Contract` struct whose Go methods mirror the contract's public methods one-for-one, with concrete Go types instead of `[]interface{}`. The wrapper has `Connect(provider, signer)`, `Deploy(...)`, `GetLockingScript()`, and `<ContractName>ContractFromTxId(...)` helpers. For methods that have `Sig` parameters, the wrapper also generates `Prepare<Method>` / `Finalize<Method>` paired methods for the multi-signer flow.

The exact template is in [`sdk_codegen.go`](sdk_codegen.go) at `goWrapperTemplate`. Type mapping is:

| Rúnar type | Generated Go type |
|---|---|
| `bigint` | `*big.Int` |
| `boolean` | `bool` |
| `Sig`, `PubKey`, `ByteString`, `Addr`, `Ripemd160`, `Sha256`, `Point`, `SigHashPreimage` | `string` (hex) |
| anything else | `interface{}` |

Method names are converted to Go PascalCase (`releaseBySeller` → `ReleaseBySeller`); collisions with reserved names (`Connect`, `Deploy`, `Contract`, `GetLockingScript`) are escaped by prefixing `Call` (`CallConnect`).

---

## 11. Testing

### 11.1. Off-chain testing

A `.runar.go` source file is **also a runnable Go file** because the `runar` package provides Go runtime types (`Int`, `Bigint`, `Bool`, `ByteString`, `PubKey`, ...), the base structs (`SmartContract`, `StatefulSmartContract`), and a set of mock + real crypto helpers that match the on-chain semantics. This means you can unit-test contract business logic with `go test`:

```go
func TestCounter_Increment(t *testing.T) {
	c := &Counter{Count: 0}
	c.Increment()
	if c.Count != 1 {
		t.Errorf("expected Count=1, got %d", c.Count)
	}
}

func TestCounter_DecrementAtZero_Fails(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected assertion failure")
		}
	}()
	c := &Counter{Count: 0}
	c.Decrement()
}

func TestCounter_Compile(t *testing.T) {
	if err := runar.CompileCheck("Counter.runar.go"); err != nil {
		t.Fatalf("Rúnar compile check failed: %v", err)
	}
}
```

What the package does for crypto in test mode (be honest about this):

- `runar.Hash160`, `runar.Hash256`, `runar.Sha256`, `runar.Ripemd160Func` compute **real** hashes.
- `runar.CheckSig` performs **real ECDSA verification** against `runar.TestMessageDigest` (the SHA-256 of `runar-test-message-v1`). Pair it with `runar.SignTestMessage(privKeyHex)` to produce a sig that verifies under the corresponding pubkey.
- `runar.CheckMultiSig` performs real ordered multi-sig verification using the same `TestMessageDigest`.
- `runar.CheckPreimage` always returns `true`. Real preimage verification needs a full transaction context that the unit-test harness does not have.
- `runar.VerifyRabinSig`, `runar.VerifyWOTS`, `runar.VerifySLHDSA_SHA2_*` perform **real** Rabin / WOTS+ / FIPS 205 SLH-DSA verification.
- `runar.VerifySP1FRI` is the Go-only intrinsic for SP1 v6.0.2 STARK / FRI proof verification — it returns `true` in Go test mode (the heavy lifting lives in the compiled Bitcoin Script). See the doc comment on `VerifySP1FRI` in [`runar.go`](runar.go) for the signature and the docs at `docs/sp1-fri-verifier.md` for the on-chain protocol.
- The `Extract*` family of preimage helpers (`ExtractAmount`, `ExtractLocktime`, `ExtractOutputHash`, `ExtractVersion`, `ExtractSequence`, `ExtractHashPrevouts`, `ExtractOutpoint`) return deterministic test-mode values so business-logic assertions can be exercised without a real preimage.
- Three deterministic test key pairs are exported as package-level vars: `runar.Alice`, `runar.Bob`, `runar.Charlie`. Use them when writing contracts that involve signatures.

The off-chain interpreter that the SDK uses to derive new state for stateful contracts (`ComputeNewState`, `ComputeNewStateAndDataOutputs`) lives in [`anf_interpreter.go`](anf_interpreter.go). It evaluates the artifact's ANF IR with mocked crypto and is used by `PrepareCall` to compute the continuation state without round-tripping through the chain.

### 11.2. Integration testing against a regtest node

The reference end-to-end test for `Counter` is [`integration/go/counter_test.go`](../../integration/go/counter_test.go). It exercises five paths against a real BSV regtest node:

1. Deploy + increment.
2. Deploy + increment + increment (state chain).
3. Deploy + increment + decrement.
4. Deploy + increment with deliberate wrong state — expects rejection.
5. Deploy + decrement from zero — expects rejection (the contract's `assert(count > 0)`).

The integration suite uses `RPCProvider` (or `NewRegtestRPCProvider` for auto-mining) and the helpers in [`integration/go/helpers/`](../../integration/go/helpers) to fund wallets and sign with the test SDK. The same harness ships in [`integration/`](../../integration) for all seven SDKs.

The cross-SDK conformance suite at [`conformance/sdk-output/`](../../conformance/sdk-output) verifies that all 7 SDKs produce **byte-identical deployed locking scripts** for the same artifact + constructor args. The `stateful-counter` test case is one of 27 fixtures.

---

## 12. Provider configuration

### `MockProvider`

In-memory provider for unit tests. No network, no broadcast. Records every broadcast for assertions.

```go
provider := runar.NewMockProvider("regtest") // network: "mainnet", "testnet", "regtest"

provider.AddUtxo("address-string", runar.UTXO{
	Txid: "...", OutputIndex: 0, Satoshis: 100_000, Script: "76a914...88ac",
})
provider.AddTransaction(&runar.TransactionData{Txid: "...", Outputs: []runar.TxOutput{...}, Raw: "..."})
provider.AddContractUtxo("scripthash-hex", &runar.UTXO{...})

provider.SetFeeRate(50)               // override default 100 sat/KB
broadcasts := provider.GetBroadcastedTxs() // raw hex of every Broadcast() call
```

`MockProvider.Broadcast` returns a deterministic fake txid derived from the raw tx hex.

### `RPCProvider`

Talks to a Bitcoin node over JSON-RPC.

```go
provider := runar.NewRPCProvider("http://127.0.0.1:18332", "rpcuser", "rpcpass")

// Or, for regtest with auto-mine after every broadcast:
provider := runar.NewRegtestRPCProvider("http://127.0.0.1:18332", "rpcuser", "rpcpass")
```

The RPC provider implements all `Provider` methods over `getrawtransaction`, `sendrawtransaction`, `listunspent`, `gettxout`, etc.

### `WhatsOnChainProvider`

```go
provider := runar.NewWhatsOnChainProvider("mainnet") // or "testnet"
```

Wraps the public WhatsOnChain API at `https://api.whatsonchain.com/v1/bsv/{main,test}`. Note that WoC does not return locking scripts in its UTXO list response, so `GetUtxos(...).Script` will be empty — fetch the parent transaction with `GetTransaction` if you need the script.

### `GorillaPoolProvider`

```go
provider := runar.NewGorillaPoolProvider("mainnet") // or "testnet"
```

Wraps the GorillaPool 1sat Ordinals API. In addition to the `Provider` interface this provider exposes ordinal-specific methods: `GetInscriptionsByAddress`, `GetInscription`, `GetBSV20Balance`, `GetBSV20Utxos`, `GetBSV21Balance`, `GetBSV21Utxos`.

### `WalletProvider`

BRC-100 wallet-backed provider — see [Section 7.3](#73-brc-100-wallet-signing-walletprovider--walletsigner).

---

## 13. Full API reference

Every exported symbol in package `runar`. Sorted alphabetically. Source links point to the file the symbol lives in.

#### `Addr`

```go
type Addr = ByteString
```

20-byte address (typically `Hash160` of a public key). [runar.go](runar.go).

#### `AssertGroth16WitnessAssisted`

```go
func AssertGroth16WitnessAssisted()
```

Marker intrinsic recognised by the compiler to start a Mode-3 witness-assisted Groth16 verifier preamble in a stateful contract. Has no Go runtime effect. [bn254.go](bn254.go).

#### `AssertGroth16WitnessAssistedWithMSM`

```go
func AssertGroth16WitnessAssistedWithMSM()
```

Variant of `AssertGroth16WitnessAssisted` that emits the multi-scalar-multiplication backend. [bn254.go](bn254.go).

#### `Assert`

```go
func Assert(cond bool)
```

Panics if `cond` is false. Compiles to `OP_VERIFY` in Bitcoin Script. The primary control mechanism in Rúnar contracts. [runar.go](runar.go).

#### `BSV20Deploy` / `BSV20Mint` / `BSV20Transfer`

```go
func BSV20Deploy(tick, max string, lim, dec *string) *Inscription
func BSV20Mint(tick, amt string) *Inscription
func BSV20Transfer(tick, amt string) *Inscription
```

Build BSV-20 (v1, tick-based) ordinals inscriptions. `lim`/`dec` are optional — pass `nil` to omit. Returns a ready-to-attach `*Inscription`. [sdk_ordinals.go](sdk_ordinals.go).

#### `BSV21DeployMint` / `BSV21Transfer`

```go
func BSV21DeployMint(amt string, dec, sym, icon *string) *Inscription
func BSV21Transfer(id, amt string) *Inscription
```

Build BSV-21 (v2, ID-based) ordinals inscriptions. [sdk_ordinals.go](sdk_ordinals.go).

#### `Bigint`

```go
type Bigint = int64
```

The Rúnar runtime integer type. Backed by `int64` because Go has no operator overloading; the compiler pipeline carries integer values as `*big.Int` internally so any literal of any size compiles correctly. For values >= 2^63 in Go-mock tests, use [`BigintBig`](#bigintbig). [runar.go](runar.go).

#### `BigintBig`

```go
type BigintBig = *big.Int
```

Arbitrary-precision integer for Go-mock tests that consume gnark-generated fixtures. Pair with the `*Big`-suffixed BN254 helpers. [runar.go](runar.go).

#### `BigintBigAdd` / `Sub` / `Mul` / `Mod` / `Div` / `Less` / `LessEq` / `Greater` / `GreaterEq` / `Equal` / `NotEqual`

```go
func BigintBigAdd(a, b *big.Int) *big.Int
// ... (eleven helpers)
```

Operator helpers for `BigintBig`-typed contract fields. The Go-contract DSL rewrites calls like `runar.BigintBigLess(a, b)` into the equivalent Script comparison node. nil operands are treated as zero. [runar.go](runar.go).

#### `Bin2Num` / `Bin2NumBig`

```go
func Bin2Num(data ByteString) int64
func Bin2NumBig(data ByteString) *big.Int
```

Decode a Bitcoin Script little-endian sign-magnitude byte string into an integer. Inverse of `Num2Bin`. The non-`Big` variant truncates out-of-range values to the low 64 bits. [runar.go](runar.go).

#### `Blake3Compress` / `Blake3Hash`

```go
func Blake3Compress(chainingValue, block ByteString) ByteString
func Blake3Hash(message ByteString) ByteString
```

Mock BLAKE3 helpers — return 32 zero bytes in Go test mode. The compiled Script emits the real BLAKE3 codegen (~10,000 opcodes per compression). [runar.go](runar.go).

#### `Bn254FieldAdd` / `Sub` / `Mul` / `Inv` / `Neg` / `NegP` (and `*P` byte-array variants)

Real BN254 field arithmetic over the prime `21888242871839275222246405745257275088696311157297823662689037894645226208583`. [bn254.go](bn254.go).

#### `Bn254G1Add` / `ScalarMul` / `Negate` / `OnCurve` (and `*P` `Point`-typed variants)

Real BN254 G1 group operations. The `*P` variants take and return `Point` (`ByteString` of `x[32]||y[32]`); the non-`P` variants take raw `[]byte`. [bn254.go](bn254.go).

#### `Bn254G2FromGnark` / `Bn254Fp12FromGnark`

Convert gnark-crypto's BN254 G2 / Fp12 element layouts into the Rúnar Go-mock's flat `*big.Int` representation. [bn254.go](bn254.go).

#### `Bn254MultiPairing4` / `Bn254MultiPairing3`

Real BN254 multi-pairing helpers used by Groth16 verifier mocks. [bn254.go](bn254.go).

#### `Bool`

```go
type Bool = bool
```

[runar.go](runar.go).

#### `BuildCallOptions`

```go
type BuildCallOptions struct {
	ContractOutputs          []ContractOutput
	AdditionalContractInputs []AdditionalContractInput
	DataOutputs              []ContractOutput
}
```

Optional knobs for `BuildCallTransaction`. [sdk_calling.go](sdk_calling.go).

#### `BuildCallTransaction`

```go
func BuildCallTransaction(
	currentUtxo UTXO,
	unlockingScript string,
	newLockingScript string,
	newSatoshis int64,
	changeAddress string,
	changeScript string,
	additionalUtxos []UTXO,
	feeRate int64,
	opts ...*BuildCallOptions,
) (tx *transaction.Transaction, inputCount int, changeAmount int64)
```

Build a method-call transaction. Returns the parsed `go-sdk` transaction (with the primary unlocking script already placed), the total input count, and the change amount. Does not sign, does not broadcast. [sdk_calling.go](sdk_calling.go).

#### `BuildDeployTransaction`

```go
func BuildDeployTransaction(
	lockingScript string,
	utxos []UTXO,
	satoshis int64,
	changeAddress string,
	changeScript string,
	feeRate ...int64,
) (tx *transaction.Transaction, inputCount int, err error)
```

Build an unsigned deploy transaction. Returns `error` if the funding inputs don't cover `satoshis + fee`. Variadic `feeRate` defaults to 100 sat/KB. [sdk_deployment.go](sdk_deployment.go).

#### `BuildInscriptionEnvelope`

```go
func BuildInscriptionEnvelope(contentType, data string) string
```

Build a 1sat ordinals envelope as hex (no-op `OP_FALSE OP_IF ... OP_ENDIF` block). `contentType` is the MIME type, `data` is hex-encoded content. [sdk_ordinals.go](sdk_ordinals.go).

#### `BuildP2PKHScript`

```go
func BuildP2PKHScript(address string) string
```

Build a P2PKH locking script from an address, raw 20-byte pubkey hash hex, or a 33/65-byte compressed/uncompressed public key hex. **Panics** on an invalid input. [sdk_deployment.go](sdk_deployment.go).

#### `ByteString`

```go
type ByteString string
```

The base byte-sequence type. Backed by `string` so `==` works for equality (matching Rúnar's `===` semantics). All other byte types are aliases or wrappers around `ByteString`. [runar.go](runar.go).

#### `Cat`

```go
func Cat(a, b ByteString) ByteString
```

Byte concatenation; compiles to `OP_CAT`. [runar.go](runar.go).

#### `CheckMultiSig`

```go
func CheckMultiSig(sigs []Sig, pks []PubKey) bool
```

Real ordered multi-sig verification matching `OP_CHECKMULTISIG` semantics (1:1 ordered pairing). [runar.go](runar.go).

#### `CheckPreimage`

```go
func CheckPreimage(preimage SigHashPreimage) bool
```

Always returns `true` in Go test mode. The compiled Script does the real check. [runar.go](runar.go).

#### `CheckSig`

```go
func CheckSig(sig Sig, pk PubKey) bool
```

Real ECDSA verification against `TestMessageDigest`. Pair with `SignTestMessage` to produce sigs that verify. [runar.go](runar.go).

#### `Clamp`

```go
func Clamp(value, lo, hi int64) int64
```

Returns `value` clamped to `[lo, hi]`. [runar.go](runar.go).

#### `CompileCheck`

```go
func CompileCheck(contractFile string) error
```

Run the Rúnar frontend (parse → validate → typecheck) on a contract source file. Auto-dispatches on extension across all nine `.runar.{ts,sol,move,go,rs,py,zig,rb,java}` formats. Returns `error` on any frontend failure with a colon-joined list of issues. [compile_check.go](compile_check.go).

#### `ComputeNewState` / `ComputeNewStateAndDataOutputs`

```go
func ComputeNewState(
	anf *ANFProgram,
	methodName string,
	currentState map[string]interface{},
	args map[string]interface{},
	constructorArgs []interface{},
) (map[string]interface{}, error)

func ComputeNewStateAndDataOutputs(
	anf *ANFProgram,
	methodName string,
	currentState map[string]interface{},
	args map[string]interface{},
	constructorArgs []interface{},
) (map[string]interface{}, []ContractOutput, error)
```

Run the artifact's ANF IR interpreter to derive the post-call state (and any `addDataOutput` entries) without round-tripping through the chain. Used internally by `PrepareCall`; useful for off-chain dry-runs. Returns `error` if the method name is not found in the ANF. [anf_interpreter.go](anf_interpreter.go).

#### `ComputeOpPushTx` / `ComputeOpPushTxWithCodeSep`

```go
func ComputeOpPushTx(txHex string, inputIndex int, subscript string, satoshis int64) ([]byte, []byte, error)
func ComputeOpPushTxWithCodeSep(txHex string, inputIndex int, subscript string, satoshis int64, codeSeparatorIndex int) ([]byte, []byte, error)
```

Compute the OP_PUSH_TX DER signature (signed with the well-known `k=1` private key, low-S enforced) and the BIP-143 preimage for a contract input. The `*WithCodeSep` variant honours an OP_CODESEPARATOR at the given byte offset; pass `-1` for "no code separator". Returns `error` on parse failure or out-of-range input index. [sdk_oppushtx.go](sdk_oppushtx.go).

#### `ConstructorSlot` / `CodeSepIndexSlot`

```go
type ConstructorSlot struct {
	ParamIndex int `json:"paramIndex"`
	ByteOffset int `json:"byteOffset"`
}
type CodeSepIndexSlot struct {
	ByteOffset   int `json:"byteOffset"`
	CodeSepIndex int `json:"codeSepIndex"`
}
```

Slot metadata embedded in `RunarArtifact` so the SDK knows where to splice constructor args and code-separator index placeholders. [sdk_types.go](sdk_types.go).

#### `ContractOutput`

```go
type ContractOutput struct {
	Script   string
	Satoshis int64
}
```

Output spec for `BuildCallOptions`. [sdk_calling.go](sdk_calling.go).

#### `DataOutputs` (on `StatefulSmartContract`)

```go
func (s *StatefulSmartContract) DataOutputs() []OutputSnapshot
```

Returns data outputs recorded by `AddDataOutput` during the last test invocation. [runar.go](runar.go).

#### `DecodePushData`

```go
func DecodePushData(hex string, offset int) (string, int)
```

Decode the push-data element at the given hex offset. Returns the pushed bytes (hex) and the total hex chars consumed. [sdk_state.go](sdk_state.go).

#### `DecodeScriptInt`

```go
func DecodeScriptInt(hex string) int64
```

Decode a minimally-encoded Bitcoin Script integer from hex. [sdk_state.go](sdk_state.go).

#### `DeployOptions`

```go
type DeployOptions struct {
	Satoshis      int64
	ChangeAddress string
}
```

[sdk_types.go](sdk_types.go).

#### `DeployWithWalletOptions` / `DeployWithWalletResult`

```go
type DeployWithWalletOptions struct { Satoshis int64; Description, Basket string; Tags []string }
type DeployWithWalletResult struct { Txid, RawTx string }
```

[sdk_wallet.go](sdk_wallet.go).

#### `DeserializeState`

```go
func DeserializeState(fields []StateField, scriptHex string) map[string]interface{}
```

Decode state values from a hex-encoded data section (the bytes after `OP_RETURN`). [sdk_state.go](sdk_state.go).

#### `Divmod` / `Gcd` / `GcdBig` / `Log2` / `Log2Big`

Builtin math helpers; map to compiler intrinsics. [runar.go](runar.go).

#### `EcAdd` / `EcMul` / `EcMulGen` / `EcNegate` / `EcOnCurve` / `EcModReduce` / `EcEncodeCompressed` / `EcMakePoint` / `EcPointX` / `EcPointY`

Real secp256k1 arithmetic for off-chain testing. In compiled Script these map to EC codegen opcodes. EC constants (`EC_P`, `EC_N`, `EC_G`) live in the language layer (`runar-lang/src/ec.ts`). [ec.go](ec.go).

#### `EncodePushData`

```go
func EncodePushData(dataHex string) string
```

Wrap a hex-encoded byte string in the minimal Bitcoin Script push-data opcode (direct push, OP_PUSHDATA1/2/4). [sdk_state.go](sdk_state.go).

#### `EncodeScriptInt`

```go
func EncodeScriptInt(n int64) string
```

Encode an integer in push-data format for state serialization. [sdk_state.go](sdk_state.go).

#### `EnvelopeBounds`

```go
type EnvelopeBounds struct { StartHex, EndHex int }
```

Hex-char offsets bounding a 1sat ordinals envelope inside a script. [sdk_ordinals.go](sdk_ordinals.go).

#### `EstimateCallFee` / `EstimateDeployFee`

```go
func EstimateCallFee(lockingScriptByteLen, unlockingScriptByteLen, numFundingInputs int, feeRate ...int64) int64
func EstimateDeployFee(numInputs int, lockingScriptByteLen int, feeRate ...int64) int64
```

Fee estimators. Variadic `feeRate` defaults to 100 sat/KB. [sdk_deployment.go](sdk_deployment.go).

#### `ExternalSigner`

```go
type ExternalSigner struct { /* unexported */ }
func NewExternalSigner(pubKeyHex, address string, signFn SignFunc) *ExternalSigner
```

`Signer` implementation that delegates `Sign` to a caller-provided callback. Useful when keys live in a custom HSM / wallet daemon you do not want to ship as a `WalletClient`. [sdk_signer.go](sdk_signer.go).

#### `Extract*` (preimage helpers)

```go
func ExtractAmount(p SigHashPreimage) int64
func ExtractHashPrevouts(p SigHashPreimage) Sha256Digest
func ExtractLocktime(p SigHashPreimage) int64
func ExtractOutpoint(p SigHashPreimage) ByteString
func ExtractOutputHash(p SigHashPreimage) Sha256Digest
func ExtractSequence(p SigHashPreimage) int64
func ExtractVersion(p SigHashPreimage) int64
```

Test-mode preimage accessors. Return deterministic mock values. The compiled Script implements the real BIP-143 substring extractions. [runar.go](runar.go).

#### `ExtractConstructorArgs`

```go
func ExtractConstructorArgs(artifact *RunarArtifact, scriptHex string) map[string]interface{}
```

Walk an on-chain locking script using `artifact.ConstructorSlots` and decode each constructor arg. [sdk_script_utils.go](sdk_script_utils.go).

#### `ExtractStateFromScript`

```go
func ExtractStateFromScript(artifact *RunarArtifact, scriptHex string) map[string]interface{}
```

Read state from a full locking script hex. Returns `nil` if the artifact has no state fields or no recognizable state section. [sdk_state.go](sdk_state.go).

#### `FindInscriptionEnvelope` / `ParseInscriptionEnvelope` / `StripInscriptionEnvelope`

Locate, parse, and strip 1sat inscription envelopes from a script hex. [sdk_ordinals.go](sdk_ordinals.go).

#### `FindLastOpReturn`

```go
func FindLastOpReturn(scriptHex string) int
```

Walk the script as Bitcoin Script opcodes (skipping push data) to find the last `OP_RETURN` byte boundary. Returns the hex-char offset, or `-1` if none. [sdk_state.go](sdk_state.go).

#### `FromTxId`

```go
func FromTxId(artifact *RunarArtifact, txid string, outputIndex int, provider Provider) (*RunarContract, error)
```

Reconnect to an existing deployed contract by fetching its deployment transaction through `provider`. Returns `error` if the provider lookup fails or the output index is out of range. [sdk_contract.go](sdk_contract.go).

#### `FromUtxo`

```go
func FromUtxo(artifact *RunarArtifact, utxo UTXO) *RunarContract
```

Synchronous equivalent of `FromTxId` when the UTXO data is already in hand (e.g. from an overlay service). Does not call the provider. [sdk_contract.go](sdk_contract.go).

#### `GenerateGo`

```go
func GenerateGo(artifact *RunarArtifact) string
```

Produce a typed Go wrapper source file for the given artifact. See [Section 10](#10-typed-contract-bindings-generatego). [sdk_codegen.go](sdk_codegen.go).

#### `GorillaPoolProvider`

```go
type GorillaPoolProvider struct { Network string; /* unexported */ }
func NewGorillaPoolProvider(network string) *GorillaPoolProvider

func (p *GorillaPoolProvider) GetInscriptionsByAddress(address string) ([]InscriptionInfo, error)
func (p *GorillaPoolProvider) GetInscription(inscriptionId string) (*InscriptionDetail, error)
func (p *GorillaPoolProvider) GetBSV20Balance(address, tick string) (string, error)
func (p *GorillaPoolProvider) GetBSV20Utxos(address, tick string) ([]UTXO, error)
func (p *GorillaPoolProvider) GetBSV21Balance(address, id string) (string, error)
func (p *GorillaPoolProvider) GetBSV21Utxos(address, id string) ([]UTXO, error)
```

Plus the standard `Provider` interface methods. [sdk_gorillapool.go](sdk_gorillapool.go).

#### `Groth16PublicInput`

```go
func Groth16PublicInput(i int64) Bigint
```

Compiler intrinsic that resolves to the i-th public input of a Mode-3 witness-assisted Groth16 verifier inside a stateful method body. Returns 0 in Go test mode. [bn254.go](bn254.go).

#### `Groth16Verify`

```go
func Groth16Verify(proofBlob, publicValues, vkHash ByteString) bool
```

Generic Groth16 verifier intrinsic. Returns `true` in Go test mode; the compiled Script does the real work. [runar.go](runar.go).

#### `Groth16WAContract`

```go
type Groth16WAContract struct { /* unexported */ }
func NewGroth16WAContract(artifact *RunarArtifact) *Groth16WAContract

func (g *Groth16WAContract) Artifact() *RunarArtifact
func (g *Groth16WAContract) NumPubInputs() int
func (g *Groth16WAContract) VKDigest() string
func (g *Groth16WAContract) CurrentUTXO() *UTXO
func (g *Groth16WAContract) SetCurrentUTXO(u *UTXO)
func (g *Groth16WAContract) LockingScript() string
func (g *Groth16WAContract) Connect(provider Provider, signer Signer)
func (g *Groth16WAContract) Deploy(provider Provider, signer Signer, opts DeployOptions) (string, *TransactionData, error)
func (g *Groth16WAContract) CallWithWitness(
	provider Provider, signer Signer,
	w *bn254witness.Witness,
	changeAddress string, outputScriptHex string,
) (string, *TransactionData, error)
```

Wrapper for artifacts produced by the `runarc groth16-wa` compiler backend. The verifying key is baked into the locking script at compile time, so deploy is just "send funds to this script", and spend takes a raw witness bundle (`*bn254witness.Witness`) instead of an ABI-encoded arg list. **Panics** if constructed with a nil artifact or one that lacks `Groth16WA` metadata. [sdk_groth16.go](sdk_groth16.go).

#### `Groth16WAMeta`

```go
type Groth16WAMeta struct {
	NumPubInputs int    `json:"numPubInputs"`
	VKDigest     string `json:"vkDigest"`
}
```

Metadata stored on `RunarArtifact.Groth16WA` to identify Groth16 WA artifacts. [sdk_types.go](sdk_types.go).

#### `Hash160` / `Hash256` / `Sha256` / `Sha256Hash` / `Ripemd160Func`

Real hash functions. `Hash160` = RIPEMD-160(SHA-256(...)), `Hash256` = double SHA-256, `Sha256` = single SHA-256, `Sha256Hash` is a back-compat alias for `Sha256`. [runar.go](runar.go).

#### `Inscription` / `InscriptionInfo` / `InscriptionDetail`

```go
type Inscription struct { ContentType, Data string }
type InscriptionInfo struct { Txid string; Vout int; Origin, ContentType string; ContentLength, Height int }
type InscriptionDetail struct { InscriptionInfo; Data string }
```

[sdk_ordinals.go](sdk_ordinals.go), [sdk_gorillapool.go](sdk_gorillapool.go).

#### `InsertUnlockingScript`

```go
func InsertUnlockingScript(txHex string, inputIndex int, unlockScript string) string
```

Re-write the scriptSig at `inputIndex` in a raw transaction hex. **Panics** if `inputIndex` is out of range. Kept for backward compatibility — prefer setting `tx.Inputs[i].UnlockingScript` directly when you can. [sdk_calling.go](sdk_calling.go).

#### `Int`

```go
type Int = int64
```

The Rúnar runtime integer type (alias of `int64`, identical to `Bigint`). [runar.go](runar.go).

#### `KbField*` / `KbExt4*` / `BbField*` / `BbExt4*`

KoalaBear and BabyBear field arithmetic primitives used by the SP1 / Plonky3 verifier covenants. [runar.go](runar.go).

#### `Len`

```go
func Len(data ByteString) int64
```

Byte length. [runar.go](runar.go).

#### `LocalSigner`

```go
type LocalSigner struct { /* unexported */ }
func NewLocalSigner(keyInput string) (*LocalSigner, error)
```

`Signer` backed by an in-memory secp256k1 private key. `keyInput` is either a 64-char hex or a WIF (starts with `5`, `K`, or `L`). Real ECDSA + BIP-143 signing via `go-sdk`. Suitable for CLI tooling and tests; for production wallets use `ExternalSigner` or `WalletSigner`. [sdk_signer.go](sdk_signer.go).

#### `MatchesArtifact`

```go
func MatchesArtifact(artifact *RunarArtifact, scriptHex string) bool
```

Determine whether an on-chain script was produced from the given artifact (regardless of constructor args). [sdk_script_utils.go](sdk_script_utils.go).

#### `MerkleRootHash256` / `MerkleRootSha256` / `MerkleRootPoseidon2KB` / `MerkleRootPoseidon2KBv`

Merkle-root computation helpers — the SHA-256 forms accept a leaf, proof, index, and depth; the Poseidon2 KB forms work over 8-element field state. [runar.go](runar.go).

#### `Min` / `Max` / `Within` / `Abs` / `AbsBig` / `Sign`

[runar.go](runar.go).

#### `MockPreimage`

```go
func MockPreimage() SigHashPreimage
```

181-byte zero placeholder. [runar.go](runar.go).

#### `MockProvider`

```go
type MockProvider struct { /* unexported */ }
func NewMockProvider(network string) *MockProvider

func (m *MockProvider) AddTransaction(tx *TransactionData)
func (m *MockProvider) AddUtxo(address string, utxo UTXO)
func (m *MockProvider) AddContractUtxo(scriptHash string, utxo *UTXO)
func (m *MockProvider) GetBroadcastedTxs() []string
func (m *MockProvider) SetFeeRate(rate int64)
```

Plus the standard `Provider` interface methods. `Broadcast` returns a deterministic fake txid. [sdk_provider.go](sdk_provider.go).

#### `MockSignerImpl`

```go
type MockSignerImpl struct { /* unexported */ }
func NewMockSigner(pubKeyHex, address string) *MockSignerImpl
```

Deterministic mock `Signer`. Returns a 72-byte placeholder DER signature on every call. Empty `pubKeyHex` / `address` get sensible zero defaults. [sdk_signer.go](sdk_signer.go).

#### `MulDiv` / `MulDivBig` / `PercentOf` / `PercentOfBig` / `Pow` / `PowBig` / `Safediv` / `Safemod` / `Sqrt` / `SqrtBig`

Builtin math helpers. [runar.go](runar.go).

#### `Num2Bin` / `Num2BinBig`

```go
func Num2Bin(v int64, length int64) ByteString
func Num2BinBig(v *big.Int, length int64) ByteString
```

Encode an integer as a little-endian sign-magnitude byte string of the requested length. Inverse of `Bin2Num`. [runar.go](runar.go).

#### `OpPushTxPubKeyHex`

```go
func OpPushTxPubKeyHex() string
```

Hex-encoded compressed public key (= generator point G) corresponding to the well-known `k=1` private key used for OP_PUSH_TX signatures. [sdk_oppushtx.go](sdk_oppushtx.go).

#### `OutputKind` / `OutputSnapshot`

```go
type OutputKind string
const (
	OutputKindState OutputKind = "state"
	OutputKindData  OutputKind = "data"
)

type OutputSnapshot struct {
	Satoshis int64
	Values   []any
	Kind     OutputKind
}
```

Used by `StatefulSmartContract` test instrumentation to record `AddOutput` / `AddDataOutput` calls. [runar.go](runar.go).

#### `OutputSpec`

```go
type OutputSpec struct {
	Satoshis int64
	State    map[string]interface{}
}
```

One continuation output for multi-output `Call`s. [sdk_types.go](sdk_types.go).

#### `P256Add` / `Mul` / `MulGen` / `Negate` / `OnCurve` / `EncodeCompressed` / `Keygen` / `Sign` / `VerifyECDSAP256` and the `P256Point` / `P256KeyPair` types

NIST P-256 helpers. [p256.go](p256.go).

#### `P384Add` / `Mul` / `MulGen` / `Negate` / `OnCurve` / `EncodeCompressed` / `Keygen` / `Sign` / `VerifyECDSAP384` and the `P384Point` / `P384KeyPair` types

NIST P-384 helpers. [p384.go](p384.go).

#### `Point`

```go
type Point = ByteString
```

64-byte secp256k1 EC point (x[32]||y[32], big-endian, no prefix). [runar.go](runar.go).

#### `PreparedCall`

```go
type PreparedCall struct {
	Sighash     string  // 64-char hex; BIP-143 hash external signers sign
	Preimage    string  // hex; full BIP-143 preimage
	OpPushTxSig string  // hex; OP_PUSH_TX DER sig (empty if not needed)
	TxHex       string  // hex; built TX
	SigIndices  []int   // user-visible arg positions awaiting external Sig values
	// ... unexported fields consumed by FinalizeCall
}
```

[sdk_types.go](sdk_types.go).

#### `Provider`

```go
type Provider interface {
	GetTransaction(txid string) (*TransactionData, error)
	GetRawTransaction(txid string) (string, error)
	Broadcast(tx *transaction.Transaction) (string, error)
	GetUtxos(address string) ([]UTXO, error)
	GetContractUtxo(scriptHash string) (*UTXO, error)
	GetNetwork() string
	GetFeeRate() (int64, error)
}
```

[sdk_provider.go](sdk_provider.go).

#### `PubKey` / `PubKeyFromPrivKey`

```go
type PubKey = ByteString
func PubKeyFromPrivKey(privKeyHex string) PubKey
```

Compressed (33-byte) public key derivation from a hex private key. [ecdsa.go](ecdsa.go).

#### `Rabin*` (`RabinSign`, `RabinSignToBytes`, `RabinTestKeyN`, `RabinTestP`, `RabinTestQ`)

Real Rabin-signature generation helpers for tests. [rabin.go](rabin.go).

#### `RabinPubKey` / `RabinSig`

Type aliases of `ByteString`. [runar.go](runar.go).

#### `Ripemd160Hash`

`type Ripemd160Hash = ByteString`. [runar.go](runar.go).

#### `RPCProvider`

```go
type RPCProvider struct { /* unexported */ }
func NewRPCProvider(url, user, pass string) *RPCProvider
func NewRegtestRPCProvider(url, user, pass string) *RPCProvider // auto-mines after each broadcast
```

Plus the standard `Provider` interface methods. [rpc_provider.go](rpc_provider.go).

#### `RunarArtifact`

```go
type RunarArtifact struct {
	Version              string
	CompilerVersion      string
	ContractName         string
	ABI                  ABI
	Script               string             // hex template (constructor slots are placeholders)
	ASM                  string
	StateFields          []StateField       // empty for stateless
	ConstructorSlots     []ConstructorSlot
	CodeSepIndexSlots    []CodeSepIndexSlot
	BuildTimestamp       string
	CodeSeparatorIndex   *int               // post-substitution single index
	CodeSeparatorIndices []int              // all indices
	ANF                  *ANFProgram        // ANF IR for state computation
	Groth16WA            *Groth16WAMeta
}
```

The compiled output of a Rúnar compiler. Loaded from JSON. [sdk_types.go](sdk_types.go).

#### `RunarContract`

```go
type RunarContract struct {
	Artifact *RunarArtifact
	// ... unexported fields
}
func NewRunarContract(artifact *RunarArtifact, constructorArgs []interface{}) *RunarContract

func (c *RunarContract) Connect(provider Provider, signer Signer)
func (c *RunarContract) WithInscription(inscription *Inscription) *RunarContract
func (c *RunarContract) GetInscription() *Inscription

func (c *RunarContract) Deploy(provider Provider, signer Signer, options DeployOptions) (string, *TransactionData, error)
func (c *RunarContract) Call(methodName string, args []interface{}, provider Provider, signer Signer, options *CallOptions) (string, *TransactionData, error)
func (c *RunarContract) PrepareCall(methodName string, args []interface{}, provider Provider, signer Signer, options *CallOptions) (*PreparedCall, error)
func (c *RunarContract) FinalizeCall(prepared *PreparedCall, signatures map[int]string, provider Provider) (string, *TransactionData, error)
func (c *RunarContract) DeployWithWallet(options *DeployWithWalletOptions) (*DeployWithWalletResult, error)

func (c *RunarContract) GetLockingScript() string
func (c *RunarContract) BuildUnlockingScript(methodName string, args []interface{}) string
func (c *RunarContract) GetState() map[string]interface{}
func (c *RunarContract) SetState(newState map[string]interface{})
func (c *RunarContract) GetCurrentUtxo() *UTXO
func (c *RunarContract) SetCurrentUtxo(utxo *UTXO)
```

The runtime contract object. **`NewRunarContract` panics** when the constructor arg count doesn't match the artifact ABI; **`BuildUnlockingScript` panics** when `methodName` is not a public method. Provider/signer arguments may be `nil` after `Connect` has been called. [sdk_contract.go](sdk_contract.go).

#### `SelectUtxos`

```go
func SelectUtxos(utxos []UTXO, targetSatoshis int64, lockingScriptByteLen int, feeRate ...int64) []UTXO
```

Largest-first UTXO selector. Returns the smallest set whose total value covers the target plus the estimated deploy fee. [sdk_deployment.go](sdk_deployment.go).

#### `SerializeGroth16WAWitnessForTests`

```go
func SerializeGroth16WAWitnessForTests(w *bn254witness.Witness) string
```

Public wrapper around the internal serializer for inspection in tests. Production callers should use `CallOptions.Groth16WAWitness`. [sdk_groth16.go](sdk_groth16.go).

#### `SerializeState`

```go
func SerializeState(fields []StateField, values map[string]interface{}) string
```

Encode state values as a hex Bitcoin-Script data section (no `OP_RETURN` prefix). [sdk_state.go](sdk_state.go).

#### `Sha256Compress` / `Sha256Finalize`

```go
func Sha256Compress(state, block ByteString) ByteString
func Sha256Finalize(state, remaining ByteString, msgBitLen int64) ByteString
```

Real SHA-256 compression and FIPS 180-4 padding for partial-hash verification patterns. **Panics** on wrong input lengths. [runar.go](runar.go).

#### `Sha256Digest` / `Sha256Hash` / `Sha256` (functions)

See above. [runar.go](runar.go).

#### `Sig` / `SigHashPreimage`

`type Sig = ByteString`, `type SigHashPreimage = ByteString`. [runar.go](runar.go).

#### `SignFunc`

```go
type SignFunc func(txHex string, inputIndex int, subscript string, satoshis int64, sigHashType *int) (string, error)
```

The callback signature `ExternalSigner` adapts. Returns DER signature + sighash byte, hex-encoded. [sdk_signer.go](sdk_signer.go).

#### `SignTestMessage`

```go
func SignTestMessage(privKeyHex string) Sig
```

Signs `TestMessageDigest` so `CheckSig` against the corresponding pubkey returns `true` in tests. [ecdsa.go](ecdsa.go).

#### `Signer`

```go
type Signer interface {
	GetPublicKey() (string, error)
	GetAddress() (string, error)
	Sign(txHex string, inputIndex int, subscript string, satoshis int64, sigHashType *int) (string, error)
}
```

[sdk_signer.go](sdk_signer.go).

#### `SLHKeygen` / `SLHSign` / `SLHVerify` / `SLHParams` / `SLHKeyPair` / `AllSHA2Params`

Real FIPS 205 SLH-DSA implementation (SPHINCS+) for the six SHA-2 parameter sets. [slh_dsa.go](slh_dsa.go).

#### `SmartContract` / `StatefulSmartContract`

Base structs to embed in contract definitions. `StatefulSmartContract` provides `AddOutput`, `AddRawOutput`, `AddDataOutput`, `Outputs`, `DataOutputs`, `ResetOutputs`, `GetStateScript`, and a `TxPreimage` field for tests. [runar.go](runar.go).

#### `StateField`

```go
type StateField struct {
	Name         string
	Type         string
	Index        int
	InitialValue interface{}
	FixedArray   *ABIFixedArray
}
```

[sdk_types.go](sdk_types.go).

#### `Substr`

```go
func Substr(data ByteString, start, length int64) ByteString
```

Compiles to `OP_SUBSTR`. [runar.go](runar.go).

#### `TerminalOutput`

```go
type TerminalOutput struct {
	ScriptHex string
	Satoshis  int64
}
```

[sdk_types.go](sdk_types.go).

#### `TestKeyPair` / `Alice` / `Bob` / `Charlie`

Pre-computed test ECDSA key pairs. `Charlie` is derived deterministically at init time. [test_keys.go](test_keys.go).

#### `TestMessage` / `TestMessageDigest`

Constants used by `CheckSig`/`SignTestMessage`. [ecdsa.go](ecdsa.go).

#### `TokenWallet`

```go
type TokenWallet struct { /* unexported */ }
func NewTokenWallet(artifact *RunarArtifact, provider Provider, signer Signer) *TokenWallet

func (tw *TokenWallet) GetBalance() (int64, error)
func (tw *TokenWallet) GetUtxos() ([]UTXO, error)
func (tw *TokenWallet) Transfer(recipientAddr string, amount int64) (string, error)
func (tw *TokenWallet) Merge() (string, error)
```

Convenience wrapper for fungible-token contracts that have a `transfer(sig, to)` method and a `balance` / `supply` / `amount` state field. [sdk_token_wallet.go](sdk_token_wallet.go).

#### `ToBool`

```go
func ToBool(n int64) bool
```

[runar.go](runar.go).

#### `TransactionData` / `TxInput` / `TxOutput` / `UTXO`

The SDK's wire-shape structs for transactions and UTXOs. See full definitions in [sdk_types.go](sdk_types.go).

#### `VerifyRabinSig` / `VerifyWOTS` / `VerifySLHDSA_SHA2_*` / `VerifySP1FRI`

Real (`VerifyRabinSig`, `VerifyWOTS`, `VerifySLHDSA_SHA2_*`) or mocked (`VerifySP1FRI` returns `true`) verification helpers — see [Section 11.1](#111-off-chain-testing). All compile to full on-chain verifiers. `VerifySP1FRI` is the Go-only intrinsic delivered as part of the R10 milestone — it is the contract-side entry point for SP1 v6.0.2 STARK / FRI proof verification. [runar.go](runar.go).

#### `WalletActionOutput` / `WalletActionResult` / `WalletOutput`

Wire shapes used by `WalletClient` methods. [sdk_wallet.go](sdk_wallet.go).

#### `WalletClient`

```go
type WalletClient interface {
	GetPublicKey(protocolID [2]interface{}, keyID string) (string, error)
	CreateSignature(hashToDirectlySign []byte, protocolID [2]interface{}, keyID string) ([]byte, error)
	CreateAction(description string, outputs []WalletActionOutput) (*WalletActionResult, error)
	ListOutputs(basket string, tags []string, limit int) ([]WalletOutput, error)
}
```

The BRC-100 wallet abstraction; provide your own implementation. [sdk_wallet.go](sdk_wallet.go).

#### `WalletProvider` / `WalletProviderOptions`

```go
type WalletProviderOptions struct {
	Wallet        WalletClient
	Signer        Signer
	Basket        string
	FundingTag    string  // default "funding"
	ArcUrl        string  // default "https://arc.gorillapool.io"
	OverlayUrl    string
	OverlayTopics []string
	Network       string  // default "mainnet"
	FeeRate       float64 // default 100
}
type WalletProvider struct { /* unexported */ }
func NewWalletProvider(opts WalletProviderOptions) *WalletProvider

func (p *WalletProvider) EnsureFunding(minSatoshis int64) error
```

Plus the standard `Provider` interface methods. Broadcasts via ARC; reads UTXOs from the wallet's basket; resolves transactions via the optional overlay service or local cache. `EnsureFunding` creates a funding UTXO via `CreateAction` if the wallet doesn't already hold enough. [sdk_wallet.go](sdk_wallet.go).

#### `WalletSigner` / `WalletSignerOptions`

```go
type WalletSignerOptions struct {
	ProtocolID [2]interface{}
	KeyID      string
	Wallet     WalletClient
}
type WalletSigner struct { /* unexported */ }
func NewWalletSigner(opts WalletSignerOptions) *WalletSigner
```

`Signer` that computes the BIP-143 sighash locally and delegates the ECDSA step to the wallet via `CreateSignature`. Pubkey is cached after the first call. [sdk_wallet.go](sdk_wallet.go).

#### `WhatsOnChainProvider`

```go
type WhatsOnChainProvider struct { Network string; /* unexported */ }
func NewWhatsOnChainProvider(network string) *WhatsOnChainProvider
```

Plus the standard `Provider` interface methods. [sdk_woc_provider.go](sdk_woc_provider.go).

#### `WotsKeygen` / `WotsSign` / `WOTSKeyPair`

Real WOTS+ key generation and signing for tests. Verification goes through `VerifyWOTS`. [wots.go](wots.go).

---

## 14. Error handling

The Go SDK follows the standard Go convention: every operation that can fail returns a trailing `error`, never throws. The error is descriptive and wraps the underlying cause with `%w` so `errors.Is` / `errors.As` work.

```go
txid, _, err := contract.Deploy(provider, signer, runar.DeployOptions{Satoshis: 5000})
if err != nil {
	// e.g. "RunarContract.Deploy: getting UTXOs: ..."
	return fmt.Errorf("deploy counter: %w", err)
}
```

Common error messages you will see (all string-matched, no exported sentinel error vars):

| Function | Condition | Message prefix |
|---|---|---|
| `RunarContract.Deploy` | no provider/signer connected | `RunarContract.Deploy: no provider/signer available` |
| `RunarContract.Deploy` | provider has no UTXOs for the signer's address | `RunarContract.Deploy: no UTXOs found for address` |
| `RunarContract.Call` / `PrepareCall` | unknown method name | `RunarContract.PrepareCall: method '...' not found` |
| `RunarContract.Call` / `PrepareCall` | wrong arg count | `RunarContract.PrepareCall: method '...' expects N args, got M` |
| `RunarContract.Call` / `PrepareCall` | called before `Deploy` / `FromTxId` | `RunarContract.PrepareCall: contract is not deployed` |
| `RunarContract.FinalizeCall` | no provider | `RunarContract.FinalizeCall: no provider available` |
| `BuildDeployTransaction` | insufficient funds | `buildDeployTransaction: insufficient funds. Need X sats, have Y` |
| `Groth16WAContract.CallWithWitness` | no current UTXO / nil witness / both or neither output specified | `Groth16WAContract.CallWithWitness: ...` |
| `LocalSigner` / `WalletSigner` | bad subscript hex, OOR input index, ECDSA failure | `LocalSigner: ...` / `WalletSigner: ...` |

### Programmer-error panics

Four functions panic instead of returning an error. These conditions only happen when calling code passes obviously-wrong arguments — they are not recoverable failure modes you should handle dynamically.

| Function | Panic condition | Panic message format |
|---|---|---|
| `NewRunarContract` | constructor arg count doesn't match the artifact ABI | `RunarContract: expected N constructor args for ContractName, got M` |
| `RunarContract.BuildUnlockingScript` | method name is not a public method | `buildUnlockingScript: public method 'name' not found` |
| `InsertUnlockingScript` | input index is out of range for the raw transaction | `insertUnlockingScript: input index N out of range (M inputs)` |
| `BuildP2PKHScript` | address is not valid 40/66/130-char hex and not a valid Base58Check address | `BuildP2PKHScript: invalid address "...": ...` |

`NewGroth16WAContract` and `Sha256Compress` / `Sha256Finalize` also panic on programmer errors — see their entries in the API reference.

---

## 15. Troubleshooting / FAQ

**Q: `RunarContract.Call: method 'increment' not found`. The artifact has it.**

A: Method names are case-sensitive and must match the ABI exactly. The Rúnar Go DSL parser converts Go-side `Increment` (capitalized) to ABI `increment` (lowercase first letter); pass the lowercase name to `Call` / `PrepareCall`.

**Q: `BuildUnlockingScript` panics with "public method 'name' not found".**

A: Same as above. The name must match `artifact.ABI.Methods[i].Name` for some method with `IsPublic == true`.

**Q: Stateful call gets rejected with a hashOutputs mismatch.**

A: The state you supplied (via `CallOptions.NewState`) does not match what `checkPreimage` expects. Either let the SDK auto-derive the state by passing `nil` for `NewState`, or — if you genuinely want to test a rejection path — accept the rejection as the correct behaviour.

**Q: `BuildP2PKHScript` panics on a Bech32 address.**

A: BSV does not use Bech32; addresses are Base58Check P2PKH. Convert before passing in, or pass the raw 20-byte pubkey hash hex directly.

**Q: `MockProvider.GetUtxos` returns an empty slice after `Deploy`.**

A: `MockProvider` does not auto-track outputs from broadcasts as new spendable UTXOs. The contract UTXO is tracked on the `RunarContract` itself (`GetCurrentUtxo`), not in the provider. For follow-up calls that need the deployed contract UTXO, the SDK reads it from the contract object — no provider lookup is required.

**Q: Why is `LocalSigner` always producing mainnet addresses?**

A: `NewLocalSigner` derives an `AddressString` with `mainnet=true`. If you need a testnet address, derive it yourself from the public key bytes via `go-sdk`'s `script.NewAddressFromPublicKey(..., false)` and wrap it in an `ExternalSigner` whose `GetAddress` returns the testnet form.

**Q: `WhatsOnChainProvider.GetUtxos` returns UTXOs with empty `Script`.**

A: Documented limitation — WoC's `/address/{addr}/unspent` endpoint does not include locking scripts. Fetch the parent transaction with `GetTransaction(utxo.Txid)` if you need the script.

**Q: I want to use the SDK in async / concurrent code.**

A: Each `RunarContract` instance is **not** safe for concurrent use (state and current-UTXO mutation, no internal locking). Build one contract object per goroutine, or guard a shared one with a mutex. Provider and signer implementations should document their own concurrency story; `MockProvider` and `WalletProvider` are safe for concurrent reads via internal locking.

---

## 16. Versioning and stability

Module path: `github.com/icellan/runar/packages/runar-go`. The Rúnar project follows semantic versioning at the workspace level; the SDK and the compilers are released together. Breaking changes that affect either the runtime API surface (this README's [Section 13](#13-full-api-reference)) or the deployed locking script bytes (the conformance suite's golden hashes) are gated on a major version bump.

Stability tiers (use as a guide for what to build production code on top of):

| Tier | Surfaces |
|---|---|
| Stable | `RunarContract` lifecycle (`Deploy`, `Call`, `PrepareCall`, `FinalizeCall`, `FromTxId`, `FromUtxo`, `GetState`, `GetLockingScript`), all `Provider` / `Signer` interfaces, `MockProvider`, `MockSignerImpl`, `LocalSigner`, `ExternalSigner`, `RPCProvider`, `WhatsOnChainProvider`, `GorillaPoolProvider`, `BuildP2PKHScript`, `EncodePushData`, `EncodeScriptInt`, `FindLastOpReturn`, `SerializeState`, `DeserializeState`, the type aliases (`Bigint`, `PubKey`, ...). |
| Stable, surface still expanding | `WalletProvider` / `WalletSigner` (BRC-100), `Inscription` + BSV-20/21 helpers, `TokenWallet`, `GenerateGo`, `Groth16WAContract`. |
| Experimental | `VerifySP1FRI` codegen (Go runtime returns `true`; on-chain verifier under R10 follow-up work), Mode-3 witness-assisted Groth16 (`AssertGroth16WitnessAssisted*`, `Groth16PublicInput`, `CallOptions.Groth16WAWitness`). |

The `MockSignerImpl` name (rather than `MockSigner` as in the other SDKs) is preserved because changing it would be a breaking import-name change for existing callers.

---

## 17. Links

- Project root: <https://github.com/icellan/runar>
- Rúnar language playground: <https://runar.build>
- Language specification: [`spec/`](../../spec)
- Go compiler source: [`compilers/go/`](../../compilers/go)
- Go example contracts: [`examples/go/`](../../examples/go)
- Go integration tests (regtest): [`integration/go/`](../../integration/go)
- Cross-SDK output conformance suite: [`conformance/sdk-output/`](../../conformance/sdk-output)
- Sister SDKs: [`packages/runar-sdk/`](../runar-sdk) (TypeScript), [`packages/runar-rs/`](../runar-rs) (Rust), [`packages/runar-py/`](../runar-py) (Python), [`packages/runar-zig/`](../runar-zig) (Zig), [`packages/runar-rb/`](../runar-rb) (Ruby), [`packages/runar-java/`](../runar-java) (Java).
