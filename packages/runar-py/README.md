# runar

Python runtime and deployment SDK for Rúnar smart contracts on Bitcoin SV. Write contracts in Python (or any of the eight other supported source formats), test them off-chain with mocked crypto, then deploy and call them on-chain through pluggable providers and signers.

This package contains both the contract authoring runtime (base classes, types, intrinsics) and the deployment SDK (`runar.sdk`). The Rúnar compiler itself ships separately as `runar-compiler` and is only required for `compile_check`.

---

## Table of contents

1. [Title](#runar)
2. Table of contents
3. [Installation](#installation)
4. [Quick start](#quick-start)
5. [Core concepts](#core-concepts)
6. [Writing a contract](#writing-a-contract)
7. [Compiling](#compiling)
8. [Deploying contracts](#deploying-contracts)
9. [Calling contract methods](#calling-contract-methods)
   - [9a. Single-signer (`call`)](#9a-single-signer-call)
   - [9b. Multi-signer (`prepare_call` / `finalize_call`)](#9b-multi-signer-prepare_call--finalize_call)
   - [9c. BRC-100 wallet signing](#9c-brc-100-wallet-signing)
10. [Stateful contracts](#stateful-contracts)
11. [UTXO and fee management](#utxo-and-fee-management)
12. [Typed contract bindings (`generate_python`)](#typed-contract-bindings-generate_python)
13. [Testing](#testing)
    - [13a. Off-chain testing](#13a-off-chain-testing)
    - [13b. Integration testing against a regtest node](#13b-integration-testing-against-a-regtest-node)
14. [Provider configuration](#provider-configuration)
15. [Full API reference](#full-api-reference)
16. [Error handling](#error-handling)
17. [Troubleshooting / FAQ](#troubleshooting--faq)
18. [Versioning and stability](#versioning-and-stability)
19. [Links](#links)

---

## Installation

```bash
pip install runar
```

`runar` requires Python >= 3.10. The package has **zero required dependencies** — the entire SDK uses only the standard library (`hashlib`, `urllib.request`, `struct`, `json`, `dataclasses`).

### Optional extras

| Extra | What you get | Install |
|-------|--------------|---------|
| `bsv-sdk` | Native C-extension ECDSA in `LocalSigner` (faster than the bundled pure-Python signer) | `pip install bsv-sdk` |
| `runar-compiler` | The Rúnar compiler frontend, required only for `compile_check(...)` | `pip install runar-compiler` |
| `coincurve` | Optional secp256k1 backend | `pip install runar[crypto]` |

`LocalSigner` automatically detects whether `bsv-sdk` is installed and falls back to the bundled pure-Python ECDSA implementation otherwise. Both produce identical low-S DER signatures.

### From source

```bash
git clone https://github.com/icellan/runar
cd runar/packages/runar-py
pip install -e .
```

---

## Quick start

Deploy a `Counter` contract, increment it twice, then verify the on-chain state. This example uses `MockProvider` so you can run it without any network or node — switch to `RPCProvider` or `WhatsOnChainProvider` (see Section 14) to talk to a real chain.

```python
import json
from runar.sdk import (
    RunarContract, RunarArtifact, MockProvider, MockSigner,
    DeployOptions, Utxo,
)

# 1. Load the compiled artifact (produced by `runar compile Counter.runar.py`)
with open("Counter.artifact.json") as f:
    artifact = RunarArtifact.from_dict(json.load(f))

# 2. Set up provider + signer + funding UTXO
signer = MockSigner(address="00" * 20)
provider = MockProvider("testnet")
provider.add_utxo(signer.get_address(), Utxo(
    txid="aa" * 32, output_index=0,
    satoshis=100_000, script="76a914" + "00" * 20 + "88ac",
))

# 3. Construct the contract with initial state count=0 and connect
contract = RunarContract(artifact, [0])
contract.connect(provider, signer)

# 4. Deploy
deploy_txid, _ = contract.deploy(options=DeployOptions(satoshis=5000))
assert len(deploy_txid) == 64
assert contract.get_state()["count"] == 0

# 5. Call increment twice — state auto-advances
contract.call("increment", [])
contract.call("increment", [])

# 6. Verify state
assert contract.get_state()["count"] == 2
```

The full Counter contract source lives at [`examples/python/stateful-counter/Counter.runar.py`](../../examples/python/stateful-counter/Counter.runar.py). The same flow against a regtest node is in [`integration/python/test_counter.py`](../../integration/python/test_counter.py).

---

## Core concepts

These names are the cross-SDK canonical vocabulary used in the documentation. Each appears in `runar.sdk` with a Python-idiomatic name.

| Concept | Python type | What it is |
|---------|-------------|------------|
| **Artifact** | [`RunarArtifact`](runar/sdk/types.py) | The compiled contract: locking-script template, ABI, state schema, constructor and code-separator slots, ANF IR. Loaded from JSON, immutable. |
| **Contract** | [`RunarContract`](runar/sdk/contract.py) | The runtime object that wraps an artifact + constructor args + state + current UTXO. Knows how to deploy, call, prepare/finalize, and serialize state. |
| **Provider** | [`Provider`](runar/sdk/provider.py) (ABC) | Read/write blockchain interface. Fetches transactions/UTXOs and broadcasts new ones. Pluggable. |
| **Signer** | [`Signer`](runar/sdk/signer.py) (ABC) | Key-management interface. Produces compressed pubkey, P2PKH address, and BIP-143 ECDSA signatures over given subscripts. Pluggable. |
| **Wallet** | [`WalletClient`](runar/sdk/wallet.py) (ABC) | BRC-100 wallet client (browser/extension wallet). Backs a `WalletProvider` + `WalletSigner` pair when the SDK can't hold raw keys. |
| **Call** | `RunarContract.call(...)` | A method invocation on a deployed contract: spend the contract UTXO, optionally produce a continuation UTXO, optionally produce data outputs, broadcast. |
| **PreparedCall** | [`PreparedCall`](runar/sdk/types.py) | The output of the two-pass calling flow: a built-but-unsigned tx hex + per-Sig sighashes that an external signer (hardware wallet, multi-party) can sign offline. |
| **State** | `dict` returned from `contract.get_state()` | The mutable Bitcoin-Script-encoded payload after the contract's last `OP_RETURN`. Stateful-contract-only. |
| **UTXO** | [`Utxo`](runar/sdk/types.py) | The contract's current on-chain output (txid, vout, satoshis, script). Tracked across deploy → call → call. |
| **Inscription** | [`Inscription`](runar/sdk/ordinals.py) | A 1sat ordinals envelope spliced between code and state in the locking script. Immutable across state transitions. |

---

## Writing a contract

Rúnar contracts are normal Python classes in `.runar.py` files. They subclass `SmartContract` (stateless) or `StatefulSmartContract` (stateful), and the compiler lowers them to Bitcoin Script.

### snake_case vs camelCase

Python contract source uses `snake_case` identifiers. The Rúnar parser converts them to `camelCase` in the AST so all seven compilers produce byte-identical output:

| Python source | AST / on-chain ABI |
|---------------|--------------------|
| `pub_key_hash` | `pubKeyHash` |
| `check_sig` | `checkSig` |
| `release_by_seller` | `releaseBySeller` |

The deployment SDK (this package) is `snake_case` throughout — `contract.get_state()`, `prepare_call`, `op_push_tx_sig`. The conversion only applies inside contract source.

### Type annotations

Use the type aliases from `runar` for properties and parameters. They map to compiler primitives:

| Python | Rúnar primitive | Bytes | Notes |
|--------|-----------------|-------|-------|
| `int` / `Bigint` | `bigint` | variable | Arbitrary-precision integers |
| `bool` | `boolean` | 1 | |
| `bytes` / `ByteString` | `ByteString` | variable | |
| `PubKey` | `PubKey` | 33 | Compressed secp256k1 |
| `Sig` | `Sig` | ~72 | DER-encoded ECDSA + sighash byte |
| `Addr` | `Addr` | 20 | HASH160 of pubkey |
| `Sha256` / `Sha256Digest` | `Sha256` | 32 | |
| `Ripemd160` | `Ripemd160` | 20 | |
| `Point` | `Point` | 64 | x \|\| y, big-endian, no prefix |
| `P256Point` | `P256Point` | 64 | NIST P-256 |
| `P384Point` | `P384Point` | 96 | NIST P-384 |
| `SigHashPreimage` | `SigHashPreimage` | ~181 | BIP-143 preimage |
| `RabinSig` / `RabinPubKey` | `RabinSig` / `RabinPubKey` | variable | |
| `Readonly[T]` | adds `readonly: true` to the property | — | Stateful contracts only |
| `FixedArray[T, N]` | `FixedArray<T, N>` | N×width(T) | Fixed-length array |

### Python idioms used in contract source

- `assert_(expr)` or `assert expr` — Rúnar assertion, fails the script if false.
- `//` — integer division (lowers to `OP_DIV`).
- `and`, `or`, `not` — boolean operators (lowered to `OP_BOOLAND`, `OP_BOOLOR`, `OP_NOT`).
- `@public` — marks a method as a spending entry point. Methods without `@public` are private and inlined.
- `Readonly[T]` — marks a property as immutable in `StatefulSmartContract`.

### Example — stateless P2PKH

```python
# P2PKH.runar.py
from runar import SmartContract, Addr, Sig, PubKey, public, assert_, hash160, check_sig


class P2PKH(SmartContract):
    pub_key_hash: Addr  # readonly (all SmartContract properties are)

    def __init__(self, pub_key_hash: Addr):
        super().__init__(pub_key_hash)
        self.pub_key_hash = pub_key_hash

    @public
    def unlock(self, sig: Sig, pub_key: PubKey):
        assert_(hash160(pub_key) == self.pub_key_hash)
        assert_(check_sig(sig, pub_key))
```

### Example — stateful Counter

```python
# Counter.runar.py
from runar import StatefulSmartContract, Bigint, public, assert_


class Counter(StatefulSmartContract):
    count: Bigint  # mutable (stateful, persists across transactions)

    def __init__(self, count: Bigint):
        super().__init__(count)
        self.count = count

    @public
    def increment(self):
        self.count += 1

    @public
    def decrement(self):
        assert_(self.count > 0)
        self.count -= 1
```

For `StatefulSmartContract`, the compiler injects `checkPreimage` at the start of every public method and a state-continuation output at the end — you do not write either by hand.

### Constructor rule

Constructors must call `super(...)` as their first statement, passing every property in declaration order. The compiler checks this.

### Allowed call surface

Only Rúnar built-in functions and methods on `self` are callable from contract source. `print()`, `math.floor()`, third-party libraries — anything not in the Rúnar prelude — is rejected at typecheck. See Section 15 for the full intrinsic list.

---

## Compiling

The `compile_check` helper runs your source through the Rúnar frontend (parse → validate → typecheck) and raises on any error. It does not produce an artifact — use the `runar` CLI or `runar_compiler.compile_from_source(...)` for that.

```python
from runar import compile_check

# Pass a path
compile_check("Counter.runar.py")

# Or pass the source directly with a filename for error messages
compile_check(source_string, file_name="Counter.runar.py")
```

Source: [runar/compile_check.py](runar/compile_check.py).

`compile_check` requires the `runar_compiler` package. It raises `RuntimeError` (with the underlying error context) if the package is not installed:

```python
import pytest
from runar import compile_check

with pytest.raises(RuntimeError):
    compile_check("class Broken(\n", file_name="Broken.runar.py")
```

To produce a deployable artifact:

```bash
runar compile Counter.runar.py --out Counter.artifact.json
```

Or programmatically:

```python
import json
from runar_compiler import compile_from_source, artifact_to_json
from runar.sdk import RunarArtifact

compiled = compile_from_source("Counter.runar.py")
artifact_dict = json.loads(artifact_to_json(compiled))
artifact = RunarArtifact.from_dict(artifact_dict)
```

---

## Deploying contracts

`RunarContract.deploy(...)` builds a P2PKH-funded transaction whose first output is the contract's locking script, signs all funding inputs, and broadcasts via the provider. The contract instance tracks the resulting UTXO so subsequent `call(...)` invocations spend from it.

```python
from runar.sdk import RunarContract, MockProvider, MockSigner, DeployOptions, Utxo

contract = RunarContract(artifact, [0])  # constructor args matching artifact.abi.constructor_params

signer = MockSigner(address="00" * 20)
provider = MockProvider("testnet")
provider.add_utxo(signer.get_address(), Utxo(
    txid="aa" * 32, output_index=0,
    satoshis=100_000, script="76a914" + "00" * 20 + "88ac",
))

contract.connect(provider, signer)

txid, tx = contract.deploy(options=DeployOptions(
    satoshis=5_000,                        # value to lock in the contract output
    change_address=signer.get_address(),   # optional; defaults to signer.get_address()
))
assert len(txid) == 64

utxo = contract.get_utxo()
assert utxo.txid == txid
assert utxo.satoshis == 5_000
```

`DeployOptions` (see [runar/sdk/types.py:179](runar/sdk/types.py)):

| Field | Type | Default | Meaning |
|-------|------|---------|---------|
| `satoshis` | `int` | `10000` | Value to lock in the contract output |
| `change_address` | `str` | `''` | Where to send change; defaults to signer's address |

`deploy()` returns `(txid: str, tx: TransactionData)`. The provider must contain enough UTXOs at `signer.get_address()` to cover `satoshis + fee`, where the fee is computed from the actual locking-script size at the provider's `get_fee_rate()`.

### Reconnecting to an existing deployment

```python
from runar.sdk import RunarContract

# By txid + vout (provider must have the tx)
contract = RunarContract.from_txid(artifact, txid, output_index=0, provider=provider)

# By a known UTXO (no provider lookup needed)
contract = RunarContract.from_utxo(artifact, utxo)

assert contract.get_state() == {"count": 2}  # state extracted from the on-chain script
```

---

## Calling contract methods

A call spends the current contract UTXO with an unlocking script that satisfies one of its `@public` methods. The SDK builds the transaction, computes any required `OP_PUSH_TX` signature and BIP-143 preimage, advances internal state for stateful contracts, signs (or returns a sighash for offline signing), and broadcasts.

### 9a. Single-signer (`call`)

The one-step path — use this when the SDK has direct access to the signing key.

```python
from runar.sdk import CallOptions

txid, _ = contract.call(
    "increment",                        # method name
    [],                                 # user-visible args (empty for Counter.increment)
    provider=provider, signer=signer,   # optional if connect() was called
    options=CallOptions(),              # optional
)
```

`CallOptions` (see [runar/sdk/types.py:204](runar/sdk/types.py)):

| Field | Type | Meaning |
|-------|------|---------|
| `satoshis` | `int` | Override output amount for the continuation UTXO. `0` keeps the input amount. |
| `change_address` | `str` | Override change address |
| `change_pub_key` | `str` | Override change pubkey hex (used for `_changePKH` injection) |
| `new_state` | `dict \| None` | Force-override the auto-computed new state (mostly for negative tests) |
| `outputs` | `list[OutputSpec \| dict] \| None` | Multi-output continuation (one continuation UTXO per spec) |
| `additional_contract_inputs` | `list[Utxo \| dict] \| None` | Additional contract UTXOs to merge in this call |
| `additional_contract_input_args` | `list[list] \| None` | Per-input args for additional contract inputs |
| `terminal_outputs` | `list[TerminalOutput \| dict] \| None` | Exact outputs for a terminal method (no continuation, no change) |
| `funding_utxos` | `list[Utxo] \| None` | Explicit funding UTXOs for terminal methods |
| `data_outputs` | `list[dict] \| None` | Override `this.addDataOutput(...)` resolution |

If a method's parameter list contains `Sig`, `PubKey`, `SigHashPreimage`, or `ByteString` (for prevouts) and you pass `None` at that position, the SDK auto-resolves them: `PubKey` from the signer, `Sig` via signing, `SigHashPreimage` via BIP-143 computation, `ByteString` (prevouts) from the built tx.

### 9b. Multi-signer (`prepare_call` / `finalize_call`)

The two-step path — use this when the signer cannot run inline (hardware wallet, multi-party MPC, web frontend posting to a backend signing service). `prepare_call` builds the transaction and emits a `PreparedCall` containing the BIP-143 sighash; `finalize_call` injects external signatures and broadcasts.

```python
from runar.sdk import PreparedCall

prepared = contract.prepare_call(
    "increment", [],
    provider=provider, signer=signer,
)

# `prepared.sighash` is the 32-byte digest the external signer must sign.
# `prepared.tx_hex` is the built transaction (P2PKH funding inputs already signed).
# `prepared.sig_indices` lists which arg positions need external Sig values.

signatures: dict[int, str] = {}
for idx in prepared.sig_indices:
    signatures[idx] = my_external_signer.sign(prepared.sighash)  # returns DER hex + sighash flag

txid, tx = contract.finalize_call(prepared, signatures, provider=provider)
```

`PreparedCall` is fully serializable as JSON-friendly fields ([`runar/sdk/types.py:223`](runar/sdk/types.py)) — pass the public fields (`sighash`, `preimage`, `tx_hex`, `sig_indices`) to a remote signer over the wire and reconstruct on return.

### 9c. BRC-100 wallet signing

`WalletProvider` + `WalletSigner` integrate with BRC-100 compatible wallets (browser extensions, native wallet apps). The wallet owns the keys; the SDK never sees them.

```python
from runar.sdk import WalletClient, WalletProvider, WalletSigner

class MyWallet(WalletClient):
    def get_public_key(self, protocol_id: tuple, key_id: str) -> str:
        ...  # call out to the wallet
    def create_signature(self, hash_to_sign: bytes, protocol_id: tuple, key_id: str) -> bytes:
        ...
    def create_action(self, description: str, outputs: list[dict]) -> dict:
        ...
    def list_outputs(self, basket: str, tags: list[str], limit: int = 100) -> list[dict]:
        ...

wallet = MyWallet()
signer = WalletSigner(wallet, protocol_id=(2, "my app"), key_id="1")
provider = WalletProvider(
    wallet, signer,
    basket="runar-funding",
    arc_url="https://arc.gorillapool.io",
    overlay_url="https://overlay.example.com",
    network="mainnet",
)

contract = RunarContract(artifact, [0])
contract.connect(provider, signer)

# For deploy through the wallet (no SDK funding logic), use deploy_with_wallet:
txid, output_index = contract.deploy_with_wallet(satoshis=1, description="Deploy Counter")
```

Sources: [runar/sdk/wallet.py](runar/sdk/wallet.py).

`WalletProvider.ensure_funding(min_satoshis)` will create a fresh funding UTXO via `wallet.create_action(...)` if the basket balance is insufficient. `WalletProvider` broadcasts via GorillaPool ARC by default and looks up transactions through an optional overlay service plus a local cache.

---

## Stateful contracts

For `StatefulSmartContract`, the compiler injects:

1. **`checkPreimage` at method entry** — verifies that the BIP-143 preimage passed in the unlocking script matches the spending transaction.
2. **A state-continuation output at method exit** — the new locking script is `<original code> OP_RETURN <serialized new state>`, and `hashOutputs` in the preimage proves the spender produced the right output.

The SDK manages all three of these for you:

- It tracks the contract's current UTXO (`contract.get_utxo()`).
- It runs the artifact's ANF interpreter ([`runar/sdk/anf_interpreter.py`](runar/sdk/anf_interpreter.py)) over your method to compute the new state from the current state and the args you passed.
- It computes the OP_PUSH_TX signature ([`runar/sdk/oppushtx.py`](runar/sdk/oppushtx.py)) using the well-known k=1 private key.
- It serializes new state with the same NUM2BIN sign-magnitude format the on-chain script expects ([`runar/sdk/state.py`](runar/sdk/state.py)).

```python
contract = RunarContract(counter_artifact, [0])
contract.connect(provider, signer)
contract.deploy(options=DeployOptions(satoshis=5_000))

assert contract.get_state() == {"count": 0}

contract.call("increment", [])
assert contract.get_state() == {"count": 1}

contract.call("increment", [])
assert contract.get_state() == {"count": 2}

contract.call("decrement", [])
assert contract.get_state() == {"count": 1}
```

### Multi-output continuation

`this.addOutput(satoshis, ...values)` in contract source produces N continuation UTXOs (one per call). On the SDK side, pass `outputs=[...]`:

```python
from runar.sdk import OutputSpec, CallOptions

contract.call(
    "split",
    [],
    options=CallOptions(outputs=[
        OutputSpec(satoshis=2_500, state={"count": 1}),
        OutputSpec(satoshis=2_500, state={"count": 1}),
    ]),
)
```

### Raw and data outputs

- `this.addRawOutput(satoshis, scriptBytes)` produces an output with arbitrary script bytes. Not part of the continuation hash.
- `this.addDataOutput(satoshis, scriptBytes)` produces an output that *is* part of the continuation hash, in declaration order, between state outputs and the change output.

The SDK auto-resolves `addDataOutput` calls via the ANF interpreter. To override, pass `CallOptions(data_outputs=[{"script": hex, "satoshis": int}, ...])`.

### State serialization format

```python
from runar.sdk import serialize_state, deserialize_state

state_hex = serialize_state(artifact.state_fields, {"count": 5})
# → '0500000000000000' (8-byte LE sign-magnitude per bigint)

decoded = deserialize_state(artifact.state_fields, state_hex)
assert decoded == {"count": 5}
```

---

## UTXO and fee management

The SDK uses a **largest-first** UTXO selection strategy. Fees are computed from the *actual* locking and unlocking script sizes at the provider's `get_fee_rate()` (sat/KB).

```python
from runar.sdk import select_utxos, estimate_deploy_fee, estimate_call_fee

selected = select_utxos(all_utxos, target_satoshis=5_000, locking_script_byte_len=200, fee_rate=100)
fee = estimate_deploy_fee(num_inputs=len(selected), locking_script_byte_len=200, fee_rate=100)
call_fee = estimate_call_fee(
    locking_script_byte_len=200,
    unlocking_script_byte_len=300,
    num_funding_inputs=1,
    fee_rate=100,
)
```

All providers default to a 100 sat/KB rate (BSV standard relay fee). Override with `provider.set_fee_rate(rate)` on `MockProvider`, or supply your own `Provider` subclass.

The contract's current UTXO is tracked automatically:

```python
utxo = contract.get_utxo()
assert utxo is not None
assert utxo.txid == last_call_txid
assert utxo.output_index == 0
```

`get_utxo()` returns `None` after a terminal method call, before deploy, or for stateless contracts that have already been spent.

### Reading state from a UTXO directly

```python
from runar.sdk import extract_constructor_args, matches_artifact

assert matches_artifact(artifact, utxo.script)
ctor_values = extract_constructor_args(artifact, utxo.script)
assert ctor_values["count"] == 0
```

---

## Typed contract bindings (`generate_python`)

`generate_python(artifact)` produces a typed wrapper class for a compiled contract. The wrapper exposes one method per `@public` contract method with the right Python type hints, hides compiler-injected params (`SigHashPreimage`, `_changePKH`, `_changeAmount`), and routes through `RunarContract.call` / `prepare_call` / `finalize_call`.

```python
from runar.sdk import generate_python

source = generate_python(counter_artifact)
# Write to disk, import, then use:
#
#   from generated_counter import Counter
#   c = Counter(0)
#   c.connect(provider, signer)
#   c.deploy(satoshis=5000)
#   c.increment()
#   c.decrement()
```

The generator is template-based ([runar/sdk/codegen.py:525](runar/sdk/codegen.py)) and uses zero external deps. For methods with `Sig` parameters it also emits `prepare_<name>` / `finalize_<name>` pairs that wrap the multi-signer flow.

---

## Testing

### 13a. Off-chain testing

Contracts are normal Python classes — instantiate them directly and call methods. The `runar` package's intrinsics (`check_sig`, `check_preimage`, `verify_wots`, etc.) return `True` for business-logic testing while real hashes (`hash160`, `sha256`, `ripemd160`) are computed for real.

```python
import pytest
from runar import hash160, mock_sig, mock_pub_key

# Import a contract module with the standard naming
from examples.python.p2pkh.P2PKH_runar_py import P2PKH  # or use importlib

def test_unlock_succeeds():
    pub_key = mock_pub_key()
    contract = P2PKH(pub_key_hash=hash160(pub_key))
    contract.unlock(mock_sig(), pub_key)  # no exception = success

def test_unlock_with_wrong_pubkey_fails():
    pub_key = mock_pub_key()
    wrong_pub_key = b"\x03" + b"\x00" * 32
    contract = P2PKH(pub_key_hash=hash160(pub_key))
    with pytest.raises(AssertionError):
        contract.unlock(mock_sig(), wrong_pub_key)
```

Mock helpers ([runar/builtins.py](runar/builtins.py)):

| Function | Returns |
|----------|---------|
| `mock_sig()` | Deterministic 72-byte placeholder DER signature |
| `mock_pub_key()` | Deterministic 33-byte compressed pubkey placeholder |
| `mock_preimage()` | Deterministic 181-byte BIP-143 preimage placeholder |

Real hashes / verifiers (always real math): `hash160`, `hash256`, `sha256`, `ripemd160`, `verify_rabin_sig`, `verify_wots`, `verify_slh_dsa_sha2_*`, `verify_ecdsa_p256`, `verify_ecdsa_p384`, `ec_add`, `ec_mul`, `ec_mul_gen`, `bb_field_*`, `kb_field_*`, `bn254_field_*`, `merkle_root_*`, `blake3_compress`, `blake3_hash`, `sha256_compress`, `sha256_finalize`.

To dynamically load a contract by file path (the pattern `tests/conftest.py` uses):

```python
import importlib.util
from pathlib import Path

def load_contract(file_name: str):
    path = Path(__file__).parent / "examples" / file_name
    spec = importlib.util.spec_from_file_location(path.stem, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod
```

### 13b. Integration testing against a regtest node

Live integration tests use `RPCProvider` against a local BSV regtest node and `LocalSigner` (or `ExternalSigner`-wrapped `LocalSigner`) for real BIP-143 ECDSA signing.

```python
from runar.sdk import RPCProvider, RunarContract, DeployOptions
from runar.sdk.local_signer import LocalSigner

provider = RPCProvider.regtest("http://localhost:18332", "bitcoin", "bitcoin")

priv_key_hex = "0123456789abcdef" * 4
signer = LocalSigner(priv_key_hex)
# Fund signer.get_address() via the regtest RPC before continuing.

contract = RunarContract(counter_artifact, [0])
contract.connect(provider, signer)

deploy_txid, _ = contract.deploy(options=DeployOptions(satoshis=5_000))
contract.call("increment", [])
contract.call("increment", [])
assert contract.get_state()["count"] == 2
```

The reference end-to-end test is [`integration/python/test_counter.py`](../../integration/python/test_counter.py) — five cases covering increment, chain, increment-then-decrement, wrong-state-rejected, and decrement-from-zero-rejected.

### Cross-SDK byte identity

The Python SDK is part of a 7-language family (TypeScript, Go, Rust, Python, Java, Ruby, Zig). The conformance suite at [`conformance/sdk-output/`](../../conformance/sdk-output/) verifies that all SDKs produce byte-identical deployed locking scripts for the same artifact and constructor args. The Counter fixture is at [`conformance/sdk-output/tests/stateful-counter/`](../../conformance/sdk-output/tests/stateful-counter/).

---

## Provider configuration

### MockProvider

In-memory provider for tests and local development. Holds UTXOs, transactions, and broadcasted txs in dicts.

```python
from runar.sdk import MockProvider, Utxo

provider = MockProvider("testnet")  # or "mainnet"
provider.add_utxo("address1", Utxo(txid="aa" * 32, output_index=0, satoshis=100_000, script="..."))
provider.set_fee_rate(50)  # default 100 sat/KB

txid = provider.broadcast(raw_tx_hex)
broadcasted = provider.get_broadcasted_txs()
```

Source: [runar/sdk/provider.py:51](runar/sdk/provider.py).

### RPCProvider

JSON-RPC provider for any Bitcoin-protocol node. Stdlib-only HTTP via `urllib.request`.

```python
from runar.sdk import RPCProvider

provider = RPCProvider("http://localhost:18332", "rpc_user", "rpc_pass", network="testnet")

# Convenience constructor for regtest with auto-mining after every broadcast:
provider = RPCProvider.regtest("http://localhost:18332", "bitcoin", "bitcoin")
```

Source: [runar/sdk/rpc_provider.py](runar/sdk/rpc_provider.py).

### WhatsOnChainProvider

REST API backed by [whatsonchain.com](https://whatsonchain.com/).

```python
from runar.sdk import WhatsOnChainProvider

provider = WhatsOnChainProvider(network="mainnet")  # or "testnet"
```

Source: [runar/sdk/woc_provider.py](runar/sdk/woc_provider.py). `get_utxos(address)` does not return locking scripts (WoC limitation); `get_contract_utxo(script_hash)` does work.

### GorillaPoolProvider

REST API backed by [gorillapool.io](https://gorillapool.io/) — adds 1sat ordinals, BSV-20, and BSV-21 token endpoints.

```python
from runar.sdk import GorillaPoolProvider

provider = GorillaPoolProvider(network="mainnet")

# Standard provider methods plus:
inscriptions = provider.get_inscriptions_by_address(address)
balance = provider.get_bsv20_balance(address, "RUNAR")
token_utxos = provider.get_bsv21_utxos(address, token_id="<txid>_<vout>")
```

Source: [runar/sdk/gorillapool.py](runar/sdk/gorillapool.py).

### WalletProvider

BRC-100 wallet integration. See Section 9c above. Source: [runar/sdk/wallet.py](runar/sdk/wallet.py).

---

## Full API reference

All exports are in alphabetical order. Type hints reflect the signatures in the source.

### `runar` (root package)

#### `assert_(condition: bool) -> None`

Rúnar assertion. Raises `AssertionError("runar: assertion failed")` if `condition` is false.

```python
from runar import assert_
assert_(1 + 1 == 2)
```

#### `bb_ext4_inv0(...) / bb_ext4_inv1 / bb_ext4_inv2 / bb_ext4_inv3`

BabyBear quartic extension field (x^4 - 11) inverse, returning each output coefficient. Used by SP1 proof verification.

#### `bb_ext4_mul0(...) / bb_ext4_mul1 / bb_ext4_mul2 / bb_ext4_mul3`

BabyBear quartic extension field multiplication, returning each output coefficient.

#### `bb_field_add(a: int, b: int) -> int` / `bb_field_sub` / `bb_field_mul` / `bb_field_inv`

BabyBear (p = 2^31 - 2^27 + 1) field arithmetic.

#### `blake3_compress(state, block) -> tuple` / `blake3_hash(data: bytes) -> bytes`

BLAKE3 single-block compression and full-message hash.

#### `bool_cast(x: int) -> bool`

Truthiness coercion of a bigint.

#### `bn254_field_add(a, b) / _sub / _mul / _inv / _neg`

BN254 base field arithmetic, used for pairing-based verification.

#### `cat(a: bytes, b: bytes) -> bytes`

Concatenate two byte strings.

#### `check_multi_sig(sigs: list, pub_keys: list) -> bool`

Bitcoin-style multi-signature check. Verifies each `sig` against the next `pub_key` in order. Returns `True` if every signature matches.

#### `check_preimage(preimage: bytes) -> bool`

Always returns `True` for off-chain testing. The compiler emits `OP_CHECKSIGVERIFY`-style on-chain logic.

#### `check_sig(sig, pub_key) -> bool`

Verifies a real ECDSA signature over the fixed `TEST_MESSAGE_DIGEST`. Accepts both raw `bytes` and hex-encoded `str`.

#### `clamp(x: int, lo: int, hi: int) -> int`

Clamp `x` to `[lo, hi]`.

#### `compile_check(source_or_path: str, file_name: str | None = None) -> None`

Run the Rúnar frontend (parse → validate → typecheck) on a contract. Path or source string. Raises `RuntimeError` on any error or if `runar_compiler` is not installed.

#### `divmod_(a: int, b: int) -> tuple[int, int]`

Quotient/remainder pair, mirroring `OP_DIV`/`OP_MOD`.

#### `ec_add(p: bytes, q: bytes) -> bytes`

secp256k1 point addition. Inputs and outputs are 64-byte `Point` (x[32] || y[32], big-endian, no prefix).

#### `ec_encode_compressed(p: bytes) -> bytes`

Encode a 64-byte `Point` as a 33-byte compressed public key (`02`/`03` prefix + x).

#### `ec_make_point(x: int, y: int) -> bytes`

Construct a 64-byte `Point` from two integers.

#### `ec_mod_reduce(x: int) -> int`

Reduce an integer modulo `EC_N` (the secp256k1 curve order).

#### `ec_mul(p: bytes, k: int) -> bytes`

secp256k1 scalar multiplication.

#### `ec_mul_gen(k: int) -> bytes`

`k * G` — generator multiplication.

#### `ec_negate(p: bytes) -> bytes`

Negate the y-coordinate.

#### `ec_on_curve(p: bytes) -> bool`

True iff `p` lies on secp256k1.

#### `ec_point_x(p: bytes) -> int` / `ec_point_y(p: bytes) -> int`

Extract coordinate as integer.

#### `EC_G: bytes` / `EC_N: int` / `EC_P: int`

secp256k1 generator (64-byte Point), curve order, and field prime.

#### `ecdsa_sign(priv_key: int, message_hash: bytes) -> bytes` / `ecdsa_verify(...)`

Pure-Python secp256k1 ECDSA. Used by the bundled fallback in `LocalSigner`.

#### `extract_amount(preimage: bytes) -> int` / `extract_locktime` / `extract_output_hash` / `extract_version` / `extract_sequence` / `extract_hash_prevouts` / `extract_outpoint`

BIP-143 preimage field extractors — pull individual fields out of a `SigHashPreimage`.

#### `gcd(a: int, b: int) -> int`

Greatest common divisor.

#### `hash160(data: bytes) -> bytes` / `hash256` / `sha256` / `ripemd160`

Real hashes via `hashlib`. Accept both `bytes` and hex `str`.

#### `int_to_str(n: int) -> bytes`

Encode an integer as Bitcoin Script number bytes.

#### `kb_ext4_*` / `kb_field_*`

KoalaBear (p = 2^31 - 2^24 + 1) field arithmetic and quartic extension (x^4 - 3).

#### `len_(data: bytes) -> int`

Length in bytes.

#### `log2(n: int) -> int`

Integer log base 2.

#### `merkle_root_sha256(leaves: list[bytes], path: list[bytes]) -> bytes` / `merkle_root_hash256`

Merkle root computation matching the on-chain implementation.

#### `mock_pub_key() -> bytes` / `mock_sig() -> bytes` / `mock_preimage() -> bytes`

Deterministic placeholders for off-chain testing.

#### `mul_div(a: int, b: int, c: int) -> int`

`(a * b) // c` without intermediate overflow concerns (Python ints are arbitrary precision, so this is just the formula).

#### `num2bin(value: int, length: int) -> bytes` / `bin2num(data: bytes) -> int`

NUM2BIN / BIN2NUM equivalents — fixed-width LE sign-magnitude bytes.

#### `p256_keygen() -> P256KeyPair` / `p256_sign(key_pair, message) -> bytes`

Real NIST P-256 key generation and signing.

#### `p384_keygen() -> P384KeyPair` / `p384_sign(key_pair, message) -> bytes`

Real NIST P-384 key generation and signing.

#### `percent_of(value: int, percent: int) -> int`

`(value * percent) // 100`.

#### `pow_(base: int, exp: int) -> int`

Bounded exponentiation.

#### `pub_key_from_priv_key(priv_key: int) -> bytes`

Derive a 33-byte compressed pubkey via `priv_key * G` on secp256k1.

#### `public(func: F) -> F`

Decorator marking a contract method as a public spending entry point. Source: [runar/decorators.py](runar/decorators.py).

#### `reverse_bytes(data: bytes) -> bytes`

Reverse byte order.

#### `safediv(a: int, b: int) -> int` / `safemod(a: int, b: int) -> int`

Integer division/mod with explicit zero-check semantics.

#### `sign(x: int) -> int`

`-1`, `0`, or `1`.

#### `sign_test_message(priv_key: int) -> bytes`

Sign the fixed `TEST_MESSAGE` for fixture generation.

#### `slh_keygen(param_set: str) -> SLHKeyPair` / `slh_verify(pub_key, message, signature, param_set) -> bool`

Real SLH-DSA (FIPS 205) key generation and verification.

#### `SmartContract`

Base class for stateless contracts. Source: [runar/base.py](runar/base.py).

#### `sqrt(n: int) -> int`

Integer square root.

#### `StatefulSmartContract`

Base class for stateful contracts. Provides `add_output(satoshis, *values)`, `add_raw_output(satoshis, script_bytes)`, `add_data_output(satoshis, script_bytes)`, and `reset_outputs()`. Source: [runar/base.py](runar/base.py).

#### `substr(data: bytes, start: int, length: int) -> bytes`

Substring (slice) of a byte string.

#### `verify_ecdsa_p256(msg, sig, pubkey) -> bool` / `verify_ecdsa_p384`

Real NIST P-256 / P-384 ECDSA verification. `sig` is `r[32] || s[32]` (or `[48]` for P-384), `pubkey` is the compressed encoding.

#### `verify_rabin_sig(msg, sig, padding, pub_key) -> bool`

Rabin signature verification: `(sig**2 + padding) mod n == SHA256(msg) mod n`.

#### `verify_slh_dsa_sha2_128s` / `_128f` / `_192s` / `_192f` / `_256s` / `_256f`

Real FIPS 205 SLH-DSA verification, six parameter sets.

#### `verify_wots(msg, sig, pub_key) -> bool`

Real WOTS+ one-time signature verification.

#### `within(x: int, lo: int, hi: int) -> bool`

`lo <= x < hi`.

#### `wots_keygen() -> WOTSKeyPair` / `wots_sign(key_pair, message) -> bytes`

Real WOTS+ key generation and signing.

#### Test key fixtures

`TestKeyPair`, `TEST_KEYS`, `ALICE`, `BOB`, `CHARLIE`, `DAVE`, `EVE`, `FRANK`, `GRACE`, `HEIDI`, `IVAN`, `JUDY` — deterministic key fixtures shared across all 7 SDKs. Source: [runar/test_keys.py](runar/test_keys.py).

#### Type aliases

`Bigint`, `Int`, `ByteString`, `PubKey`, `Sig`, `Addr`, `Sha256`, `Sha256Digest`, `Ripemd160`, `SigHashPreimage`, `RabinSig`, `RabinPubKey`, `Point`, `P256Point`, `P384Point`, `Readonly[T]`, `FixedArray`. Source: [runar/types.py](runar/types.py).

---

### `runar.sdk`

#### `Abi`

Container for `constructor_params: list[AbiParam]` and `methods: list[AbiMethod]`. Part of `RunarArtifact`.

#### `AbiMethod`

```python
@dataclass
class AbiMethod:
    name: str
    params: list[AbiParam]
    is_public: bool = True
    is_terminal: bool | None = None
```

#### `AbiParam`

```python
@dataclass
class AbiParam:
    name: str
    type: str
    fixed_array: dict | None = None  # populated for FixedArray<T, N> params
```

#### `bsv20_deploy(tick: str, max_supply: str, lim: str | None = None, dec: str | None = None) -> Inscription`

Build a BSV-20 v1 deploy inscription envelope.

#### `bsv20_mint(tick: str, amt: str) -> Inscription`

#### `bsv20_transfer(tick: str, amt: str) -> Inscription`

#### `bsv21_deploy_mint(amt: str, dec: str | None = None, sym: str | None = None, icon: str | None = None) -> Inscription`

Build a BSV-21 v2 deploy+mint inscription envelope.

#### `bsv21_transfer(token_id: str, amt: str) -> Inscription`

`token_id` format: `<txid>_<vout>`.

#### `build_call_transaction(current_utxo, unlocking_script, new_locking_script, new_satoshis, change_address, change_script='', additional_utxos=None, fee_rate=100, contract_outputs=None, additional_contract_inputs=None, data_outputs=None) -> tuple[str, int, int]`

Low-level transaction builder for method calls. Returns `(tx_hex, input_count, change_amount)`. Source: [runar/sdk/calling.py:11](runar/sdk/calling.py).

#### `build_deploy_transaction(locking_script, utxos, satoshis, change_address, change_script='', fee_rate=100) -> tuple[str, int]`

Low-level deploy transaction builder. Returns `(tx_hex, input_count)`. Raises `ValueError` if UTXOs are insufficient. Source: [runar/sdk/deployment.py:12](runar/sdk/deployment.py).

#### `build_inscription_envelope(content_type: str, data: str) -> str`

Build a 1sat ordinals envelope: `OP_FALSE OP_IF "ord" OP_1 PUSH(content_type) OP_0 PUSH(data) OP_ENDIF`.

#### `build_p2pkh_script(address_or_pub_key: str) -> str`

Build a standard P2PKH locking script. Accepts a Base58Check address, a 40-char hex pubkey hash, or a 66/130-char hex public key.

#### `CallOptions`

See Section 9a. Source: [runar/sdk/types.py:204](runar/sdk/types.py).

#### `CodeSepIndexSlot`

```python
@dataclass
class CodeSepIndexSlot:
    byte_offset: int
    code_sep_index: int
```

Where a `codeSeparatorIndex` placeholder lives in the script template. Substituted at deployment.

#### `compute_new_state(anf, method_name, current_state, args, constructor_args=None) -> dict`

Run the artifact's ANF interpreter to compute the new state after a method call. Used internally by `RunarContract.call`. Source: [runar/sdk/anf_interpreter.py:25](runar/sdk/anf_interpreter.py).

#### `compute_op_push_tx(tx_hex, input_index, subscript, satoshis, code_separator_index=-1) -> tuple[str, str]`

Compute the OP_PUSH_TX DER signature (with sighash flag) and BIP-143 preimage. Uses k=1 for ECDSA — the on-chain script verifies against the generator point. Source: [runar/sdk/oppushtx.py:27](runar/sdk/oppushtx.py).

#### `ConstructorSlot`

```python
@dataclass
class ConstructorSlot:
    param_index: int
    byte_offset: int
```

Where a constructor argument placeholder lives in the script template.

#### `DeployOptions`

See Section 8. Source: [runar/sdk/types.py:179](runar/sdk/types.py).

#### `deserialize_state(fields: list[StateField], script_hex: str) -> dict`

Decode raw state bytes back into a `dict` keyed by field name.

#### `EnvelopeBounds`

```python
@dataclass
class EnvelopeBounds:
    start_hex: int
    end_hex: int
```

Hex-char offsets bounding an inscription envelope within a script.

#### `estimate_call_fee(locking_script_byte_len, unlocking_script_byte_len, num_funding_inputs, fee_rate=100) -> int`

#### `estimate_deploy_fee(num_inputs, locking_script_byte_len, fee_rate=100) -> int`

#### `ExternalSigner`

Callback-based `Signer`. Use this when the actual signing happens in another process (hardware wallet, MPC service, browser extension).

```python
def my_sign(tx_hex, input_index, subscript, satoshis, sighash_type):
    return remote.sign(tx_hex, input_index, subscript, satoshis, sighash_type)

signer = ExternalSigner(pub_key_hex, address, my_sign)
```

Source: [runar/sdk/signer.py:62](runar/sdk/signer.py).

#### `extract_constructor_args(artifact: RunarArtifact, script_hex: str) -> dict`

Extract constructor argument values from a compiled on-chain script.

#### `find_inscription_envelope(script_hex: str) -> EnvelopeBounds | None`

Locate an inscription envelope within a script. Returns `None` if no envelope is found.

#### `find_last_op_return(script_hex: str) -> int`

Find the last OP_RETURN opcode boundary in a script. Returns the hex-char offset, or `-1` if not found.

#### `generate_python(artifact: RunarArtifact) -> str`

Generate a typed Python wrapper class for a compiled artifact. See Section 12.

#### `GorillaPoolProvider`

REST provider plus 1sat ordinals + BSV-20/21 endpoints. See Section 14. Source: [runar/sdk/gorillapool.py](runar/sdk/gorillapool.py).

```python
class GorillaPoolProvider(Provider):
    def __init__(self, network: str = 'mainnet'): ...
    # Standard Provider methods, plus:
    def get_inscriptions_by_address(self, address: str) -> list[dict]: ...
    def get_inscription(self, inscription_id: str) -> dict: ...
    def get_bsv20_balance(self, address: str, tick: str) -> str: ...
    def get_bsv20_utxos(self, address: str, tick: str) -> list[Utxo]: ...
    def get_bsv21_balance(self, address: str, token_id: str) -> str: ...
    def get_bsv21_utxos(self, address: str, token_id: str) -> list[Utxo]: ...
```

#### `Inscription`

```python
@dataclass
class Inscription:
    content_type: str  # MIME type, e.g. "image/png"
    data: str          # hex-encoded payload
```

#### `insert_unlocking_script(tx_hex: str, input_index: int, unlock_script: str) -> str`

Replace the scriptSig of input `input_index` with `unlock_script`, returning the new tx hex. Used internally during multi-pass signing.

#### `LocalSigner`

```python
class LocalSigner(Signer):
    def __init__(self, key_hex: str): ...
```

Holds a 64-char hex private key in memory. Uses `bsv-sdk` if installed; otherwise falls back to the bundled pure-Python ECDSA in `runar.ecdsa`. Both backends implement BIP-143 sighash + low-S deterministic signing. Source: [runar/sdk/local_signer.py:52](runar/sdk/local_signer.py).

```python
signer = LocalSigner("01" * 32)
print(signer.get_public_key())   # 66-char hex compressed pubkey
print(signer.get_address())      # Base58Check P2PKH address
sig_hex = signer.sign(tx_hex, input_index=0, subscript=script_hex, satoshis=10_000)
```

Raises `RuntimeError` only if neither backend is usable.

#### `matches_artifact(artifact: RunarArtifact, script_hex: str) -> bool`

True iff the on-chain script was produced from the given artifact (regardless of which constructor args were used).

#### `MockProvider`

```python
class MockProvider(Provider):
    def __init__(self, network: str = 'testnet'): ...
    def add_transaction(self, tx: TransactionData) -> None: ...
    def add_utxo(self, address: str, utxo: Utxo) -> None: ...
    def add_contract_utxo(self, script_hash: str, utxo: Utxo) -> None: ...
    def get_broadcasted_txs(self) -> list[str]: ...
    def set_fee_rate(self, rate: int) -> None: ...
```

In-memory provider for tests. Returns deterministic 64-char hex txids derived from a counter and the broadcast bytes. Source: [runar/sdk/provider.py:51](runar/sdk/provider.py).

#### `MockSigner`

```python
class MockSigner(Signer):
    def __init__(self, pub_key_hex: str = '', address: str = ''): ...
```

Returns a placeholder 72-byte signature `30 + (00 * 70) + 41`. Suitable only for tests where signature *content* doesn't matter (e.g., tests that exercise tx structure or fee math, not real verification).

#### `OutputSpec`

```python
@dataclass
class OutputSpec:
    satoshis: int
    state: dict
```

One continuation UTXO for multi-output stateful methods. Pass via `CallOptions(outputs=[...])`.

#### `parse_inscription_envelope(script_hex: str) -> Inscription | None`

Parse the first inscription envelope found in a script. Returns `None` if none.

#### `PreparedCall`

Output of `RunarContract.prepare_call`. Public fields callers use:

| Field | Type | Meaning |
|-------|------|---------|
| `sighash` | `str` | 64-char hex BIP-143 sighash for external signers |
| `preimage` | `str` | Full BIP-143 preimage hex |
| `op_push_tx_sig` | `str` | OP_PUSH_TX DER signature hex (empty if not needed) |
| `tx_hex` | `str` | The built tx (P2PKH funding signed, primary input has placeholder Sigs) |
| `sig_indices` | `list[int]` | User-arg positions that need external signatures |

Internal fields (consumed by `finalize_call`): `method_name`, `resolved_args`, `method_selector_hex`, `is_stateful`, `is_terminal`, `needs_op_push_tx`, `method_needs_change`, `change_pkh_hex`, `change_amount`, `method_needs_new_amount`, `new_amount`, `preimage_index`, `contract_utxo`, `new_locking_script`, `new_satoshis`, `has_multi_output`, `contract_outputs`, `code_sep_idx`.

Source: [runar/sdk/types.py:223](runar/sdk/types.py).

#### `Provider`

ABC for blockchain access. Required methods:

```python
class Provider(ABC):
    def get_transaction(self, txid: str) -> TransactionData: ...
    def broadcast(self, tx) -> str: ...
    def get_utxos(self, address: str) -> list[Utxo]: ...
    def get_contract_utxo(self, script_hash: str) -> Utxo | None: ...
    def get_network(self) -> str: ...
    def get_fee_rate(self) -> int: ...
    def get_raw_transaction(self, txid: str) -> str: ...
```

`broadcast` accepts either a hex string or anything with a `.hex()` method.

#### `RPCProvider`

```python
class RPCProvider(Provider):
    def __init__(self, url: str, user: str, password: str, *, auto_mine: bool = False, network: str = 'testnet'): ...

    @classmethod
    def regtest(cls, url: str, user: str, password: str) -> 'RPCProvider':
        """auto_mine=True, network='regtest'."""
```

JSON-RPC over `urllib.request`. Returns `RuntimeError` on RPC errors. Source: [runar/sdk/rpc_provider.py:18](runar/sdk/rpc_provider.py).

#### `RunarArtifact`

```python
@dataclass
class RunarArtifact:
    version: str = ''
    compiler_version: str = ''
    contract_name: str = ''
    abi: Abi = field(default_factory=Abi)
    script: str = ''
    asm: str = ''
    state_fields: list[StateField] = field(default_factory=list)
    constructor_slots: list[ConstructorSlot] = field(default_factory=list)
    code_sep_index_slots: list[CodeSepIndexSlot] = field(default_factory=list)
    build_timestamp: str = ''
    code_separator_index: int | None = None
    code_separator_indices: list[int] | None = None
    anf: dict | None = None

    @staticmethod
    def from_dict(d: dict) -> 'RunarArtifact': ...
```

The compiled output of a Rúnar compiler. Use `RunarArtifact.from_dict(json.load(f))` to load from JSON.

#### `RunarContract`

```python
class RunarContract:
    def __init__(self, artifact: RunarArtifact, constructor_args: list): ...

    def connect(self, provider: Provider, signer: Signer) -> None: ...
    def get_utxo(self) -> Utxo | None: ...
    def get_state(self) -> dict: ...
    def set_state(self, new_state: dict) -> None: ...
    def get_locking_script(self) -> str: ...
    def build_unlocking_script(self, method_name: str, args: list) -> str: ...

    def deploy(
        self,
        provider: Provider | None = None,
        signer: Signer | None = None,
        options: DeployOptions | None = None,
    ) -> tuple[str, TransactionData]: ...

    def deploy_with_wallet(
        self, satoshis: int = 1, description: str = '',
    ) -> tuple[str, int]: ...

    def call(
        self,
        method_name: str,
        args: list | None = None,
        provider: Provider | None = None,
        signer: Signer | None = None,
        options: CallOptions | None = None,
    ) -> tuple[str, TransactionData]: ...

    def prepare_call(
        self,
        method_name: str,
        args: list | None = None,
        provider: Provider | None = None,
        signer: Signer | None = None,
        options: CallOptions | None = None,
    ) -> PreparedCall: ...

    def finalize_call(
        self,
        prepared: PreparedCall,
        signatures: dict[int, str],
        provider: Provider | None = None,
    ) -> tuple[str, TransactionData]: ...

    @classmethod
    def from_utxo(cls, artifact: RunarArtifact, utxo: Utxo) -> 'RunarContract': ...

    @staticmethod
    def from_txid(artifact: RunarArtifact, txid: str, output_index: int, provider: Provider) -> 'RunarContract': ...

    def with_inscription(self, inscription: Inscription) -> 'RunarContract': ...

    @property
    def inscription(self) -> Inscription | None: ...
```

Raises `ValueError` if constructor args don't match the artifact's ABI; `RuntimeError` if `deploy` / `call` is invoked without a provider/signer or before deployment. Source: [runar/sdk/contract.py:28](runar/sdk/contract.py).

#### `SdkValue`

`Union[int, bool, bytes, str]` — the value types accepted as contract method arguments.

#### `select_utxos(utxos, target_satoshis, locking_script_byte_len, fee_rate=100) -> list[Utxo]`

Largest-first UTXO selection.

#### `serialize_state(fields: list[StateField], values: dict) -> str`

Encode state values into raw hex bytes (NUM2BIN sign-magnitude format).

#### `Signer`

ABC for key management. Required methods:

```python
class Signer(ABC):
    def get_public_key(self) -> str: ...   # 66-char hex compressed
    def get_address(self) -> str: ...      # Base58Check or 40-char hex pubkey hash
    def sign(self, tx_hex: str, input_index: int, subscript: str, satoshis: int, sighash_type: int | None = None) -> str: ...
```

`sign` returns a DER-encoded signature with sighash flag byte appended, hex-encoded.

#### `StateField`

```python
@dataclass
class StateField:
    name: str
    type: str
    index: int
    initial_value: object = None
    fixed_array: dict | None = None
```

#### `strip_inscription_envelope(script_hex: str) -> str`

Remove the inscription envelope from a script, returning the bare script. Returns the input unchanged if no envelope is found.

#### `TerminalOutput`

```python
@dataclass
class TerminalOutput:
    script_hex: str
    satoshis: int
```

Exact-output spec for terminal-method calls (no continuation, no change).

#### `TokenWallet`

```python
class TokenWallet:
    def __init__(self, artifact: RunarArtifact, provider: Provider, signer: Signer): ...
    def get_balance(self) -> int: ...
    def transfer(self, recipient_addr: str, amount: int) -> str: ...
    def merge(self) -> str: ...
    def get_utxos(self) -> list[Utxo]: ...
```

Higher-level wrapper for fungible-token contracts. Assumes the artifact has a `transfer` method and a state field named `balance`, `supply`, or `amount`. Source: [runar/sdk/token_wallet.py:22](runar/sdk/token_wallet.py).

#### `Transaction`

Backward-compat alias for `TransactionData`.

#### `TransactionData`

```python
@dataclass
class TransactionData:
    txid: str
    version: int = 1
    inputs: list[TxInput] = field(default_factory=list)
    outputs: list[TxOutput] = field(default_factory=list)
    locktime: int = 0
    raw: str = ''
```

#### `TxInput`

```python
@dataclass
class TxInput:
    txid: str
    output_index: int
    script: str  # hex-encoded scriptSig
    sequence: int = 0xFFFFFFFF
```

#### `TxOutput`

```python
@dataclass
class TxOutput:
    satoshis: int
    script: str  # hex-encoded locking script
```

#### `Utxo`

```python
@dataclass
class Utxo:
    txid: str
    output_index: int
    satoshis: int
    script: str  # hex-encoded locking script
```

#### `WalletClient`

ABC for BRC-100 wallet integrations. Subclass and implement four methods:

```python
class WalletClient(ABC):
    def get_public_key(self, protocol_id: tuple, key_id: str) -> str: ...
    def create_signature(self, hash_to_sign: bytes, protocol_id: tuple, key_id: str) -> bytes: ...
    def create_action(self, description: str, outputs: list[dict]) -> dict: ...
    def list_outputs(self, basket: str, tags: list[str], limit: int = 100) -> list[dict]: ...
```

Source: [runar/sdk/wallet.py:29](runar/sdk/wallet.py).

#### `WalletProvider`

```python
class WalletProvider(Provider):
    def __init__(
        self,
        wallet: WalletClient,
        signer: Signer,
        basket: str,
        funding_tag: str = 'funding',
        arc_url: str = 'https://arc.gorillapool.io',
        overlay_url: str | None = None,
        network: str = 'mainnet',
        fee_rate: int = 100,
    ): ...

    def cache_tx(self, txid: str, raw_hex: str) -> None: ...
    def ensure_funding(self, min_satoshis: int) -> None: ...
```

`Provider` backed by a BRC-100 wallet for UTXO management, ARC for broadcast, and an optional overlay service for transaction lookups. Source: [runar/sdk/wallet.py:106](runar/sdk/wallet.py).

#### `WalletSigner`

```python
class WalletSigner(Signer):
    SIGHASH_ALL_FORKID: int = 0x41

    def __init__(self, wallet: WalletClient, protocol_id: tuple, key_id: str): ...
    def sign_hash(self, sighash_hex: str) -> str: ...
```

Computes BIP-143 sighash locally, then delegates ECDSA signing to the wallet. Use `sign_hash` directly with `PreparedCall.sighash` for the multi-signer flow. Source: [runar/sdk/wallet.py:303](runar/sdk/wallet.py).

#### `WhatsOnChainProvider`

```python
class WhatsOnChainProvider(Provider):
    def __init__(self, network: str = 'mainnet'): ...
```

WoC REST API. Source: [runar/sdk/woc_provider.py:17](runar/sdk/woc_provider.py).

---

## Error handling

The Python SDK uses standard library exceptions throughout. Catch what makes sense for your call site:

| Exception | When |
|-----------|------|
| `ValueError` | Constructor arg count mismatch; method args of wrong arity; `from_txid` output index out of range; invalid output spec; `build_deploy_transaction` insufficient funds; `LocalSigner` invalid hex key length; `insert_unlocking_script` input index out of range. |
| `RuntimeError` | `deploy`/`call`/`prepare_call`/`finalize_call` called without a provider, signer, or prior deployment; `MockProvider` lookup miss; provider HTTP/RPC errors; `compile_check` parse/validate/typecheck failures or missing `runar_compiler`; `LocalSigner` neither backend usable; `WalletProvider` ARC broadcast failures or overlay fetch failures. |
| `AssertionError` | `assert_(False)` in contract code; failed `assert` in contract code. |
| `TypeError` | `_as_bytes` argument is not `bytes` or hex `str`. |
| `ImportError` | Internal — bubbled up to `RuntimeError("runar_compiler package not available...")` by `compile_check`. |

```python
import pytest
from runar.sdk import RunarContract, MockProvider, MockSigner, DeployOptions

def test_deploy_without_funds_raises():
    artifact = ...  # any artifact
    contract = RunarContract(artifact, [])
    with pytest.raises(RuntimeError, match='no UTXOs'):
        contract.deploy(MockProvider('testnet'), MockSigner(), DeployOptions(satoshis=1))

def test_call_before_deploy_raises():
    artifact = ...
    contract = RunarContract(artifact, [])
    with pytest.raises(RuntimeError, match='not deployed'):
        contract.call('spend')

def test_wrong_constructor_arity_raises():
    with pytest.raises(ValueError, match='constructor args'):
        RunarContract(artifact_with_one_param, [])
```

---

## Troubleshooting / FAQ

**Q. Where do I get an artifact JSON?**

Run `runar compile MyContract.runar.py --out MyContract.artifact.json`, or call `runar_compiler.compile_from_source(...)` and serialize via `artifact_to_json`.

**Q. `compile_check` raises `RuntimeError("runar_compiler package not available...")`.**

Install the compiler: `pip install runar-compiler`, or from source: `cd compilers/python && pip install -e .`.

**Q. `LocalSigner.__init__` raises `RuntimeError: LocalSigner requires either the bsv-sdk package or the runar.ecdsa fallback`.**

Both signing backends failed to import. The fallback (`runar.ecdsa` + `runar.ec`) ships with this package, so this only happens if those modules themselves fail to import — usually a corrupted install. Reinstall: `pip install --force-reinstall runar`.

**Q. Why is signing slow?**

The pure-Python ECDSA fallback in `runar.ecdsa` is ~100x slower than the C-extension `bsv-sdk`. Install `pip install bsv-sdk` for production use; `LocalSigner` switches to it automatically on import.

**Q. `deploy()` raises `ValueError: insufficient funds`.**

Your provider's UTXOs at `signer.get_address()` total less than `satoshis + estimated_fee`. Either fund the address with more sats or lower `DeployOptions(satoshis=...)`.

**Q. `call()` raises `RuntimeError: contract is not deployed`.**

You're calling on a fresh `RunarContract` instance. Either call `deploy()` first or reconnect: `contract = RunarContract.from_txid(artifact, txid, 0, provider)` / `RunarContract.from_utxo(artifact, utxo)`.

**Q. My snake_case method name doesn't match the artifact's ABI.**

Python contract sources are converted to camelCase in the AST. Pass the camelCase form to `contract.call("releaseBySeller", [...])`. The SDK API on the Python side stays snake_case (`prepare_call`, `op_push_tx_sig`).

**Q. State doesn't update after `call()`.**

For stateless contracts (`SmartContract`) there is no state to update — `get_state()` returns `{}`. For stateful contracts, `call()` runs the ANF interpreter to compute the new state automatically; if you need to override (e.g., negative tests), pass `CallOptions(new_state={...})`.

**Q. The contract is rejected on-chain even though my off-chain test passed.**

Off-chain testing uses mock crypto (`check_sig` always True). On-chain, the script verifies real signatures. If your contract calls `check_sig`, the SDK auto-resolves `Sig` parameters to real signatures from the connected `Signer` — so this only happens if you passed a `MockSigner` to a real provider.

**Q. `WhatsOnChainProvider.get_utxos(address)` returns UTXOs with empty `script` fields.**

WoC's `address/<a>/unspent` endpoint doesn't include locking scripts. Use `get_contract_utxo(script_hash)` for contract UTXOs (which does include scripts), or fetch the locking script via `get_transaction(txid)` and read `outputs[output_index].script`.

**Q. How do I sign with a hardware wallet?**

Use `prepare_call(...)`, send `prepared.sighash` to the device for signing, then call `finalize_call(prepared, {idx: signature_hex})`. See Section 9b.

**Q. How do I use a BRC-100 browser-extension wallet?**

Subclass `WalletClient` to bridge to your wallet's API, then use `WalletProvider` + `WalletSigner`. See Section 9c.

---

## Versioning and stability

`runar` follows semantic versioning. The current version (see [pyproject.toml](pyproject.toml)) tracks the wider Rúnar release train — minor versions add features and may change ABI; patch versions are backward-compatible.

The compiled artifact JSON format (`RunarArtifact`) is part of the cross-SDK conformance contract and is stable across all 7 SDKs at any given version. See [conformance/sdk-output/](../../conformance/sdk-output/) for byte-identity proofs.

The `runar.sdk` API surface is considered stable; deprecations are signaled in the changelog one minor release before removal.

---

## Links

- Source: <https://github.com/icellan/runar>
- Compiler: <https://pypi.org/project/runar-compiler/>
- Cross-SDK conformance: [`conformance/sdk-output/`](../../conformance/sdk-output/)
- Counter quick-start contract: [`examples/python/stateful-counter/Counter.runar.py`](../../examples/python/stateful-counter/Counter.runar.py)
- Reference integration test: [`integration/python/test_counter.py`](../../integration/python/test_counter.py)
- Format guide: [`docs/formats/python.md`](../../docs/formats/python.md)
- Language spec: [`spec/`](../../spec/)
- BRC-100 wallet protocol: <https://brc.dev/100>
- BSV-20 / BSV-21 token spec: <https://docs.1satordinals.com/>
- BIP-143 (sighash): <https://github.com/bitcoin/bips/blob/master/bip-0143.mediawiki>
