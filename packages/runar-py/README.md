# runar-py

**Python runtime package for writing and testing Rúnar smart contracts.**

---

## Overview

The `runar` Python package provides types, base classes, mock crypto, real hashes, EC operations, and a deployment SDK for writing, testing, and deploying Rúnar smart contracts in Python.

Zero required dependencies. EC operations use pure Python int arithmetic with secp256k1 curve parameters. Real hash functions use Python's `hashlib` stdlib.

---

## Installation

```bash
pip install runar-lang
# or
pip install -e packages/runar-py   # from the repo root
```

Optional dependency for real EC (coincurve):
```bash
pip install runar-lang[crypto]
```

---

## Writing Contracts

Contracts are standard Python classes extending `SmartContract` (stateless) or `StatefulSmartContract` (stateful):

```python
from runar import SmartContract, Addr, Sig, PubKey, public, assert_, hash160, check_sig

class P2PKH(SmartContract):
    pub_key_hash: Addr

    def __init__(self, pub_key_hash: Addr):
        super().__init__(pub_key_hash)
        self.pub_key_hash = pub_key_hash

    @public
    def unlock(self, sig: Sig, pub_key: PubKey):
        assert_(hash160(pub_key) == self.pub_key_hash)
        assert_(check_sig(sig, pub_key))
```

Python contracts use snake_case identifiers which the compiler converts to camelCase in the AST (`pub_key_hash` → `pubKeyHash`, `check_sig` → `checkSig`).

---

## Testing Contracts

```python
import pytest
from runar import hash160, mock_sig, mock_pub_key
from conftest import load_contract

contract_mod = load_contract("P2PKH.runar.py")
P2PKH = contract_mod.P2PKH

def test_unlock():
    pk = mock_pub_key()
    c = P2PKH(pub_key_hash=hash160(pk))
    c.unlock(mock_sig(), pk)

def test_unlock_wrong_key():
    pk = mock_pub_key()
    wrong_pk = b'\x03' + b'\x00' * 32
    c = P2PKH(pub_key_hash=hash160(pk))
    with pytest.raises(AssertionError):
        c.unlock(mock_sig(), wrong_pk)
```

Mock crypto functions (`check_sig`, `check_preimage`, `verify_wots`, etc.) always return `True` for business logic testing. Hash functions (`hash160`, `sha256`, etc.) use real `hashlib` implementations.

---

## Compile Check

Verify that a contract is valid Rúnar that will compile to Bitcoin Script:

```python
from runar import compile_check

compile_check("P2PKH.runar.py")  # raises on error
```

Runs the contract through the Rúnar frontend (parse → validate → typecheck).

---

## Types

| Python Type | Rúnar AST Type |
|-------------|---------------|
| `int` / `Bigint` | `bigint` |
| `bool` | `boolean` |
| `bytes` / `ByteString` | `ByteString` |
| `PubKey` | `PubKey` |
| `Sig` | `Sig` |
| `Addr` | `Addr` |
| `Sha256` | `Sha256` |
| `Ripemd160` | `Ripemd160` |
| `SigHashPreimage` | `SigHashPreimage` |
| `RabinSig` | `RabinSig` |
| `RabinPubKey` | `RabinPubKey` |
| `Point` | `Point` |
| `Readonly[T]` | Marks property `readonly: true` |

---

## Built-in Functions

### Crypto
- `check_sig(sig, pub_key)` — Mock: always returns `True`
- `check_multi_sig(sigs, pub_keys)` — Mock: always returns `True`
- `check_preimage(preimage)` — Mock: always returns `True`
- `verify_rabin_sig(msg, sig, pub_key)` — Mock: always returns `True`

### Hashing (real implementations)
- `hash160(data)`, `hash256(data)`, `sha256(data)`, `ripemd160(data)`

### Byte manipulation
- `num2bin(value, length)`, `bin2num(data)`, `cat(a, b)`, `substr(data, start, length)`
- `reverse_bytes(data)`, `len_(data)`

### Math
- `abs`, `min`, `max`, `within`, `safediv`, `safemod`, `clamp`, `sign`
- `pow_`, `mul_div`, `percent_of`, `sqrt`, `gcd`, `divmod_`, `log2`, `bool_cast`

### EC (secp256k1)
- `ec_add(p, q)`, `ec_mul(p, k)`, `ec_mul_gen(k)`, `ec_negate(p)`
- `ec_on_curve(p)`, `ec_mod_reduce(x)`, `ec_encode_compressed(p)`
- `ec_make_point(x, y)`, `ec_point_x(p)`, `ec_point_y(p)`
- Constants: `EC_P`, `EC_N`, `EC_G`

### Post-Quantum
- `verify_wots(message, signature, pub_key)` — Mock: always returns `True`
- `verify_slh_dsa_sha2_128s`, `verify_slh_dsa_sha2_128f`, etc. — Mock: always return `True`
- `wots_keygen()`, `wots_sign(key_pair, message)` — Real WOTS+ key generation and signing
- `slh_keygen(param_set)`, `slh_verify(pub_key, message, signature, param_set)` — Real SLH-DSA

---

## Deployment SDK

The `runar.sdk` subpackage provides a deployment SDK equivalent to the TypeScript, Go, and Rust SDKs:

```python
from runar.sdk import RunarContract, MockProvider, MockSigner, DeployOptions

# Load a compiled artifact
contract = RunarContract(artifact, constructor_args)

# Connect provider and signer
provider = MockProvider()
signer = MockSigner()
contract.connect(provider, signer)

# Deploy
result = contract.deploy(DeployOptions(satoshis=10000))

# Call a method
result = contract.call("increment", [])
```

### SDK Exports

- `RunarContract` — Wraps a compiled artifact, manages state and UTXO tracking
- `MockProvider` — In-memory provider for testing
- `MockSigner` / `ExternalSigner` — Signer implementations
- `build_deploy_transaction`, `build_call_transaction` — Low-level transaction builders
- `serialize_state`, `deserialize_state` — State serialization

---

## Package Structure

```
runar/
  __init__.py          # Public API exports
  types.py             # Type aliases (Bigint, ByteString, PubKey, etc.)
  base.py              # SmartContract, StatefulSmartContract base classes
  builtins.py          # Built-in functions (crypto mocks, real hashes, math)
  decorators.py        # @public decorator
  ec.py                # Pure Python secp256k1 EC operations
  wots.py              # WOTS+ key generation and signing
  slhdsa_impl.py       # SLH-DSA (FIPS 205) implementation
  compile_check.py     # Contract validation via the Python compiler
  sdk/                 # Deployment SDK (RunarContract, providers, signers)
```
