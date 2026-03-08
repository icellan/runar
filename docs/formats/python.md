# Python Contract Format

**Status:** Experimental
**File extension:** `.runar.py`
**Supported compilers:** TypeScript, Go, Rust (all three)

---

## Overview

The Python format lets you write Runar contracts as Python classes extending `SmartContract` or `StatefulSmartContract`. Contracts use standard Python syntax with snake_case naming, `@public` decorators, and `Readonly[T]` type annotations.

All three compilers (TypeScript, Go, Rust) support `.runar.py` parsing, so Python-format contracts produce identical Bitcoin Script across all compilers.

---

## Syntax

### Imports

```python
from runar import SmartContract, Addr, Sig, PubKey, public, assert_, hash160, check_sig
```

The `from runar import ...` line is consumed by the parser but does not affect compilation. All Runar types and built-in functions are available regardless of what is imported.

### Class Declaration

```python
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

- Extend `SmartContract` (stateless) or `StatefulSmartContract` (stateful)
- One contract class per file
- Constructor must call `super().__init__(...)` as the first statement

### Properties

```python
class Auction(StatefulSmartContract):
    auctioneer: Readonly[PubKey]      # immutable
    highest_bidder: PubKey             # mutable (stateful)
    highest_bid: Bigint                # mutable (stateful)
    deadline: Readonly[Bigint]         # immutable
```

- In `SmartContract`, all properties are automatically readonly
- In `StatefulSmartContract`, wrap readonly properties with `Readonly[T]`
- Properties without `Readonly` are mutable state fields

### Property Initializers

Properties can have default values using `= value` syntax after the type annotation:

```python
class GameBoard(StatefulSmartContract):
    count: Bigint = 0                    # mutable with default
    active: Readonly[bool] = True        # readonly with default
    owner: Readonly[PubKey]              # no default — required in constructor
```

Properties with initializers are excluded from the auto-generated constructor. Only properties without defaults need to be passed as constructor arguments. Initializers must be literal values (`0`, `True`, `False`, `b'\xde\xad'`).

### Method Visibility

| Python syntax | Runar visibility |
|--------------|-----------------|
| `@public` decorator before `def` | `public` (spending entry point) |
| No decorator (or `_` prefix convention) | `private` (inlined helper) |

```python
@public
def unlock(self, sig: Sig, pub_key: PubKey):
    ...

def _compute_threshold(self, a: Bigint, b: Bigint) -> Bigint:
    return a * b + 1
```

### Name Conversion

All Python snake_case identifiers are converted to camelCase in the AST:

| Python | AST |
|--------|-----|
| `pub_key_hash` | `pubKeyHash` |
| `highest_bid` | `highestBid` |
| `check_sig` | `checkSig` |
| `extract_locktime` | `extractLocktime` |
| `ec_mul_gen` | `ecMulGen` |

Special cases:
- `__init__` becomes the constructor
- `self.prop` becomes `this.prop`
- `assert_` maps to `assert` (trailing underscore stripped)
- `verify_wots` maps to `verifyWOTS` (not `verifyWots`)
- All SLH-DSA variants have explicit mappings (e.g., `verify_slh_dsa_sha2_128s` -> `verifySLHDSA_SHA2_128s`)

---

## Type Mappings

| Python Type | Runar AST Type |
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

## Operators

| Python | AST / Bitcoin Script |
|--------|---------------------|
| `==` / `!=` | `===` / `!==` (strict equality) |
| `//` | `/` (integer division, OP_DIV) |
| `**` | `pow()` call |
| `and` / `or` / `not` | `&&` / `\|\|` / `!` |
| `<<` / `>>` | `OP_LSHIFT` / `OP_RSHIFT` |
| `x if cond else y` | ternary expression |

---

## Assertions

Both function-call and statement forms are supported:

```python
assert_(check_sig(sig, pub_key))    # function form
assert check_sig(sig, pub_key)      # statement form (keyword)
```

Both compile to the same AST: `CallExpr { callee: "assert", args: [...] }`.

---

## Loops

Only bounded `for i in range(...)` loops are supported:

```python
for i in range(5):           # i = 0, 1, 2, 3, 4
    ...

for i in range(a, b):        # i = a, a+1, ..., b-1
    ...
```

---

## Byte Literals

```python
data = b'\xde\xad\xbe\xef'           # hex byte string
data = bytes.fromhex("deadbeef")      # equivalent
```

---

## Examples

### Stateless Contract (P2PKH)

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

### Stateful Contract (Counter)

```python
from runar import StatefulSmartContract, Bigint, public, assert_

class Counter(StatefulSmartContract):
    count: Bigint

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

### EC Operations (Convergence Proof)

```python
from runar import (
    SmartContract, Point, Bigint, public, assert_,
    ec_add, ec_negate, ec_mul_gen, ec_point_x, ec_point_y, ec_on_curve,
)

class ConvergenceProof(SmartContract):
    r_a: Point
    r_b: Point

    def __init__(self, r_a: Point, r_b: Point):
        super().__init__(r_a, r_b)
        self.r_a = r_a
        self.r_b = r_b

    @public
    def prove_convergence(self, delta_o: Bigint):
        assert_(ec_on_curve(self.r_a))
        assert_(ec_on_curve(self.r_b))
        diff = ec_add(self.r_a, ec_negate(self.r_b))
        expected = ec_mul_gen(delta_o)
        assert_(ec_point_x(diff) == ec_point_x(expected))
        assert_(ec_point_y(diff) == ec_point_y(expected))
```

---

## Testing Python Contracts

Python contracts can be tested natively using pytest with the `runar` package:

```python
import pytest
from runar import hash160, mock_sig, mock_pub_key

# Import the contract file
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

Mock crypto functions (`check_sig`, `check_preimage`, `verify_wots`, etc.) always return `True` for business logic testing. Hash functions (`hash160`, `sha256`, etc.) use real hashlib implementations.

---

## Runtime Package

The `runar` Python package (`packages/runar-py/`) provides:

- **Types**: `Bigint`, `ByteString`, `PubKey`, `Sig`, `Addr`, `Point`, `Readonly[T]`, etc.
- **Base classes**: `SmartContract`, `StatefulSmartContract`
- **Decorators**: `@public`
- **Mock crypto**: `check_sig`, `check_preimage`, `verify_wots`, `verify_slh_dsa_*` (always return True)
- **Real hashes**: `hash160`, `hash256`, `sha256`, `ripemd160` (via hashlib)
- **Real EC**: `ec_add`, `ec_mul`, `ec_mul_gen`, `ec_negate`, `ec_on_curve`, etc. (pure Python secp256k1)
- **Math**: `safediv`, `sqrt`, `gcd`, `clamp`, `sign`, `pow_`, `mul_div`, `percent_of`, `log2`
- **SDK**: `RunarContract`, `MockProvider`, `MockSigner`, `build_deploy_transaction`, etc.

Zero required dependencies. EC operations use pure Python int arithmetic with secp256k1 curve parameters.
