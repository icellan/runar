# Rust DSL Contract Format

**Status:** Experimental
**File extension:** `.runar.rs`
**Supported compilers:** Rust only

---

## Overview

The Rust DSL format lets you write Rúnar contracts as idiomatic Rust code using attribute macros. Contracts are Rust structs annotated with `#[runar::contract]`, and methods are defined in `impl` blocks annotated with `#[runar::methods(ContractName)]`. The Rust compiler parses these directly into the Rúnar AST.

Contracts are also valid Rust that can be compiled and tested natively with `cargo test`, using the `runar` mock crate which provides types and mock crypto functions.

This format is **only supported by the Rust compiler** (`compilers/rust`). The TypeScript and Go compilers cannot parse `.runar.rs` files.

---

## Syntax

### Struct Declaration

```rust
use runar::prelude::*;

#[runar::contract]
pub struct P2PKH {
    #[readonly]
    pub pub_key_hash: Addr,
}
```

- `#[runar::contract]` marks the struct as a Rúnar contract. The parser auto-detects whether the contract is stateless or stateful based on field annotations: if any field lacks `#[readonly]`, the contract is treated as `StatefulSmartContract`.
- `#[runar::stateful_contract]` can be used instead to explicitly mark a contract as stateful. This is equivalent to `#[runar::contract]` when any field lacks `#[readonly]`.
- `#[readonly]` marks immutable properties (baked into the locking script).
- Fields without `#[readonly]` are mutable (stateful).
- Fields should be `pub` so tests can construct the struct directly.
- All fields use snake_case; the Rúnar parser converts to camelCase for the AST.

### Property Initializers

Properties can have default values using a private `init()` method in the `impl` block. The `init()` method must take only `&mut self`, have no `#[public]` attribute, and contain only `self.property = value` assignments with literal values:

```rust
#[runar::contract]
pub struct GameBoard {
    pub count: Bigint,
    #[readonly]
    pub active: Bool,
    #[readonly]
    pub owner: PubKey,
}

#[runar::methods(GameBoard)]
impl GameBoard {
    fn init(&mut self) {
        self.count = 0;
        self.active = true;
    }

    #[public]
    pub fn increment(&mut self) {
        self.count += 1;
    }
}
```

Properties assigned in `init()` are excluded from the auto-generated constructor. Only properties without defaults (`owner` above) need to be passed as constructor arguments. The `init()` method is consumed by the parser and does not appear in the compiled output.

### Method Blocks

```rust
#[runar::methods(P2PKH)]
impl P2PKH {
    #[public]
    pub fn unlock(&self, sig: &Sig, pub_key: &PubKey) {
        assert!(hash160(pub_key) == self.pub_key_hash);
        assert!(check_sig(sig, pub_key));
    }
}
```

- `#[runar::methods(ContractName)]` links the impl block to the contract struct.
- `#[public]` marks spending entry points. Methods without `#[public]` are private helpers.
- The first parameter is `&self` (stateless) or `&mut self` (stateful).
- Byte-type parameters use references (`&Sig`, `&PubKey`) to avoid ownership issues.

### assert!() and assert_eq!()

```rust
assert!(condition);
assert_eq!(a, b);     // equivalent to assert!(a == b)
```

Maps to `assert(expr)` and `assert(a === b)` in the AST.

### Property Access

```rust
self.pub_key_hash     // readonly property
self.count            // mutable property
```

The parser converts snake_case to camelCase.

### State Mutation

```rust
self.count += 1;       // increment
self.count -= 1;       // decrement
self.count = new_val;  // assignment
```

`+= 1` and `-= 1` emit `IncrementExpr`/`DecrementExpr` nodes.

### Variable Declarations

```rust
let msg = num2bin(&price, 8);     // immutable binding (const)
let mut total = 0;                // mutable binding (let)
```

### add_output (Stateful Contracts)

For contracts that produce multiple outputs, define an output type and tracking field:

```rust
#[derive(Clone)]
pub struct FtOutput {
    pub satoshis: Bigint,
    pub owner: PubKey,
    pub balance: Bigint,
}

#[runar::contract]
pub struct FungibleToken {
    pub owner: PubKey,
    pub balance: Bigint,
    #[readonly]
    pub token_id: ByteString,
    pub outputs: Vec<FtOutput>,
}
```

Then define `add_output` as a method, using `.clone()` where the borrow checker requires it:

```rust
impl FungibleToken {
    pub fn add_output(&mut self, satoshis: Bigint, owner: PubKey, balance: Bigint) {
        self.outputs.push(FtOutput { satoshis, owner, balance });
    }

    pub fn transfer(&mut self, sig: &Sig, to: PubKey, amount: Bigint, output_satoshis: Bigint) {
        assert!(check_sig(sig, &self.owner));
        assert!(amount > 0);
        assert!(amount <= self.balance);
        let change_owner = self.owner.clone();
        let change_balance = self.balance - amount;
        self.add_output(output_satoshis, to, amount);
        self.add_output(output_satoshis, change_owner, change_balance);
    }
}
```

The Rúnar compiler parses `self.add_output(...)` as `this.addOutput(...)` regardless of the Rust implementation details.

### For Loops

```rust
for i in 0..10 {
    // body
}
```

Range syntax maps to a bounded for loop. The upper bound must be a compile-time constant.

### If/Else

```rust
if amount > threshold {
    // ...
} else {
    // ...
}
```

### Ternary (if expression)

```rust
let x = if cond { a } else { b };
```

---

## Type Mapping

| Rust type | Rúnar type |
|-----------|-----------|
| `Bigint` / `Int` / `i64` / `u64` / `i128` / `u128` | `bigint` |
| `bool` / `Bool` | `boolean` |
| `ByteString` | `ByteString` |
| `PubKey` | `PubKey` |
| `Sig` | `Sig` |
| `Sha256` | `Sha256` |
| `Ripemd160` | `Ripemd160` |
| `Addr` | `Addr` |
| `SigHashPreimage` | `SigHashPreimage` |
| `RabinSig` | `RabinSig` |
| `RabinPubKey` | `RabinPubKey` |
| `Point` | `Point` |

All byte types are `Vec<u8>` aliases. Integer types are `i64` aliases.

---

## Built-in Functions

Built-in functions use snake_case and take references for byte-type arguments:

### Assert and Crypto

| Rust function | Rúnar built-in |
|--------------|---------------|
| `assert!(cond)` | `assert(cond)` |
| `assert_eq!(a, b)` | `assert(a === b)` |
| `check_sig(&sig, &pk)` | `checkSig(sig, pk)` |
| `check_multi_sig(&sigs, &pks)` | `checkMultiSig(sigs, pks)` |
| `check_preimage(&pre)` | `checkPreimage(pre)` |
| `verify_rabin_sig(&msg, &sig, &pad, &pk)` | `verifyRabinSig(msg, sig, pad, pk)` |

### Hash Functions

| Rust function | Rúnar built-in |
|--------------|---------------|
| `hash256(&data)` | `hash256(data)` |
| `hash160(&data)` | `hash160(data)` |
| `sha256(&data)` | `sha256(data)` |
| `ripemd160(&data)` | `ripemd160(data)` |

### Math Functions

| Rust function | Rúnar built-in |
|--------------|---------------|
| `abs(n)` | `abs(n)` |
| `min(a, b)` | `min(a, b)` |
| `max(a, b)` | `max(a, b)` |
| `within(x, lo, hi)` | `within(x, lo, hi)` |
| `safediv(a, b)` | `safediv(a, b)` |
| `safemod(a, b)` | `safemod(a, b)` |
| `clamp(val, lo, hi)` | `clamp(val, lo, hi)` |
| `sign(n)` | `sign(n)` |
| `pow(base, exp)` | `pow(base, exp)` |
| `mul_div(a, b, c)` | `mulDiv(a, b, c)` |
| `percent_of(amount, bps)` | `percentOf(amount, bps)` |
| `sqrt(n)` | `sqrt(n)` |
| `gcd(a, b)` | `gcd(a, b)` |
| `divmod(a, b)` | `divmod(a, b)` |
| `log2(n)` | `log2(n)` |
| `bool_cast(n)` | `bool(n)` |

### Byte Operations

| Rust function | Rúnar built-in |
|--------------|---------------|
| `len(&data)` | `len(data)` |
| `cat(&a, &b)` | `cat(a, b)` |
| `substr(&data, start, len)` | `substr(data, start, len)` |
| `left(&data, n)` | `left(data, n)` |
| `right(&data, n)` | `right(data, n)` |
| `reverse_bytes(&data)` | `reverseBytes(data)` |
| `num2bin(&n, size)` | `num2bin(n, size)` |
| `bin2num(&data)` / `bin_2_num(&data)` | `bin2num(data)` |
| `int2str(n, radix)` / `int_2_str(n, radix)` | `int2str(n, radix)` |
| `to_byte_string(&data)` | `toByteString(data)` |

### Preimage Extract Functions

| Rust function | Rúnar built-in |
|--------------|---------------|
| `extract_version(&pre)` | `extractVersion(pre)` |
| `extract_hash_prevouts(&pre)` | `extractHashPrevouts(pre)` |
| `extract_hash_sequence(&pre)` | `extractHashSequence(pre)` |
| `extract_outpoint(&pre)` | `extractOutpoint(pre)` |
| `extract_input_index(&pre)` | `extractInputIndex(pre)` |
| `extract_script_code(&pre)` | `extractScriptCode(pre)` |
| `extract_amount(&pre)` | `extractAmount(pre)` |
| `extract_sequence(&pre)` | `extractSequence(pre)` |
| `extract_output_hash(&pre)` | `extractOutputHash(pre)` |
| `extract_outputs(&pre)` | `extractOutputs(pre)` |
| `extract_locktime(&pre)` | `extractLocktime(pre)` |
| `extract_sig_hash_type(&pre)` | `extractSigHashType(pre)` |

### Post-Quantum Signature Verification

| Rust function | Rúnar built-in |
|--------------|---------------|
| `verify_wots(&msg, &sig, &pk)` | `verifyWOTS(msg, sig, pk)` |
| `verify_slh_dsa_sha2_128s(&msg, &sig, &pk)` | `verifySLHDSA_SHA2_128s(msg, sig, pk)` |
| `verify_slh_dsa_sha2_128f(&msg, &sig, &pk)` | `verifySLHDSA_SHA2_128f(msg, sig, pk)` |
| `verify_slh_dsa_sha2_192s(&msg, &sig, &pk)` | `verifySLHDSA_SHA2_192s(msg, sig, pk)` |
| `verify_slh_dsa_sha2_192f(&msg, &sig, &pk)` | `verifySLHDSA_SHA2_192f(msg, sig, pk)` |
| `verify_slh_dsa_sha2_256s(&msg, &sig, &pk)` | `verifySLHDSA_SHA2_256s(msg, sig, pk)` |
| `verify_slh_dsa_sha2_256f(&msg, &sig, &pk)` | `verifySLHDSA_SHA2_256f(msg, sig, pk)` |

### EC (secp256k1) Functions

| Rust function | Rúnar built-in |
|--------------|---------------|
| `ec_add(&a, &b)` | `ecAdd(a, b)` |
| `ec_mul(&p, k)` | `ecMul(p, k)` |
| `ec_mul_gen(k)` | `ecMulGen(k)` |
| `ec_negate(&p)` | `ecNegate(p)` |
| `ec_on_curve(&p)` | `ecOnCurve(p)` |
| `ec_mod_reduce(value, modulus)` | `ecModReduce(value, mod)` |
| `ec_encode_compressed(&p)` | `ecEncodeCompressed(p)` |
| `ec_make_point(x, y)` | `ecMakePoint(x, y)` |
| `ec_point_x(&p)` | `ecPointX(p)` |
| `ec_point_y(&p)` | `ecPointY(p)` |

EC constants are available from `runar::prelude`:

| Rust constant | Rúnar constant |
|--------------|---------------|
| `EC_P` | `EC_P` |
| `EC_N` | `EC_N` |
| `EC_G` | `EC_G` |

---

## Testing

Contracts can be tested natively with `cargo test`. Each test file includes the contract via `#[path]`:

```rust
// p2pkh/P2PKH_test.rs
#[path = "P2PKH.runar.rs"]
mod contract;

use contract::*;
use runar::prelude::*;

#[test]
fn test_unlock() {
    let pk = mock_pub_key();
    let c = P2PKH { pub_key_hash: hash160(&pk) };
    c.unlock(&mock_sig(), &pk);
}

#[test]
#[should_panic]
fn test_unlock_wrong_key() {
    let pk = mock_pub_key();
    let wrong_pk = vec![0x03; 33];
    let c = P2PKH { pub_key_hash: hash160(&pk) };
    c.unlock(&mock_sig(), &wrong_pk);
}
```

The `runar` crate provides:
- **Mock crypto:** `check_sig`, `check_preimage`, `verify_rabin_sig` always return `true`
- **Real hashes:** `hash160`, `hash256`, `sha256`, `ripemd160` compute real hashes
- **Test helpers:** `mock_sig()`, `mock_pub_key()`, `mock_preimage()`

Run tests with `cargo test` from the `examples/` directory.

---

## Examples

### P2PKH

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
    pub fn unlock(&self, sig: &Sig, pub_key: &PubKey) {
        assert!(hash160(pub_key) == self.pub_key_hash);
        assert!(check_sig(sig, pub_key));
    }
}
```

### Counter

```rust
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

### Stateful Counter (explicit `stateful_contract`)

This is equivalent to the Counter example above, but uses the explicit `#[runar::stateful_contract]` attribute instead of relying on auto-detection from missing `#[readonly]` annotations:

```rust
use runar::prelude::*;

#[runar::stateful_contract]
pub struct StatefulCounter {
    pub count: Bigint,
}

#[runar::methods(StatefulCounter)]
impl StatefulCounter {
    #[public]
    pub fn increment(&mut self) {
        self.count += 1;
    }

    #[public]
    pub fn reset(&mut self) {
        self.count = 0;
    }
}
```

In practice, `#[runar::contract]` is sufficient for stateful contracts since the parser auto-detects statefulness. Use `#[runar::stateful_contract]` when you want to be explicit about the intent.

### Escrow

```rust
use runar::prelude::*;

#[runar::contract]
pub struct Escrow {
    #[readonly]
    pub buyer: PubKey,
    #[readonly]
    pub seller: PubKey,
    #[readonly]
    pub arbiter: PubKey,
}

#[runar::methods(Escrow)]
impl Escrow {
    #[public]
    pub fn release_by_seller(&self, sig: &Sig) {
        assert!(check_sig(sig, &self.seller));
    }

    #[public]
    pub fn release_by_arbiter(&self, sig: &Sig) {
        assert!(check_sig(sig, &self.arbiter));
    }

    #[public]
    pub fn refund_to_buyer(&self, sig: &Sig) {
        assert!(check_sig(sig, &self.buyer));
    }

    #[public]
    pub fn refund_by_arbiter(&self, sig: &Sig) {
        assert!(check_sig(sig, &self.arbiter));
    }
}
```

---

## Name Conversion Rules

| Rust (snake_case) | AST (camelCase) |
|-------------------|-----------------|
| `pub_key_hash` | `pubKeyHash` |
| `highest_bidder` | `highestBidder` |
| `release_by_seller` | `releaseBySeller` |
| `tx_preimage` | `txPreimage` |

Type names and struct names remain PascalCase (unchanged).

### Constructor

The constructor is auto-generated from the struct fields. Properties with defaults (set via the `init()` method) are excluded from the constructor parameters. There is no explicit constructor syntax.

---

## Differences from Real Rust

| Feature | Real Rust | Rúnar Rust DSL |
|---------|-----------|---------------|
| Ownership | Full borrow checker | Simplified; use `.clone()` where needed for `add_output` |
| Traits | Supported | Not supported |
| Enums | Supported | Not supported; use `bigint` constants |
| Pattern matching | `match` | Not supported; use if/else |
| Error handling | `Result<T, E>` | Use `assert!` |
| Generics | Supported | Not supported |
| Modules | `mod`, `use` | Single contract per file |
| Macros | Custom | Only `assert!` and `assert_eq!` |
| Tests | `#[test]` in same file | Separate `_test.rs` files with `#[path]` include |
