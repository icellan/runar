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

- `#[runar::contract]` marks the struct as a Rúnar contract. The parser auto-detects whether the contract is stateless or stateful based on field annotations: if any field lacks `#[readonly]`, the contract is treated as `StatefulSmartContract`. Use `#[runar::inductive_contract]` for contracts requiring backward chain verification (`InductiveSmartContract`).
- `#[runar::stateful_contract]` can be used instead to explicitly mark a contract as stateful. This is equivalent to `#[runar::contract]` when any field lacks `#[readonly]`.
- `#[readonly]` marks immutable properties (baked into the locking script).
- Fields without `#[readonly]` are mutable (stateful).
- Fields should be `pub` so tests can construct the struct directly.
- All fields use snake_case; the Rúnar parser converts to camelCase for the AST.

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
| `Bigint` / `Int` / `i64` | `bigint` |
| `bool` | `boolean` |
| `ByteString` | `ByteString` |
| `PubKey` | `PubKey` |
| `Sig` | `Sig` |
| `Sha256` | `Sha256` |
| `Ripemd160` | `Ripemd160` |
| `Addr` | `Addr` |
| `SigHashPreimage` | `SigHashPreimage` |
| `RabinSig` | `RabinSig` |
| `RabinPubKey` | `RabinPubKey` |

All byte types are `Vec<u8>` aliases. Integer types are `i64` aliases.

---

## Built-in Functions

Built-in functions use snake_case and take references for byte-type arguments:

| Rust function | Rúnar built-in |
|--------------|---------------|
| `assert!(cond)` | `assert(cond)` |
| `assert_eq!(a, b)` | `assert(a === b)` |
| `check_sig(&sig, &pk)` | `checkSig(sig, pk)` |
| `check_multi_sig(&sigs, &pks)` | `checkMultiSig(sigs, pks)` |
| `hash256(&data)` | `hash256(data)` |
| `hash160(&data)` | `hash160(data)` |
| `sha256(&data)` | `sha256(data)` |
| `ripemd160(&data)` | `ripemd160(data)` |
| `num2bin(&n, size)` | `num2bin(n, size)` |
| `check_preimage(&pre)` | `checkPreimage(pre)` |
| `extract_locktime(&pre)` | `extractLocktime(pre)` |
| `extract_output_hash(&pre)` | `extractOutputHash(pre)` |
| `verify_rabin_sig(&msg, &sig, &pad, &pk)` | `verifyRabinSig(msg, sig, pad, pk)` |
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

The constructor is auto-generated from the struct fields. There is no explicit constructor syntax.

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
