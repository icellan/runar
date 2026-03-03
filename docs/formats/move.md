# Move-like Contract Format

**Status:** Experimental
**File extension:** `.runar.move`
**Supported compilers:** TypeScript, Go, Rust

---

## Overview

The Move-like format uses syntax inspired by the Move language (as seen in Sui and Aptos). Contracts are defined as modules containing a resource struct and public/private functions. This format appeals to developers from the Move ecosystem who think in terms of resources and ownership.

This is **not** Move. There is no borrow checker, no ability system, and no module system beyond a single contract per file. The syntax borrows Move's structural conventions while compiling to Bitcoin SV Script.

---

## Syntax

### Module Structure

```move
module P2PKH {
    use runar::SmartContract;

    resource struct P2PKH {
        pub_key_hash: Addr readonly,
    }

    public fun unlock(sig: Sig, pub_key: PubKey) {
        assert!(hash160(pub_key) == self.pub_key_hash);
        assert!(check_sig(sig, pub_key));
    }
}
```

### Module Declaration

```move
module ContractName {
    use runar::SmartContract;
    // or
    use runar::StatefulSmartContract;
    // or
    use runar::InductiveSmartContract;

    // resource struct + functions
}
```

The `use` declaration specifies the base class. `runar::SmartContract` for stateless contracts, `runar::StatefulSmartContract` for stateful contracts, `runar::InductiveSmartContract` for stateful contracts with backward chain verification.

### Resource Struct

```move
resource struct Counter {
    count: bigint,           // mutable (stateful)
}

resource struct P2PKH {
    pub_key_hash: Addr readonly,   // immutable
}
```

Properties are declared inside the resource struct. The `readonly` modifier after the type marks immutable properties.

**snake_case convention:** Move uses snake_case for identifiers. The parser automatically converts snake_case field names and function names to camelCase for the AST:

| Move (snake_case) | AST (camelCase) |
|-------------------|-----------------|
| `pub_key_hash` | `pubKeyHash` |
| `highest_bidder` | `highestBidder` |
| `highest_bid` | `highestBid` |
| `oracle_pub_key` | `oraclePubKey` |
| `token_id` | `tokenId` |
| `output_satoshis` | `outputSatoshis` |

### Functions

```move
public fun unlock(sig: Sig, pub_key: PubKey) {
    // public method (spending entry point)
}

fun helper(x: bigint): bigint {
    // private method (inlined)
}
```

- `public fun` maps to `visibility: 'public'`.
- `fun` (without `public`) maps to `visibility: 'private'`.
- Return types use `: Type` syntax after the parameter list.

### assert!() and assert_eq!()

```move
assert!(condition);
assert_eq!(a, b);     // equivalent to assert!(a == b)
```

Both use the macro call syntax (`!`). `assert!` maps to `assert(expr)` and `assert_eq!(a, b)` maps to `assert(a === b)`.

### Property Access

```move
self.pub_key_hash       // access a property
self.count              // access mutable state
```

The `self` keyword replaces `this`. The parser converts `self` references to property access expressions.

### Reference Stripping

Move uses `&` and `&mut` references extensively. The Rúnar Move parser strips these:

```move
public fun settle(price: &bigint, sig: &Sig) {
    // &bigint → bigint, &Sig → Sig in the AST
}
```

References have no semantic effect in the Rúnar compilation model -- there is no heap, no borrow checker, and all values are stack-based.

### State Mutation

```move
self.count = self.count + 1;   // explicit assignment
self.highest_bidder = bidder;
```

Unlike TypeScript Rúnar, Move syntax does not have `++` and `--` operators. Use explicit assignment.

### add_output

```move
add_output(satoshis, owner, balance);
```

The `add_output` function (snake_case) maps to `this.addOutput()` in the AST.

---

## Examples

### P2PKH

```move
module P2PKH {
    use runar::SmartContract;

    resource struct P2PKH {
        pub_key_hash: Addr readonly,
    }

    public fun unlock(sig: Sig, pub_key: PubKey) {
        assert!(hash160(pub_key) == self.pub_key_hash);
        assert!(check_sig(sig, pub_key));
    }
}
```

### Counter

```move
module Counter {
    use runar::StatefulSmartContract;

    resource struct Counter {
        count: bigint,
    }

    public fun increment() {
        self.count = self.count + 1;
    }

    public fun decrement() {
        assert!(self.count > 0);
        self.count = self.count - 1;
    }
}
```

### Escrow

```move
module Escrow {
    use runar::SmartContract;

    resource struct Escrow {
        buyer: PubKey readonly,
        seller: PubKey readonly,
        arbiter: PubKey readonly,
    }

    public fun release_by_seller(sig: Sig) {
        assert!(check_sig(sig, self.seller));
    }

    public fun release_by_arbiter(sig: Sig) {
        assert!(check_sig(sig, self.arbiter));
    }

    public fun refund_to_buyer(sig: Sig) {
        assert!(check_sig(sig, self.buyer));
    }

    public fun refund_by_arbiter(sig: Sig) {
        assert!(check_sig(sig, self.arbiter));
    }
}
```

### Auction

```move
module Auction {
    use runar::StatefulSmartContract;

    resource struct Auction {
        auctioneer: PubKey readonly,
        highest_bidder: PubKey,
        highest_bid: bigint,
        deadline: bigint readonly,
    }

    public fun bid(bidder: PubKey, bid_amount: bigint) {
        assert!(bid_amount > self.highest_bid);
        assert!(extract_locktime(self.tx_preimage) < self.deadline);

        self.highest_bidder = bidder;
        self.highest_bid = bid_amount;
    }

    public fun close(sig: Sig) {
        assert!(check_sig(sig, self.auctioneer));
        assert!(extract_locktime(self.tx_preimage) >= self.deadline);
    }
}
```

### OraclePriceFeed

```move
module OraclePriceFeed {
    use runar::SmartContract;

    resource struct OraclePriceFeed {
        oracle_pub_key: RabinPubKey readonly,
        receiver: PubKey readonly,
    }

    public fun settle(price: bigint, rabin_sig: RabinSig, padding: ByteString, sig: Sig) {
        let msg = num2bin(price, 8);
        assert!(verify_rabin_sig(msg, rabin_sig, padding, self.oracle_pub_key));
        assert!(price > 50000);
        assert!(check_sig(sig, self.receiver));
    }
}
```

### CovenantVault

```move
module CovenantVault {
    use runar::SmartContract;

    resource struct CovenantVault {
        owner: PubKey readonly,
        recipient: Addr readonly,
        min_amount: bigint readonly,
    }

    public fun spend(sig: Sig, amount: bigint, tx_preimage: SigHashPreimage) {
        assert!(check_sig(sig, self.owner));
        assert!(check_preimage(tx_preimage));
        assert!(amount >= self.min_amount);
    }
}
```

### FungibleToken

```move
module FungibleToken {
    use runar::StatefulSmartContract;

    resource struct FungibleToken {
        owner: PubKey,
        balance: bigint,
        token_id: ByteString readonly,
    }

    public fun transfer(sig: Sig, to: PubKey, amount: bigint, output_satoshis: bigint) {
        assert!(check_sig(sig, self.owner));
        assert!(amount > 0);
        assert!(amount <= self.balance);

        add_output(output_satoshis, to, amount);
        add_output(output_satoshis, self.owner, self.balance - amount);
    }

    public fun send(sig: Sig, to: PubKey, output_satoshis: bigint) {
        assert!(check_sig(sig, self.owner));
        add_output(output_satoshis, to, self.balance);
    }

    public fun merge(sig: Sig, total_balance: bigint, output_satoshis: bigint) {
        assert!(check_sig(sig, self.owner));
        assert!(total_balance >= self.balance);
        add_output(output_satoshis, self.owner, total_balance);
    }
}
```

### SimpleNFT

```move
module SimpleNFT {
    use runar::StatefulSmartContract;

    resource struct SimpleNFT {
        owner: PubKey,
        token_id: ByteString readonly,
        metadata: ByteString readonly,
    }

    public fun transfer(sig: Sig, new_owner: PubKey, output_satoshis: bigint) {
        assert!(check_sig(sig, self.owner));
        add_output(output_satoshis, new_owner);
    }

    public fun burn(sig: Sig) {
        assert!(check_sig(sig, self.owner));
    }
}
```

---

## Differences from Real Move

| Feature | Real Move (Sui/Aptos) | Rúnar Move-like |
|---------|----------------------|----------------|
| Borrow checker | Full ownership and borrowing model | No borrow checker; references stripped |
| Abilities | `key`, `store`, `copy`, `drop` | Not supported |
| Module system | Multi-module packages | Single module per file = one contract |
| Generic types | Full generics | Not supported (except FixedArray) |
| `object::new` / `transfer` | Sui object creation | Not applicable; UTXO model |
| Events | `event::emit` | Not supported |
| Dynamic fields | `dynamic_field` | Not supported |
| `vector<T>` | Dynamic-length vectors | Not supported; use fixed arrays |
| Entry functions | `entry fun` | `public fun` = entry point |
| Test functions | `#[test]` | Separate test files |
| Storage model | Global object store | UTXO-based; state in transaction outputs |

---

## Name Conversion Rules

The parser applies these conversions automatically:

| Category | Move convention | AST convention |
|----------|---------------|----------------|
| Property names | `snake_case` | `camelCase` |
| Method names | `snake_case` | `camelCase` |
| Parameter names | `snake_case` | `camelCase` |
| Built-in functions | `snake_case` (`check_sig`) | `camelCase` (`checkSig`) |
| Contract name | PascalCase | PascalCase (unchanged) |
| Type names | PascalCase | PascalCase (unchanged) |

Built-in function name mapping:

| Move | Rúnar |
|------|------|
| `check_sig` | `checkSig` |
| `check_multi_sig` | `checkMultiSig` |
| `hash_160` / `hash160` | `hash160` |
| `hash_256` / `hash256` | `hash256` |
| `check_preimage` | `checkPreimage` |
| `extract_locktime` | `extractLocktime` |
| `extract_output_hash` | `extractOutputHash` |
| `extract_amount` | `extractAmount` |
| `verify_rabin_sig` | `verifyRabinSig` |
| `num_2_bin` / `num2bin` | `num2bin` |
| `reverse_byte_string` | `reverseByteString` |
| `to_byte_string` | `toByteString` |
| `add_output` | `addOutput` |
