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

    // resource struct + functions
}
```

The `use` declaration specifies the base class. `runar::SmartContract` for stateless contracts, `runar::StatefulSmartContract` for stateful contracts.

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

### Property Initializers

Properties can have default values using `= value` syntax in the resource struct:

```move
resource struct GameBoard {
    count: bigint = 0,                     // mutable with default
    active: Bool readonly = true,          // readonly with default
    owner: PubKey readonly,                // no default — required in constructor
}
```

Properties with initializers are excluded from the auto-generated constructor. Only properties without defaults need to be passed as constructor arguments. Initializers must be literal values (`0`, `true`, `false`, hex byte strings).

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

The parser recognizes both `self` and `contract` as receivers for property access. Both are converted to `this.property` in the AST:

```move
self.pub_key_hash       // access a property via self
self.count              // access mutable state via self
contract.pub_key_hash   // access a property via contract
contract.count          // access mutable state via contract
```

The `self` and `contract` keywords are interchangeable. Use whichever style you prefer. `self` is the idiomatic Move convention; `contract` can be passed as a function parameter for explicitness.

### Reference Stripping

Move uses `&` and `&mut` references extensively. The Runar Move parser strips these:

```move
public fun settle(price: &bigint, sig: &Sig) {
    // &bigint -> bigint, &Sig -> Sig in the AST
}
```

References have no semantic effect in the Runar compilation model -- there is no heap, no borrow checker, and all values are stack-based.

### State Mutation

```move
self.count = self.count + 1;   // explicit assignment
self.highest_bidder = bidder;
```

Unlike TypeScript Runar, Move syntax does not have `++` and `--` operators. Use explicit assignment.

### add_output

The `add_output` function creates transaction outputs for stateful contracts. Both bare calls and receiver-qualified calls are valid:

```move
add_output(satoshis, owner, balance);          // bare call
self.add_output(satoshis, owner, balance);     // via self
contract.add_output(satoshis, owner, balance); // via contract
```

All three forms map to `this.addOutput()` in the AST. Values are positional, matching mutable properties in declaration order.

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

        self.add_output(output_satoshis, to, amount);
        self.add_output(output_satoshis, self.owner, self.balance - amount);
    }

    public fun send(sig: Sig, to: PubKey, output_satoshis: bigint) {
        assert!(check_sig(sig, self.owner));
        self.add_output(output_satoshis, to, self.balance);
    }

    public fun merge(sig: Sig, total_balance: bigint, output_satoshis: bigint) {
        assert!(check_sig(sig, self.owner));
        assert!(total_balance >= self.balance);
        self.add_output(output_satoshis, self.owner, total_balance);
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
        self.add_output(output_satoshis, new_owner);
    }

    public fun burn(sig: Sig) {
        assert!(check_sig(sig, self.owner));
    }
}
```

---

## Differences from Real Move

| Feature | Real Move (Sui/Aptos) | Runar Move-like |
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

The snake_case to camelCase conversion handles underscores before both letters and digits: `hash_160` becomes `hash160`, `num_2_bin` becomes `num2Bin` (then the builtin map normalizes it to `num2bin`).

---

## Built-in Function Name Mapping

### Hashing

| Move | Runar |
|------|------|
| `hash_160` / `hash160` | `hash160` |
| `hash_256` / `hash256` | `hash256` |
| `sha256` | `sha256` |
| `ripemd160` | `ripemd160` |

### Signature Verification

| Move | Runar |
|------|------|
| `check_sig` | `checkSig` |
| `check_multi_sig` | `checkMultiSig` |
| `check_preimage` | `checkPreimage` |
| `verify_rabin_sig` | `verifyRabinSig` |

### Post-Quantum Signature Verification

| Move | Runar |
|------|------|
| `verify_wots` | `verifyWOTS` |
| `verify_slhdsa_sha2_128s` | `verifySLHDSA_SHA2_128s` |
| `verify_slhdsa_sha2_128f` | `verifySLHDSA_SHA2_128f` |
| `verify_slhdsa_sha2_192s` | `verifySLHDSA_SHA2_192s` |
| `verify_slhdsa_sha2_192f` | `verifySLHDSA_SHA2_192f` |
| `verify_slhdsa_sha2_256s` | `verifySLHDSA_SHA2_256s` |
| `verify_slhdsa_sha2_256f` | `verifySLHDSA_SHA2_256f` |

The `verify_slh_dsa_sha2_*` spelling (with `slh` and `dsa` as separate words) also works.

### Byte Operations

| Move | Runar |
|------|------|
| `cat` | `cat` |
| `substr` | `substr` |
| `split` | `split` |
| `left` | `left` |
| `right` | `right` |
| `len` | `len` |
| `reverse_bytes` / `reverse_byte_string` | `reverseBytes` |
| `num_2_bin` / `num2bin` | `num2bin` |
| `bin_2_num` / `bin2num` | `bin2num` |
| `int_2_str` / `int2str` | `int2str` |
| `to_byte_string` | `toByteString` |
| `pack` | `pack` |
| `unpack` | `unpack` |
| `bool` | `bool` |

### Preimage Extractors

These functions extract fields from a BIP-143 sighash preimage:

| Move | Runar |
|------|------|
| `extract_version` | `extractVersion` |
| `extract_hash_prevouts` | `extractHashPrevouts` |
| `extract_hash_sequence` | `extractHashSequence` |
| `extract_outpoint` | `extractOutpoint` |
| `extract_script_code` | `extractScriptCode` |
| `extract_sequence` | `extractSequence` |
| `extract_sig_hash_type` | `extractSigHashType` |
| `extract_input_index` | `extractInputIndex` |
| `extract_outputs` | `extractOutputs` |
| `extract_amount` | `extractAmount` |
| `extract_locktime` | `extractLocktime` |
| `extract_output_hash` | `extractOutputHash` |

### Output Construction

| Move | Runar |
|------|------|
| `add_output` / `self.add_output` / `contract.add_output` | `addOutput` |

### Math Builtins

| Move | Runar |
|------|------|
| `abs` | `abs` |
| `min` | `min` |
| `max` | `max` |
| `within` | `within` |
| `safediv` | `safediv` |
| `safemod` | `safemod` |
| `clamp` | `clamp` |
| `sign` | `sign` |
| `pow` | `pow` |
| `mul_div` | `mulDiv` |
| `percent_of` | `percentOf` |
| `sqrt` | `sqrt` |
| `gcd` | `gcd` |
| `divmod` | `divmod` |
| `log2` | `log2` |

### EC (secp256k1) Builtins

| Move | Runar |
|------|------|
| `ec_add` | `ecAdd` |
| `ec_mul` | `ecMul` |
| `ec_mul_gen` | `ecMulGen` |
| `ec_negate` | `ecNegate` |
| `ec_on_curve` | `ecOnCurve` |
| `ec_mod_reduce` | `ecModReduce` |
| `ec_encode_compressed` | `ecEncodeCompressed` |
| `ec_make_point` | `ecMakePoint` |
| `ec_point_x` | `ecPointX` |
| `ec_point_y` | `ecPointY` |

EC constants use UPPER_SNAKE_CASE:

| Move constant | Runar constant |
|--------------|---------------|
| `EC_P` | `EC_P` |
| `EC_N` | `EC_N` |
| `EC_G` | `EC_G` |

The `Point` type (64-byte ByteString subtype) is available directly as `Point` in Move syntax.
