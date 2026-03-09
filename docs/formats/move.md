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
    use runar::types::{Addr, PubKey, Sig};
    use runar::crypto::{hash160, check_sig};

    resource struct P2PKH {
        pub_key_hash: Addr,
    }

    public fun unlock(contract: &P2PKH, sig: Sig, pub_key: PubKey) {
        assert!(hash160(pub_key) == contract.pub_key_hash, 0);
        assert!(check_sig(sig, pub_key), 0);
    }
}
```

### Module Declaration

```move
module ContractName {
    use runar::types::{PubKey, Sig};
    use runar::crypto::{check_sig};

    // struct (stateless) or resource struct (stateful) + functions
}
```

The `use` declarations import types and built-in functions. Use `runar::types::{...}` for type imports and `runar::crypto::{...}` for cryptographic builtins. The contract model (stateless vs stateful) is determined by the struct keyword: plain `struct` for stateless contracts (SmartContract), `resource struct` for stateful contracts (StatefulSmartContract).

### Resource Struct

```move
// Stateful contract — mutable state persists across transactions
resource struct Counter {
    count: bigint,           // mutable by default in resource struct
}

// Stateless contract — all fields are readonly (baked into locking script)
struct CovenantVault {
    owner: PubKey,
    recipient: Addr,
    min_amount: bigint,
}
```

In stateful contracts (`resource struct`), fields are mutable by default. Use `&mut Type` prefix to explicitly mark mutable fields when you need to distinguish mutable from immutable properties:

```move
resource struct FungibleToken {
    owner: &mut PubKey,           // mutable — updated on transfer
    balance: &mut bigint,         // mutable — adjusted on transfer/merge
    merge_balance: &mut bigint,   // mutable — used during merge
    token_id: ByteString,         // immutable — baked into locking script
}
```

In stateless contracts (plain `struct`), all fields are readonly.

### Property Initializers

Properties can have default values using `= value` syntax in the resource struct:

```move
resource struct BoundedCounter {
    count: &mut bigint = 0,          // mutable with default
    max_count: bigint,               // no default — required in constructor
    active: Bool = true,             // default value
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
public fun unlock(contract: &P2PKH, sig: Sig, pub_key: PubKey) {
    // public method (spending entry point)
    // contract: &ContractName for readonly access
}

public fun increment(contract: &mut Counter) {
    // public method (spending entry point)
    // contract: &mut ContractName for mutable access
}

fun helper(x: bigint): bigint {
    // private method (inlined)
}
```

- `public fun` maps to `visibility: 'public'`.
- `fun` (without `public`) maps to `visibility: 'private'`.
- The first parameter is `contract: &ContractName` (readonly) or `contract: &mut ContractName` (mutable). This parameter provides access to the contract's fields via `contract.field_name`.
- Return types use `: Type` syntax after the parameter list.

### assert!() and assert_eq!()

```move
assert!(condition, 0);
assert_eq!(a, b);     // equivalent to assert!(a == b, 0)
```

Both use the macro call syntax (`!`). `assert!` maps to `assert(expr)` and `assert_eq!(a, b)` maps to `assert(a === b)`. The second argument is an error code (conventionally `0`).

### Property Access

Functions access contract properties through the `contract` parameter:

```move
contract.pub_key_hash       // access a readonly property
contract.count              // access mutable state
contract.owner              // access a property
```

The `contract` parameter is passed explicitly as the first function argument with a reference type (`&ContractName` or `&mut ContractName`). Both `self` and `contract` are recognized as receivers by the parser and converted to `this.property` in the AST, but the idiomatic Move-like convention uses the explicit `contract` parameter.

### Reference Stripping

Move uses `&` and `&mut` references extensively. The Runar Move parser strips these from regular parameters:

```move
public fun settle(contract: &OraclePriceFeed, price: &bigint, sig: &Sig) {
    // &bigint -> bigint, &Sig -> Sig in the AST
}
```

References have no semantic effect in the Runar compilation model -- there is no heap, no borrow checker, and all values are stack-based. The `contract` parameter's reference type (`&` vs `&mut`) does have semantic meaning: it determines whether the function can mutate contract state.

### State Mutation

```move
contract.count = contract.count + 1;   // explicit assignment
contract.highest_bidder = bidder;
```

Unlike TypeScript Runar, Move syntax does not have `++` and `--` operators. Use explicit assignment. The function must take `contract: &mut ContractName` to mutate state.

### add_output

The `add_output` function creates transaction outputs for stateful contracts:

```move
contract.add_output(satoshis, owner, balance, 0);  // via contract parameter
```

Values are positional, matching mutable properties in declaration order. The function is called on the `contract` parameter.

---

## Examples

### P2PKH

```move
module P2PKH {
    use runar::types::{Addr, PubKey, Sig};
    use runar::crypto::{hash160, check_sig};

    resource struct P2PKH {
        pub_key_hash: Addr,
    }

    public fun unlock(contract: &P2PKH, sig: Sig, pub_key: PubKey) {
        assert!(hash160(pub_key) == contract.pub_key_hash, 0);
        assert!(check_sig(sig, pub_key), 0);
    }
}
```

### Counter

```move
module Counter {
    resource struct Counter {
        count: bigint,
    }

    public fun increment(contract: &mut Counter) {
        contract.count = contract.count + 1;
    }

    public fun decrement(contract: &mut Counter) {
        assert!(contract.count > 0, 0);
        contract.count = contract.count - 1;
    }
}
```

### Escrow

```move
module Escrow {
    use runar::types::{PubKey, Sig};
    use runar::crypto::{check_sig};

    resource struct Escrow {
        buyer: PubKey,
        seller: PubKey,
        arbiter: PubKey,
    }

    public fun release(contract: &Escrow, seller_sig: Sig, arbiter_sig: Sig) {
        assert!(check_sig(seller_sig, contract.seller), 0);
        assert!(check_sig(arbiter_sig, contract.arbiter), 0);
    }

    public fun refund(contract: &Escrow, buyer_sig: Sig, arbiter_sig: Sig) {
        assert!(check_sig(buyer_sig, contract.buyer), 0);
        assert!(check_sig(arbiter_sig, contract.arbiter), 0);
    }
}
```

### Auction

```move
module Auction {
    use runar::types::{PubKey, Sig};
    use runar::crypto::{check_sig, extract_locktime};

    resource struct Auction {
        auctioneer: PubKey,
        highest_bidder: PubKey,
        highest_bid: bigint,
        deadline: bigint,
    }

    public fun bid(contract: &mut Auction, sig: Sig, bidder: PubKey, bid_amount: bigint) {
        assert!(check_sig(sig, bidder), 0);
        assert!(bid_amount > contract.highest_bid, 0);
        assert!(extract_locktime(contract.tx_preimage) < contract.deadline, 0);

        contract.highest_bidder = bidder;
        contract.highest_bid = bid_amount;
    }

    public fun close(contract: &mut Auction, sig: Sig) {
        assert!(check_sig(sig, contract.auctioneer), 0);
        assert!(extract_locktime(contract.tx_preimage) >= contract.deadline, 0);
    }
}
```

### OraclePriceFeed

```move
module OraclePriceFeed {
    use runar::types::{PubKey, Sig, ByteString, RabinSig, RabinPubKey};
    use runar::crypto::{check_sig, verify_rabin_sig, num2bin};

    resource struct OraclePriceFeed {
        oracle_pub_key: RabinPubKey,
        receiver: PubKey,
    }

    public fun settle(contract: &OraclePriceFeed, price: bigint, rabin_sig: RabinSig, padding: ByteString, sig: Sig) {
        let msg = num2bin(price, 8);
        assert!(verify_rabin_sig(msg, rabin_sig, padding, contract.oracle_pub_key), 0);
        assert!(price > 50000, 0);
        assert!(check_sig(sig, contract.receiver), 0);
    }
}
```

### CovenantVault

```move
module CovenantVault {
    use runar::types::{PubKey, Sig, Addr, ByteString, SigHashPreimage};
    use runar::crypto::{check_sig, check_preimage, extract_output_hash, hash256, num2bin, cat};

    struct CovenantVault {
        owner: PubKey,
        recipient: Addr,
        min_amount: bigint,
    }

    public fun spend(contract: &CovenantVault, sig: Sig, tx_preimage: SigHashPreimage) {
        assert!(check_sig(sig, contract.owner), 0);
        assert!(check_preimage(tx_preimage), 0);

        let p2pkh_script: ByteString = cat(cat(0x1976a914, contract.recipient), 0x88ac);
        let expected_output: ByteString = cat(num2bin(contract.min_amount, 8), p2pkh_script);
        assert!(hash256(expected_output) == extract_output_hash(tx_preimage), 0);
    }
}
```

### FungibleToken

```move
module FungibleToken {
    use runar::types::{PubKey, Sig, ByteString};
    use runar::crypto::{check_sig, hash256, extract_hash_prevouts, extract_outpoint, substr};

    resource struct FungibleToken {
        owner: &mut PubKey,
        balance: &mut bigint,
        merge_balance: &mut bigint,
        token_id: ByteString,
    }

    public fun transfer(contract: &mut FungibleToken, sig: Sig, to: PubKey, amount: bigint, output_satoshis: bigint) {
        assert!(check_sig(sig, contract.owner), 0);
        assert!(output_satoshis >= 1, 0);
        let total_balance: bigint = contract.balance + contract.merge_balance;
        assert!(amount > 0, 0);
        assert!(amount <= total_balance, 0);

        contract.add_output(output_satoshis, to, amount, 0);
        if (amount < total_balance) {
            contract.add_output(output_satoshis, contract.owner, total_balance - amount, 0);
        }
    }

    public fun send(contract: &mut FungibleToken, sig: Sig, to: PubKey, output_satoshis: bigint) {
        assert!(check_sig(sig, contract.owner), 0);
        assert!(output_satoshis >= 1, 0);

        contract.add_output(output_satoshis, to, contract.balance + contract.merge_balance, 0);
    }

    public fun merge(contract: &mut FungibleToken, sig: Sig, other_balance: bigint, all_prevouts: ByteString, output_satoshis: bigint) {
        assert!(check_sig(sig, contract.owner), 0);
        assert!(output_satoshis >= 1, 0);
        assert!(other_balance >= 0, 0);

        assert!(hash256(all_prevouts) == extract_hash_prevouts(contract.tx_preimage), 0);

        let my_outpoint: ByteString = extract_outpoint(contract.tx_preimage);
        let first_outpoint: ByteString = substr(all_prevouts, 0, 36);
        let my_balance: bigint = contract.balance + contract.merge_balance;

        if (my_outpoint == first_outpoint) {
            contract.add_output(output_satoshis, contract.owner, my_balance, other_balance);
        } else {
            contract.add_output(output_satoshis, contract.owner, other_balance, my_balance);
        }
    }
}
```

### SimpleNFT

```move
module SimpleNFT {
    use runar::types::{PubKey, Sig, ByteString};
    use runar::crypto::{check_sig};

    resource struct SimpleNFT {
        owner: &mut PubKey,
        token_id: ByteString,
        metadata: ByteString,
    }

    public fun transfer(contract: &mut SimpleNFT, sig: Sig, new_owner: PubKey, output_satoshis: bigint) {
        assert!(check_sig(sig, contract.owner), 0);
        assert!(output_satoshis >= 1, 0);
        contract.add_output(output_satoshis, new_owner);
    }

    public fun burn(contract: &mut SimpleNFT, sig: Sig) {
        assert!(check_sig(sig, contract.owner), 0);
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
| `contract.add_output` | `addOutput` |

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
