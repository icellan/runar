# Solidity-like Contract Format

**Status:** Experimental
**File extension:** `.runar.sol`
**Supported compilers:** TypeScript, Go, Rust

---

## Overview

The Solidity-like format provides a familiar syntax for developers coming from Ethereum. It uses Solidity's structural conventions -- `pragma`, `contract ... is ...`, `function`, `require` -- while compiling to Bitcoin SV Script through the standard Rúnar pipeline.

This is **not** Solidity. It borrows syntax but has different semantics, a different type system, and targets a fundamentally different execution model (UTXO-based Script vs. account-based EVM). The goal is to reduce the learning curve, not to provide Solidity compatibility.

---

## Syntax

### File Structure

```solidity
pragma runar ^0.1.0;

contract P2PKH is SmartContract {
    Addr immutable pubKeyHash;

    function unlock(Sig sig, PubKey pubKey) public {
        require(hash160(pubKey) == pubKeyHash);
        require(checkSig(sig, pubKey));
    }
}
```

### Pragma

```solidity
pragma runar ^0.1.0;
```

The `pragma` directive specifies the Rúnar language version. It follows Solidity conventions but uses `runar` instead of `solidity`. The version constraint is advisory -- the compiler checks compatibility but the pragma is not included in the output.

### Contract Declaration

```solidity
contract Name is SmartContract { ... }
contract Name is StatefulSmartContract { ... }
contract Name is InductiveSmartContract { ... }
```

The `is` keyword replaces TypeScript's `extends`. The base class must be `SmartContract`, `StatefulSmartContract`, or `InductiveSmartContract`.

### Properties

```solidity
Type immutable name;    // readonly property
Type name;              // mutable property (stateful)
```

The `immutable` keyword replaces TypeScript's `readonly`. Properties without `immutable` are mutable state fields.

Types are written before the name (Solidity style), not after with a colon (TypeScript style).

### Property Initializers

Properties can have default values using `= value` syntax:

```solidity
contract GameBoard is StatefulSmartContract {
    int256 count = 0;                    // mutable with default
    bool immutable active = true;        // readonly with default
    PubKey immutable owner;              // no default — required in constructor
}
```

Properties with initializers are excluded from the auto-generated constructor. Only properties without defaults need to be passed as constructor arguments. Initializers must be literal values (`0`, `true`, `false`, hex byte strings).

### Methods

```solidity
function name(Type param1, Type param2) public {
    // body
}

function helper(Type param) private returns (Type) {
    // body
}
```

- `public` methods are spending entry points (maps to `visibility: 'public'`).
- `private` methods are inlined helpers (maps to `visibility: 'private'`).
- `returns (Type)` is used for private methods that return a value. Public methods implicitly return void.

### require() and assert()

```solidity
require(condition);
```

`require(expr)` maps directly to `assert(expr)`. Both are accepted; `require` is idiomatic Solidity, `assert` is idiomatic Rúnar. They compile to the same `OP_VERIFY`.

### Operators

| Solidity syntax | Rúnar equivalent | Notes |
|----------------|-----------------|-------|
| `==` | `===` | Equality (no type coercion in either language) |
| `!=` | `!==` | Inequality |
| `+`, `-`, `*`, `/`, `%` | Same | Arithmetic |
| `<`, `<=`, `>`, `>=` | Same | Comparison |
| `&&`, `\|\|`, `!` | Same | Logical |
| `condition ? a : b` | Same | Ternary |

The parser automatically converts `==` to `===` and `!=` to `!==` in the AST.

### Property Access

```solidity
pubKeyHash          // access property directly (no this. prefix needed)
this.pubKeyHash     // also valid (explicit)
```

Unlike TypeScript Rúnar where `this.` is required, the Solidity format allows bare property names. The parser resolves them to `PropertyAccessExpr` nodes.

### State Mutation

```solidity
this.count++;
this.count--;
this.count = newValue;
this.highestBidder = bidder;
```

In stateful contracts, mutable properties can be assigned directly. The compiler auto-injects `checkPreimage` and state continuation.

### addOutput

```solidity
this.addOutput(satoshis, owner, balance, 0);
```

The `addOutput` call uses the same positional convention as TypeScript: the first argument is satoshis, followed by values matching mutable properties in declaration order.

---

## Examples

### P2PKH

```solidity
pragma runar ^0.1.0;

contract P2PKH is SmartContract {
    Addr immutable pubKeyHash;

    function unlock(Sig sig, PubKey pubKey) public {
        require(hash160(pubKey) == pubKeyHash);
        require(checkSig(sig, pubKey));
    }
}
```

### Counter

```solidity
pragma runar ^0.1.0;

contract Counter is StatefulSmartContract {
    bigint count;

    constructor(bigint _count) {
        count = _count;
    }

    function increment() public {
        this.count++;
    }

    function decrement() public {
        require(this.count > 0);
        this.count--;
    }
}
```

Note: `int256` is an alias for `bigint` in the Solidity format. Both are accepted; the parser normalizes `int256` to `bigint`. Plain integer literals (without the `n` suffix) are accepted.

### Escrow

```solidity
pragma runar ^0.1.0;

contract Escrow is SmartContract {
    PubKey immutable buyer;
    PubKey immutable seller;
    PubKey immutable arbiter;

    constructor(PubKey _buyer, PubKey _seller, PubKey _arbiter) {
        buyer = _buyer;
        seller = _seller;
        arbiter = _arbiter;
    }

    function release(Sig sellerSig, Sig arbiterSig) public {
        require(checkSig(sellerSig, this.seller));
        require(checkSig(arbiterSig, this.arbiter));
    }

    function refund(Sig buyerSig, Sig arbiterSig) public {
        require(checkSig(buyerSig, this.buyer));
        require(checkSig(arbiterSig, this.arbiter));
    }
}
```

This is a dual-sig escrow: both spending paths require two signatures. The arbiter must co-sign every spend, preventing unilateral action by either the buyer or the seller.

### Auction

```solidity
pragma runar ^0.1.0;

contract Auction is StatefulSmartContract {
    PubKey immutable auctioneer;
    PubKey highestBidder;
    bigint highestBid;
    bigint immutable deadline;

    constructor(PubKey _auctioneer, PubKey _highestBidder, bigint _highestBid, bigint _deadline) {
        auctioneer = _auctioneer;
        highestBidder = _highestBidder;
        highestBid = _highestBid;
        deadline = _deadline;
    }

    function bid(Sig sig, PubKey bidder, bigint bidAmount) public {
        require(checkSig(sig, bidder));
        require(bidAmount > this.highestBid);
        require(extractLocktime(this.txPreimage) < this.deadline);

        this.highestBidder = bidder;
        this.highestBid = bidAmount;
    }

    function close(Sig sig) public {
        require(checkSig(sig, this.auctioneer));
        require(extractLocktime(this.txPreimage) >= this.deadline);
    }
}
```

### OraclePriceFeed

```solidity
pragma runar ^0.1.0;

contract OraclePriceFeed is SmartContract {
    RabinPubKey immutable oraclePubKey;
    PubKey immutable receiver;

    constructor(RabinPubKey _oraclePubKey, PubKey _receiver) {
        oraclePubKey = _oraclePubKey;
        receiver = _receiver;
    }

    function settle(bigint price, RabinSig rabinSig, ByteString padding, Sig sig) public {
        let ByteString msg = num2bin(price, 8);
        require(verifyRabinSig(msg, rabinSig, padding, this.oraclePubKey));
        require(price > 50000);
        require(checkSig(sig, this.receiver));
    }
}
```

### CovenantVault

```solidity
pragma runar ^0.1.0;

contract CovenantVault is SmartContract {
    PubKey immutable owner;
    Addr immutable recipient;
    bigint immutable minAmount;

    constructor(PubKey _owner, Addr _recipient, bigint _minAmount) {
        owner = _owner;
        recipient = _recipient;
        minAmount = _minAmount;
    }

    function spend(Sig sig, SigHashPreimage txPreimage) public {
        require(checkSig(sig, this.owner));
        require(checkPreimage(txPreimage));

        // Construct expected P2PKH output and verify against hashOutputs
        ByteString p2pkhScript = cat(cat(0x1976a914, this.recipient), 0x88ac);
        ByteString expectedOutput = cat(num2bin(this.minAmount, 8), p2pkhScript);
        require(hash256(expectedOutput) == extractOutputHash(txPreimage));
    }
}
```

This contract demonstrates the covenant pattern: the locking script constrains not just *who* can spend the funds, but *how* they may be spent. It constructs the expected P2PKH output on-chain and verifies its hash against the transaction's `hashOutputs` field, enforcing both the destination and the minimum amount at the consensus level.

### FungibleToken

```solidity
pragma runar ^0.1.0;

contract FungibleToken is StatefulSmartContract {
    PubKey owner;
    bigint balance;
    bigint mergeBalance;
    ByteString immutable tokenId;

    constructor(PubKey _owner, bigint _balance, bigint _mergeBalance, ByteString _tokenId) {
        owner = _owner;
        balance = _balance;
        mergeBalance = _mergeBalance;
        tokenId = _tokenId;
    }

    function transfer(Sig sig, PubKey to, bigint amount, bigint outputSatoshis) public {
        require(checkSig(sig, this.owner));
        require(outputSatoshis >= 1);
        bigint totalBalance = this.balance + this.mergeBalance;
        require(amount > 0);
        require(amount <= totalBalance);

        this.addOutput(outputSatoshis, to, amount, 0);
        if (amount < totalBalance) {
            this.addOutput(outputSatoshis, this.owner, totalBalance - amount, 0);
        }
    }

    function send(Sig sig, PubKey to, bigint outputSatoshis) public {
        require(checkSig(sig, this.owner));
        require(outputSatoshis >= 1);

        this.addOutput(outputSatoshis, to, this.balance + this.mergeBalance, 0);
    }

    function merge(Sig sig, bigint otherBalance, ByteString allPrevouts, bigint outputSatoshis) public {
        require(checkSig(sig, this.owner));
        require(outputSatoshis >= 1);
        require(otherBalance >= 0);

        require(hash256(allPrevouts) == extractHashPrevouts(this.txPreimage));

        ByteString myOutpoint = extractOutpoint(this.txPreimage);
        ByteString firstOutpoint = substr(allPrevouts, 0, 36);
        bigint myBalance = this.balance + this.mergeBalance;

        if (myOutpoint == firstOutpoint) {
            this.addOutput(outputSatoshis, this.owner, myBalance, otherBalance);
        } else {
            this.addOutput(outputSatoshis, this.owner, otherBalance, myBalance);
        }
    }
}
```

The `mergeBalance` property enables secure cross-input merge verification. Each input places its own verified balance in a position-dependent slot, and `hashOutputs` in BIP-143 forces both inputs to agree on the exact same output, preventing inflation attacks.

### SimpleNFT

```solidity
pragma runar ^0.1.0;

contract SimpleNFT is StatefulSmartContract {
    PubKey owner;
    ByteString immutable tokenId;
    ByteString immutable metadata;

    constructor(PubKey _owner, ByteString _tokenId, ByteString _metadata) {
        owner = _owner;
        tokenId = _tokenId;
        metadata = _metadata;
    }

    function transfer(Sig sig, PubKey newOwner, bigint outputSatoshis) public {
        require(checkSig(sig, this.owner));
        require(outputSatoshis >= 1);
        this.addOutput(outputSatoshis, newOwner);
    }

    function burn(Sig sig) public {
        require(checkSig(sig, this.owner));
    }
}
```

---

## Differences from Real Solidity

| Feature | Real Solidity | Rúnar Solidity-like |
|---------|--------------|-------------------|
| Execution model | Account-based EVM | UTXO-based Bitcoin Script |
| Integer types | `uint256`, `int256`, etc. | `int256` is an alias for `bigint`; no unsigned types |
| `msg.sender` | Implicit caller | Not available; use `checkSig` for authorization |
| `payable` | Modifier for receiving ETH | Not applicable; satoshis are UTXO-based |
| Events | `emit Event(...)` | Not supported |
| Mappings | `mapping(K => V)` | Not supported; use properties |
| Inheritance | Multiple inheritance | Single base class only (`SmartContract`, `StatefulSmartContract`, or `InductiveSmartContract`) |
| Libraries | `library` keyword | Not supported |
| Modifiers | `modifier onlyOwner` | Not supported; use `require` in method body |
| Constructor | `constructor(...) payable` | Auto-generated from properties |
| `revert` | `revert("message")` | Use `require(false)` or `assert(false)` |
| Storage | Persistent account storage | State is in the UTXO; mutable properties propagated via OP_PUSH_TX |
| Gas | Execution metered by gas | No gas; script size limits apply |
| Loops | Unbounded `for`/`while` | Bounded `for` only; unrolled at compile time |

---

## Type Mapping

| Solidity-like type | Rúnar type |
|-------------------|-----------|
| `int` | `bigint` |
| `uint` | `bigint` |
| `int256` | `bigint` |
| `uint256` | `bigint` |
| `bool` | `boolean` |
| `bytes` | `ByteString` |
| `PubKey` | `PubKey` |
| `Sig` | `Sig` |
| `Sha256` | `Sha256` |
| `Ripemd160` | `Ripemd160` |
| `Addr` / `address` | `Addr` |
| `SigHashPreimage` | `SigHashPreimage` |
| `RabinSig` | `RabinSig` |
| `RabinPubKey` | `RabinPubKey` |
| `Point` | `Point` |

Both Solidity-style names (`int256`, `bool`, `bytes`, `address`) and Rúnar-native names (`bigint`, `boolean`, `ByteString`, `Addr`) are accepted. The parser normalizes to Rúnar types.

---

## Built-in Functions

All Rúnar built-in functions are available using their standard names. The Solidity-like format does not rename builtins — use the same names as in TypeScript Rúnar (e.g. `sha256`, `checkSig`, `assert`/`require`).

### EC Point Operations

Elliptic curve operations on secp256k1 points are available:

| Function | Signature | Description |
|----------|-----------|-------------|
| `ecAdd` | `(a: Point, b: Point) => Point` | Point addition |
| `ecMul` | `(p: Point, k: bigint) => Point` | Scalar multiplication |
| `ecMulGen` | `(k: bigint) => Point` | Generator multiplication |
| `ecNegate` | `(p: Point) => Point` | Point negation |
| `ecOnCurve` | `(p: Point) => bool` | Curve membership check |
| `ecModReduce` | `(value: bigint, mod: bigint) => bigint` | Modular reduction |
| `ecEncodeCompressed` | `(p: Point) => ByteString` | Compress to 33-byte pubkey |
| `ecMakePoint` | `(x: bigint, y: bigint) => Point` | Construct point from coordinates |
| `ecPointX` | `(p: Point) => bigint` | Extract x-coordinate |
| `ecPointY` | `(p: Point) => bigint` | Extract y-coordinate |

### EC Constants

| Constant | Description |
|----------|-------------|
| `EC_P` | secp256k1 field prime |
| `EC_N` | secp256k1 group order |
| `EC_G` | Generator point |

### Post-Quantum Signature Verification (Experimental)

| Function | Signature | Description |
|----------|-----------|-------------|
| `verifyWOTS` | `(msg: ByteString, sig: ByteString, pubkey: ByteString) => bool` | WOTS+ verification (w=16, SHA-256). One-time use per keypair. |
| `verifySLHDSA_SHA2_128s` | `(msg: ByteString, sig: ByteString, pubkey: ByteString) => bool` | SLH-DSA-SHA2-128s (FIPS 205). Stateless, multi-use. |
| `verifySLHDSA_SHA2_128f` | `(msg: ByteString, sig: ByteString, pubkey: ByteString) => bool` | SLH-DSA-SHA2-128f. Fast variant. |
| `verifySLHDSA_SHA2_192s` | `(msg: ByteString, sig: ByteString, pubkey: ByteString) => bool` | SLH-DSA-SHA2-192s. 192-bit security. |
| `verifySLHDSA_SHA2_192f` | `(msg: ByteString, sig: ByteString, pubkey: ByteString) => bool` | SLH-DSA-SHA2-192f. Fast variant. |
| `verifySLHDSA_SHA2_256s` | `(msg: ByteString, sig: ByteString, pubkey: ByteString) => bool` | SLH-DSA-SHA2-256s. 256-bit security. |
| `verifySLHDSA_SHA2_256f` | `(msg: ByteString, sig: ByteString, pubkey: ByteString) => bool` | SLH-DSA-SHA2-256f. Fast variant. |
