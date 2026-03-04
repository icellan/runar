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
```

The `is` keyword replaces TypeScript's `extends`. The base class must be `SmartContract` or `StatefulSmartContract`.

### Properties

```solidity
Type immutable name;    // readonly property
Type name;              // mutable property (stateful)
```

The `immutable` keyword replaces TypeScript's `readonly`. Properties without `immutable` are mutable state fields.

Types are written before the name (Solidity style), not after with a colon (TypeScript style).

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
count++;
count--;
count = newValue;
highestBidder = bidder;
```

In stateful contracts, mutable properties can be assigned directly. The compiler auto-injects `checkPreimage` and state continuation.

### addOutput

```solidity
addOutput(satoshis, owner, balance);
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
    int256 count;

    function increment() public {
        count++;
    }

    function decrement() public {
        require(count > 0);
        count--;
    }
}
```

Note: `int256` is an alias for `bigint` in the Solidity format. Plain integer literals (without the `n` suffix) are accepted.

### Escrow

```solidity
pragma runar ^0.1.0;

contract Escrow is SmartContract {
    PubKey immutable buyer;
    PubKey immutable seller;
    PubKey immutable arbiter;

    function releaseBySeller(Sig sig) public {
        require(checkSig(sig, seller));
    }

    function releaseByArbiter(Sig sig) public {
        require(checkSig(sig, arbiter));
    }

    function refundToBuyer(Sig sig) public {
        require(checkSig(sig, buyer));
    }

    function refundByArbiter(Sig sig) public {
        require(checkSig(sig, arbiter));
    }
}
```

### Auction

```solidity
pragma runar ^0.1.0;

contract Auction is StatefulSmartContract {
    PubKey immutable auctioneer;
    PubKey highestBidder;
    int256 highestBid;
    int256 immutable deadline;

    function bid(PubKey bidder, int256 bidAmount) public {
        require(bidAmount > highestBid);
        require(extractLocktime(txPreimage) < deadline);

        highestBidder = bidder;
        highestBid = bidAmount;
    }

    function close(Sig sig) public {
        require(checkSig(sig, auctioneer));
        require(extractLocktime(txPreimage) >= deadline);
    }
}
```

### OraclePriceFeed

```solidity
pragma runar ^0.1.0;

contract OraclePriceFeed is SmartContract {
    RabinPubKey immutable oraclePubKey;
    PubKey immutable receiver;

    function settle(int256 price, RabinSig rabinSig, ByteString padding, Sig sig) public {
        ByteString msg = num2bin(price, 8);
        require(verifyRabinSig(msg, rabinSig, padding, oraclePubKey));
        require(price > 50000);
        require(checkSig(sig, receiver));
    }
}
```

### CovenantVault

```solidity
pragma runar ^0.1.0;

contract CovenantVault is SmartContract {
    PubKey immutable owner;
    Addr immutable recipient;
    int256 immutable minAmount;

    function spend(Sig sig, int256 amount, SigHashPreimage txPreimage) public {
        require(checkSig(sig, owner));
        require(checkPreimage(txPreimage));
        require(amount >= minAmount);
    }
}
```

### FungibleToken

```solidity
pragma runar ^0.1.0;

contract FungibleToken is StatefulSmartContract {
    PubKey owner;
    int256 balance;
    ByteString immutable tokenId;

    function transfer(Sig sig, PubKey to, int256 amount, int256 outputSatoshis) public {
        require(checkSig(sig, owner));
        require(amount > 0);
        require(amount <= balance);

        addOutput(outputSatoshis, to, amount);
        addOutput(outputSatoshis, owner, balance - amount);
    }

    function send(Sig sig, PubKey to, int256 outputSatoshis) public {
        require(checkSig(sig, owner));
        addOutput(outputSatoshis, to, balance);
    }

    function merge(Sig sig, int256 totalBalance, int256 outputSatoshis) public {
        require(checkSig(sig, owner));
        require(totalBalance >= balance);
        addOutput(outputSatoshis, owner, totalBalance);
    }
}
```

### SimpleNFT

```solidity
pragma runar ^0.1.0;

contract SimpleNFT is StatefulSmartContract {
    PubKey owner;
    ByteString immutable tokenId;
    ByteString immutable metadata;

    function transfer(Sig sig, PubKey newOwner, int256 outputSatoshis) public {
        require(checkSig(sig, owner));
        addOutput(outputSatoshis, newOwner);
    }

    function burn(Sig sig) public {
        require(checkSig(sig, owner));
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
| Inheritance | Multiple inheritance | Single base class only (`SmartContract` or `StatefulSmartContract`) |
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
| `int256` | `bigint` |
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
| `ecMul` | `(p: Point, k: int256) => Point` | Scalar multiplication |
| `ecMulGen` | `(k: int256) => Point` | Generator multiplication |
| `ecNegate` | `(p: Point) => Point` | Point negation |
| `ecOnCurve` | `(p: Point) => bool` | Curve membership check |
| `ecModReduce` | `(value: int256, mod: int256) => int256` | Modular reduction |
| `ecEncodeCompressed` | `(p: Point) => bytes` | Compress to 33-byte pubkey |
| `ecMakePoint` | `(x: int256, y: int256) => Point` | Construct point from coordinates |
| `ecPointX` | `(p: Point) => int256` | Extract x-coordinate |
| `ecPointY` | `(p: Point) => int256` | Extract y-coordinate |

### EC Constants

| Constant | Description |
|----------|-------------|
| `EC_P` | secp256k1 field prime |
| `EC_N` | secp256k1 group order |
| `EC_G` | Generator point |
