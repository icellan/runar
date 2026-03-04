# Go Contract Format

**Status:** Experimental
**File extension:** `.runar.go`
**Supported compilers:** Go only

---

## Overview

The Go format lets you write Rúnar contracts as idiomatic Go code. Contracts are Go structs embedding `runar.SmartContract` or `runar.StatefulSmartContract`, with methods defined as receiver functions. The Go compiler parses these directly -- no intermediate conversion to TypeScript.

This format is **only supported by the Go compiler** (`compilers/go`). The TypeScript and Rust compilers cannot parse `.runar.go` files. If you need cross-compiler portability, use the TypeScript format instead.

---

## Syntax

### Package and Imports

```go
package contracts

import "runar"
```

The package name is ignored by the compiler. The `"runar"` import provides the base types and built-in functions.

### Struct Declaration

```go
type P2PKH struct {
    runar.SmartContract
    PubKeyHash runar.Addr `runar:"readonly"`
}
```

- Embed `runar.SmartContract` or `runar.StatefulSmartContract` as the first field (anonymous embed).
- Properties are struct fields with `runar.Type` types.
- The `runar:"readonly"` struct tag marks immutable properties.
- Fields without the `readonly` tag are mutable (stateful).

### Exported vs. Unexported

Go's visibility rules map to Rúnar method visibility:

| Go convention | Rúnar visibility |
|--------------|-----------------|
| `func (c *P2PKH) Unlock(...)` (exported) | `public` |
| `func (c *P2PKH) helper(...)` (unexported) | `private` |

Exported methods (capitalized first letter) are spending entry points. Unexported methods are inlined helpers.

### Methods

```go
func (c *P2PKH) Unlock(sig runar.Sig, pubKey runar.PubKey) {
    runar.Assert(runar.Hash160(pubKey) == c.PubKeyHash)
    runar.Assert(runar.CheckSig(sig, pubKey))
}
```

- The receiver is always a pointer to the contract struct (`*P2PKH`).
- The receiver variable name (`c` above) is conventional but any name works.
- Public methods must not return a value.
- Private methods may return a value.

### runar.Assert

```go
runar.Assert(condition)
```

Maps to `assert(condition)` in the AST. Fails the script if the condition is false.

### Property Access

```go
c.PubKeyHash       // access a readonly property
c.Count            // access a mutable property
```

Properties are accessed through the receiver variable. The parser strips the receiver prefix and creates `PropertyAccessExpr` nodes.

### State Mutation

```go
c.Count++
c.Count--
c.Count = newValue
c.HighestBidder = bidder
```

Go's `++` and `--` statements and assignment work as expected for mutable properties.

### Variable Declarations

```go
msg := runar.Num2Bin(price, 8)     // short variable declaration (let)
var msg runar.ByteString = expr     // explicit type (const if never reassigned)
```

Short variable declarations (`:=`) map to `let` bindings. The compiler infers mutability: if the variable is never reassigned, it is treated as `const`.

### addOutput

```go
c.AddOutput(satoshis, owner, balance)
```

Called as a method on the receiver. Arguments are positional, matching mutable properties in declaration order.

### For Loops

```go
for i := int64(0); i < 10; i++ {
    // body
}
```

The loop bound must be a compile-time constant. The loop is unrolled at compile time.

### If/Else

```go
if amount > threshold {
    // ...
} else if amount == 0 {
    // ...
} else {
    // ...
}
```

### Ternary

Go does not have a ternary operator. Use if/else blocks to achieve the same effect. The compiler may optimize simple if/else patterns to `OP_IF`/`OP_ELSE`/`OP_ENDIF`.

---

## Type Mapping

| Go type | Rúnar type |
|---------|-----------|
| `int64` / `runar.BigInt` | `bigint` |
| `bool` | `boolean` |
| `runar.ByteString` | `ByteString` |
| `runar.PubKey` | `PubKey` |
| `runar.Sig` | `Sig` |
| `runar.Sha256` | `Sha256` |
| `runar.Ripemd160` | `Ripemd160` |
| `runar.Addr` | `Addr` |
| `runar.SigHashPreimage` | `SigHashPreimage` |
| `runar.RabinSig` | `RabinSig` |
| `runar.RabinPubKey` | `RabinPubKey` |
| `runar.Point` | `Point` |

Integer literals are plain Go integers (`0`, `42`, `50000`). The parser treats them as `bigint` values (no `n` suffix needed).

---

## Built-in Functions

Built-in functions are accessed through the `runar` package with PascalCase names:

| Go function | Rúnar built-in |
|------------|---------------|
| `runar.Assert(cond)` | `assert(cond)` |
| `runar.CheckSig(sig, pk)` | `checkSig(sig, pk)` |
| `runar.CheckMultiSig(sigs, pks)` | `checkMultiSig(sigs, pks)` |
| `runar.Hash256(data)` | `hash256(data)` |
| `runar.Hash160(data)` | `hash160(data)` |
| `runar.Sha256(data)` | `sha256(data)` |
| `runar.Ripemd160(data)` | `ripemd160(data)` |
| `runar.Len(data)` | `len(data)` |
| `runar.Num2Bin(n, size)` | `num2bin(n, size)` |
| `runar.Pack(n)` | `pack(n)` |
| `runar.Unpack(data)` | `unpack(data)` |
| `runar.Abs(n)` | `abs(n)` |
| `runar.Min(a, b)` | `min(a, b)` |
| `runar.Max(a, b)` | `max(a, b)` |
| `runar.Within(x, lo, hi)` | `within(x, lo, hi)` |
| `runar.Safediv(a, b)` | `safediv(a, b)` |
| `runar.Safemod(a, b)` | `safemod(a, b)` |
| `runar.Clamp(val, lo, hi)` | `clamp(val, lo, hi)` |
| `runar.Sign(n)` | `sign(n)` |
| `runar.Pow(base, exp)` | `pow(base, exp)` |
| `runar.MulDiv(a, b, c)` | `mulDiv(a, b, c)` |
| `runar.PercentOf(amount, bps)` | `percentOf(amount, bps)` |
| `runar.Sqrt(n)` | `sqrt(n)` |
| `runar.Gcd(a, b)` | `gcd(a, b)` |
| `runar.Divmod(a, b)` | `divmod(a, b)` |
| `runar.Log2(n)` | `log2(n)` |
| `runar.ToBool(n)` | `bool(n)` |
| `runar.CheckPreimage(pre)` | `checkPreimage(pre)` |
| `runar.ExtractLocktime(pre)` | `extractLocktime(pre)` |
| `runar.ExtractOutputHash(pre)` | `extractOutputHash(pre)` |
| `runar.ExtractAmount(pre)` | `extractAmount(pre)` |
| `runar.VerifyRabinSig(msg, sig, pad, pk)` | `verifyRabinSig(msg, sig, pad, pk)` |
| `runar.EcAdd(a, b)` | `ecAdd(a, b)` |
| `runar.EcMul(p, k)` | `ecMul(p, k)` |
| `runar.EcMulGen(k)` | `ecMulGen(k)` |
| `runar.EcNegate(p)` | `ecNegate(p)` |
| `runar.EcOnCurve(p)` | `ecOnCurve(p)` |
| `runar.EcModReduce(value, mod)` | `ecModReduce(value, mod)` |
| `runar.EcEncodeCompressed(p)` | `ecEncodeCompressed(p)` |
| `runar.EcMakePoint(x, y)` | `ecMakePoint(x, y)` |
| `runar.EcPointX(p)` | `ecPointX(p)` |
| `runar.EcPointY(p)` | `ecPointY(p)` |

EC constants are available as package-level variables:

| Go constant | Rúnar constant |
|------------|---------------|
| `runar.EC_P` | `EC_P` |
| `runar.EC_N` | `EC_N` |
| `runar.EC_G` | `EC_G` |

---

## Examples

### P2PKH

```go
package contracts

import "runar"

type P2PKH struct {
    runar.SmartContract
    PubKeyHash runar.Addr `runar:"readonly"`
}

func (c *P2PKH) Unlock(sig runar.Sig, pubKey runar.PubKey) {
    runar.Assert(runar.Hash160(pubKey) == c.PubKeyHash)
    runar.Assert(runar.CheckSig(sig, pubKey))
}
```

### Counter

```go
package contracts

import "runar"

type Counter struct {
    runar.StatefulSmartContract
    Count int64
}

func (c *Counter) Increment() {
    c.Count++
}

func (c *Counter) Decrement() {
    runar.Assert(c.Count > 0)
    c.Count--
}
```

### Escrow

```go
package contracts

import "runar"

type Escrow struct {
    runar.SmartContract
    Buyer  runar.PubKey `runar:"readonly"`
    Seller runar.PubKey `runar:"readonly"`
    Arbiter runar.PubKey `runar:"readonly"`
}

func (c *Escrow) ReleaseBySeller(sig runar.Sig) {
    runar.Assert(runar.CheckSig(sig, c.Seller))
}

func (c *Escrow) ReleaseByArbiter(sig runar.Sig) {
    runar.Assert(runar.CheckSig(sig, c.Arbiter))
}

func (c *Escrow) RefundToBuyer(sig runar.Sig) {
    runar.Assert(runar.CheckSig(sig, c.Buyer))
}

func (c *Escrow) RefundByArbiter(sig runar.Sig) {
    runar.Assert(runar.CheckSig(sig, c.Arbiter))
}
```

### Auction

```go
package contracts

import "runar"

type Auction struct {
    runar.StatefulSmartContract
    Auctioneer    runar.PubKey `runar:"readonly"`
    HighestBidder runar.PubKey
    HighestBid    int64
    Deadline      int64 `runar:"readonly"`
}

func (c *Auction) Bid(bidder runar.PubKey, bidAmount int64) {
    runar.Assert(bidAmount > c.HighestBid)
    runar.Assert(runar.ExtractLocktime(c.TxPreimage) < c.Deadline)

    c.HighestBidder = bidder
    c.HighestBid = bidAmount
}

func (c *Auction) Close(sig runar.Sig) {
    runar.Assert(runar.CheckSig(sig, c.Auctioneer))
    runar.Assert(runar.ExtractLocktime(c.TxPreimage) >= c.Deadline)
}
```

### OraclePriceFeed

```go
package contracts

import "runar"

type OraclePriceFeed struct {
    runar.SmartContract
    OraclePubKey runar.RabinPubKey `runar:"readonly"`
    Receiver     runar.PubKey      `runar:"readonly"`
}

func (c *OraclePriceFeed) Settle(price int64, rabinSig runar.RabinSig, padding runar.ByteString, sig runar.Sig) {
    msg := runar.Num2Bin(price, 8)
    runar.Assert(runar.VerifyRabinSig(msg, rabinSig, padding, c.OraclePubKey))
    runar.Assert(price > 50000)
    runar.Assert(runar.CheckSig(sig, c.Receiver))
}
```

### CovenantVault

```go
package contracts

import "runar"

type CovenantVault struct {
    runar.SmartContract
    Owner     runar.PubKey `runar:"readonly"`
    Recipient runar.Addr   `runar:"readonly"`
    MinAmount int64       `runar:"readonly"`
}

func (c *CovenantVault) Spend(sig runar.Sig, amount int64, txPreimage runar.SigHashPreimage) {
    runar.Assert(runar.CheckSig(sig, c.Owner))
    runar.Assert(runar.CheckPreimage(txPreimage))
    runar.Assert(amount >= c.MinAmount)
}
```

### FungibleToken

```go
package contracts

import "runar"

type FungibleToken struct {
    runar.StatefulSmartContract
    Owner   runar.PubKey      `runar:""`
    Balance int64
    TokenId runar.ByteString  `runar:"readonly"`
}

func (c *FungibleToken) Transfer(sig runar.Sig, to runar.PubKey, amount int64, outputSatoshis int64) {
    runar.Assert(runar.CheckSig(sig, c.Owner))
    runar.Assert(amount > 0)
    runar.Assert(amount <= c.Balance)

    c.AddOutput(outputSatoshis, to, amount)
    c.AddOutput(outputSatoshis, c.Owner, c.Balance - amount)
}

func (c *FungibleToken) Send(sig runar.Sig, to runar.PubKey, outputSatoshis int64) {
    runar.Assert(runar.CheckSig(sig, c.Owner))
    c.AddOutput(outputSatoshis, to, c.Balance)
}

func (c *FungibleToken) Merge(sig runar.Sig, totalBalance int64, outputSatoshis int64) {
    runar.Assert(runar.CheckSig(sig, c.Owner))
    runar.Assert(totalBalance >= c.Balance)
    c.AddOutput(outputSatoshis, c.Owner, totalBalance)
}
```

### SimpleNFT

```go
package contracts

import "runar"

type SimpleNFT struct {
    runar.StatefulSmartContract
    Owner    runar.PubKey     `runar:""`
    TokenId  runar.ByteString `runar:"readonly"`
    Metadata runar.ByteString `runar:"readonly"`
}

func (c *SimpleNFT) Transfer(sig runar.Sig, newOwner runar.PubKey, outputSatoshis int64) {
    runar.Assert(runar.CheckSig(sig, c.Owner))
    c.AddOutput(outputSatoshis, newOwner)
}

func (c *SimpleNFT) Burn(sig runar.Sig) {
    runar.Assert(runar.CheckSig(sig, c.Owner))
}
```

---

## Name Conventions

Go uses PascalCase for exported identifiers. The parser converts to camelCase for the AST:

| Go identifier | AST identifier |
|--------------|----------------|
| `PubKeyHash` (field) | `pubKeyHash` (property) |
| `HighestBidder` (field) | `highestBidder` (property) |
| `Unlock` (method) | `unlock` (method) |
| `ReleaseBySeller` (method) | `releaseBySeller` (method) |

Unexported identifiers (lowercase first letter) are kept as-is.

### Constructor

The constructor is auto-generated from the struct fields. The parser creates a constructor that:
1. Accepts all fields as parameters (in declaration order).
2. Calls `super(...)` with all parameters.
3. Assigns each parameter to the corresponding property.

There is no explicit constructor syntax in the Go format.
