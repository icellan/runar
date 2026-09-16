# Go Contract Format

**Status:** Experimental
**File extension:** `.runar.go`
**Supported compilers:** TypeScript, Go, Rust, Python, Zig, Ruby, Java (all seven)

---

## Overview

The Go format lets you write Rúnar contracts as idiomatic Go code. Contracts are Go structs embedding `runar.SmartContract` or `runar.StatefulSmartContract`, with methods defined as receiver functions. The Go compiler parses these directly -- no intermediate conversion to TypeScript.

This format is supported by all seven compilers (TypeScript, Go, Rust, Python, Zig, Ruby, Java) via their respective `parser_go*` modules, so `.runar.go` contracts produce identical Bitcoin Script across compilers.

---

## Syntax

### Package and Imports

```go
package contracts

import runar "github.com/icellan/runar/packages/runar-go"
```

The package name is ignored by the compiler. The `runar` import provides the base types and built-in functions. The import is aliased to `runar` for use in the contract code.

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

### Property Initializers

Properties can have default values using a private `init()` method on the struct. The `init()` method must be unexported (lowercase), take no parameters, and contain only `self.Property = value` assignments with literal values:

```go
type GameBoard struct {
    runar.StatefulSmartContract
    Count    int64
    Active   runar.Bool `runar:"readonly"`
    Owner    runar.PubKey `runar:"readonly"`
}

func (c *GameBoard) init() {
    c.Count = 0
    c.Active = true
}
```

Properties assigned in `init()` are excluded from the auto-generated constructor. Only properties without defaults (`Owner` above) need to be passed as constructor arguments. The `init()` method is consumed by the parser and does not appear in the compiled output.

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
| `int64` / `runar.Int` / `runar.Bigint` / `runar.BigintBig` | `bigint` |
| `bool` | `boolean` |
| `runar.ByteString` | `ByteString` |
| `runar.PubKey` | `PubKey` |
| `runar.Sig` | `Sig` |
| `runar.Sha256Digest` | `Sha256` |
| `runar.Ripemd160` | `Ripemd160` |
| `runar.Addr` | `Addr` |
| `runar.SigHashPreimage` | `SigHashPreimage` |
| `runar.RabinSig` | `RabinSig` |
| `runar.RabinPubKey` | `RabinPubKey` |
| `runar.Point` | `Point` |

Integer literals are plain Go integers (`0`, `42`, `50000`). The parser treats them as `bigint` values (no `n` suffix needed).

### Integers wider than int64

Rúnar's `bigint` is arbitrary precision and so is the Script it compiles to. The
`.runar.go` **runtime** type `runar.Bigint` is `int64`, because Go has no
operator overloading and a `*big.Int` alias would take `+`, `<` and friends away
from contract source — and would silently redefine `==` as pointer identity,
which compiles and compares the wrong thing.

Nothing narrows silently as a result. Every helper in `packages/runar-go` whose
result can exceed `int64` — `Pow`, `MulDiv`, `PercentOf`, `Sqrt`, `Bin2Num`,
`Num2Bin`, `Bn254FieldNegP` — panics rather than returning a truncated answer,
and names the wide peer to use instead.

For values past 2^63, type the field or parameter `runar.BigintBig` (`*big.Int`)
and spell the arithmetic with the helper functions. **Both type names lower to
the same `bigint` primitive, and the helpers lower to the same operator nodes,
so the emitted Script is byte-identical either way:**

| Contract source | Rúnar node |
|---|---|
| `a + b` / `runar.BigintBigAdd(a, b)` | `+` |
| `a - b` / `runar.BigintBigSub(a, b)` | `-` |
| `a * b` / `runar.BigintBigMul(a, b)` | `*` |
| `a / b` / `runar.BigintBigDiv(a, b)` | `/` |
| `a % b` / `runar.BigintBigMod(a, b)` | `%` |
| `a == b` / `runar.BigintBigEqual(a, b)` | `===` |
| `a != b` / `runar.BigintBigNotEqual(a, b)` | `!==` |
| `a < b` / `runar.BigintBigLess(a, b)` | `<` |
| `a <= b` / `runar.BigintBigLessEq(a, b)` | `<=` |
| `a > b` / `runar.BigintBigGreater(a, b)` | `>` |
| `a >= b` / `runar.BigintBigGreaterEq(a, b)` | `>=` |

`examples/go/ec-primitives` and `examples/go/ec-demo` use this for 256-bit
secp256k1 coordinates; `examples/go/p256-primitives` and
`examples/go/p384-primitives` for NIST scalars.

One thing has no Go spelling: a bigint **literal** wider than `int64`. Go
constants are exact and must fit the type they land in, and no constant
expression converts to a pointer, so
`115792089237316195423570985008687907852837564279074904382605163141518161494337`
cannot appear in a `.runar.go` file at all. A contract needing one is written in
any of the other eight formats — every compiler accepts all nine and produces
byte-identical Script. The three ports in `examples/go` that still carry
`//go:build ignore` for a numeric reason (`integer-boundary`, `schnorr-zkp`,
`go-dsl-bytestring-literal`) are exactly the ones that need such a literal;
`examples/go/build-exclusions` is the ratchet that keeps that set honest.

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
| `runar.Cat(a, b)` | `cat(a, b)` |
| `runar.Substr(data, start, len)` | `substr(data, start, len)` |
| `runar.Split(data, index)` | `split(data, index)` |
| `runar.Left(data, len)` | `left(data, len)` |
| `runar.Right(data, len)` | `right(data, len)` |
| `runar.ReverseBytes(data)` | `reverseBytes(data)` |
| `runar.Bin2Num(data)` | `bin2num(data)` |
| `runar.Int2Str(n, size)` | `int2str(n, size)` |
| `runar.ToByteString(hex)` | `toByteString(hex)` |
| `runar.ExtractVersion(pre)` | `extractVersion(pre)` |
| `runar.ExtractHashPrevouts(pre)` | `extractHashPrevouts(pre)` |
| `runar.ExtractHashSequence(pre)` | `extractHashSequence(pre)` |
| `runar.ExtractOutpoint(pre)` | `extractOutpoint(pre)` |
| `runar.ExtractScriptCode(pre)` | `extractScriptCode(pre)` |
| `runar.ExtractSequence(pre)` | `extractSequence(pre)` |
| `runar.ExtractSigHashType(pre)` | `extractSigHashType(pre)` |
| `runar.ExtractInputIndex(pre)` | `extractInputIndex(pre)` |
| `runar.ExtractOutputs(pre)` | `extractOutputs(pre)` |
| `runar.VerifyWOTS(msg, sig, pubkey)` | `verifyWOTS(msg, sig, pubkey)` |
| `runar.VerifySLHDSA_SHA2_128s(msg, sig, pubkey)` | `verifySLHDSA_SHA2_128s(msg, sig, pubkey)` |
| `runar.VerifySLHDSA_SHA2_128f(msg, sig, pubkey)` | `verifySLHDSA_SHA2_128f(msg, sig, pubkey)` |
| `runar.VerifySLHDSA_SHA2_192s(msg, sig, pubkey)` | `verifySLHDSA_SHA2_192s(msg, sig, pubkey)` |
| `runar.VerifySLHDSA_SHA2_192f(msg, sig, pubkey)` | `verifySLHDSA_SHA2_192f(msg, sig, pubkey)` |
| `runar.VerifySLHDSA_SHA2_256s(msg, sig, pubkey)` | `verifySLHDSA_SHA2_256s(msg, sig, pubkey)` |
| `runar.VerifySLHDSA_SHA2_256f(msg, sig, pubkey)` | `verifySLHDSA_SHA2_256f(msg, sig, pubkey)` |

### Names that are both a type and a function

`Sha256` and `Ripemd160` are Rúnar **type** names as well as Rúnar **builtin**
names, and the Go surface spells a type conversion and a call identically —
`runar.Sha256(x)`. The rule is positional and has no exceptions:

- In **type** position (`Digest runar.Sha256`, `func (c *C) M(d runar.Sha256)`)
  the name is the type.
- In **call** position (`runar.Sha256(preimage)`) the name is the **function**,
  and the table above applies: it hashes.

There is deliberately no conversion spelling for these two. Both are
`ByteString` subtypes, so a conversion would have been an identity on the value
and emitted no bytes; use the value directly, or `runar.ToByteString(...)` if you
need an explicit widening. `runar.Sha256Hash(...)` is an unambiguous alias for
the SHA-256 call if you prefer to avoid the overloaded spelling entirely.

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

import runar "github.com/icellan/runar/packages/runar-go"

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

import runar "github.com/icellan/runar/packages/runar-go"

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

import runar "github.com/icellan/runar/packages/runar-go"

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

import runar "github.com/icellan/runar/packages/runar-go"

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

import runar "github.com/icellan/runar/packages/runar-go"

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

import runar "github.com/icellan/runar/packages/runar-go"

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

import runar "github.com/icellan/runar/packages/runar-go"

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

import runar "github.com/icellan/runar/packages/runar-go"

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
1. Accepts fields **without initializers** as parameters (in declaration order).
2. Calls `super(...)` with all parameters.
3. Assigns each parameter to the corresponding property.

Properties with defaults (set via the `init()` method) are excluded from the constructor parameters. There is no explicit constructor syntax in the Go format.
