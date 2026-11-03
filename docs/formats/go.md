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

### Operator Precedence

The Go tier parses `.runar.go` with Go's own five-level operator precedence
(`* / % << >> & &^` binds tighter than `+ - | ^`, which binds tighter than the
comparisons, then `&&`, then `||`). TypeScript and the other five tiers parse
`.runar.go` with the C-style ladder Rúnar uses on every other surface
(`* / %` > `+ -` > `<< >>` > relational > equality > `&` > `^` > `|` > `&&` >
`||`). The two ladders agree on most operator pairs, but for some pairs an
unparenthesised `x OP1 y OP2 z` groups left under one scheme and right under
the other — e.g. `a + b << c` is `a + (b << c)` under Go precedence but
`(a + b) << c` under the C ladder; `a & b == c` is `(a & b) == c` under Go but
`a & (b == c)` under the C ladder (and the latter does not even type-check).

Since N-056 (per user decision R51), all seven compilers refuse an
unparenthesised `.runar.go` expression wherever the two schemes would group it
differently, with one shared diagnostic:

```
ambiguous operator precedence in .runar.go: `a <op1> b <op2> c` groups differently
under Go precedence than in Rúnar's other surfaces; add parentheses
```

The refused combinations are the adjacent-operator-class pairs on which the
two ladders disagree (classes: `mul` = `* / %`, `add` = `+ -`, `shift` =
`<< >>`, `and` = `&`, `xor` = `^`, `or` = `|`, `rel` = `< <= > >=`, `eq` =
`== !=`; `&&`/`||` never conflict with anything):

| First operator's class | Second operator's class is one of |
|---|---|
| `shift` | `mul`, `add` |
| `and` | `mul`, `shift`, `add`, `rel`, `eq` |
| `add` | `shift`, `and` |
| `or` | `add`, `xor`, `rel`, `eq` |
| `xor` | `add`, `rel`, `eq` |
| `rel` | `and`, `or`, `xor` |
| `eq` | `and`, `or`, `xor`, `rel` |

Add parentheses to disambiguate — whichever grouping you parenthesise, both
spellings compile once the grouping is explicit:

```go
// Refused: ambiguous operator precedence in .runar.go: `a + b << c` groups
// differently under Go precedence than in Rúnar's other surfaces; add
// parentheses
runar.Assert((a + b << 2) == c.T)

// Accepted: parenthesised, so the grouping is unambiguous (and matches what
// Go itself would do with this source)
runar.Assert((a + (b << 2)) == c.T)
```

Expressions where the two schemes already agree — most operator pairs —
compile unparenthesised exactly as before.

---

## Compiler Directives

```go
type Directives struct {
	runar.SmartContract
	PubKeyHash runar.Addr       `runar:"readonly"`
	DeployTag  runar.ByteString `runar:"readonly,embedAlways"`   // @embedAlways
}

//runar:sighash SINGLE|FORKID
func (c *Directives) SpendSingle(sig runar.Sig, pubKey runar.PubKey) { ... }   // @sighash
```

- `embedAlways` is an option of the `runar` struct tag. The tag holds
  comma-separated options in any order (`readonly`, `embedAlways`).
- `//runar:sighash FLAGS` is a directive comment in Go's own `//go:` style: no
  space after `//`, on its own line above the method. Other comment lines may
  sit between it and the `func`. It must be followed by a space and the flag
  list. `//runar:` with any other name, or a `//runar:sighash` not followed by a
  method, is an error. (`// runar:sighash`, with a space, is an ordinary
  comment.)

The flag list is the same as the `.runar.ts` `@sighash` directive: `|`-separated
names from `ALL`, `NONE`, `SINGLE`, `FORKID`, `ANYONECANPAY`, exactly one base
type (`ALL`/`NONE`/`SINGLE`), and `FORKID` is mandatory. Every tier refuses — it
never ignores — a sighash spelling on a non-public method, two on one method, a
malformed argument, a bad flag set, and either directive on the wrong kind of
member. A `@sighash` / `@embedAlways` COMMENT is rejected on this surface
(the parser does not read comments), with an error naming the spelling above.
See [Compiler Directives](../language-reference.md#compiler-directives) for what
the two directives do, and `examples/go/compiler-directives/` for a worked
port of both (N-093).

## Type Mapping

| Go type | Rúnar type |
|---------|-----------|
| `int64` / `runar.Int` / `runar.Bigint` / `runar.BigintBig` | `bigint` |
| `bool` | `boolean` |
| `runar.ByteString` | `ByteString` |
| `runar.PubKey` | `PubKey` |
| `runar.Sig` | `Sig` |
| `runar.Sha256Digest` | `Sha256` |
| `runar.Ripemd160Hash` | `Ripemd160` |
| `runar.Addr` | `Addr` |
| `runar.SigHashPreimage` | `SigHashPreimage` |
| `runar.RabinSig` | `RabinSig` |
| `runar.RabinPubKey` | `RabinPubKey` |
| `runar.Point` | `Point` |

Integer literals are plain Go integers (`0`, `42`, `50000`). The parser treats them as `bigint` values (no `n` suffix needed).

### ByteString literals

A bare string literal used as a ByteString value is **refused**. Natively
(`go test`) `"006a"` is four ASCII bytes, while the compiler used to read it as
the two hex bytes `00 6a`, so one source meant two different programs. Spell the
value explicitly:

| You mean | Write | Natively | Compiles to |
|---|---|---|---|
| the hex bytes `00 6a` | `runar.HexToBytes("006a")` | decodes hex (panics on odd length or a non-hex digit) | `OP_PUSH 00 6a` |
| the ASCII text `hi` | `runar.ByteString("hi")` | the string's bytes | `OP_PUSH 68 69` |

```go
c.P2pkhPrefix = runar.HexToBytes("1976a914")   // not  c.P2pkhPrefix = "1976a914"
```

The refusal covers `ByteString` and every subtype (`PubKey`, `Sig`, `Addr`,
`Ripemd160Hash`, `Sha256Digest`, `Point`, ...). Every tier prints the same
diagnostic, `file:line:col: bare string literal "006a" is ambiguous in .runar.go
source: ...`, at the literal's opening quote. Still legal: the empty string `""`
(zero bytes either way) and the opcode body of `runar.Asm("51", 0, 1)`, which is
not a ByteString value. The argument of `runar.HexToBytes` is read with Go's
string-literal rules (escapes decoded, a backtick literal verbatim) and the
decoded text must be hex.

### Integers wider than int64

Rúnar's `bigint` is arbitrary precision and so is the Script it compiles to. The
`.runar.go` **runtime** type `runar.Bigint` is `int64`, because Go has no
operator overloading and a `*big.Int` alias would take `+`, `<` and friends away
from contract source — and would silently redefine `==` as pointer identity,
which compiles and compares the wrong thing.

Nothing narrows silently as a result. Every helper in `packages/runar-go` whose
result can exceed `int64` — `Pow`, `MulDiv`, `PercentOf`, `Bin2Num`,
`Num2Bin`, `Bn254FieldNegP`, `Abs`, `Gcd` — panics rather than returning a
truncated answer, and names the wide peer to use instead. `Sqrt` is not on
that list: √int64 always fits int64, and its only panic is `"sqrt: negative
input"`, which does not name `SqrtBig`.

`Abs` and `Gcd` were absent from that list, and from the behaviour, until the
sentence was checked against the code. `Abs(math.MinInt64)` returned
`math.MinInt64` — a negative absolute value — and `Gcd(math.MinInt64, 0)`
returned `math.MaxInt64` as an "overflow sentinel", which is a wrong answer
rather than an error. Script numbers are arbitrary-width after Genesis, so the
emitted `OP_ABS` computes the true `2^63`: a contract guarding
`runar.Assert(runar.Abs(x) > 0)` was refused by `go test` and **spent on chain**
for `x = -2^63`.

`TestNarrowHelpersRefuseWhatTheyCannotHold` covers `Abs` and `Gcd`
specifically. It does **not** enforce the list above — this sentence previously
claimed it did, which would have made the list appear machine-checked
when two rows were. The other six are each covered by their own test
(`TestPow_Overflow`, `TestMulDiv_Overflow`, `TestPercentOf_Overflow`, and the
`Bin2Num` / `Num2Bin` / `Bn254FieldNegP` width tests), so the behaviour is
guarded — but adding another helper to this list without a test would be caught
by nothing. The list is maintained by hand. Treat it that way.

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

Four `*Big` helpers are not operators but ordinary builtins, and are callable
from contract source the same way. The `Big` suffix names a different Go
**runtime** type (`*big.Int`, so the Go-side mock does not narrow), not a
different Script operation — each lowers to the unsuffixed builtin and emits
identical bytes:

| Contract source | Rúnar node |
|---|---|
| `runar.AbsBig(n)` | `abs(n)` |
| `runar.GcdBig(a, b)` | `gcd(a, b)` |
| `runar.Num2BinBig(n, size)` | `num2bin(n, size)` |
| `runar.Bin2NumBig(data)` | `bin2num(data)` |

`AbsBig` and `GcdBig` are the peers `Abs(math.MinInt64)` and
`Gcd(math.MinInt64, 0)` name when they panic. Until R-AbsGcd no tier's Go
builtin table carried them, so a contract author following that advice got
`unknown function 'absBig'` from all seven and a `runar.BigintBig` value could
not be passed to abs or gcd at all. The pair is now gated cross-tier by
`conformance/subtype-parity/GoBigintBigOperators.runar.go` and its `abs`/`gcd`
reference half, which requires all seven tiers to accept it AND to emit the
bytes the unsuffixed spelling emits.

The other wide helpers the package header mentions — `PowBig`, `MulDivBig`,
`PercentOfBig`, `SqrtBig`, `Log2Big` — are Go-callable only. They are not in
any tier's builtin table and are **not** spellings a `.runar.go` contract can
use.

`examples/go/ec-primitives` and `examples/go/ec-demo` use this for 256-bit
secp256k1 coordinates; `examples/go/p256-primitives` and
`examples/go/p384-primitives` for NIST scalars.

One thing has no Go spelling: a bigint **literal** wider than `int64`. Go
constants are exact and must fit the type they land in, and no constant
expression converts to a pointer, so
`115792089237316195423570985008687907852837564279074904382605163141518161494337`
cannot appear in a `.runar.go` file at all. A contract needing one is written in
any of the other eight formats — every compiler accepts all nine and produces
byte-identical Script. Three of the five ports in `examples/go` that still carry
`//go:build ignore` (`integer-boundary`, `schnorr-zkp`,
`go-dsl-bytestring-literal`) are held out by exactly this — they need such a
literal. The numeric limit is **not** the whole list, and reading it as such is
how two of the exclusions stayed unexamined: the other two are
`all-readonly-cleanstack` (Go's unused-local rule vs a deliberately unused
binding) and `multisig-2of3` (the `[N]T{...}` composite literal three of the
seven `.runar.go` parsers require does not convert to the slice the mock's
`CheckMultiSig` takes). Each of the five says which it is at the top of its own
file, and `examples/go/build-exclusions` is the ratchet that keeps the set
honest — it asserts the set exactly, so it has to move in the same commit as an
exclusion does.

`byte-builtins` and `state-ripemd160` were on that list until the RIPEMD-160
digest type gained its real name: both needed `runar.Ripemd160Hash` in type
position, which no tier's `.runar.go` type table mapped. Both build and run
under `go test` now.

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
`runar.Sha256(x)`. Go cannot bind one identifier to both, so `packages/runar-go`
binds the **function** in each case and gives the digest types distinct names:

| Purpose | Spelling |
|---|---|
| the SHA-256 **hash** | `runar.Sha256(data)` (alias `runar.Sha256Hash`) |
| the SHA-256 **digest type** | `runar.Sha256Digest` |
| the RIPEMD-160 **hash** | `runar.Ripemd160(data)` |
| the RIPEMD-160 **digest type** | `runar.Ripemd160Hash` |

`runar.Sha256Hash` is a real second contract spelling: it is a compatibility
alias carried in all seven tiers' builtin tables, and contracts use it today
(`examples/go/r1-k1-wallet`, `examples/go/byte-builtins`). `Ripemd160Func` is
**not** its counterpart, and this table used to imply it was. It is the Go-side
original name that `runar.Ripemd160` delegates to in one line — callable from
Go test code, in no tier's builtin table, and a contract that writes it is
rejected by all seven with `unknown function 'ripemd160Func'` (measured). Write
`runar.Ripemd160(data)`; it needs no alias because nothing shadows it in call
position. `tests/go-md-call-spellings-resolve.test.ts` now holds every
`(alias ...)` in this file to that standard.

Use the `…Digest` / `…Hash` type names in field and parameter annotations. They
are what a `.runar.go` file needs to be **both** valid Go and valid Rúnar, which
is the whole point of this surface: the same file compiles against the mock
types under `go test` and through the Rúnar frontend. The bare `runar.Sha256` /
`runar.Ripemd160` spellings in type position are still accepted by the Rúnar
parser for backwards compatibility, but they do not compile as Go —
`runar.Ripemd160 (value of type func(...) ...) is not a type` — so a file using
them gets only half of what the surface is for.

In **call** position the rule is unambiguous: the name is the **function** and
the table above applies — it hashes. There is deliberately no conversion
spelling for these two. Both digest types are `ByteString` subtypes, so a
conversion would have been an identity on the value and emitted no bytes; use
the value directly, or `runar.ToByteString(...)` if you need an explicit
widening. Reading `runar.Sha256(preimage)` as a *cast* is not a style
preference: it drops the hash opcode, and two tiers once shipped that, which
made the digest baked into the locking script the spending key. See
`conformance/go_surface_hash_spelling_execution_test.go`, and
`conformance/subtype-parity/GoDigestTypeSpellings.runar.go` for the type half.

### EC constants are NOT reachable from this surface (measured)

| Go constant | Rúnar constant | Status |
|------------|---------------|--------|
| `runar.EC_P` | `EC_P` | **not available** |
| `runar.EC_N` | `EC_N` | **not available** |
| `runar.EC_G` | `EC_G` | **not available** |

This table used to say the three were "available as package-level variables".
They are not, in either half of what a `.runar.go` file has to be:

- **As Go.** `packages/runar-go` does not export `EC_P`, `EC_N` or `EC_G`. The
  values exist as the unexported `ecP` / `ecN` / `ecGX` in `ec.go`, so
  `runar.EC_P` does not compile.
- **As Rúnar.** No tier compiles it, and they fail in two different ways. The
  go, ts, rust, zig and ruby Go-surface parsers have no entry for the name, so
  the default leading-character rule turns it into `eC_P` and the type checker
  answers `Undefined variable 'eC_P'`. The python and java parsers DO map it to
  `EC_P`, get past the type checker, and then fail in stack lowering with
  `method parameter 'EC_P' is not on the stack` — a message about a parameter
  that does not exist.

The constants are real in the TypeScript surface
(`packages/runar-lang/src/ec.ts` exports all three). Reaching them from
`.runar.go` needs an SDK export plus a parser entry in all seven tiers, which is
not done. Until then, write the value as a literal in a format that can hold one
— see "Integers wider than int64" above for why `.runar.go` cannot.

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
    // The bid must be paid into the pot (continuation = prior pot + bid).
    runar.Assert(runar.ContinuationAmount() >= runar.ExtractAmount(c.TxPreimage)+bidAmount)
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

### Identifier Collision Rule

The PascalCase to camelCase conversion is not injective: two different identifiers may convert to the same Rúnar name (e.g., `K` and `k` both become `k`). A contract that declares two distinct source spellings that map to one Rúnar name is refused with: `identifier collision: '<a>' and '<b>' both convert to '<name>'; rename one of them`. Single use of one spelling is fine.

### Constructor

The constructor is auto-generated from the struct fields. The parser creates a constructor that:
1. Accepts fields **without initializers** as parameters (in declaration order).
2. Calls `super(...)` with all parameters.
3. Assigns each parameter to the corresponding property.

Properties with defaults (set via the `init()` method) are excluded from the constructor parameters. There is no explicit constructor syntax in the Go format.
