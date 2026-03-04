# Rúnar Language Reference

Rúnar is a strict subset of TypeScript designed for compilation to Bitcoin SV Script. Every Rúnar source file is valid TypeScript -- it type-checks with `tsc` and gets full IDE support -- but only the constructs described in this document are accepted by the Rúnar compiler.

---

## Contract Structure

A Rúnar source file contains exactly one contract class that extends `SmartContract` (stateless) or `StatefulSmartContract` (stateful):

**Stateless contract** — all properties are `readonly`:

```typescript
import { SmartContract, assert, checkSig } from 'runar-lang';
import type { PubKey, Sig } from 'runar-lang';

class P2PKH extends SmartContract {
  readonly pubKeyHash: Addr;

  constructor(pubKeyHash: Addr) {
    super(pubKeyHash);
    this.pubKeyHash = pubKeyHash;
  }

  public unlock(sig: Sig, pubKey: PubKey) {
    assert(hash160(pubKey) === this.pubKeyHash);
    assert(checkSig(sig, pubKey));
  }
}
```

**Stateful contract** — has mutable properties, state persists across transactions:

```typescript
import { StatefulSmartContract, assert } from 'runar-lang';

class Counter extends StatefulSmartContract {
  count: bigint;  // mutable = stateful

  constructor(count: bigint) {
    super(count);
    this.count = count;
  }

  public increment() {
    this.count++;
  }
}
```

`StatefulSmartContract` automatically handles the OP_PUSH_TX pattern: preimage verification at method entry and state continuation at exit for any method that modifies state. Access preimage fields via `this.txPreimage`.

### Rules

- One class per file, extending `SmartContract` or `StatefulSmartContract`.
- No decorators, no generics on the class.
- Imports are restricted to `runar-lang` (or `runar` / `runar/builtins`).

---

## Properties

Properties declare the contract's on-chain state.

### Readonly Properties

```typescript
readonly pubKeyHash: Addr;
```

- Set once in the constructor. Cannot be reassigned.
- Embedded directly in the locking script as push data at deploy time.
- The compiler may inline the value at all use sites.

### Mutable Properties

```typescript
count: bigint;
```

- Initialized in the constructor. Can be reassigned in public methods.
- Changes are propagated across transactions using the OP_PUSH_TX pattern.
- Having any mutable property makes the contract **stateful**. Use `StatefulSmartContract` as the base class.

Properties must not have initializers at the declaration site. All initialization happens in the constructor.

---

## Methods

### Public Methods

Public methods are **spending entry points**. Each corresponds to a path in the locking script.

```typescript
public unlock(sig: Sig, pubKey: PubKey) {
  assert(hash160(pubKey) === this.pubKeyHash);
  assert(checkSig(sig, pubKey));
}
```

- Must return `void`.
- In `SmartContract`, must end with an `assert(...)` call as the final statement. In `StatefulSmartContract`, the compiler auto-injects the final assert.
- Parameters form part of the unlocking script (scriptSig).
- When a contract has multiple public methods, a dispatch table is generated. The unlocking script includes a method index.

### Private Methods

Private methods are **helpers** that are inlined at call sites during compilation.

```typescript
private square(x: bigint): bigint {
  return x * x;
}
```

- May return a value.
- Cannot be called from outside the contract.
- Recursion (direct or mutual) is disallowed.

---

## Types

### Primitive Types

| Type | Description | Script Encoding |
|------|-------------|-----------------|
| `bigint` | Arbitrary-precision integer | Script number (little-endian, sign-magnitude) |
| `boolean` | `true` or `false` | `OP_TRUE` (0x01) or `OP_FALSE` (empty) |

`bigint` literals use the `n` suffix: `0n`, `42n`, `-1n`.

### ByteString Types

| Type | Size (bytes) | Description |
|------|-------------|-------------|
| `ByteString` | variable | Raw immutable byte sequence |
| `PubKey` | 33 | Compressed secp256k1 public key |
| `Sig` | 71-73 | DER-encoded ECDSA signature + sighash byte |
| `Sha256` | 32 | SHA-256 digest |
| `Ripemd160` | 20 | RIPEMD-160 digest |
| `Addr` | 20 | Bitcoin address (hash160 of pubkey) |
| `SigHashPreimage` | variable | Transaction sighash preimage for OP_PUSH_TX |

All domain types (`PubKey`, `Sig`, etc.) are subtypes of `ByteString`. A domain type value can be used wherever a `ByteString` is expected (widening), but not the reverse (narrowing requires an explicit cast function).

### Rabin Types

| Type | Description | Underlying |
|------|-------------|------------|
| `RabinSig` | Rabin signature value | `bigint` |
| `RabinPubKey` | Rabin public key | `bigint` |

Both are subtypes of `bigint`.

### FixedArray

```typescript
const keys: FixedArray<PubKey, 3> = [pk1, pk2, pk3];
const first: PubKey = keys[0n];
```

- `N` must be a compile-time constant positive integer literal.
- Represented as N consecutive stack items in Script.
- Supports index read (`arr[i]`), index write (`arr[i] = val`), and `.length`.

### Disallowed Types

`number`, `string`, `any`, `unknown`, `never`, `null`, `undefined`, `Array<T>`, `T[]`, object types, interfaces, type aliases, union types, `Map`, `Set`, `Promise`, and all standard library types.

---

## Operators

### Arithmetic (operands: `bigint`)

| Operator | Description | Opcode |
|----------|-------------|--------|
| `a + b` | Addition | `OP_ADD` |
| `a - b` | Subtraction | `OP_SUB` |
| `a * b` | Multiplication | `OP_MUL` |
| `a / b` | Truncating division | `OP_DIV` |
| `a % b` | Modulo | `OP_MOD` |

### ByteString Concatenation

| Operator | Description | Opcode |
|----------|-------------|--------|
| `a + b` | Concatenation (both `ByteString`) | `OP_CAT` |

Mixing `bigint` and `ByteString` with `+` is a compile-time error.

### Comparison (operands: `bigint`)

| Operator | Description | Opcode |
|----------|-------------|--------|
| `<` | Less than | `OP_LESSTHAN` |
| `<=` | Less than or equal | `OP_LESSTHANOREQUAL` |
| `>` | Greater than | `OP_GREATERTHAN` |
| `>=` | Greater than or equal | `OP_GREATERTHANOREQUAL` |

### Equality (operands: same type or subtype)

| Operator | Description | Opcode |
|----------|-------------|--------|
| `===` / `==` | Equality | `OP_NUMEQUAL` (bigint) or `OP_EQUAL` (bytes) |
| `!==` / `!=` | Inequality | `OP_NUMEQUAL OP_NOT` (bigint) or `OP_EQUAL OP_NOT` (bytes) |

Both `==` and `===` have identical semantics in Rúnar (no type coercion). The compiler recommends `===`.

### Logical (operands: `boolean`)

| Operator | Description | Opcode |
|----------|-------------|--------|
| `&&` | Logical AND | `OP_BOOLAND` |
| `\|\|` | Logical OR | `OP_BOOLOR` |

Both operands are always evaluated (eager evaluation). At the ANF IR level, both sides are lowered as flat `bin_op` nodes -- there is no short-circuit lowering. At the Stack IR/opcode level, these compile to `OP_BOOLAND` and `OP_BOOLOR` respectively.

### Bitwise (operands: `bigint`)

| Operator | Description | Opcode |
|----------|-------------|--------|
| `a & b` | Bitwise AND | `OP_AND` |
| `a \| b` | Bitwise OR | `OP_OR` |
| `a ^ b` | Bitwise XOR | `OP_XOR` |
| `~a` | Bitwise NOT | `OP_INVERT` |

### Shift (operands: `bigint`)

| Operator | Description | Opcode |
|----------|-------------|--------|
| `a << b` | Left shift | `OP_LSHIFT` |
| `a >> b` | Right shift | `OP_RSHIFT` |

### Unary

| Operator | Description | Opcode |
|----------|-------------|--------|
| `!a` | Logical NOT (boolean) | `OP_NOT` |
| `-a` | Arithmetic negation (bigint) | `OP_NEGATE` |

### Ternary

```typescript
const x = cond ? a : b;
```

Compiles to `OP_IF <a> OP_ELSE <b> OP_ENDIF`. Both branches must produce the same stack depth.

---

## Statements

### Variable Declarations

```typescript
const x: bigint = 42n;   // immutable
let y = hash160(pubKey);  // mutable, type inferred
```

Type annotations can be omitted when an initializer is present (the type is inferred).

### Assignment

```typescript
y = 100n;              // reassign a let variable
this.count = newCount; // update a mutable property
arr[0n] = newVal;      // update a FixedArray element
```

Assigning to a `const` variable or a `readonly` property is a compile-time error.

### If / Else

```typescript
if (amount > threshold) {
  // ...
} else if (amount === 0n) {
  // ...
} else {
  // ...
}
```

### Bounded For Loops

```typescript
for (let i: bigint = 0n; i < 10n; i++) {
  // loop body
}
```

- The bound (right side of the comparison) must be a compile-time constant.
- Only simple increment (`++`) or decrement (`--`) is allowed.
- Loops are unrolled at compile time -- there are no runtime loops in Bitcoin Script.

### Assert

```typescript
assert(condition);            // fails the script if condition is false
assert(condition, "message"); // message is stripped at compile time
```

`assert` compiles to `OP_VERIFY` (or the condition is left on the stack if it is the final statement).

### Return (private methods only)

```typescript
private helper(x: bigint): bigint {
  return x * 2n;
}
```

---

## Built-in Functions

### Cryptographic

| Function | Signature | Opcode(s) |
|----------|-----------|-----------|
| `checkSig` | `(sig: Sig, pk: PubKey) => boolean` | `OP_CHECKSIG` |
| `checkMultiSig` | `(sigs: Sig[], pks: PubKey[]) => boolean` | `OP_CHECKMULTISIG` |
| `hash256` | `(data: ByteString) => Sha256` | `OP_HASH256` (double SHA-256) |
| `hash160` | `(data: ByteString) => Ripemd160` | `OP_HASH160` (SHA-256 then RIPEMD-160) |
| `sha256` | `(data: ByteString) => Sha256` | `OP_SHA256` |
| `ripemd160` | `(data: ByteString) => Ripemd160` | `OP_RIPEMD160` |

### Byte Operations

| Function | Signature | Opcode(s) |
|----------|-----------|-----------|
| `len` | `(data: ByteString) => bigint` | `OP_SIZE OP_NIP` |
| `reverseBytes` | `(data: ByteString) => ByteString` | `OP_SPLIT` / `OP_CAT` loop (bounded, max 520 bytes) |
| `toByteString` | `(hex: string) => ByteString` | Compile-time literal construction |
| `cat` | `(a: ByteString, b: ByteString) => ByteString` | `OP_CAT` |
| `substr` | `(data: ByteString, start: bigint, length: bigint) => ByteString` | `OP_SPLIT` (twice) |
| `split` | `(data: ByteString, pos: bigint) => ByteString` | `OP_SPLIT` — returns two values on the stack (left and right) |
| `left` | `(data: ByteString, n: bigint) => ByteString` | `OP_SPLIT OP_DROP` — returns the leftmost n bytes |
| `right` | `(data: ByteString, n: bigint) => ByteString` | `OP_SWAP OP_SIZE OP_ROT OP_SUB OP_SPLIT OP_NIP` — returns the rightmost n bytes |
| `int2str` | `(n: bigint, size: bigint) => ByteString` | `OP_NUM2BIN` |
| `bin2num` | `(data: ByteString) => bigint` | `OP_BIN2NUM` |

### Conversion

| Function | Signature | Opcode(s) |
|----------|-----------|-----------|
| `pack` | `(n: bigint) => ByteString` | No-op (type-level cast) |
| `unpack` | `(data: ByteString) => bigint` | `OP_BIN2NUM` |
| `num2bin` | `(n: bigint, size: bigint) => ByteString` | `OP_NUM2BIN` |

### Math

#### Basic Math (single-opcode)

| Function | Signature | Opcode(s) |
|----------|-----------|-----------|
| `abs` | `(n: bigint) => bigint` | `OP_ABS` |
| `min` | `(a: bigint, b: bigint) => bigint` | `OP_MIN` |
| `max` | `(a: bigint, b: bigint) => bigint` | `OP_MAX` |
| `within` | `(x: bigint, lo: bigint, hi: bigint) => boolean` | `OP_WITHIN` |
| `sign` | `(n: bigint) => bigint` | `OP_DUP OP_IF OP_DUP OP_ABS OP_SWAP OP_DIV OP_ENDIF` — returns -1, 0, or 1 (guards against div-by-zero when n=0) |
| `bool` | `(n: bigint) => boolean` | `OP_0NOTEQUAL` — converts integer to boolean |

#### Safe Arithmetic

| Function | Signature | Opcode(s) |
|----------|-----------|-----------|
| `safediv` | `(a: bigint, b: bigint) => bigint` | `OP_DUP OP_0NOTEQUAL OP_VERIFY OP_DIV` — aborts if `b` is zero |
| `safemod` | `(a: bigint, b: bigint) => bigint` | `OP_DUP OP_0NOTEQUAL OP_VERIFY OP_MOD` — aborts if `b` is zero |

#### Clamping and Scaling

| Function | Signature | Opcode(s) |
|----------|-----------|-----------|
| `clamp` | `(val: bigint, lo: bigint, hi: bigint) => bigint` | `OP_MAX OP_MIN` — constrains `val` to `[lo, hi]` |
| `mulDiv` | `(a: bigint, b: bigint, c: bigint) => bigint` | `OP_MUL OP_DIV` — computes `(a * b) / c` |
| `percentOf` | `(amount: bigint, bps: bigint) => bigint` | `OP_MUL <10000> OP_DIV` — basis-point percentage: `(amount * bps) / 10000` |

#### Advanced Math (multi-opcode sequences)

| Function | Signature | Opcode(s) |
|----------|-----------|-----------|
| `pow` | `(base: bigint, exp: bigint) => bigint` | 32-iteration bounded conditional multiply loop |
| `sqrt` | `(n: bigint) => bigint` | 16-iteration Newton's method: `guess = (guess + n/guess) / 2` |
| `gcd` | `(a: bigint, b: bigint) => bigint` | 256-iteration Euclidean algorithm |
| `divmod` | `(a: bigint, b: bigint) => bigint` | `OP_2DUP OP_DIV OP_ROT OP_ROT OP_MOD OP_DROP` — computes both quotient and remainder, returns quotient (the remainder is discarded). Despite the name suggesting both values, only the quotient is returned to the caller. |
| `log2` | `(n: bigint) => bigint` | 64-iteration unrolled bit-scanning loop — exact floor(log2(n)) |

> **Note on `pow`:** For compile-time constant exponents (e.g. `pow(x, 3n)`), the constant folder evaluates the result at compile time. For runtime exponents, a bounded 32-iteration loop is emitted, supporting exponents up to 32.
>
> **Note on `sqrt`:** Returns the integer (floor) square root. For `sqrt(10n)`, the result is `3n`.
>
> **Note on `log2`:** This computes the exact floor(log2(n)) using a 64-iteration unrolled bit-scanning loop that right-shifts the input until it reaches 1, counting iterations.

### Control

| Function | Signature | Opcode(s) |
|----------|-----------|-----------|
| `assert` | `(cond: boolean) => void` | `OP_VERIFY` |

### Preimage (Stateful Contracts)

In `StatefulSmartContract`, `checkPreimage` and state continuation are handled automatically by the compiler. The preimage is available via `this.txPreimage`. Use the `extract*` functions to read specific fields:

| Function | Signature | Description |
|----------|-----------|-------------|
| `this.txPreimage` | `SigHashPreimage` | Implicit preimage property (StatefulSmartContract only) |
| `extractVersion` | `(preimage: SigHashPreimage) => bigint` | Extract tx version (nVersion, 4 bytes at offset 0) |
| `extractHashPrevouts` | `(preimage: SigHashPreimage) => Sha256` | Extract hashPrevouts (32 bytes at offset 4) |
| `extractHashSequence` | `(preimage: SigHashPreimage) => Sha256` | Extract hashSequence (32 bytes at offset 36) |
| `extractOutpoint` | `(preimage: SigHashPreimage) => ByteString` | Extract outpoint (txid + vout, 36 bytes at offset 68) |
| `extractScriptCode` | `(preimage: SigHashPreimage) => ByteString` | Extract scriptCode (variable length, follows outpoint) |
| `extractAmount` | `(preimage: SigHashPreimage) => bigint` | Extract input amount (value in satoshis, 8 bytes) |
| `extractSequence` | `(preimage: SigHashPreimage) => bigint` | Extract input nSequence (4 bytes) |
| `extractOutputHash` | `(preimage: SigHashPreimage) => Sha256` | Extract hashOutputs (32 bytes) |
| `extractOutputs` | `(preimage: SigHashPreimage) => Sha256` | Alias for `extractOutputHash` |
| `extractLocktime` | `(preimage: SigHashPreimage) => bigint` | Extract nLocktime (4 bytes) |
| `extractSigHashType` | `(preimage: SigHashPreimage) => bigint` | Extract sighash type (4 bytes, e.g. 0x41 for ALL\|FORKID) |
| `extractInputIndex` | `(preimage: SigHashPreimage) => bigint` | Extract prevout index (vout) from the outpoint field |

### Oracle

| Function | Signature | Description |
|----------|-----------|-------------|
| `verifyRabinSig` | `(msg, sig, padding, pubKey) => boolean` | Verify a Rabin signature |

### Post-Quantum Signature Verification (Experimental)

> These functions are experimental and APIs may change.

| Function | Signature | Description |
|----------|-----------|-------------|
| `verifyWOTS` | `(msg, sig, pubkey) => boolean` | WOTS+ verification (w=16, SHA-256). One-time use per keypair. Sig: 2,144 B. |
| `verifySLHDSA_SHA2_128s` | `(msg, sig, pubkey) => boolean` | SLH-DSA-SHA2-128s (FIPS 205). Stateless, multi-use. Sig: 7,856 B. |
| `verifySLHDSA_SHA2_128f` | `(msg, sig, pubkey) => boolean` | SLH-DSA-SHA2-128f. Fast variant. Sig: 17,088 B. |
| `verifySLHDSA_SHA2_192s` | `(msg, sig, pubkey) => boolean` | SLH-DSA-SHA2-192s. 192-bit security. Sig: 16,224 B. |
| `verifySLHDSA_SHA2_192f` | `(msg, sig, pubkey) => boolean` | SLH-DSA-SHA2-192f. Fast variant. Sig: 35,664 B. |
| `verifySLHDSA_SHA2_256s` | `(msg, sig, pubkey) => boolean` | SLH-DSA-SHA2-256s. 256-bit security. Sig: 29,792 B. |
| `verifySLHDSA_SHA2_256f` | `(msg, sig, pubkey) => boolean` | SLH-DSA-SHA2-256f. Fast variant. Sig: 49,856 B. |

---

## Disallowed Features

The following TypeScript features are explicitly excluded from Rúnar, with rationale:

| Feature | Reason |
|---------|--------|
| `while` / `do-while` | No unbounded loops in Script |
| Recursion | Requires unbounded stack |
| `async` / `await` | No asynchrony on-chain |
| Closures / arrow functions | No heap-allocated environments |
| `try` / `catch` / `finally` | Script has no exception model |
| `any` / `unknown` | Defeats static analysis |
| Dynamic arrays (`T[]`) | No heap allocation |
| `number` | Ambiguous precision; use `bigint` |
| Decorators | Not representable in Script |
| Arbitrary function calls | Only Rúnar built-in functions and contract methods are allowed |
| Arbitrary imports | Sandboxed compilation |
| Multiple classes per file | One contract = one locking script |
| Enums | Use `bigint` constants |
| Interfaces / type aliases | Use concrete types only |
| Template literals | Not needed; use `toByteString` |
| Optional chaining (`?.`) / nullish coalescing (`??`) | No null/undefined in Rúnar |
| Spread operator (`...`) | Dynamic arity not supported |
| `typeof` / `instanceof` | No runtime type information |
| `new` expressions | Contract instantiation is handled by the framework |
