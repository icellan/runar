# TSOP Language Reference

TSOP is a strict subset of TypeScript designed for compilation to Bitcoin SV Script. Every TSOP source file is valid TypeScript -- it type-checks with `tsc` and gets full IDE support -- but only the constructs described in this document are accepted by the TSOP compiler.

---

## Contract Structure

A TSOP source file contains exactly one contract class that extends `SmartContract`:

```typescript
import { SmartContract, assert, PubKey, Sig, checkSig } from 'tsop-lang';

class MyContract extends SmartContract {
  // Properties (contract state)
  readonly fixedValue: bigint;
  mutableValue: bigint;

  // Constructor (deployment parameters)
  constructor(fixedValue: bigint, mutableValue: bigint) {
    super(fixedValue, mutableValue);
    this.fixedValue = fixedValue;
    this.mutableValue = mutableValue;
  }

  // Public methods (spending entry points)
  public spend(sig: Sig, pubKey: PubKey) {
    assert(checkSig(sig, pubKey));
  }

  // Private methods (inlined helpers)
  private helper(x: bigint): bigint {
    return x * x;
  }
}
```

### Rules

- One class per file, extending `SmartContract` directly.
- No decorators, no generics on the class, no intermediate base classes.
- Imports are restricted to `tsop-lang` (or `tsop` / `tsop/builtins`).

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
- Having any mutable property makes the contract **stateful**.

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
- Must end with an `assert(...)` call as the final statement.
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
| `!==` / `!=` | Inequality | `OP_NUMNOTEQUAL` (bigint) or `OP_EQUAL OP_NOT` (bytes) |

Both `==` and `===` have identical semantics in TSOP (no type coercion). The compiler recommends `===`.

### Logical (operands: `boolean`)

| Operator | Description | Notes |
|----------|-------------|-------|
| `&&` | Logical AND | Short-circuit evaluated |
| `\|\|` | Logical OR | Short-circuit evaluated |

Short-circuit operators are lowered to `OP_IF`/`OP_ELSE`/`OP_ENDIF` in the IR.

### Bitwise (operands: `bigint`)

| Operator | Description | Opcode |
|----------|-------------|--------|
| `~a` | Bitwise NOT | `OP_INVERT` |

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
| `reverseByteString` | `(data: ByteString, size: bigint) => ByteString` | Sequence of `OP_SPLIT` and `OP_SWAP` |
| `toByteString` | `(hex: string) => ByteString` | Compile-time literal construction |

### Conversion

| Function | Signature | Opcode(s) |
|----------|-----------|-----------|
| `pack` | `(n: bigint) => ByteString` | `OP_NUM2BIN` |
| `unpack` | `(data: ByteString) => bigint` | `OP_BIN2NUM` |
| `num2bin` | `(n: bigint, size: bigint) => ByteString` | `OP_NUM2BIN` |

### Math

| Function | Signature | Opcode(s) |
|----------|-----------|-----------|
| `abs` | `(n: bigint) => bigint` | `OP_ABS` |
| `min` | `(a: bigint, b: bigint) => bigint` | `OP_MIN` |
| `max` | `(a: bigint, b: bigint) => bigint` | `OP_MAX` |
| `within` | `(x: bigint, lo: bigint, hi: bigint) => boolean` | `OP_WITHIN` |

### Control

| Function | Signature | Opcode(s) |
|----------|-----------|-----------|
| `assert` | `(cond: boolean) => void` | `OP_VERIFY` |
| `exit` | `(success: boolean) => void` | `OP_RETURN` |

### Preimage (Stateful Contracts)

| Function | Signature | Description |
|----------|-----------|-------------|
| `checkPreimage` | `(preimage: SigHashPreimage) => boolean` | Verify sighash preimage matches current tx |
| `this.getStateScript()` | `() => ByteString` | Serialize current mutable state |
| `extractOutputHash` | `(preimage: SigHashPreimage) => Sha256` | Extract hashOutputs from preimage |
| `extractLocktime` | `(preimage: SigHashPreimage) => bigint` | Extract nLocktime from preimage |
| `verifyRabinSig` | `(msg, sig, padding, pubKey) => boolean` | Verify a Rabin signature |

---

## Disallowed Features

The following TypeScript features are explicitly excluded from TSOP, with rationale:

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
| Arbitrary imports | Sandboxed compilation |
| Multiple classes per file | One contract = one locking script |
| Enums | Use `bigint` constants |
| Interfaces / type aliases | Use concrete types only |
| Template literals | Not needed; use `toByteString` |
| Optional chaining (`?.`) / nullish coalescing (`??`) | No null/undefined in TSOP |
| Spread operator (`...`) | Dynamic arity not supported |
| `typeof` / `instanceof` | No runtime type information |
| `new` expressions | Contract instantiation is handled by the framework |
