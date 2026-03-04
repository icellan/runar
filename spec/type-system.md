# Rúnar Type System

**Version:** 0.1.0
**Status:** Draft

This document specifies the type system for Rúnar. The type system is designed to be simple, fully static, and to guarantee that all programs can be compiled to finite Bitcoin Script.

---

## 1. Overview

Rúnar uses a structural type system with the following characteristics:

- **Fully static**: All types are resolved at compile time. There is no runtime type information.
- **No subtype polymorphism**: Except for the domain-type-to-ByteString relationship.
- **No generics**: Except for the built-in `FixedArray<T, N>`.
- **Affine typing for UTXO safety**: Certain values (notably UTXO references and preimages) must be consumed exactly once.

---

## 2. Type Hierarchy

```
          Top (not expressible in Rúnar)
           |
     +-----+-----+
     |            |
   bigint     ByteString     boolean
     |            |
     |      +-----+-----+-----+-----+-----+-----+
     |      |     |      |     |     |     |     |
     |   PubKey  Sig  Sha256  Ripemd160  Addr  SigHashPreimage  Point
     |
  +--+--+
  |     |
RabinSig RabinPubKey
```

### 2.1 Base Types

#### `bigint`

- Represents arbitrary-precision integers.
- Encoded as Bitcoin Script numbers (little-endian, sign-magnitude, minimal encoding).
- Script numbers in BSV have a configurable maximum size; by default the consensus limit is large (post-Genesis BSV removed the 4-byte restriction).
- Supports arithmetic, comparison, and bitwise operations.

#### `boolean`

- Two values: `true` and `false`.
- Represented on the stack as `OP_TRUE` (non-zero) and `OP_FALSE` (`OP_0`, empty byte vector).
- Result type of comparison and logical operations.
- `bigint` values are NOT implicitly convertible to `boolean`. Use explicit comparison: `x !== 0n`.

#### `ByteString`

- Immutable sequence of bytes.
- No character encoding semantics -- purely binary data.
- Constructed via `toByteString('hex...')`.
- Supports concatenation (`+` operator maps to `OP_CAT`), slicing (via built-in functions `split(data, index)`, `left(data, len)`, `right(data, len)`, `substr(data, start, len)`), and length (`len()`).

### 2.2 Domain Types

Domain types are **subtypes of `ByteString`** with additional compile-time size constraints. A value of a domain type can be used anywhere a `ByteString` is expected, but not vice versa.

| Type       | Size (bytes) | Description                                  |
|------------|-------------|----------------------------------------------|
| `PubKey`   | 33          | Compressed secp256k1 public key              |
| `Sig`      | 71-73       | DER-encoded ECDSA signature + sighash byte   |
| `Sha256`   | 32          | SHA-256 digest                               |
| `Ripemd160`| 20          | RIPEMD-160 digest                            |
| `Addr`     | 20          | Bitcoin address (= RIPEMD-160 of SHA-256 of pubkey) |
| `SigHashPreimage` | variable | Serialized sighash preimage for OP_PUSH_TX |
| `Point`    | 64          | secp256k1 elliptic curve point (affine coordinates) |

#### Point Encoding

The `Point` type represents a secp256k1 elliptic curve point as 64 bytes of raw coordinate data:

- Bytes 0-31: x-coordinate, 32 bytes, big-endian unsigned integer
- Bytes 32-63: y-coordinate, 32 bytes, big-endian unsigned integer
- No prefix byte (unlike compressed public keys which have a 02/03 prefix)

Both coordinates are elements of the secp256k1 field `F_p` where `p = 2^256 - 2^32 - 977`. A valid point satisfies the curve equation `y^2 === x^3 + 7 (mod p)`.

The `Point` type is distinct from `PubKey` (33-byte compressed format). Use `ecEncodeCompressed(p)` to convert a `Point` to a compressed `PubKey`-compatible `ByteString`.

#### Subtyping Rule

```
         ByteString
        /    |    \     \       \          \         \
    PubKey  Sig  Sha256  Ripemd160  Addr  SigHashPreimage  Point

    T <: ByteString    for all domain types T
    T <: T             reflexivity
```

A domain type value can be **widened** to `ByteString` implicitly. Narrowing (going from `ByteString` to a domain type) requires an explicit cast function:

```typescript
const addr: Addr = pubKeyToAddr(pubKey);      // OK: built-in returns Addr
const bs: ByteString = addr;                   // OK: widening
const addr2: Addr = bs;                        // ERROR: narrowing without cast
```

> **Implementation note:** The current type checker accepts `ByteString` where a domain type is expected (bidirectional compatibility). This is more permissive than the spec's stated narrowing restriction. This relaxation simplifies common patterns like passing concatenation results to domain-typed parameters.

### 2.3 Rabin Types

These are subtypes of `bigint` used for Rabin signature verification:

| Type         | Underlying | Description              |
|--------------|-----------|--------------------------|
| `RabinSig`   | `bigint`  | Rabin signature value    |
| `RabinPubKey`| `bigint`  | Rabin public key         |

```
       bigint
      /      \
  RabinSig  RabinPubKey
```

The same subtyping rules apply: `RabinSig <: bigint` and `RabinPubKey <: bigint`.

### 2.4 FixedArray<T, N>

```
FixedArray<T, N>    where T : Type, N : positive integer literal
```

- `N` MUST be a compile-time constant positive integer literal.
- All elements have the same type `T`.
- `T` can be any Rúnar type, including another `FixedArray` (for multi-dimensional arrays).
- Index access is bounds-checked at compile time where possible.
- On the Bitcoin Script stack, a `FixedArray<T, N>` is represented as N consecutive stack items.

#### Operations

| Operation | Syntax | Result Type |
|---|---|---|
| Index read | `arr[i]` | `T` |
| Index write | `arr[i] = val` | `void` |
| Length | `arr.length` | `bigint` (compile-time constant) |

#### Example

```typescript
const keys: FixedArray<PubKey, 3> = [pk1, pk2, pk3];
const first: PubKey = keys[0n];
```

---

## 3. Type Inference

Rúnar supports limited type inference via TypeScript's inference rules:

### 3.1 Variable Declaration Inference

When a variable declaration includes an initializer, the type annotation may be omitted:

```typescript
const x = 42n;                    // inferred: bigint
const flag = true;                // inferred: boolean
const h = sha256(data);           // inferred: Sha256
let result = checkSig(sig, pk);   // inferred: boolean
```

### 3.2 Inference Rules

```
                    Literal Typing
    ──────────────────────────────────────────
    42n : bigint
    true : boolean
    false : boolean
    toByteString('ab') : ByteString

                    Variable Declaration
    e : T
    ─────────────────────────────────────
    const x = e    ⊢  x : T
    let x = e      ⊢  x : T

                    Variable with Annotation
    e : S    S <: T
    ─────────────────────────────────────
    const x: T = e    ⊢  x : T

                    Binary Arithmetic
    e1 : bigint    e2 : bigint    op ∈ {+, -, *, /, %}
    ─────────────────────────────────────────────────
    e1 op e2 : bigint

                    Comparison
    e1 : T    e2 : T    op ∈ {==, ===, !=, !==, <, <=, >, >=}
    ─────────────────────────────────────────────────────────
    e1 op e2 : boolean

                    Logical
    e1 : boolean    e2 : boolean    op ∈ {&&, ||}
    ──────────────────────────────────────────────
    e1 op e2 : boolean

                    Negation
    e : boolean
    ─────────────
    !e : boolean

                    Arithmetic Negation
    e : bigint
    ──────────────
    -e : bigint

                    Ternary
    e_cond : boolean    e_then : T    e_else : T
    ──────────────────────────────────────────────
    e_cond ? e_then : e_else : T

                    ByteString Concatenation
    e1 : ByteString    e2 : ByteString
    ─────────────────────────────────────
    e1 + e2 : ByteString
```

### 3.3 Overloaded `+` Operator

The `+` operator is overloaded:

| Left Type | Right Type | Result Type | Script Opcode |
|---|---|---|---|
| `bigint` | `bigint` | `bigint` | `OP_ADD` |
| `ByteString` | `ByteString` | `ByteString` | `OP_CAT` |

Mixing `bigint` and `ByteString` with `+` is a **compile-time error**.

---

## 4. Affine Type Rules for UTXO Safety

Rúnar enforces affine type discipline on certain values to prevent common smart contract bugs.

### 4.1 Motivation

In the UTXO model, a coin can only be spent once. If a contract's logic allows a value to be "duplicated" at the semantic level without proper checks, it may lead to double-spend vulnerabilities or unintended script behavior.

### 4.2 Affine Values

The following types are treated as **affine** (may be used at most once):

| Type | Reason |
|---|---|
| `SigHashPreimage` | Must be checked exactly once via `checkPreimage()` |
| `Sig` | Should be verified, not duplicated |

### 4.3 Affine Rules

```
                    Affine Use
    x : T_affine    x is live
    ──────────────────────────
    use(x)  ⊢  x is consumed

                    No Duplication
    x : T_affine    x is consumed
    ──────────────────────────────
    use(x)  ⊢  ERROR: value already consumed

                    Conditional Consumption
    x : T_affine
    if (cond) { use(x) } else { use(x) }
    ──────────────────────────────────────
    OK: x consumed in both branches exactly once

                    Conditional Partial
    x : T_affine
    if (cond) { use(x) } else { /* no use */ }
    ─────────────────────────────────────────────
    WARNING: x may not be consumed on all paths
```

### 4.4 Practical Impact

```typescript
public unlock(sig: Sig, pubKey: PubKey, preimage: SigHashPreimage): void {
    // preimage must be checked exactly once:
    assert(this.checkPreimage(preimage));  // consumes preimage

    // This would be an error:
    // assert(this.checkPreimage(preimage));  // ERROR: preimage already consumed

    assert(checkSig(sig, pubKey));  // consumes sig
}
```

---

## 5. Property Types

### 5.1 Readonly Properties (Immutable)

```typescript
readonly pubKeyHash: Addr;
```

- Set once in the constructor.
- Cannot be reassigned in any method.
- Embedded directly into the locking script as push data.
- The compiler may inline the value at all use sites.

### 5.2 Mutable Properties (Stateful)

```typescript
counter: bigint;
```

- Initialized in the constructor.
- Can be reassigned in public methods via `this.counter = newValue`.
- Changes are propagated using the **OP_PUSH_TX** pattern: the new state is encoded in the output script of the spending transaction, and `checkPreimage` verifies that the transaction output matches.
- The compiler generates state serialization/deserialization code.

### 5.3 State Serialization

For stateful contracts, the compiler generates a locking script with state data appended after an `OP_RETURN` separator:

```
<code_part> OP_RETURN <field_0> <field_1> ... <field_n>
```

The `OP_RETURN` terminates script execution so the state fields are never executed as opcodes. When a stateful method executes, it:

1. Reads current state from the sighash preimage (which includes the full scriptCode with the state data).
2. Executes the method logic, potentially modifying state properties.
3. Constructs the new locking script with `<code_part> OP_RETURN <updated_fields>`.
4. Verifies (via `checkPreimage`) that the transaction output contains the new locking script.

---

## 6. Type Compatibility

### 6.1 Assignment Compatibility

A value of type `S` is assignable to a target of type `T` if:

1. `S` and `T` are the same type, OR
2. `S <: T` (subtype relationship), OR
3. `S` is a domain type and `T` is `ByteString` (widening), OR
4. `S` is `RabinSig` or `RabinPubKey` and `T` is `bigint` (widening).

### 6.2 Equality Compatibility

Two values can be compared with `==` / `===` / `!=` / `!==` if:

- They have the same type, OR
- One is a subtype of the other.

Comparing `bigint` with `ByteString` is a **compile-time error**.

### 6.3 Comparison Compatibility

The relational operators `<`, `<=`, `>`, `>=` are only defined for:

- `bigint` compared with `bigint`.

Using relational operators on `ByteString` or domain types is a **compile-time error**.

---

## 7. Type Checking Algorithm

The Rúnar type checker operates in the following phases:

### Phase 1: Declaration Collection

- Collect all property declarations and their types.
- Collect all method signatures (parameters, return types, visibility).
- Verify one class extending `SmartContract`.

### Phase 2: Constructor Checking

- Verify `super()` call is first.
- Verify all properties are assigned.
- Type-check all expressions in the constructor body.

### Phase 3: Method Body Checking

For each method:

1. Build the type environment: `{ this: ContractType, params..., locals... }`.
2. Type-check each statement.
3. For public methods: verify the last statement is `assert(...)`.
4. For private methods: verify the return type matches the declared type.
5. Verify affine values are properly consumed.

### Phase 4: Whole-Program Checks

- Verify no recursion (build call graph, check for cycles).
- Verify all for-loop bounds are compile-time constants.
- Verify total unrolled code size is within limits.

---

## 8. Type Encoding for Script

| Rúnar Type | Script Representation |
|---|---|
| `bigint` | Script number (little-endian sign-magnitude, minimal encoding) |
| `boolean` | `OP_TRUE` (0x01) or `OP_FALSE` (empty) |
| `ByteString` | Raw bytes pushed with appropriate `OP_PUSHDATA` |
| `PubKey` | 33 bytes pushed directly |
| `Sig` | DER bytes pushed directly |
| `Sha256` | 32 bytes pushed directly |
| `Ripemd160` | 20 bytes pushed directly |
| `Addr` | 20 bytes pushed directly |
| `SigHashPreimage` | Variable-length bytes pushed directly |
| `Point` | 64 bytes pushed directly (x[32] \|\| y[32], big-endian) |
| `RabinSig` | Script number |
| `RabinPubKey` | Script number |
| `FixedArray<T,N>` | N consecutive stack items, each encoded as T |

---

## 9. Examples

### 9.1 Simple Types

```typescript
const x: bigint = 42n;                           // OK
const y: boolean = true;                          // OK
const z: ByteString = toByteString('deadbeef');   // OK
const w: bigint = true;                           // ERROR: boolean not assignable to bigint
```

### 9.2 Domain Type Widening

```typescript
function helper(data: ByteString): Sha256 {
    return sha256(data);
}

const pk: PubKey = /* ... */;
const h = helper(pk);  // OK: PubKey widens to ByteString
```

### 9.3 FixedArray

```typescript
const arr: FixedArray<bigint, 3> = [1n, 2n, 3n];
const sum: bigint = arr[0n] + arr[1n] + arr[2n];

// Nested arrays:
const matrix: FixedArray<FixedArray<bigint, 2>, 2> = [[1n, 2n], [3n, 4n]];
const val: bigint = matrix[0n][1n];  // 2n
```

### 9.4 Stateful Contract Types

```typescript
export class Counter extends StatefulSmartContract {
    counter: bigint;  // mutable -- state is carried across transactions

    constructor(counter: bigint) {
        super(counter);
        this.counter = counter;
    }

    public increment(amount: bigint): void {
        this.counter += amount;
        // Compiler auto-injects: checkPreimage at entry, state continuation at exit
    }
}
```
