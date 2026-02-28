# TSOP ABI Specification

**Version:** 0.1.0
**Status:** Draft

This document specifies the Application Binary Interface (ABI) for TSOP smart contracts. The ABI defines how constructor parameters, method parameters, and state fields are encoded and decoded for on-chain interaction.

---

## 1. Overview

The ABI serves as the interface contract between:

- The **compiler**, which produces the ABI as part of the artifact.
- The **SDK**, which uses the ABI to construct unlocking scripts and decode state.
- **External tools**, which may inspect or interact with deployed contracts.

The ABI describes:
1. Constructor parameters (for deployment).
2. Public method signatures (for spending).
3. State field layout (for stateful contracts).

---

## 2. ABI Schema

```json
{
    "constructor": {
        "params": [
            { "name": "string", "type": "string" }
        ]
    },
    "methods": [
        {
            "name": "string",
            "params": [
                { "name": "string", "type": "string" }
            ],
            "index": 0
        }
    ]
}
```

---

## 3. Constructor ABI

### 3.1 Structure

```json
{
    "constructor": {
        "params": [
            { "name": "paramName", "type": "TypeName" }
        ]
    }
}
```

### 3.2 Fields

| Field | Type | Description |
|---|---|---|
| `params` | `Param[]` | Ordered list of constructor parameters |

Each `Param`:

| Field | Type | Description |
|---|---|---|
| `name` | `string` | Parameter name (matches source code) |
| `type` | `string` | TSOP type name (see Type Encoding below) |

### 3.3 Semantics

Constructor parameters correspond to the values embedded in the locking script at deployment time. They fill the placeholders in the script template.

### 3.4 Parameter Order

Parameters are listed in **declaration order** (matching the constructor signature in source). When the SDK builds the locking script, it replaces placeholders by name, so order is only significant for documentation and tooling consistency.

### 3.5 Example

Source:
```typescript
constructor(pubKeyHash: Addr, minAmount: bigint) {
    super(pubKeyHash, minAmount);
    this.pubKeyHash = pubKeyHash;
    this.minAmount = minAmount;
}
```

ABI:
```json
{
    "constructor": {
        "params": [
            { "name": "pubKeyHash", "type": "Addr" },
            { "name": "minAmount", "type": "bigint" }
        ]
    }
}
```

---

## 4. Method ABI

### 4.1 Structure

```json
{
    "methods": [
        {
            "name": "methodName",
            "params": [
                { "name": "paramName", "type": "TypeName" }
            ],
            "index": 0
        }
    ]
}
```

### 4.2 Fields

Each method entry:

| Field | Type | Description |
|---|---|---|
| `name` | `string` | Method name |
| `params` | `Param[]` | Ordered list of method parameters |
| `index` | `number` | Method dispatch index (0-based) |

### 4.3 Method Index

The `index` field determines how the method is selected during spending:

- **Single-method contracts**: The `index` is always `0`. No method selector is pushed onto the unlocking script.
- **Multi-method contracts**: The unlocking script includes the method index as the last push data item. The locking script's dispatch table routes to the correct method based on this index.

Method indices are assigned in **declaration order** in the source file, starting from `0`.

### 4.4 Parameter Order and Unlocking Script Layout

For a method with parameters `[p1, p2, ..., pn]`, the unlocking script pushes values in **reverse order**:

```
Unlocking script: <pn> <pn-1> ... <p2> <p1> [<method_index>]
```

This results in `p1` being on top of the stack when the locking script begins execution, which matches the natural left-to-right reading of the parameter list.

### 4.5 Example

Source:
```typescript
public unlock(sig: Sig, pubKey: PubKey): void { ... }
public refund(sig: Sig, preimage: SigHashPreimage): void { ... }
```

ABI:
```json
{
    "methods": [
        {
            "name": "unlock",
            "params": [
                { "name": "sig", "type": "Sig" },
                { "name": "pubKey", "type": "PubKey" }
            ],
            "index": 0
        },
        {
            "name": "refund",
            "params": [
                { "name": "sig", "type": "Sig" },
                { "name": "preimage", "type": "SigHashPreimage" }
            ],
            "index": 1
        }
    ]
}
```

Unlocking script to call `unlock`:
```
<pubKey> <sig> OP_0
```
(OP_0 is the method index for `unlock`)

Unlocking script to call `refund`:
```
<preimage> <sig> OP_1
```
(OP_1 is the method index for `refund`)

---

## 5. Type Encoding

### 5.1 Type Names

Types are encoded as strings in the ABI:

| TSOP Type | ABI Type String | Encoding Description |
|---|---|---|
| `bigint` | `"bigint"` | Script number (LE sign-magnitude, minimal) |
| `boolean` | `"boolean"` | `OP_TRUE` (0x01) or `OP_FALSE` (empty) |
| `ByteString` | `"ByteString"` | Raw bytes |
| `PubKey` | `"PubKey"` | 33 bytes (compressed secp256k1 key) |
| `Sig` | `"Sig"` | DER-encoded signature + sighash byte |
| `Sha256` | `"Sha256"` | 32 bytes |
| `Ripemd160` | `"Ripemd160"` | 20 bytes |
| `Addr` | `"Addr"` | 20 bytes |
| `SigHashPreimage` | `"SigHashPreimage"` | Variable-length bytes |
| `RabinSig` | `"RabinSig"` | Script number |
| `RabinPubKey` | `"RabinPubKey"` | Script number |
| `FixedArray<T, N>` | `{"array": "T", "size": N}` | N consecutive push data items |

### 5.2 bigint Encoding

Integers are encoded as **Bitcoin Script numbers**:

1. Little-endian byte order.
2. Sign-magnitude: the most significant bit of the last byte is the sign bit.
3. Minimal encoding: no unnecessary leading zero bytes (except when needed for the sign bit).

| Value | Hex Encoding | Push Opcode |
|---|---|---|
| `0` | (empty) | `OP_0` |
| `1` | `01` | `OP_1` |
| `-1` | `81` | `OP_1NEGATE` |
| `127` | `7f` | `<1> 7f` |
| `128` | `8000` | `<2> 8000` |
| `-128` | `8080` | `<2> 8080` |
| `255` | `ff00` | `<2> ff00` |
| `256` | `0001` | `<2> 0001` |

### 5.3 boolean Encoding

| Value | Script Encoding |
|---|---|
| `true` | `OP_TRUE` (0x51, which pushes byte `0x01`) |
| `false` | `OP_FALSE` (0x00, which pushes empty byte vector) |

### 5.4 ByteString and Domain Type Encoding

Byte data is pushed using the standard push data opcodes:

| Data Length | Push Method |
|---|---|
| 0 bytes | `OP_0` |
| 1-75 bytes | `<length_byte> <data>` (direct push) |
| 76-255 bytes | `OP_PUSHDATA1 <1-byte-length> <data>` |
| 256-65535 bytes | `OP_PUSHDATA2 <2-byte-length-LE> <data>` |
| 65536+ bytes | `OP_PUSHDATA4 <4-byte-length-LE> <data>` |

Domain types (PubKey, Sig, Sha256, Ripemd160, Addr, SigHashPreimage) use the same encoding -- they are just byte vectors with expected sizes.

### 5.5 FixedArray Encoding

A `FixedArray<T, N>` is encoded as N separate push data items, one per element, in **forward order** (element 0 is pushed first, ending up deepest on the stack):

```
FixedArray<PubKey, 3> = [pk1, pk2, pk3]

Script: <pk1> <pk2> <pk3>
Stack:  [pk3, pk2, pk1]   (pk3 on top)
```

---

## 6. State Field Descriptors

### 6.1 Structure

State fields are described separately from the ABI but are included in the artifact:

```json
{
    "stateFields": [
        {
            "name": "counter",
            "type": "bigint",
            "index": 0
        },
        {
            "name": "owner",
            "type": "PubKey",
            "index": 1
        }
    ]
}
```

### 6.2 Fields

| Field | Type | Description |
|---|---|---|
| `name` | `string` | Property name |
| `type` | `string` | TSOP type (same encoding as ABI types) |
| `index` | `number` | Position in state serialization (0-based) |

### 6.3 State Serialization Format

State is encoded in the locking script as:

```
<field_0> <field_1> ... <field_n> OP_DROP OP_DROP ... OP_DROP <code_part>
```

Each field is pushed as a data item using the type encoding rules above. Fields are pushed in **index order** (field 0 first). The `OP_DROP` sequence removes the state data from the stack before the contract code executes.

The number of `OP_DROP` opcodes equals the number of state fields.

### 6.4 State Reading

The contract reads its current state from the **sighash preimage** rather than from the stack. The preimage contains the scriptCode, which includes the state data. The compiler generates code to parse the state from the scriptCode portion of the preimage.

### 6.5 State Writing

When a stateful method modifies state, the compiler generates code to:

1. Serialize the new state values.
2. Concatenate them with `OP_DROP` opcodes.
3. Append the code part (which is constant).
4. Place the result in the expected output.
5. Use `checkPreimage` to verify the output matches.

---

## 7. ABI for Common Patterns

### 7.1 P2PKH (Pay-to-Public-Key-Hash)

```json
{
    "constructor": {
        "params": [
            { "name": "pubKeyHash", "type": "Addr" }
        ]
    },
    "methods": [
        {
            "name": "unlock",
            "params": [
                { "name": "sig", "type": "Sig" },
                { "name": "pubKey", "type": "PubKey" }
            ],
            "index": 0
        }
    ]
}
```

### 7.2 Multi-Sig (2-of-3)

```json
{
    "constructor": {
        "params": [
            { "name": "pubKeys", "type": { "array": "PubKey", "size": 3 } }
        ]
    },
    "methods": [
        {
            "name": "unlock",
            "params": [
                { "name": "sigs", "type": { "array": "Sig", "size": 2 } }
            ],
            "index": 0
        }
    ]
}
```

### 7.3 Counter (Stateful)

```json
{
    "constructor": {
        "params": [
            { "name": "counter", "type": "bigint" }
        ]
    },
    "methods": [
        {
            "name": "increment",
            "params": [
                { "name": "amount", "type": "bigint" },
                { "name": "preimage", "type": "SigHashPreimage" }
            ],
            "index": 0
        }
    ]
}
```

State fields:
```json
[
    { "name": "counter", "type": "bigint", "index": 0 }
]
```

---

## 8. ABI Validation Rules

A conforming ABI must satisfy:

1. **Non-empty constructor**: The constructor must have at least one parameter (a contract with no properties is useless).
2. **Non-empty methods**: There must be at least one public method.
3. **Unique method names**: No two methods may share the same name.
4. **Sequential indices**: Method indices must be `0, 1, 2, ...` with no gaps.
5. **Valid types**: All type strings must be recognized TSOP types.
6. **Unique parameter names**: Within each method, parameter names must be unique.
7. **Constructor-property alignment**: Constructor parameters must correspond 1:1 to contract properties (both readonly and mutable) in declaration order.
