# Rúnar ANF IR Specification

**Version:** 0.1.0
**Status:** Draft

This document specifies the Administrative Normal Form (ANF) Intermediate Representation used by Rúnar. The ANF IR is the **canonical conformance boundary**: all Rúnar compilers MUST produce byte-identical ANF IR for the same input program. This enables interoperability, testing, and verification across implementations.

---

## 1. Design Principles

1. **Canonical**: There is exactly one valid ANF IR for any given Rúnar source program. Two conforming compilers must produce identical output.
2. **Explicit**: All intermediate computations are named. There are no nested expressions.
3. **Serializable**: The IR has a well-defined JSON serialization using RFC 8785 (JSON Canonicalization Scheme / JCS).
4. **Flat**: Method bodies are flat lists of bindings -- no nested blocks except for `if` and `loop` nodes.
5. **Typed** (planned): Per-binding type annotations may be added in a future version as an optional `type` field on bindings.

> **Implementation note:** Per-binding type annotations are a planned future extension. If added, they would appear as a `type` field on `ANFBinding`.

---

## 2. Top-Level Structure

### ANFProgram

```
ANFProgram = {
    contractName: string,         // Name of the contract class
    properties: ANFProperty[],    // Property declarations in order
    methods: ANFMethod[]          // Methods in declaration order
}
```

### ANFProperty

```
ANFProperty = {
    name: string,                 // Property name
    type: ANFType,                // Property type
    readonly: boolean,            // true = immutable, false = stateful
    initialValue?: string | bigint | boolean  // Optional initial value for the property
}
```

### ANFMethod

```
ANFMethod = {
    name: string,                 // Method name
    params: ANFParam[],           // Parameters in declaration order
    body: ANFBinding[],           // Flat list of bindings
    isPublic: boolean             // true = entry point, false = helper
}
```

### ANFParam

```
ANFParam = {
    name: string,                 // Parameter name
    type: ANFType                 // Parameter type
}
```

---

## 3. ANF Bindings

Every intermediate result in the IR is assigned to a named temporary. A method body is a sequence of bindings.

```
ANFBinding = {
    name: string,                 // Temporary name: t0, t1, t2, ...
    value: ANFValue               // The computation
}
```

### Naming Convention

Temporaries are named sequentially starting from `t0` within each method body:

```
t0, t1, t2, t3, ...
```

The numbering resets for each method. The compiler MUST use sequential `t{i}` names for intermediate computations -- no gaps, no reordering.

**Exception: variable declarations and reassignments.** When the source code declares a variable (e.g., `let x = ...`) or reassigns one, the compiler emits a binding using the original variable name (e.g., `x`) instead of a sequential temp name. These named bindings are interleaved with the `t{i}` temporaries and do not affect the sequential numbering of temp names. For example, a method body might contain: `t0, t1, x, t2, t3, counter, t4, ...`.

---

## 4. ANF Value Nodes

Each `ANFValue` is a tagged union. The `kind` field determines which other fields are present.

### 4.1 `load_param`

Load a method parameter.

```json
{
    "kind": "load_param",
    "name": "sig"
}
```

| Field | Type | Description |
|---|---|---|
| `kind` | `"load_param"` | Node discriminator |
| `name` | `string` | Parameter name |

### 4.2 `load_prop`

Load a contract property (via `this.propName`).

```json
{
    "kind": "load_prop",
    "name": "pubKeyHash"
}
```

| Field | Type | Description |
|---|---|---|
| `kind` | `"load_prop"` | Node discriminator |
| `name` | `string` | Property name |

### 4.3 `load_const`

Load a compile-time constant.

```json
{
    "kind": "load_const",
    "value": "42"
}
```

| Field | Type | Description |
|---|---|---|
| `kind` | `"load_const"` | Node discriminator |
| `value` | `string \| bigint \| boolean` | The constant value |

The `value` field holds the constant directly. In JSON serialization, `bigint` values are represented as strings or numbers, `boolean` as JSON booleans, and byte string literals as hex strings.

> **Implementation note:** When the `value` field is a string with the prefix `@ref:` (e.g., `"@ref:t3"`), it represents an alias to another binding rather than a literal constant. This is used internally by the ANF lowerer for variable aliasing (e.g., `let x = y` or reassignment `x = expr`). The stack lowerer resolves `@ref:` values by looking up the referenced binding on the virtual stack. This convention affects cross-compiler conformance: all three compilers must emit identical `@ref:` aliases for the same source input.

### 4.4 `bin_op`

Binary operation on two previously-bound values.

```json
{
    "kind": "bin_op",
    "op": "+",
    "left": "t0",
    "right": "t1"
}
```

| Field | Type | Description |
|---|---|---|
| `kind` | `"bin_op"` | Node discriminator |
| `op` | `string` | Operator (see table below) |
| `left` | `string` | Name of left operand binding |
| `right` | `string` | Name of right operand binding |
| `result_type` | `string?` | Optional operand type hint: `"bytes"` for ByteString/PubKey/Sig/Sha256 etc., omitted for numeric |

Supported operators:

| Operator | Types | Description |
|---|---|---|
| `"+"` | bigint, ByteString | Addition or concatenation |
| `"-"` | bigint | Subtraction |
| `"*"` | bigint | Multiplication |
| `"/"` | bigint | Truncating division |
| `"%"` | bigint | Modulo |
| `"==="` | any | Equality |
| `"!=="` | any | Inequality |
| `"<"` | bigint | Less than |
| `"<="` | bigint | Less than or equal |
| `">"` | bigint | Greater than |
| `">="` | bigint | Greater than or equal |
| `"&&"` | boolean | Logical AND (eager; lowered to `OP_BOOLAND`, not short-circuit) |
| `"\|\|"` | boolean | Logical OR (eager; lowered to `OP_BOOLOR`, not short-circuit) |
| `"&"` | bigint | Bitwise AND |
| `"\|"` | bigint | Bitwise OR |
| `"^"` | bigint | Bitwise XOR |
| `"<<"` | bigint | Left shift |
| `">>"` | bigint | Right shift |

### 4.5 `unary_op`

Unary operation.

```json
{
    "kind": "unary_op",
    "op": "!",
    "operand": "t3"
}
```

| Field | Type | Description |
|---|---|---|
| `kind` | `"unary_op"` | Node discriminator |
| `op` | `string` | `"!"` (logical NOT), `"-"` (negate), `"~"` (bitwise NOT) |
| `operand` | `string` | Name of operand binding |

### 4.6 `call`

Call a built-in function.

```json
{
    "kind": "call",
    "func": "checkSig",
    "args": ["t0", "t1"]
}
```

| Field | Type | Description |
|---|---|---|
| `kind` | `"call"` | Node discriminator |
| `func` | `string` | Built-in function name |
| `args` | `string[]` | Names of argument bindings |

### 4.7 `method_call`

Call a private method on the contract.

```json
{
    "kind": "method_call",
    "object": "t1",
    "method": "square",
    "args": ["t2"]
}
```

| Field | Type | Description |
|---|---|---|
| `kind` | `"method_call"` | Node discriminator |
| `object` | `string` | Name of the receiver binding (typically `this`) |
| `method` | `string` | Private method name |
| `args` | `string[]` | Names of argument bindings |

Note: In the canonical ANF IR, `method_call` nodes are preserved (not inlined). Inlining happens in a later compiler phase. This keeps the ANF IR closer to the source and enables independent verification of inlining correctness.

### 4.8 `if`

Conditional with two branches. Both branches are sequences of bindings that produce a result.

```json
{
    "kind": "if",
    "cond": "t5",
    "then": [
        { "name": "t6", "value": { "kind": "load_const", "value": "1" } }
    ],
    "else": [
        { "name": "t7", "value": { "kind": "load_const", "value": "0" } }
    ]
}
```

| Field | Type | Description |
|---|---|---|
| `kind` | `"if"` | Node discriminator |
| `cond` | `string` | Name of boolean binding |
| `then` | `ANFBinding[]` | Bindings in the then branch |
| `else` | `ANFBinding[]` | Bindings in the else branch |

Branch temporary names continue the global sequence. If the `if` node is at position `k`, then `then` temporaries start at `t{k+1}`, and `else` temporaries start after the last `then` temporary.

### 4.9 `loop`

Bounded loop with a count and body. The loop body is a sequence of bindings executed `count` times with an iteration variable.

```json
{
    "kind": "loop",
    "count": 3,
    "body": [
        { "name": "t10", "value": { "kind": "load_const", "value": "0" } }
    ],
    "iterVar": "i"
}
```

| Field | Type | Description |
|---|---|---|
| `kind` | `"loop"` | Node discriminator |
| `count` | `number` | Number of iterations |
| `body` | `ANFBinding[]` | Bindings executed each iteration |
| `iterVar` | `string` | Name of the iteration variable |

### 4.10 `assert`

Assert a condition.

```json
{
    "kind": "assert",
    "value": "t4"
}
```

| Field | Type | Description |
|---|---|---|
| `kind` | `"assert"` | Node discriminator |
| `value` | `string` | Name of boolean binding |

### 4.11 `update_prop`

Update a mutable property.

```json
{
    "kind": "update_prop",
    "name": "counter",
    "value": "t8"
}
```

| Field | Type | Description |
|---|---|---|
| `kind` | `"update_prop"` | Node discriminator |
| `name` | `string` | Property name |
| `value` | `string` | Name of new value binding |

### 4.12 `get_state_script`

Get the serialized state script for the current contract state.

```json
{
    "kind": "get_state_script"
}
```

No additional fields.

### 4.13 `check_preimage`

Verify the sighash preimage.

```json
{
    "kind": "check_preimage",
    "preimage": "t9"
}
```

| Field | Type | Description |
|---|---|---|
| `kind` | `"check_preimage"` | Node discriminator |
| `preimage` | `string` | Name of preimage binding |

### 4.14 `add_output`

Add an output to the transaction being constructed (used by stateful contracts for multi-output patterns).

```json
{
    "kind": "add_output",
    "satoshis": "t10",
    "stateValues": ["t11", "t12"]
}
```

| Field | Type | Description |
|---|---|---|
| `kind` | `"add_output"` | Node discriminator |
| `satoshis` | `string` | Name of binding holding the satoshis amount |
| `stateValues` | `string[]` | Names of bindings for each mutable property value, in declaration order |

### 4.15 `deserialize_state`

Deserialize contract state fields from a verified preimage (used by stateful contracts). The compiler emits this node after `check_preimage` to extract the current values of mutable state properties from the transaction preimage.

```json
{
    "kind": "deserialize_state",
    "preimage": "t5"
}
```

| Field | Type | Description |
|---|---|---|
| `kind` | `"deserialize_state"` | Node discriminator |
| `preimage` | `string` | Name of binding holding the verified preimage (from `check_preimage`) |

After this node executes, the compiler creates bindings for each mutable property's current value, extracted from the preimage's output script.

---

## 5. ANF Types

Types are represented as strings in the IR:

| Rúnar Type | ANF Type Representation | Description |
|---|---|---|
| `bigint` | `"bigint"` | Arbitrary-precision integer |
| `boolean` | `"boolean"` | Boolean value |
| `ByteString` | `"ByteString"` | Raw byte sequence |
| `PubKey` | `"PubKey"` | 33-byte compressed public key |
| `Sig` | `"Sig"` | DER-encoded ECDSA signature |
| `Sha256` | `"Sha256"` | 32-byte SHA-256 hash |
| `Ripemd160` | `"Ripemd160"` | 20-byte RIPEMD-160 hash |
| `Addr` | `"Addr"` | 20-byte address (RIPEMD-160 of SHA-256) |
| `SigHashPreimage` | `"SigHashPreimage"` | BIP-143 sighash preimage |
| `Point` | `"Point"` | 64-byte EC point (x[32] \|\| y[32], big-endian) |
| `RabinSig` | `"RabinSig"` | Rabin signature value |
| `RabinPubKey` | `"RabinPubKey"` | Rabin public key |
| `void` | `"void"` | No value |
| `FixedArray<T, N>` | `"FixedArray<T, N>"` | Fixed-length array of element type T |

---

## 6. Canonical Serialization

The ANF IR MUST be serialized according to **RFC 8785 (JSON Canonicalization Scheme)**:

1. **Object keys** are sorted lexicographically by Unicode code point.
2. **No whitespace** between tokens (most compact form).
3. **Numbers** use shortest representation with no trailing zeros.
4. **Strings** use minimal escaping (only `"`, `\`, and control characters are escaped).
5. **No duplicate keys**.
6. **UTF-8 encoding** for the output byte stream.

This ensures that any two conforming compilers produce byte-identical JSON for the same Rúnar source.

### Verification

Given a Rúnar source file `input.ts`, any conforming compiler must satisfy:

```
sha256(compile_to_anf(input.ts)) == sha256(reference_compile_to_anf(input.ts))
```

---

## 7. Transformation from Source to ANF

### 7.1 Algorithm

The ANF transformation processes the TypeScript AST top-down:

1. **Flatten expressions**: Every sub-expression that is not a trivial value (variable reference or literal) is bound to a temporary.
2. **Preserve evaluation order**: Left-to-right, depth-first.
3. **Lower control flow**: `if`/`else` becomes `if` nodes. `for` loops become `loop` nodes with explicit iterations.
4. **Resolve `this`**: Property accesses become `load_prop` nodes. Method calls become `method_call` nodes.

### 7.2 Canonicalization Rules

To ensure deterministic output:

- Temporaries are numbered sequentially per method.
- Sub-expressions are flattened left-to-right.
- Constants are always wrapped in `load_const` (never inlined into `bin_op` etc.).
- Logical operators (`&&`, `||`) are lowered to eager `bin_op` nodes (not short-circuit `if` nodes).

### 7.3 Logical Operator Lowering

The expression `a && b` is lowered to an eager `bin_op`:

```
t0 = <evaluate a>
t1 = <evaluate b>
t2 = bin_op("&&", t0, t1)
```

Similarly, `a || b` is lowered to an eager `bin_op`:

```
t0 = <evaluate a>
t1 = <evaluate b>
t2 = bin_op("||", t0, t1)
```

Both operands are evaluated unconditionally. This differs from TypeScript's short-circuit semantics but is safe in Rúnar because expressions are pure (no side effects beyond `assert`).

---

## 8. Complete Example

### Source

```typescript
import { SmartContract, assert, checkSig, PubKey, Sig } from 'runar-lang';

export class P2PKH extends SmartContract {
    readonly pubKeyHash: Addr;

    constructor(pubKeyHash: Addr) {
        super(pubKeyHash);
        this.pubKeyHash = pubKeyHash;
    }

    public unlock(sig: Sig, pubKey: PubKey): void {
        assert(hash160(pubKey) === this.pubKeyHash);
        assert(checkSig(sig, pubKey));
    }
}
```

### ANF IR (pretty-printed for readability)

```json
{
    "contractName": "P2PKH",
    "methods": [
        {
            "body": [
                {
                    "name": "t0",
                    "value": {
                        "kind": "load_param",
                        "name": "pubKey"
                    }
                },
                {
                    "name": "t1",
                    "value": {
                        "kind": "call",
                        "func": "hash160",
                        "args": [
                            "t0"
                        ]
                    }
                },
                {
                    "name": "t2",
                    "value": {
                        "kind": "load_prop",
                        "name": "pubKeyHash"
                    }
                },
                {
                    "name": "t3",
                    "value": {
                        "kind": "bin_op",
                        "op": "===",
                        "left": "t1",
                        "right": "t2"
                    }
                },
                {
                    "name": "t4",
                    "value": {
                        "kind": "assert",
                        "value": "t3"
                    }
                },
                {
                    "name": "t5",
                    "value": {
                        "kind": "load_param",
                        "name": "sig"
                    }
                },
                {
                    "name": "t6",
                    "value": {
                        "kind": "load_param",
                        "name": "pubKey"
                    }
                },
                {
                    "name": "t7",
                    "value": {
                        "kind": "call",
                        "func": "checkSig",
                        "args": [
                            "t5",
                            "t6"
                        ]
                    }
                },
                {
                    "name": "t8",
                    "value": {
                        "kind": "assert",
                        "value": "t7"
                    }
                }
            ],
            "isPublic": true,
            "name": "unlock",
            "params": [
                {
                    "name": "sig",
                    "type": "Sig"
                },
                {
                    "name": "pubKey",
                    "type": "PubKey"
                }
            ]
        }
    ],
    "properties": [
        {
            "name": "pubKeyHash",
            "readonly": true,
            "type": "Addr"
        }
    ]
}
```

Note: The above is pretty-printed for readability. The canonical form (per RFC 8785) has no whitespace and keys sorted lexicographically.

---

## 9. Validation Rules

A conforming ANF IR must satisfy:

1. **Sequential naming**: Bindings use sequential `t{i}` names for compiler-generated temporaries, except for user-declared variables (e.g., `let x = ...` or reassignments) which retain their original names. Named bindings are interleaved with the `t{i}` sequence and do not affect the sequential numbering of temporaries (see Section 3, Naming Convention).
2. **Forward references only**: A binding may only reference temporaries with smaller indices (i.e., defined earlier in the same body or branch).
3. **No orphan references**: Every name referenced in an `ANFValue` must be either a method parameter, a property name, or a previously defined temporary.
4. **Public method assertion**: For `SmartContract` (stateless) contracts, the last binding in a public method's body must have kind `assert`. For `StatefulSmartContract` contracts, the compiler auto-injects bindings (preimage check, state continuation) so this rule does not apply.

---

## 10. Extensibility

New `ANFValue` kinds may be added in future versions. A conforming implementation MUST reject unknown kinds rather than silently ignoring them.
