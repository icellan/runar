# TSOP ANF IR Specification

**Version:** 0.1.0
**Status:** Draft

This document specifies the Administrative Normal Form (ANF) Intermediate Representation used by TSOP. The ANF IR is the **canonical conformance boundary**: all TSOP compilers MUST produce byte-identical ANF IR for the same input program. This enables interoperability, testing, and verification across implementations.

---

## 1. Design Principles

1. **Canonical**: There is exactly one valid ANF IR for any given TSOP source program. Two conforming compilers must produce identical output.
2. **Explicit**: All intermediate computations are named. There are no nested expressions.
3. **Serializable**: The IR has a well-defined JSON serialization using RFC 8785 (JSON Canonicalization Scheme / JCS).
4. **Flat**: Method bodies are flat lists of bindings -- no nested blocks except for `if` and `loop` nodes.
5. **Typed**: Every binding carries its resolved type.

---

## 2. Top-Level Structure

### ANFProgram

```
ANFProgram = {
    version: string,              // IR format version, e.g. "0.1.0"
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
    readonly: boolean             // true = immutable, false = stateful
}
```

### ANFMethod

```
ANFMethod = {
    name: string,                 // Method name
    params: ANFParam[],           // Parameters in declaration order
    body: ANFBinding[],           // Flat list of bindings
    isPublic: boolean,            // true = entry point, false = helper
    returnType: ANFType           // Return type ("void" for public methods)
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
    type: ANFType,                // Type of the bound value
    value: ANFValue               // The computation
}
```

### Naming Convention

Temporaries are named sequentially starting from `t0` within each method body:

```
t0, t1, t2, t3, ...
```

The numbering resets for each method. The compiler MUST use this exact naming scheme -- no gaps, no reordering. The numbering corresponds to the binding's position in the `body` array (the binding at index `i` has name `t{i}`).

---

## 4. ANF Value Nodes

Each `ANFValue` is a tagged union. The `tag` field determines which other fields are present.

### 4.1 `load_param`

Load a method parameter.

```json
{
    "tag": "load_param",
    "param": "sig"
}
```

| Field | Type | Description |
|---|---|---|
| `tag` | `"load_param"` | Node discriminator |
| `param` | `string` | Parameter name |

### 4.2 `load_prop`

Load a contract property (via `this.propName`).

```json
{
    "tag": "load_prop",
    "prop": "pubKeyHash"
}
```

| Field | Type | Description |
|---|---|---|
| `tag` | `"load_prop"` | Node discriminator |
| `prop` | `string` | Property name |

### 4.3 `load_const`

Load a compile-time constant.

```json
{
    "tag": "load_const",
    "constType": "bigint",
    "value": "42"
}
```

| Field | Type | Description |
|---|---|---|
| `tag` | `"load_const"` | Node discriminator |
| `constType` | `string` | One of: `"bigint"`, `"boolean"`, `"bytes"` |
| `value` | `string` | String representation of the value |

Value encoding:
- `bigint`: Decimal string, e.g. `"42"`, `"-1"`, `"0"`
- `boolean`: `"true"` or `"false"`
- `bytes`: Hex string (lowercase, even length), e.g. `"deadbeef"`

### 4.4 `bin_op`

Binary operation on two previously-bound values.

```json
{
    "tag": "bin_op",
    "op": "+",
    "left": "t0",
    "right": "t1"
}
```

| Field | Type | Description |
|---|---|---|
| `tag` | `"bin_op"` | Node discriminator |
| `op` | `string` | Operator (see table below) |
| `left` | `string` | Name of left operand binding |
| `right` | `string` | Name of right operand binding |

Supported operators:

| Operator | Types | Description |
|---|---|---|
| `"+"` | bigint, ByteString | Addition or concatenation |
| `"-"` | bigint | Subtraction |
| `"*"` | bigint | Multiplication |
| `"/"` | bigint | Truncating division |
| `"%"` | bigint | Modulo |
| `"=="` | any | Equality |
| `"!="` | any | Inequality |
| `"<"` | bigint | Less than |
| `"<="` | bigint | Less than or equal |
| `">"` | bigint | Greater than |
| `">="` | bigint | Greater than or equal |
| `"&&"` | boolean | Logical AND |
| `"\|\|"` | boolean | Logical OR |

### 4.5 `unary_op`

Unary operation.

```json
{
    "tag": "unary_op",
    "op": "!",
    "operand": "t3"
}
```

| Field | Type | Description |
|---|---|---|
| `tag` | `"unary_op"` | Node discriminator |
| `op` | `string` | `"!"` (logical NOT), `"-"` (negate), `"~"` (bitwise NOT) |
| `operand` | `string` | Name of operand binding |

### 4.6 `call`

Call a built-in function.

```json
{
    "tag": "call",
    "function": "checkSig",
    "args": ["t0", "t1"]
}
```

| Field | Type | Description |
|---|---|---|
| `tag` | `"call"` | Node discriminator |
| `function` | `string` | Built-in function name |
| `args` | `string[]` | Names of argument bindings |

### 4.7 `method_call`

Call a private method on the contract.

```json
{
    "tag": "method_call",
    "method": "square",
    "args": ["t2"]
}
```

| Field | Type | Description |
|---|---|---|
| `tag` | `"method_call"` | Node discriminator |
| `method` | `string` | Private method name |
| `args` | `string[]` | Names of argument bindings |

Note: In the canonical ANF IR, `method_call` nodes are preserved (not inlined). Inlining happens in a later compiler phase. This keeps the ANF IR closer to the source and enables independent verification of inlining correctness.

### 4.8 `if`

Conditional with two branches. Both branches are sequences of bindings that produce a result.

```json
{
    "tag": "if",
    "condition": "t5",
    "thenBranch": [
        { "name": "t6", "type": "bigint", "value": { "tag": "load_const", "constType": "bigint", "value": "1" } }
    ],
    "elseBranch": [
        { "name": "t7", "type": "bigint", "value": { "tag": "load_const", "constType": "bigint", "value": "0" } }
    ],
    "thenResult": "t6",
    "elseResult": "t7"
}
```

| Field | Type | Description |
|---|---|---|
| `tag` | `"if"` | Node discriminator |
| `condition` | `string` | Name of boolean binding |
| `thenBranch` | `ANFBinding[]` | Bindings in the then branch |
| `elseBranch` | `ANFBinding[]` | Bindings in the else branch |
| `thenResult` | `string` | Name of result binding in then branch |
| `elseResult` | `string` | Name of result binding in else branch |

Branch temporary names continue the global sequence. If the `if` node is at position `k`, then `thenBranch` temporaries start at `t{k+1}`, and `elseBranch` temporaries start after the last `thenBranch` temporary.

For `if` statements with no result value (side-effects only, such as property updates), `thenResult` and `elseResult` may be `null`.

### 4.9 `loop`

Unrolled bounded loop. The IR represents the loop after unrolling -- each iteration is explicit.

```json
{
    "tag": "loop",
    "iterations": [
        {
            "index": "0",
            "bindings": [
                { "name": "t10", "type": "bigint", "value": { "tag": "load_const", "constType": "bigint", "value": "0" } }
            ]
        },
        {
            "index": "1",
            "bindings": [
                { "name": "t11", "type": "bigint", "value": { "tag": "load_const", "constType": "bigint", "value": "1" } }
            ]
        }
    ]
}
```

| Field | Type | Description |
|---|---|---|
| `tag` | `"loop"` | Node discriminator |
| `iterations` | `Iteration[]` | One entry per unrolled iteration |

Each `Iteration`:

| Field | Type | Description |
|---|---|---|
| `index` | `string` | Iteration index as decimal string |
| `bindings` | `ANFBinding[]` | Bindings for this iteration |

### 4.10 `assert`

Assert a condition.

```json
{
    "tag": "assert",
    "condition": "t4"
}
```

| Field | Type | Description |
|---|---|---|
| `tag` | `"assert"` | Node discriminator |
| `condition` | `string` | Name of boolean binding |

### 4.11 `update_prop`

Update a mutable property.

```json
{
    "tag": "update_prop",
    "prop": "counter",
    "value": "t8"
}
```

| Field | Type | Description |
|---|---|---|
| `tag` | `"update_prop"` | Node discriminator |
| `prop` | `string` | Property name |
| `value` | `string` | Name of new value binding |

### 4.12 `get_state_script`

Get the serialized state script for the current contract state.

```json
{
    "tag": "get_state_script"
}
```

No additional fields.

### 4.13 `check_preimage`

Verify the sighash preimage.

```json
{
    "tag": "check_preimage",
    "preimage": "t9"
}
```

| Field | Type | Description |
|---|---|---|
| `tag` | `"check_preimage"` | Node discriminator |
| `preimage` | `string` | Name of preimage binding |

### 4.14 `array_access`

Read from a fixed array.

```json
{
    "tag": "array_access",
    "array": "t0",
    "index": "t1"
}
```

| Field | Type | Description |
|---|---|---|
| `tag` | `"array_access"` | Node discriminator |
| `array` | `string` | Name of array binding |
| `index` | `string` | Name of index binding |

### 4.15 `array_update`

Write to a fixed array (produces a new array).

```json
{
    "tag": "array_update",
    "array": "t0",
    "index": "t1",
    "value": "t2"
}
```

| Field | Type | Description |
|---|---|---|
| `tag` | `"array_update"` | Node discriminator |
| `array` | `string` | Name of array binding |
| `index` | `string` | Name of index binding |
| `value` | `string` | Name of new element binding |

---

## 5. ANF Types

Types are represented as strings or objects in the IR:

| TSOP Type | ANF Type Representation |
|---|---|
| `bigint` | `"bigint"` |
| `boolean` | `"boolean"` |
| `ByteString` | `"ByteString"` |
| `PubKey` | `"PubKey"` |
| `Sig` | `"Sig"` |
| `Sha256` | `"Sha256"` |
| `Ripemd160` | `"Ripemd160"` |
| `Addr` | `"Addr"` |
| `SigHashPreimage` | `"SigHashPreimage"` |
| `RabinSig` | `"RabinSig"` |
| `RabinPubKey` | `"RabinPubKey"` |
| `void` | `"void"` |
| `FixedArray<T, N>` | `{ "array": T, "size": N }` |

---

## 6. Canonical Serialization

The ANF IR MUST be serialized according to **RFC 8785 (JSON Canonicalization Scheme)**:

1. **Object keys** are sorted lexicographically by Unicode code point.
2. **No whitespace** between tokens (most compact form).
3. **Numbers** use shortest representation with no trailing zeros.
4. **Strings** use minimal escaping (only `"`, `\`, and control characters are escaped).
5. **No duplicate keys**.
6. **UTF-8 encoding** for the output byte stream.

This ensures that any two conforming compilers produce byte-identical JSON for the same TSOP source.

### Verification

Given a TSOP source file `input.ts`, any conforming compiler must satisfy:

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
- Short-circuit operators (`&&`, `||`) are lowered to `if` nodes.

### 7.3 Short-Circuit Lowering

The expression `a && b` is lowered to:

```
t0 = <evaluate a>
t1 = if(t0) {
    t2 = <evaluate b>
    -> t2
} else {
    t3 = load_const(boolean, "false")
    -> t3
}
```

Similarly, `a || b` is lowered to:

```
t0 = <evaluate a>
t1 = if(t0) {
    t2 = load_const(boolean, "true")
    -> t2
} else {
    t3 = <evaluate b>
    -> t3
}
```

---

## 8. Complete Example

### Source

```typescript
import { SmartContract, assert, checkSig, PubKey, Sig } from 'tsop';

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
                    "type": "PubKey",
                    "value": {
                        "param": "pubKey",
                        "tag": "load_param"
                    }
                },
                {
                    "name": "t1",
                    "type": "Ripemd160",
                    "value": {
                        "args": [
                            "t0"
                        ],
                        "function": "hash160",
                        "tag": "call"
                    }
                },
                {
                    "name": "t2",
                    "type": "Addr",
                    "value": {
                        "prop": "pubKeyHash",
                        "tag": "load_prop"
                    }
                },
                {
                    "name": "t3",
                    "type": "boolean",
                    "value": {
                        "left": "t1",
                        "op": "==",
                        "right": "t2",
                        "tag": "bin_op"
                    }
                },
                {
                    "name": "t4",
                    "type": "void",
                    "value": {
                        "condition": "t3",
                        "tag": "assert"
                    }
                },
                {
                    "name": "t5",
                    "type": "Sig",
                    "value": {
                        "param": "sig",
                        "tag": "load_param"
                    }
                },
                {
                    "name": "t6",
                    "type": "PubKey",
                    "value": {
                        "param": "pubKey",
                        "tag": "load_param"
                    }
                },
                {
                    "name": "t7",
                    "type": "boolean",
                    "value": {
                        "args": [
                            "t5",
                            "t6"
                        ],
                        "function": "checkSig",
                        "tag": "call"
                    }
                },
                {
                    "name": "t8",
                    "type": "void",
                    "value": {
                        "condition": "t7",
                        "tag": "assert"
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
            ],
            "returnType": "void"
        }
    ],
    "properties": [
        {
            "name": "pubKeyHash",
            "readonly": true,
            "type": "Addr"
        }
    ],
    "version": "0.1.0"
}
```

Note: The above is pretty-printed for readability. The canonical form (per RFC 8785) has no whitespace and keys sorted lexicographically.

---

## 9. Validation Rules

A conforming ANF IR must satisfy:

1. **Sequential naming**: Binding at index `i` in a method body has name `t{i}`.
2. **Forward references only**: A binding may only reference temporaries with smaller indices (i.e., defined earlier in the same body or branch).
3. **Type consistency**: The `type` field of each binding matches the result type of its `value` node.
4. **No orphan references**: Every name referenced in an `ANFValue` must be either a method parameter, a property name, or a previously defined temporary.
5. **Public method assertion**: The last binding in a public method's body must have tag `assert`.
6. **Single version**: The `version` field matches the specification version.

---

## 10. Extensibility

New `ANFValue` tags may be added in future versions. A conforming implementation MUST reject unknown tags rather than silently ignoring them. The `version` field indicates which tags are valid.
