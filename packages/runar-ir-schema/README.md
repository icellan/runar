# runar-ir-schema

**IR type definitions, JSON schemas, and validators for the Rúnar compilation pipeline.**

This package defines the data structures that flow between compiler passes: the Rúnar AST, the ANF IR, the Stack IR, and the compilation artifact format. It also provides JSON Schema definitions for validating serialized IR and utility functions for canonical serialization.

---

## Installation

```bash
pnpm add runar-ir-schema
```

---

## Rúnar AST

The Rúnar AST is produced by Pass 1 (Parse) and consumed by Pass 2 (Validate) and Pass 3 (Type-check). It closely mirrors the source syntax.

### Top-Level Nodes

```
ContractNode
  +-- name: string
  +-- properties: PropertyNode[]
  +-- constructor: MethodNode
  +-- methods: MethodNode[]
  +-- sourceFile: string

PropertyNode
  +-- name: string
  +-- type: TypeNode
  +-- readonly: boolean
  +-- sourceLocation: SourceLocation

MethodNode
  +-- name: string
  +-- params: ParamNode[]
  +-- body: Statement[]
  +-- visibility: 'public' | 'private'
  +-- sourceLocation: SourceLocation
```

### Expression Nodes

All expressions use a discriminated union on the `kind` field:

| Kind | Fields | Description |
|---|---|---|
| `binary_expr` | `op`, `left`, `right` | Binary operation |
| `unary_expr` | `op`, `operand` | Unary operation |
| `call_expr` | `callee`, `args` | Function call |
| `member_expr` | `object`, `property` | Member access (e.g., `obj.prop`) |
| `identifier` | `name` | Variable reference |
| `bigint_literal` | `value` | Integer literal |
| `bool_literal` | `value` | Boolean literal |
| `bytestring_literal` | `value` | Hex byte string literal |
| `ternary_expr` | `condition`, `consequent`, `alternate` | Ternary conditional |
| `property_access` | `property` | `this.x` access |
| `index_access` | `object`, `index` | Array index `arr[i]` |
| `increment_expr` | `operand`, `prefix` | `x++` or `++x` |
| `decrement_expr` | `operand`, `prefix` | `x--` or `--x` |

### Statement Nodes

| Kind | Fields | Description |
|---|---|---|
| `variable_decl` | `name`, `type?`, `init` | `const x = ...` or `let x = ...` |
| `assignment` | `target`, `value` | `x = ...` or `this.x = ...` |
| `if_statement` | `condition`, `then`, `else?` | Conditional |
| `for_statement` | `init`, `condition`, `update`, `body` | Bounded loop |
| `return_statement` | `value?` | Return from private method |
| `expression_statement` | `expression` | Expression as statement |

---

## ANF IR Specification

The ANF IR is the **canonical conformance boundary** for all Rúnar compilers. It is produced by Pass 4 (ANF Lower). Two conforming compilers MUST produce byte-identical ANF IR for the same source.

### Structure

```
ANFProgram
  +-- version: string           (e.g., "0.1.0")
  +-- contractName: string
  +-- properties: ANFProperty[]
  +-- methods: ANFMethod[]

ANFMethod
  +-- name: string
  +-- params: ANFParam[]
  +-- body: ANFBinding[]        (flat list of bindings)
  +-- isPublic: boolean
  +-- returnType: ANFType

ANFBinding
  +-- name: string              (t0, t1, t2, ...)
  +-- type: ANFType
  +-- value: ANFValue           (tagged union)
```

### ANF Value Tags

| Tag | Fields | Description |
|---|---|---|
| `load_param` | `param` | Load a method parameter |
| `load_prop` | `prop` | Load a contract property |
| `load_const` | `constType`, `value` | Load a constant value |
| `bin_op` | `op`, `left`, `right` | Binary operation on two bindings |
| `unary_op` | `op`, `operand` | Unary operation |
| `call` | `function`, `args` | Call a built-in function |
| `method_call` | `method`, `args` | Call a private method |
| `if` | `condition`, `thenBranch`, `elseBranch`, `thenResult`, `elseResult` | Conditional |
| `loop` | `iterations` | Unrolled bounded loop |
| `assert` | `condition` | Assert condition |
| `update_prop` | `prop`, `value` | Update mutable property |
| `get_state_script` | _(none)_ | Get serialized state |
| `check_preimage` | `preimage` | Verify sighash preimage |
| `array_access` | `array`, `index` | Read from array |
| `array_update` | `array`, `index`, `value` | Write to array |

### Example

Source:

```typescript
assert(hash160(pubKey) === this.pubKeyHash);
```

ANF IR:

```json
[
  { "name": "t0", "type": "PubKey",    "value": { "tag": "load_param", "param": "pubKey" } },
  { "name": "t1", "type": "Ripemd160", "value": { "tag": "call", "function": "hash160", "args": ["t0"] } },
  { "name": "t2", "type": "Addr",      "value": { "tag": "load_prop", "prop": "pubKeyHash" } },
  { "name": "t3", "type": "boolean",   "value": { "tag": "bin_op", "op": "==", "left": "t1", "right": "t2" } },
  { "name": "t4", "type": "void",      "value": { "tag": "assert", "condition": "t3" } }
]
```

---

## Stack IR

The Stack IR is produced by Pass 5 (Stack Lower). It replaces named bindings with explicit stack operations.

Each instruction is one of:

| Instruction | Description |
|---|---|
| `push_data(bytes)` | Push raw bytes onto the stack |
| `push_int(n)` | Push a Script-encoded integer |
| `opcode(op)` | Execute an opcode |
| `pick(depth)` | `OP_PICK` from stack position `depth` |
| `roll(depth)` | `OP_ROLL` from stack position `depth` |
| `to_alt` | `OP_TOALTSTACK` |
| `from_alt` | `OP_FROMALTSTACK` |
| `if_block(then, else)` | `OP_IF ... OP_ELSE ... OP_ENDIF` |

---

## Artifact Format

The compilation artifact is the output of the full pipeline:

```json
{
  "version": "0.1.0",
  "contractName": "P2PKH",
  "compilerVersion": "0.1.0",
  "script": "76a97c7e7e87a988ac",
  "abi": { ... },
  "properties": [ ... ],
  "anfIR": { ... },
  "sourceMap": { ... }
}
```

---

## Canonical JSON Serialization

The ANF IR is serialized according to **RFC 8785 (JSON Canonicalization Scheme / JCS)**:

1. Object keys sorted lexicographically by Unicode code point.
2. No whitespace between tokens.
3. Numbers in shortest representation, no trailing zeros.
4. Strings use minimal escaping.
5. No duplicate keys.
6. UTF-8 encoding.

This ensures byte-identical output across implementations. The SHA-256 of the serialized JSON is the conformance check:

```
sha256(canonical_json(compiler_A(source))) === sha256(canonical_json(compiler_B(source)))
```

---

## JSON Schema Validation

```typescript
import { validateANFIR, validateArtifact, validateRunarAST } from 'runar-ir-schema';

const result = validateANFIR(jsonData);
if (!result.valid) {
  console.error(result.errors);
}
```

Schemas are defined using JSON Schema 2020-12 and validated with AJV.

---

## Design Decision: Discriminated Unions for IR Nodes

All IR nodes use a `kind` field (for AST nodes) or `tag` field (for ANF values) as a discriminant. This pattern:

- Enables exhaustive `switch` statements in TypeScript (the compiler warns about unhandled cases).
- Makes serialization straightforward -- the discriminant field tells the deserializer which fields to expect.
- Avoids class hierarchies and `instanceof` checks, keeping the IR as plain data that can be serialized, compared, and hashed without class metadata.
- Maps naturally to JSON Schema's `oneOf` + `const` pattern for validation.
