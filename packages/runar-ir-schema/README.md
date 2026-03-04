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
  +-- kind: 'contract'
  +-- name: string
  +-- parentClass: 'SmartContract' | 'StatefulSmartContract'
  +-- properties: PropertyNode[]
  +-- constructor: MethodNode
  +-- methods: MethodNode[]
  +-- sourceFile: string

PropertyNode
  +-- kind: 'property'
  +-- name: string
  +-- type: TypeNode
  +-- readonly: boolean
  +-- sourceLocation: SourceLocation

MethodNode
  +-- kind: 'method'
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

All statement nodes include an implicit `sourceLocation: SourceLocation` field (omitted from the table for brevity).

| Kind | Fields | Description |
|---|---|---|
| `variable_decl` | `name`, `type?`, `init` | `const x = ...` or `let x = ...` |
| `assignment` | `target`, `value` | `x = ...` or `this.x = ...` |
| `if_statement` | `condition`, `then`, `else?` | Conditional |
| `for_statement` | `init: VariableDeclStatement`, `condition: Expression`, `update: Statement`, `body: Statement[]` | Bounded loop |
| `return_statement` | `value?` | Return from private method |
| `expression_statement` | `expression` | Expression as statement |

---

## ANF IR Specification

The ANF IR is the **canonical conformance boundary** for all Rúnar compilers. It is produced by Pass 4 (ANF Lower). Two conforming compilers MUST produce byte-identical ANF IR for the same source.

### Structure

```
ANFProgram
  +-- contractName: string
  +-- properties: ANFProperty[]
  +-- methods: ANFMethod[]

ANFMethod
  +-- name: string
  +-- params: ANFParam[]
  +-- body: ANFBinding[]        (flat list of bindings)
  +-- isPublic: boolean

ANFBinding
  +-- name: string              (t0, t1, t2, ...)
  +-- value: ANFValue           (discriminated on `kind`)
```

### ANF Value Kinds

| Kind | Fields | Description |
|---|---|---|
| `load_param` | `name` | Load a method parameter |
| `load_prop` | `name` | Load a contract property |
| `load_const` | `value` | Load a constant (`string \| bigint \| boolean`) |
| `bin_op` | `op`, `left`, `right`, `result_type?` | Binary operation on two bindings |
| `unary_op` | `op`, `operand` | Unary operation |
| `call` | `func`, `args` | Call a built-in function |
| `method_call` | `object`, `method`, `args` | Call a private method |
| `if` | `cond`, `then`, `else` | Conditional (branches are `ANFBinding[]`) |
| `loop` | `count`, `body`, `iterVar` | Bounded loop (`body` is `ANFBinding[]`) |
| `assert` | `value` | Assert condition |
| `update_prop` | `name`, `value` | Update mutable property |
| `get_state_script` | _(none)_ | Get serialized state |
| `check_preimage` | `preimage` | Verify sighash preimage |
| `add_output` | `satoshis`, `stateValues` | Add a transaction output (`stateValues` is `string[]`) |

### Example

Source:

```typescript
assert(hash160(pubKey) === this.pubKeyHash);
```

ANF IR:

```json
[
  { "name": "t0", "value": { "kind": "load_param", "name": "pubKey" } },
  { "name": "t1", "value": { "kind": "call", "func": "hash160", "args": ["t0"] } },
  { "name": "t2", "value": { "kind": "load_prop", "name": "pubKeyHash" } },
  { "name": "t3", "value": { "kind": "bin_op", "op": "==", "left": "t1", "right": "t2" } },
  { "name": "t4", "value": { "kind": "assert", "value": "t3" } }
]
```

---

## Stack IR

The Stack IR is produced by Pass 5 (Stack Lower). It replaces named bindings with explicit stack operations.

Each instruction is discriminated on the `op` field:

| Op | Fields | Description |
|---|---|---|
| `push` | `value` (`Uint8Array \| bigint \| boolean`) | Push a value onto the stack |
| `dup` | _(none)_ | `OP_DUP` |
| `swap` | _(none)_ | `OP_SWAP` |
| `roll` | `depth` | `OP_ROLL` from stack position `depth` |
| `pick` | `depth` | `OP_PICK` from stack position `depth` |
| `drop` | _(none)_ | `OP_DROP` |
| `opcode` | `code` (e.g., `'OP_ADD'`) | Execute an opcode |
| `if` | `then`, `else?` (both `StackOp[]`) | `OP_IF ... OP_ELSE ... OP_ENDIF` |
| `nip` | _(none)_ | `OP_NIP` |
| `over` | _(none)_ | `OP_OVER` |
| `rot` | _(none)_ | `OP_ROT` |
| `tuck` | _(none)_ | `OP_TUCK` |
| `placeholder` | `paramIndex`, `paramName` | Constructor parameter placeholder |

---

## Artifact Format

The compilation artifact (`RunarArtifact`) is the output of the full pipeline:

```json
{
  "version": "runar-v0.1.0",
  "compilerVersion": "0.1.0",
  "contractName": "P2PKH",
  "abi": { "constructor": { "params": [...] }, "methods": [...] },
  "script": "76a97c7e7e87a988ac",
  "asm": "OP_DUP OP_HASH160 ...",
  "sourceMap": { "mappings": [...] },
  "ir": { "anf": { ... }, "stack": { ... } },
  "stateFields": [{ "name": "count", "type": "bigint", "index": 0 }],
  "constructorSlots": [{ "paramIndex": 0, "byteOffset": 3 }],
  "buildTimestamp": "2025-01-01T00:00:00.000Z"
}
```

Fields `sourceMap`, `ir`, `stateFields`, and `constructorSlots` are optional.

---

## Canonical JSON Serialization

The ANF IR is serialized according to **RFC 8785 (JSON Canonicalization Scheme / JCS)**:

1. Object keys sorted by UTF-16 code-unit order (per RFC 8785).
2. No whitespace between tokens.
3. Numbers in shortest representation, no trailing zeros.
4. Strings use minimal escaping.
5. No duplicate keys.
6. UTF-8 encoding.

This ensures byte-identical output across implementations. The SHA-256 of the serialized JSON is the conformance check:

```
sha256(canonical_json(compiler_A(source))) === sha256(canonical_json(compiler_B(source)))
```

The package exports two functions for canonical serialization:

```typescript
import { canonicalJsonStringify, canonicalise } from 'runar-ir-schema';

// Serialise any JSON-compatible value to canonical JSON (RFC 8785 / JCS).
// Throws TypeError if the value contains undefined, functions, symbols, or circular references.
// BigInt values are serialised as bare integers (no quotes).
const json = canonicalJsonStringify(anfProgram);

// Parse a JSON string and re-serialise it to canonical form.
// Useful for normalising IR that was stored with pretty-printing.
const normalized = canonicalise(prettyPrintedJson);
```

---

## JSON Schema Validation

```typescript
import { validateANF, validateArtifact } from 'runar-ir-schema';

const result = validateANF(jsonData);
if (!result.valid) {
  console.error(result.errors);
}

// Or use the assert variants that throw on failure:
import { assertValidANF, assertValidArtifact } from 'runar-ir-schema';
assertValidANF(jsonData); // throws if invalid
```

Schemas are defined using JSON Schema 2020-12 and validated with Ajv.

---

## Design Decision: Discriminated Unions for IR Nodes

All IR nodes use a `kind` field as a discriminant (for AST nodes and ANF values) or an `op` field (for Stack IR operations). This pattern:

- Enables exhaustive `switch` statements in TypeScript (the compiler warns about unhandled cases).
- Makes serialization straightforward -- the discriminant field tells the deserializer which fields to expect.
- Avoids class hierarchies and `instanceof` checks, keeping the IR as plain data that can be serialized, compared, and hashed without class metadata.
- Maps naturally to JSON Schema's `oneOf` + `const` pattern for validation.
