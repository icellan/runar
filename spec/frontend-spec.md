# Rúnar Frontend Specification

**Version:** 0.1.0
**Status:** Draft

This document specifies the **language-agnostic contract** of Rúnar frontend parsers. Every parser -- regardless of input format (TypeScript, Solidity-like, Move-like, Go, Rust) -- must produce a `ContractNode` AST that conforms to this specification. The AST is the universal interface between the frontend (parsing) and the backend (validate, typecheck, ANF lower, stack lower, emit).

---

## 1. Design Principles

1. **One AST for all formats.** There is exactly one AST definition. All parsers target it. The backend never knows which format the source was written in.
2. **Canonical field names use camelCase.** Parsers for languages that use snake_case (Move, Rust) or PascalCase (Go) must convert identifiers to camelCase.
3. **Constructor is always present.** Even if the source format does not have explicit constructor syntax (Go, Rust), the parser must synthesize one.
4. **Source locations are best-effort.** Parsers should attach source locations for error reporting, but the exact line/column values are format-specific and not part of conformance testing.

---

## 2. ContractNode

The root of the AST. Every parser produces exactly one `ContractNode`.

```
ContractNode = {
    kind: "contract",
    name: string,                              // PascalCase contract name
    parentClass: "SmartContract" | "StatefulSmartContract" | "InductiveSmartContract",
    properties: PropertyNode[],                // in declaration order
    constructor: MethodNode,                   // always present
    methods: MethodNode[],                     // in declaration order (excludes constructor)
    sourceFile: string                         // path to the source file
}
```

### Rules

- `name` must be a valid PascalCase identifier.
- `parentClass` must be exactly `"SmartContract"`, `"StatefulSmartContract"`, or `"InductiveSmartContract"`.
- `properties` must be in the same order as they appear in the source (or struct definition).
- `constructor` is the synthetic or explicit constructor method.
- `methods` must be in declaration order and must not include the constructor.

### Format Mapping

| Format | Contract name source | parentClass source |
|--------|--------------------|--------------------|
| TypeScript | `class Name extends Base` | `extends SmartContract` / `extends StatefulSmartContract` / `extends InductiveSmartContract` |
| Solidity | `contract Name is Base` | `is SmartContract` / `is StatefulSmartContract` / `is InductiveSmartContract` |
| Move | `module Name { ... }` | `use runar::SmartContract` / `use runar::StatefulSmartContract` / `use runar::InductiveSmartContract` |
| Go | `type Name struct { runar.SmartContract; ... }` | embedded `runar.SmartContract` / `runar.StatefulSmartContract` / `runar.InductiveSmartContract` |
| Rust | `#[runar::contract] struct Name` / `#[runar::stateful_contract] struct Name` / `#[runar::inductive_contract] struct Name` | `#[runar::contract]` (auto-detects) / `#[runar::stateful_contract]` / `#[runar::inductive_contract]` |

---

## 3. PropertyNode

Declares a contract property (on-chain state or baked-in constant).

```
PropertyNode = {
    kind: "property",
    name: string,                    // camelCase property name
    type: TypeNode,                  // the property's type
    readonly: boolean,               // true = immutable, false = mutable (stateful)
    sourceLocation: SourceLocation
}
```

### Rules

- `name` must be camelCase.
- For `SmartContract`, all properties should have `readonly: true`.
- For `StatefulSmartContract` or `InductiveSmartContract`, at least one property should have `readonly: false`.
- Properties must not have initializer expressions; initialization happens in the constructor.

### Format Mapping

| Format | Property syntax | Readonly marker |
|--------|----------------|-----------------|
| TypeScript | `readonly name: Type;` / `name: Type;` | `readonly` keyword |
| Solidity | `Type immutable name;` / `Type name;` | `immutable` keyword |
| Move | `name: Type readonly,` / `name: Type,` | `readonly` suffix |
| Go | `Name runar.Type \`runar:"readonly"\`` | struct tag |
| Rust | `#[readonly] name: Type` / `name: Type` | `#[readonly]` attribute |

---

## 4. MethodNode

Declares a contract method (spending entry point or private helper).

```
MethodNode = {
    kind: "method",
    name: string,                        // camelCase method name
    params: ParamNode[],                 // in declaration order
    body: Statement[],                   // statement list
    visibility: "public" | "private",
    sourceLocation: SourceLocation
}
```

### Rules

- `name` must be camelCase.
- Public methods must have `visibility: "public"`.
- Private methods must have `visibility: "private"`.
- The constructor method has `name: "constructor"` and `visibility: "public"`.
- Public method bodies must not contain `return` statements with values.
- Private method bodies may contain `return` statements.

### Format Mapping

| Format | Public marker | Private marker |
|--------|--------------|----------------|
| TypeScript | `public methodName(...)` | `private methodName(...)` |
| Solidity | `function name(...) public` | `function name(...) private` |
| Move | `public fun name(...)` | `fun name(...)` |
| Go | `func (c *T) Name(...)` (exported) | `func (c *T) name(...)` (unexported) |
| Rust | `#[public] fn name(...)` | `fn name(...)` |

### ParamNode

```
ParamNode = {
    kind: "param",
    name: string,         // camelCase parameter name
    type: TypeNode
}
```

Parameter names must be camelCase. Parsers for snake_case languages must convert.

---

## 5. Constructor Synthesis

For formats without explicit constructor syntax (Go, Rust), the parser must synthesize a constructor with the following structure:

```
MethodNode = {
    kind: "method",
    name: "constructor",
    params: [
        // one ParamNode per property, in declaration order
        { kind: "param", name: prop.name, type: prop.type }
        ...
    ],
    body: [
        // super call (ExpressionStatement wrapping CallExpr)
        {
            kind: "expression_statement",
            expression: {
                kind: "call_expr",
                callee: { kind: "identifier", name: "super" },
                args: [ { kind: "identifier", name: prop.name } ... ]
            }
        },
        // property assignments
        {
            kind: "assignment",
            target: { kind: "property_access", property: prop.name },
            value: { kind: "identifier", name: prop.name }
        }
        ...
    ],
    visibility: "public"
}
```

For TypeScript and Solidity-like formats with explicit constructors, the parser reads the constructor from the source but must validate that it follows the same pattern (super call first, then property assignments).

---

## 6. TypeNode

Types are represented as tagged unions.

```
TypeNode =
    | PrimitiveTypeNode
    | FixedArrayTypeNode
    | CustomTypeNode

PrimitiveTypeNode = {
    kind: "primitive_type",
    name: PrimitiveTypeName
}

FixedArrayTypeNode = {
    kind: "fixed_array_type",
    element: TypeNode,
    length: integer       // compile-time constant, > 0
}

CustomTypeNode = {
    kind: "custom_type",
    name: string
}
```

### PrimitiveTypeName

```
PrimitiveTypeName =
    | "bigint"
    | "boolean"
    | "ByteString"
    | "PubKey"
    | "Sig"
    | "Sha256"
    | "Ripemd160"
    | "Addr"
    | "SigHashPreimage"
    | "RabinSig"
    | "RabinPubKey"
    | "void"
```

### Type Normalization Rules

Parsers must normalize format-specific type names to Rúnar canonical names:

| Input (any format) | Canonical PrimitiveTypeName |
|--------------------|---------------------------|
| `bigint`, `int256`, `i64`, `int64`, `BigInt` | `"bigint"` |
| `boolean`, `bool` | `"boolean"` |
| `ByteString`, `bytes` | `"ByteString"` |
| `Addr`, `address` | `"Addr"` |
| All other type names (`PubKey`, `Sig`, etc.) | Used as-is (already canonical) |

---

## 7. Statement Types

All parsers must produce statements using these exact `kind` values.

### VariableDeclStatement

```
{
    kind: "variable_decl",
    name: string,               // camelCase
    type?: TypeNode,            // optional; omitted when type is inferred
    mutable: boolean,           // false = const, true = let
    init: Expression,
    sourceLocation: SourceLocation
}
```

| Format | Immutable | Mutable |
|--------|-----------|---------|
| TypeScript | `const x = ...` | `let x = ...` |
| Solidity | `Type x = ...` (inferred const) | `Type x = ...` (if reassigned) |
| Move | `let x = ...` | `let x = ...` (if reassigned) |
| Go | `x := ...` (inferred) | `var x Type = ...` |
| Rust | `let x = ...` | `let mut x = ...` |

### AssignmentStatement

```
{
    kind: "assignment",
    target: Expression,         // PropertyAccessExpr, Identifier, or IndexAccessExpr
    value: Expression,
    sourceLocation: SourceLocation
}
```

### IfStatement

```
{
    kind: "if_statement",
    condition: Expression,
    then: Statement[],
    else?: Statement[],         // optional; may contain a single nested IfStatement for else-if
    sourceLocation: SourceLocation
}
```

### ForStatement

```
{
    kind: "for_statement",
    init: VariableDeclStatement,
    condition: Expression,
    update: Statement,            // ExpressionStatement wrapping IncrementExpr or DecrementExpr
    body: Statement[],
    sourceLocation: SourceLocation
}
```

| Format | Loop syntax |
|--------|-------------|
| TypeScript | `for (let i = 0n; i < 10n; i++)` |
| Solidity | `for (int256 i = 0; i < 10; i++)` |
| Move | `let i = 0; while (i < 10) { ... i = i + 1; }` (desugared to for) |
| Go | `for i := 0; i < 10; i++` |
| Rust | `for i in 0..10` |

### ReturnStatement

```
{
    kind: "return_statement",
    value?: Expression,
    sourceLocation: SourceLocation
}
```

### ExpressionStatement

```
{
    kind: "expression_statement",
    expression: Expression,
    sourceLocation: SourceLocation
}
```

Used for function calls (including `assert`), increment/decrement as statements, and the `super(...)` call.

---

## 8. Expression Types

### BinaryExpr

```
{
    kind: "binary_expr",
    op: BinaryOp,
    left: Expression,
    right: Expression
}
```

```
BinaryOp = "+" | "-" | "*" | "/" | "%" |
           "<<" | ">>" |
           "===" | "!==" | "<" | "<=" | ">" | ">=" |
           "&&" | "||" | "&" | "|" | "^"
```

**Operator normalization:** Parsers must convert `==` to `===` and `!=` to `!==`. The AST always uses strict equality.

### UnaryExpr

```
{
    kind: "unary_expr",
    op: UnaryOp,
    operand: Expression
}
```

```
UnaryOp = "!" | "-" | "~"
```

### CallExpr

```
{
    kind: "call_expr",
    callee: Expression,         // Identifier or MemberExpr
    args: Expression[]
}
```

### MemberExpr

```
{
    kind: "member_expr",
    object: Expression,
    property: string            // camelCase
}
```

### Identifier

```
{
    kind: "identifier",
    name: string                // camelCase
}
```

### BigIntLiteral

```
{
    kind: "bigint_literal",
    value: bigint               // arbitrary-precision integer
}
```

All integer literals from all formats (with or without `n` suffix) must be represented as `BigIntLiteral`.

### BoolLiteral

```
{
    kind: "bool_literal",
    value: boolean
}
```

### ByteStringLiteral

```
{
    kind: "bytestring_literal",
    value: string               // hex-encoded, lowercase, even number of characters
}
```

### TernaryExpr

```
{
    kind: "ternary_expr",
    condition: Expression,
    consequent: Expression,
    alternate: Expression
}
```

| Format | Ternary syntax |
|--------|---------------|
| TypeScript | `cond ? a : b` |
| Solidity | `cond ? a : b` |
| Move | `if (cond) a else b` (expression) |
| Go | Not supported (use if/else statement) |
| Rust | `if cond { a } else { b }` (expression) |

### PropertyAccessExpr

```
{
    kind: "property_access",
    property: string            // camelCase property name
}
```

Represents `this.x` access. The `this`/`self`/`c.` prefix is stripped; only the property name remains.

### IndexAccessExpr

```
{
    kind: "index_access",
    object: Expression,
    index: Expression
}
```

### IncrementExpr

```
{
    kind: "increment_expr",
    operand: Expression,
    prefix: boolean
}
```

| Format | Increment syntax | Representation |
|--------|-----------------|----------------|
| TypeScript | `x++` / `++x` | `prefix: false` / `prefix: true` |
| Solidity | `x++` | `prefix: false` |
| Move | Not available (use `x = x + 1`) | Parser desugars assignment to increment when pattern matches |
| Go | `x++` | `prefix: false` (Go only has postfix) |
| Rust | Not available (use `x += 1`) | Parser desugars `+= 1` to increment |

### DecrementExpr

```
{
    kind: "decrement_expr",
    operand: Expression,
    prefix: boolean
}
```

Same pattern as IncrementExpr, with `--` / `-= 1` / `x = x - 1`.

---

## 9. SourceLocation

```
SourceLocation = {
    file: string,         // source file path
    line: integer,        // 1-based line number
    column: integer       // 0-based column offset
}
```

Source locations are attached to all `PropertyNode`, `MethodNode`, and `Statement` nodes. They are used for error reporting and are not part of conformance testing (different parsers may report slightly different positions for the same logical construct).

---

## 10. Conformance Requirements

A parser is conformant if, for every valid input in its format, it produces a `ContractNode` that satisfies:

1. **Structural correctness.** All required fields are present with correct types.
2. **Name normalization.** All identifier names are camelCase (except the contract name, which is PascalCase).
3. **Type normalization.** All type names are canonical Rúnar type names.
4. **Operator normalization.** `==` is `===`, `!=` is `!==`.
5. **Constructor presence.** A constructor `MethodNode` is always present, even if synthesized.
6. **Declaration order.** Properties and methods appear in the same order as in the source.
7. **Semantic equivalence.** The AST produced from format X for a given contract must be structurally identical (modulo source locations) to the AST produced from the TypeScript version of the same contract.

Requirement 7 is the key conformance test: write the same contract in TypeScript and in another format, parse both, strip source locations, and assert deep equality.
