# TSOP Language Grammar

**Version:** 0.1.0
**Status:** Draft

This document defines the formal grammar for TSOP, a strict subset of TypeScript designed for compilation to Bitcoin SV Script. TSOP source files are valid TypeScript that can be type-checked by `tsc`, but only the constructs defined here are accepted by the TSOP compiler.

---

## 1. Notation

The grammar is specified in Extended Backus-Naur Form (EBNF) with the following conventions:

| Notation        | Meaning                              |
|-----------------|--------------------------------------|
| `'literal'`     | Terminal string                      |
| `A B`           | Sequence                            |
| `A \| B`        | Alternation                          |
| `[ A ]`         | Optional (zero or one)               |
| `{ A }`         | Repetition (zero or more)            |
| `( A )`         | Grouping                            |
| `/* comment */` | Informal description                 |

---

## 2. Source File Structure

A TSOP source file contains exactly one contract. Imports are restricted to the TSOP standard library.

```ebnf
SourceFile
    = { ImportDeclaration }
      ContractDeclaration
    ;

ImportDeclaration
    = 'import' '{' ImportSpecifierList '}' 'from' StringLiteral ';'
    ;

ImportSpecifierList
    = ImportSpecifier { ',' ImportSpecifier }
    ;

ImportSpecifier
    = Identifier [ 'as' Identifier ]
    ;
```

### Import Restrictions

- The `from` path MUST be one of the allowed TSOP library modules (e.g., `'tsop'`, `'tsop/builtins'`).
- Arbitrary filesystem or npm imports are **disallowed**.
- Re-exports and namespace imports (`import * as`) are **disallowed**.

---

## 3. Contract Declaration

```ebnf
ContractDeclaration
    = [ 'export' ] 'class' Identifier 'extends' 'SmartContract' '{'
          { PropertyDeclaration }
          ConstructorDeclaration
          { MethodDeclaration }
      '}'
    ;
```

### Rules

- Exactly one class per file.
- The class MUST extend `SmartContract` directly (no intermediate base classes).
- Decorators are **disallowed**.
- Generic type parameters on the class are **disallowed**.

---

## 4. Property Declarations

```ebnf
PropertyDeclaration
    = [ 'readonly' ] Identifier ':' Type ';'
    ;
```

### Semantics

- **`readonly`** properties are immutable. They are set in the constructor and cannot be reassigned. They are embedded in the locking script at deployment time.
- **Non-`readonly`** properties are stateful. They can be modified within public methods and their new values are propagated across transactions via `OP_PUSH_TX`.
- Properties MUST NOT have initializers at the declaration site; all initialization happens in the constructor.
- Access modifiers (`public`, `private`, `protected`) on properties are **optional** but have no semantic effect in TSOP -- all properties are accessible within the contract.

---

## 5. Constructor

```ebnf
ConstructorDeclaration
    = 'constructor' '(' ParameterList ')' '{'
          SuperCall
          { ConstructorStatement }
      '}'
    ;

SuperCall
    = 'super' '(' ArgumentList ')' ';'
    ;

ConstructorStatement
    = PropertyAssignment
    | VariableDeclaration
    | ExpressionStatement
    ;

PropertyAssignment
    = 'this' '.' Identifier '=' Expression ';'
    ;
```

### Rules

- The constructor MUST call `super(...)` as its first statement.
- The `super(...)` call MUST pass **all** declared properties in declaration order.
- Every property MUST be assigned exactly once in the constructor body (via `this.x = ...`).
- The constructor defines the contract's deployment parameters -- the values passed become the locking script.

---

## 6. Method Declarations

```ebnf
MethodDeclaration
    = MethodVisibility Identifier '(' ParameterList ')' ':' ReturnType MethodBody
    ;

MethodVisibility
    = 'public'
    | 'private'
    ;

ReturnType
    = 'void'      /* only for public methods */
    | Type         /* for private methods */
    | 'boolean'    /* for private methods */
    ;

MethodBody
    = '{' { Statement } '}'
    ;
```

### Public Methods

- Public methods are **entry points** -- they correspond to spending paths in the locking script.
- Public methods MUST return `void`.
- Public methods MUST end with an `assert(...)` call as their final statement. This assert encodes the spending condition: if it fails, the transaction is invalid.
- Parameters of public methods form part of the **unlocking script** (scriptSig).

### Private Methods

- Private methods are **helpers** -- they are inlined at call sites during compilation.
- Private methods may return a value.
- Private methods MUST NOT be called from outside the contract.
- Recursion (direct or mutual) is **disallowed**.

---

## 7. Parameter Lists

```ebnf
ParameterList
    = [ Parameter { ',' Parameter } ]
    ;

Parameter
    = Identifier ':' Type
    ;
```

- Default parameter values are **disallowed**.
- Rest parameters are **disallowed**.
- Destructuring parameters are **disallowed**.

---

## 8. Types

```ebnf
Type
    = 'bigint'
    | 'boolean'
    | 'ByteString'
    | 'PubKey'
    | 'Sig'
    | 'Sha256'
    | 'Ripemd160'
    | 'Addr'
    | 'SigHashPreimage'
    | 'RabinSig'
    | 'RabinPubKey'
    | FixedArrayType
    ;

FixedArrayType
    = 'FixedArray' '<' Type ',' IntegerLiteral '>'
    ;
```

### Type Descriptions

| Type              | Description                                    | Underlying   |
|-------------------|------------------------------------------------|--------------|
| `bigint`          | Arbitrary-precision integer (Script numbers)   | Script num   |
| `boolean`         | `true` or `false`                              | `OP_TRUE`/`OP_FALSE` |
| `ByteString`      | Immutable byte sequence                        | Stack bytes  |
| `PubKey`          | 33-byte compressed public key                  | ByteString   |
| `Sig`             | DER-encoded ECDSA signature + sighash byte     | ByteString   |
| `Sha256`          | 32-byte SHA-256 hash                           | ByteString   |
| `Ripemd160`       | 20-byte RIPEMD-160 hash                        | ByteString   |
| `Addr`            | 20-byte address (hash160 of pubkey)            | ByteString   |
| `SigHashPreimage` | Transaction sighash preimage                   | ByteString   |
| `RabinSig`        | Rabin signature (big integer)                  | bigint       |
| `RabinPubKey`     | Rabin public key (big integer)                 | bigint       |
| `FixedArray<T,N>` | Fixed-length array of N elements of type T     | N stack items|

### Disallowed Types

The following TypeScript types are **not permitted** in TSOP:

- `number` -- use `bigint` instead
- `string` -- use `ByteString` instead
- `any`, `unknown`, `never`, `void` (except as method return)
- `null`, `undefined`
- `Array<T>`, `T[]` -- use `FixedArray<T, N>` instead
- Object types, interfaces, type aliases, union types, intersection types
- `Map`, `Set`, `Promise`, and all standard library types

---

## 9. Statements

```ebnf
Statement
    = VariableDeclaration
    | AssignmentStatement
    | IfStatement
    | ForStatement
    | ExpressionStatement
    | ReturnStatement
    ;

VariableDeclaration
    = ('const' | 'let') Identifier [ ':' Type ] '=' Expression ';'
    ;

AssignmentStatement
    = AssignmentTarget '=' Expression ';'
    ;

AssignmentTarget
    = Identifier
    | 'this' '.' Identifier
    | Identifier '[' Expression ']'
    | 'this' '.' Identifier '[' Expression ']'
    ;

IfStatement
    = 'if' '(' Expression ')' Block [ 'else' ( IfStatement | Block ) ]
    ;

Block
    = '{' { Statement } '}'
    ;

ForStatement
    = 'for' '(' 'let' Identifier ':' 'bigint' '=' Expression ';'
                Identifier RelOp Expression ';'
                Identifier ( '++' | '--' ) ')' Block
    ;

RelOp
    = '<' | '<=' | '>' | '>='
    ;

ExpressionStatement
    = Expression ';'
    ;

ReturnStatement
    = 'return' [ Expression ] ';'
    ;
```

### Statement Restrictions

- **Variable declarations**: `const` variables cannot be reassigned. `let` variables can be reassigned but not re-declared in the same scope.
- **For loops**: MUST be bounded. The loop bound (the right-hand side of the comparison) MUST be a compile-time constant integer literal or `const` variable initialized to a literal. The loop variable MUST use simple increment (`++`) or decrement (`--`). Nested loops are allowed but the total unrolled iteration count must be statically determinable.
- **While loops, do-while loops**: **disallowed**.
- **Switch statements**: **disallowed** (use if/else chains).
- **Labeled statements, break, continue**: **disallowed**.
- **Throw statements**: **disallowed** (use `assert(false)`).
- **Try/catch/finally**: **disallowed**.

---

## 10. Expressions

```ebnf
Expression
    = TernaryExpression
    ;

TernaryExpression
    = LogicalOrExpression [ '?' Expression ':' Expression ]
    ;

LogicalOrExpression
    = LogicalAndExpression { '||' LogicalAndExpression }
    ;

LogicalAndExpression
    = EqualityExpression { '&&' EqualityExpression }
    ;

EqualityExpression
    = RelationalExpression { ( '==' | '===' | '!=' | '!==' ) RelationalExpression }
    ;

RelationalExpression
    = AdditiveExpression { RelOp AdditiveExpression }
    ;

AdditiveExpression
    = MultiplicativeExpression { ( '+' | '-' ) MultiplicativeExpression }
    ;

MultiplicativeExpression
    = UnaryExpression { ( '*' | '/' | '%' ) UnaryExpression }
    ;

UnaryExpression
    = ( '!' | '-' | '~' ) UnaryExpression
    | PostfixExpression
    ;

PostfixExpression
    = PrimaryExpression { PostfixOp }
    ;

PostfixOp
    = '(' ArgumentList ')'          /* function call */
    | '.' Identifier                 /* member access */
    | '[' Expression ']'             /* index access */
    ;

PrimaryExpression
    = Identifier
    | 'this'
    | Literal
    | '(' Expression ')'
    ;

ArgumentList
    = [ Expression { ',' Expression } ]
    ;
```

### Expression Restrictions

- **Type assertions** (`as`, `<T>`): **disallowed** (all types must be structurally correct).
- **`new` expressions**: **disallowed**.
- **Template literals**: **disallowed**.
- **Spread operator** (`...`): **disallowed**.
- **`typeof`, `instanceof`**: **disallowed**.
- **Optional chaining** (`?.`): **disallowed**.
- **Nullish coalescing** (`??`): **disallowed**.
- **Comma operator**: **disallowed**.
- **`await`, `yield`**: **disallowed**.
- **Arrow functions, function expressions**: **disallowed** (no closures).

---

## 11. Literals

```ebnf
Literal
    = IntegerLiteral
    | BigIntLiteral
    | BooleanLiteral
    | ByteStringLiteral
    ;

IntegerLiteral
    = DecimalDigits
    | '0x' HexDigits
    ;

BigIntLiteral
    = IntegerLiteral 'n'
    ;

BooleanLiteral
    = 'true' | 'false'
    ;

ByteStringLiteral
    = 'toByteString' '(' StringLiteral ')'
    ;

StringLiteral
    = "'" { Character } "'"
    | '"' { Character } '"'
    ;
```

### Notes

- Integer literals without the `n` suffix are only permitted in `FixedArray` type parameters and for-loop bounds. All runtime integer values MUST use the `bigint` suffix (`0n`, `42n`, etc.).
- `ByteString` values are constructed via `toByteString(hexString)` where `hexString` contains an even number of hex characters.
- Floating-point literals are **disallowed**.
- `null`, `undefined`, `NaN`, `Infinity` are **disallowed**.

---

## 12. Identifiers

```ebnf
Identifier
    = IdentifierStart { IdentifierPart }
    ;

IdentifierStart
    = Letter | '_' | '$'
    ;

IdentifierPart
    = IdentifierStart | DecimalDigit
    ;
```

Reserved words follow TypeScript conventions. Additionally, the following are reserved in TSOP:

- `SmartContract` (base class)
- All type names listed in section 8
- All built-in function names (e.g., `assert`, `checkSig`, `hash256`, `hash160`)

---

## 13. Built-in Functions

The following functions are available without import (provided by the TSOP runtime):

```ebnf
BuiltinFunction
    = 'assert'             /* assert(condition: boolean, message?: string): void */
    | 'checkSig'           /* checkSig(sig: Sig, pubKey: PubKey): boolean */
    | 'checkMultiSig'      /* checkMultiSig(sigs: FixedArray<Sig, M>, pubKeys: FixedArray<PubKey, N>): boolean */
    | 'hash256'            /* hash256(data: ByteString): Sha256 -- double SHA-256 */
    | 'hash160'            /* hash160(data: ByteString): Ripemd160 -- SHA-256 then RIPEMD-160 */
    | 'sha256'             /* sha256(data: ByteString): Sha256 */
    | 'ripemd160'          /* ripemd160(data: ByteString): Ripemd160 */
    | 'toByteString'       /* toByteString(hex: string): ByteString */
    | 'len'                /* len(data: ByteString): bigint */
    | 'reverseByteString'  /* reverseByteString(data: ByteString, size: bigint): ByteString */
    | 'pack'               /* pack(n: bigint): ByteString -- encode integer as Script number */
    | 'unpack'             /* unpack(data: ByteString): bigint -- decode Script number */
    | 'abs'                /* abs(n: bigint): bigint */
    | 'min'                /* min(a: bigint, b: bigint): bigint */
    | 'max'                /* max(a: bigint, b: bigint): bigint */
    | 'within'             /* within(x: bigint, lo: bigint, hi: bigint): boolean */
    | 'exit'               /* exit(success: boolean): void -- OP_RETURN */
    ;
```

---

## 14. Complete Example

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

---

## 15. Disallowed Features Summary

The following TypeScript features are explicitly excluded from TSOP:

| Feature | Reason |
|---|---|
| Decorators | Not representable in Script |
| Dynamic arrays (`T[]`) | No heap allocation in Script |
| `number` type | Ambiguous precision; use `bigint` |
| Unbounded loops (`while`, `do`) | Script has no looping; all loops must unroll |
| Recursion | Requires unbounded stack; cannot unroll |
| `async`/`await` | No asynchrony in Script execution |
| `try`/`catch`/`finally` | Script has no exception model |
| Closures / arrow functions | No heap-allocated environments |
| `any`, `unknown` | Defeats static analysis |
| Spread operator | Dynamic arity not supported |
| Arbitrary imports | Sandboxed compilation environment |
| Multiple classes per file | One contract = one locking script |
| Class inheritance (beyond SmartContract) | No polymorphic dispatch in Script |
| Interfaces, type aliases | Use concrete types only |
| Enums | Use `bigint` constants instead |
| Modules / namespaces | One contract per file |
| Generator functions | No coroutines in Script |
| `eval`, dynamic property access | No runtime metaprogramming |
