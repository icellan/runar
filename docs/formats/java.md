# Java Contract Format

**Status:** Experimental
**File extension:** `.runar.java`
**Supported compilers:** Java (native today). TypeScript, Go, Rust, Python, Zig, and Ruby gain `.runar.java` parsing after milestone 7 of the Java tier plan — until then, cross-compiler parity is limited to the Java compiler.

---

## Overview

The Java format lets you write Rúnar contracts as plain Java classes extending `SmartContract` or `StatefulSmartContract`. Contracts use standard Java syntax with camelCase naming, annotations for Rúnar-specific metadata (`@Public`, `@Readonly`), and `java.math.BigInteger` in place of a bespoke bigint literal.

The parser is built on the standard-JDK `javax.tools.JavaCompiler` + `com.sun.source.tree` API, so no third-party parser dependency is required. Non-contract Java constructs (inner classes, lambdas, switch expressions, generics beyond `FixedArray`, try/catch, annotations other than `@Readonly` / `@Public` / `@Stateful`) are rejected at parse time — the parser prefers loud failures over silent divergence from the other compilers.

See [`docs/java-tier-plan.md`](../java-tier-plan.md) for the full roadmap covering compiler, SDK, conformance, and integration milestones.

---

## Syntax

### Imports

```java
package runar.examples.p2pkh;

import runar.lang.SmartContract;
import runar.lang.annotations.Public;
import runar.lang.annotations.Readonly;
import runar.lang.types.Addr;
import runar.lang.types.PubKey;
import runar.lang.types.Sig;

import static runar.lang.Builtins.assertThat;
import static runar.lang.Builtins.checkSig;
import static runar.lang.Builtins.hash160;
```

The import lines are consumed by javac for type resolution but do not alter the AST. A typical contract pulls the base class from `runar.lang`, the annotations from `runar.lang.annotations`, domain types from `runar.lang.types`, and static-imports its builtins from `runar.lang.Builtins`.

### Class Declaration

```java
class P2PKH extends SmartContract {
    @Readonly Addr pubKeyHash;

    P2PKH(Addr pubKeyHash) {
        super(pubKeyHash);
        this.pubKeyHash = pubKeyHash;
    }

    @Public
    void unlock(Sig sig, PubKey pubKey) {
        assertThat(hash160(pubKey).equals(pubKeyHash));
        assertThat(checkSig(sig, pubKey));
    }
}
```

- Extend `SmartContract` (stateless) or `StatefulSmartContract` (stateful)
- One contract class per file
- Constructor must call `super(...)` as the first statement

**Contract classes in `.runar.java` files are package-private** (no `public` modifier on the class). javac rejects a public class whose compound `.runar.java` suffix does not match the class's bare simple name, so the class, its constructor, and its methods are declared without `public`. The contract stays reachable inside its own package for testing and compilation. Cross-package consumers use the typed-wrapper facade emitted by the Rúnar SDK codegen (milestone 10 of the Java tier plan), not the raw contract class.

### Properties

```java
class Auction extends StatefulSmartContract {
    @Readonly PubKey auctioneer;      // immutable
    PubKey highestBidder;              // mutable (stateful)
    BigInteger highestBid;             // mutable (stateful)
    @Readonly BigInteger deadline;     // immutable
}
```

- In `SmartContract`, all properties are implicitly readonly regardless of whether `@Readonly` is present
- In `StatefulSmartContract`, annotate readonly properties with `@Readonly` from `runar.lang.annotations`
- Unannotated fields on a `StatefulSmartContract` are mutable state fields

Fields use plain Java declarations — no `private`/`public`/`final` decoration is required. Visibility modifiers are ignored by the parser; the `@Readonly` annotation alone determines mutability.

### Property Initializers

Fields can carry a default value using a Java field initializer. Only literal values are permitted:

```java
class GameBoard extends StatefulSmartContract {
    BigInteger count = BigInteger.ZERO;              // mutable with default
    @Readonly boolean active = true;                 // readonly with default
    @Readonly ByteString magic = ByteString.fromHex("deadbeef");
    @Readonly PubKey owner;                          // no default — required in constructor
}
```

The parser accepts these literal forms:

- `BigInteger.ZERO`, `BigInteger.ONE`, `BigInteger.TWO`, `BigInteger.TEN`
- `BigInteger.valueOf(n)` where `n` is an integer literal
- `true`, `false`
- `ByteString.fromHex("...")` and `fromHex("...")` on any ByteString subtype

Properties with initializers are excluded from the auto-generated constructor. Only properties without defaults need to be passed as constructor arguments — the same rule every other format follows.

### Method Visibility

| Java syntax | Rúnar visibility |
|-------------|------------------|
| `@Public` annotation on the method | `public` (spending entry point) |
| No annotation | `private` (inlined helper) |

```java
@Public
void unlock(Sig sig, PubKey pubKey) {
    ...
}

BigInteger computeThreshold(BigInteger a, BigInteger b) {
    return a * b + BigInteger.ONE;
}
```

Public methods must return `void` — they are spending entry points whose success is determined by the assertions in their body. Private helpers may declare any Rúnar-legal return type.

### Name Conversion

None. Java identifiers are already camelCase, so the parser passes names through unchanged. Contrast this with Python, which converts `pub_key_hash` to `pubKeyHash` during parsing. A Java contract's `pubKeyHash` field arrives in the AST as `pubKeyHash`, and `checkSig` stays `checkSig`.

Special identifiers:

- The constructor method name becomes `constructor` in the AST
- `this.foo` becomes `PropertyAccessExpr("foo")`
- `super(...)` is preserved as a `CallExpr` against the identifier `super`

---

## Type Mappings

| Java Type | Rúnar AST Type |
|-----------|---------------|
| `BigInteger` / `Bigint` | `bigint` |
| `boolean` / `Boolean` | `boolean` |
| `Addr` | `Addr` |
| `Sig` | `Sig` |
| `PubKey` | `PubKey` |
| `ByteString` | `ByteString` |
| `Point` | `Point` |
| `P256Point` | `P256Point` |
| `P384Point` | `P384Point` |
| `Sha256Digest` | `Sha256` |
| `SigHashPreimage` | `SigHashPreimage` |
| `RabinSig` | `RabinSig` |
| `RabinPubKey` | `RabinPubKey` |
| `Ripemd160` / `Hash160` | `Ripemd160` |
| `OpCodeType` | `OpCodeType` |
| `FixedArray<T, N>` | Fixed-size array (expanded to scalar properties during ANF) |
| `@Readonly` | Marks property `readonly: true` |

`FixedArray` requires exactly two type arguments. The length argument must be an integer literal — the parser does not resolve symbolic constants into the type position. A future pass may relax this.

---

## Literals

Rúnar Java contracts use Java's native literal forms, with two recognised calls promoted to AST literals:

| Java source | AST literal |
|-------------|-------------|
| `7`, `42L` | `BigIntLiteral(BigInteger.valueOf(...))` |
| `BigInteger.valueOf(7)` | `BigIntLiteral(7)` |
| `BigInteger.ZERO` / `ONE` / `TWO` / `TEN` | `BigIntLiteral(0..10)` |
| `true` / `false` | `BoolLiteral` |
| `ByteString.fromHex("deadbeef")` | `ByteStringLiteral("deadbeef")` |
| `PubKey.fromHex("...")` (and other ByteString subtypes) | `ByteStringLiteral(...)` |

Bare `String` literals are rejected — use `ByteString.fromHex("...")` or a subtype's `fromHex` to author raw bytes. `char`, `float`, `double`, and `null` literals are all rejected at parse time.

Integer literals auto-promote to `BigIntLiteral`, so writing `count + 1` in a Java contract yields the same AST as `count + BigInteger.ONE`.

---

## Equality

Java has no operator overloading, so ByteString and its subtypes expose `.equals(...)` for value comparison. The parser recognises the `.equals` member-access followed by a call and treats the result as strict equality — it compiles to the same `===` AST node that `==` produces in TypeScript:

```java
assertThat(hash160(pubKey).equals(pubKeyHash));        // strict ByteString equality
```

For `BigInteger` and `boolean` values, write `==` directly — the validator routes `==` to the correct semantics based on operand type:

```java
assertThat(x == BigInteger.valueOf(7));                // bigint comparison
assertThat(active == true);                            // boolean comparison
```

There is no `Runar.eq(...)` helper and no operator overloading — arithmetic on bigints uses `+`, `-`, `*`, `/`, `%` directly.

---

## Operators

| Java | AST / Bitcoin Script |
|------|----------------------|
| `+` / `-` / `*` / `/` / `%` | `ADD` / `SUB` / `MUL` / `DIV` / `MOD` |
| `==` / `!=` | `===` / `!==` (strict equality) |
| `<` / `<=` / `>` / `>=` | comparison |
| `&&` / `\|\|` / `!` | short-circuit logical |
| `&` / `\|` / `^` / `~` | bitwise (bigint or ByteString) |
| `<<` / `>>` | `OP_LSHIFT` / `OP_RSHIFT` |
| `cond ? a : b` | ternary expression |
| unary `-x` / `+x` | `NEG` / identity |
| `++x` / `x++` / `--x` / `x--` | increment / decrement (pre- and post-) |

---

## Assertions and Loops

Assertions are function calls on `assertThat` from `runar.lang.Builtins`:

```java
assertThat(checkSig(sig, pubKey));
assertThat(count > BigInteger.ZERO);
```

Java does not have a first-class assertion statement in the Rúnar subset — always use the `assertThat(...)` form, and static-import it at the top of your file.

Only bounded `for` loops with a literal iteration count are supported:

```java
for (int i = 0; i < 5; i = i + 1) {
    ...
}
```

The loop must declare exactly one loop variable and have exactly one update expression. `while`, `do/while`, `for-each`, and `switch` are rejected at parse time.

---

## Examples

### Stateless Contract (P2PKH)

```java
package runar.examples.p2pkh;

import runar.lang.SmartContract;
import runar.lang.annotations.Public;
import runar.lang.annotations.Readonly;
import runar.lang.types.Addr;
import runar.lang.types.PubKey;
import runar.lang.types.Sig;

import static runar.lang.Builtins.assertThat;
import static runar.lang.Builtins.checkSig;
import static runar.lang.Builtins.hash160;

// Contract classes in .runar.java files are package-private so that javac
// accepts the compound .runar.java suffix (which does not match a bare
// public class name). Cross-package consumers use the typed wrappers
// emitted by the Rúnar SDK codegen (milestone 10).
class P2PKH extends SmartContract {

    @Readonly Addr pubKeyHash;

    P2PKH(Addr pubKeyHash) {
        super(pubKeyHash);
        this.pubKeyHash = pubKeyHash;
    }

    @Public
    void unlock(Sig sig, PubKey pubKey) {
        assertThat(hash160(pubKey).equals(pubKeyHash));
        assertThat(checkSig(sig, pubKey));
    }
}
```

### Stateful Contract (Counter)

```java
package runar.examples.counter;

import java.math.BigInteger;

import runar.lang.StatefulSmartContract;
import runar.lang.annotations.Public;

import static runar.lang.Builtins.assertThat;

class Counter extends StatefulSmartContract {

    BigInteger count;

    Counter(BigInteger count) {
        super(count);
        this.count = count;
    }

    @Public
    void increment() {
        this.count = this.count + BigInteger.ONE;
    }

    @Public
    void decrement() {
        assertThat(this.count > BigInteger.ZERO);
        this.count = this.count - BigInteger.ONE;
    }
}
```

`count` has no `@Readonly` annotation, so it is a mutable state field on `StatefulSmartContract`. Assignments to `this.count` generate the state continuation output when the method returns.

---

## Testing Java Contracts

Java contracts are tested with JUnit 5 against the contract's native Java business logic:

```java
package runar.examples.p2pkh;

import org.junit.jupiter.api.Test;
import runar.lang.types.Addr;
import runar.lang.types.PubKey;
import runar.lang.types.Sig;

import static org.junit.jupiter.api.Assertions.assertThrows;
import static runar.lang.Builtins.hash160;
import static runar.lang.testing.Mocks.mockPubKey;
import static runar.lang.testing.Mocks.mockSig;

class P2PKHTest {

    @Test
    void unlocksWithMatchingPubKey() {
        PubKey pk = mockPubKey();
        Addr pkh = hash160(pk).asAddr();
        P2PKH c = new P2PKH(pkh);
        c.unlock(mockSig(), pk);
    }

    @Test
    void rejectsWrongPubKey() {
        PubKey pk = mockPubKey();
        PubKey wrong = PubKey.fromHex("03" + "00".repeat(32));
        P2PKH c = new P2PKH(hash160(pk).asAddr());
        assertThrows(AssertionError.class, () -> c.unlock(mockSig(), wrong));
    }
}
```

Mock crypto functions (`checkSig`, `checkPreimage`, `verifyWOTS`, etc.) always return `true` for business-logic testing. Hash functions (`hash160`, `hash256`, `sha256`, `ripemd160`) use real implementations.

A `runar.lang.CompileCheck` helper that runs the contract source through parse → validate → typecheck ships with **milestone 11 — the off-chain simulator** of the Java tier plan. Until then, tests instantiate the contract and verify business logic as native Java; the Rúnar compile pipeline is exercised via `./gradlew :compiler:test` rather than per-test hooks.

---

## Runtime Package

The `runar-java` package (`packages/runar-java/`) provides:

- **Base classes:** `SmartContract`, `StatefulSmartContract`
- **Annotations:** `@Public`, `@Readonly`, `@Stateful` (all in `runar.lang.annotations`)
- **Types:** `Addr`, `Sig`, `PubKey`, `ByteString`, `Point`, `P256Point`, `P384Point`, `Sha256Digest`, `SigHashPreimage`, `RabinSig`, `RabinPubKey`, `Ripemd160`, `OpCodeType`, `FixedArray<T, N>` — all in `runar.lang.types`
- **Builtins:** `Builtins.assertThat`, `Builtins.hash160`, `Builtins.checkSig`, and peers (static methods)
- **Off-chain simulator:** `runar.lang.runtime` (milestone 11)
- **SDK:** `RunarContract`, `Provider`, `Signer`, transaction builders, `PreparedCall` (milestones 8–10)

Requires JDK 17 as the compile target (JDK 21 LTS works for local development). The toolchain is Gradle 8; no Spring, Jakarta EE, Guice, or Guava.

---

## Current Limitations (Phase 1)

- **Source locations are approximate.** Every AST node currently reports `line 0, column 0` for its source location. Error messages from validate/typecheck/lower passes name the file but cannot point at the offending line yet. A polishing pass attaches real positions by tracking line breaks across the source string.
- **Cross-compiler parity via milestone 7.** Today only the Java compiler can parse `.runar.java`. The TypeScript, Go, Rust, Python, Zig, and Ruby compilers gain hand-written `.runar.java` parsers in milestone 7 of the tier plan, at which point the format joins the shared conformance matrix.
- **Package-private contracts only.** The compound `.runar.java` filename forces contract classes to be package-private. Cross-package consumption depends on the typed-wrapper codegen (milestone 10).
- **No string literals in contract source.** Use `ByteString.fromHex("...")` for raw bytes.
- **`FixedArray` length must be an integer literal.** Symbolic constants in the type position are not resolved yet.
- **No nested blocks, try/catch, lambdas, switch expressions, or non-Rúnar annotations.** The parser rejects anything outside the frozen Rúnar subset.
