# runar-lang

**Contract author's import library for Rúnar smart contracts.**

This package provides the base class, domain types, built-in function declarations, and utility types that contract authors import into their `.runar.ts` files. It contains no compiler logic -- it is purely a type-level and runtime-validation library that makes Rúnar contracts valid TypeScript.

---

## Installation

```bash
pnpm add runar-lang
```

## Basic Usage

```typescript
import { SmartContract, assert, PubKey, Sig, Addr, hash160, checkSig } from 'runar-lang';

class P2PKH extends SmartContract {
  readonly pubKeyHash: Addr;

  constructor(pubKeyHash: Addr) {
    super(pubKeyHash);
    this.pubKeyHash = pubKeyHash;
  }

  public unlock(sig: Sig, pubKey: PubKey) {
    assert(hash160(pubKey) === this.pubKeyHash);
    assert(checkSig(sig, pubKey));
  }
}
```

---

## SmartContract Base Class

Every Rúnar contract extends `SmartContract`. The base class defines the structural conventions that the compiler relies on.

### Properties

Properties are declared as class fields. Their role is determined by the `readonly` modifier:

| Modifier | Semantics | Script Representation |
|---|---|---|
| `readonly` | Immutable. Set in constructor, embedded in locking script at deploy time. Cannot be reassigned. | Push data in the locking script |
| _(none)_ | Mutable (stateful). Can be reassigned in public methods. New values propagated via OP_PUSH_TX. | State prefix in the locking script |

```typescript
class MyContract extends SmartContract {
  readonly fixedValue: Addr;     // immutable -- baked into the script
  counter: bigint;               // mutable -- carried across transactions
  // ...
}
```

### Methods

| Visibility | Purpose | Return | Script Representation |
|---|---|---|---|
| `public` | Entry point (spending path). Parameters come from the unlocking script. Must end with `assert(...)`. | `void` | Branch in the dispatch table |
| `private` | Helper. Inlined at call sites during compilation. May return a value. | Any type | Inlined (no runtime existence) |

```typescript
class MyContract extends SmartContract {
  // Public: spending path -- parameters are the unlocking script data
  public unlock(sig: Sig, pubKey: PubKey) {
    assert(this.verifyIdentity(pubKey));
    assert(checkSig(sig, pubKey));
  }

  // Private: helper -- inlined at the call site above
  private verifyIdentity(pubKey: PubKey): boolean {
    return hash160(pubKey) === this.pubKeyHash;
  }
}
```

### Constructor Conventions

1. The constructor MUST call `super(...)` as its first statement.
2. The `super(...)` call MUST pass all declared properties in declaration order.
3. Every property MUST be assigned exactly once in the constructor body (`this.x = x`).

```typescript
constructor(pubKeyHash: Addr, counter: bigint) {
  super(pubKeyHash, counter);     // all properties, in order
  this.pubKeyHash = pubKeyHash;   // assign each one
  this.counter = counter;
}
```

---

## Domain Types Reference

All domain types are branded TypeScript types. At runtime they are strings (hex-encoded byte sequences) or bigints. The brands provide compile-time nominal typing via unique symbols.

| Type | Underlying | Byte Size | Constructor | Validation |
|---|---|---|---|---|
| `ByteString` | `string` | variable | `toByteString(hex)` | Even-length hex |
| `PubKey` | `string` | 33 | `PubKey(hex)` | 66 hex chars, prefix `02` or `03` |
| `Sig` | `string` | 71-73 | `Sig(hex)` | DER prefix `30`, min 8 bytes |
| `Ripemd160` | `string` | 20 | `Ripemd160(hex)` | 40 hex chars |
| `Sha256` | `string` | 32 | `Sha256(hex)` | 64 hex chars |
| `Addr` | `string` | 20 | `Addr(hex)` | 40 hex chars (alias for Ripemd160) |
| `SigHashPreimage` | `string` | variable | `SigHashPreimage(hex)` | Valid hex |
| `OpCodeType` | `string` | variable | `OpCodeType(hex)` | Valid hex |
| `RabinSig` | `bigint` | variable | literal `bigint` | -- |
| `RabinPubKey` | `bigint` | variable | literal `bigint` | -- |
| `SigHashType` | `bigint` | variable | `SigHash.ALL` etc. | -- |

### Type Hierarchy

```
        ByteString
       /    |     \      \         \            \
   PubKey  Sig  Sha256  Ripemd160  Addr  SigHashPreimage
                                    ^
                                    | (alias)
                                 Ripemd160

        bigint
       /      \
  RabinSig  RabinPubKey
```

Domain types widen to their parent implicitly: you can pass a `PubKey` where `ByteString` is expected. Narrowing requires an explicit constructor call.

### FixedArray<T, N>

Fixed-size arrays with compile-time length:

```typescript
type ThreeKeys = FixedArray<PubKey, 3>;  // resolves to [PubKey, PubKey, PubKey]
```

Supported lengths: 0-16 have direct tuple definitions. Lengths >16 use a recursive type builder. On the Script stack, a `FixedArray<T, N>` is N consecutive stack items.

---

## Built-in Functions Reference

### Cryptographic

| Function | Signature | Description |
|---|---|---|
| `checkSig` | `(sig: Sig, pubKey: PubKey) => boolean` | ECDSA signature verification |
| `checkMultiSig` | `(sigs: FixedArray<Sig, M>, pubKeys: FixedArray<PubKey, N>) => boolean` | Multi-signature verification |
| `hash256` | `(data: ByteString) => Sha256` | Double SHA-256 |
| `hash160` | `(data: ByteString) => Ripemd160` | SHA-256 then RIPEMD-160 |
| `sha256` | `(data: ByteString) => Sha256` | Single SHA-256 |
| `ripemd160` | `(data: ByteString) => Ripemd160` | Single RIPEMD-160 |

### Data Manipulation

| Function | Signature | Description |
|---|---|---|
| `toByteString` | `(hex: string) => ByteString` | Construct a byte string from hex |
| `len` | `(data: ByteString) => bigint` | Byte length |
| `reverseByteString` | `(data: ByteString, size: bigint) => ByteString` | Reverse byte order |
| `pack` | `(n: bigint) => ByteString` | Encode integer as Script number bytes |
| `unpack` | `(data: ByteString) => bigint` | Decode Script number bytes to integer |
| `num2bin` | `(n: bigint, size: bigint) => ByteString` | Encode integer with fixed byte width |

### Arithmetic

| Function | Signature | Description |
|---|---|---|
| `abs` | `(n: bigint) => bigint` | Absolute value |
| `min` | `(a: bigint, b: bigint) => bigint` | Minimum |
| `max` | `(a: bigint, b: bigint) => bigint` | Maximum |
| `within` | `(x: bigint, lo: bigint, hi: bigint) => boolean` | Range check: lo <= x < hi |

### Control

| Function | Signature | Description |
|---|---|---|
| `assert` | `(cond: boolean, msg?: string) => void` | Verify condition or fail script |
| `exit` | `(success: boolean) => void` | Terminate script immediately |

---

## Stateful Contracts

Extend `StatefulSmartContract` for contracts with mutable state. The compiler automatically handles preimage verification and state continuation:

```typescript
import { StatefulSmartContract, assert, extractLocktime } from 'runar-lang';

class Counter extends StatefulSmartContract {
  count: bigint;
  constructor(count: bigint) { super(count); this.count = count; }

  public increment() {
    this.count++;
  }
}
```

Access preimage fields via `this.txPreimage`:

| Function | Signature | Description |
|---|---|---|
| `extractOutputHash` | `(preimage: SigHashPreimage) => Sha256` | Extract the output hash from preimage |
| `extractLocktime` | `(preimage: SigHashPreimage) => bigint` | Extract locktime from preimage |
| `extractAmount` | `(preimage: SigHashPreimage) => bigint` | Extract input amount from preimage |
| `extractVersion` | `(preimage: SigHashPreimage) => bigint` | Extract tx version from preimage |

```typescript
// Example: enforce a deadline
assert(extractLocktime(this.txPreimage) >= this.deadline);
```

---

## Token Base Contracts

Import from `runar-lang/tokens`:

```typescript
import { FungibleToken, NonFungibleToken } from 'runar-lang/tokens';
```

These provide standard base classes for token contracts with built-in transfer, mint, and burn methods. Your contract extends the appropriate base and adds custom logic.

---

## Oracle Utilities

Import from `runar-lang/oracle`:

```typescript
import { verifyRabinSig } from 'runar-lang/oracle';
```

| Function | Signature | Description |
|---|---|---|
| `verifyRabinSig` | `(msg: ByteString, sig: RabinSig, padding: ByteString, pubKey: RabinPubKey) => boolean` | Rabin signature verification |

Rabin signatures are used for oracle data feeds because they are cheaper to verify on-chain than ECDSA.

---

## SigHash Constants

```typescript
import { SigHash } from 'runar-lang';

const flags = SigHash.ALL | SigHash.FORKID;
```

| Constant | Value | Description |
|---|---|---|
| `SigHash.ALL` | `0x01n` | Sign all inputs and outputs |
| `SigHash.NONE` | `0x02n` | Sign all inputs, no outputs |
| `SigHash.SINGLE` | `0x03n` | Sign all inputs, only matching output |
| `SigHash.FORKID` | `0x40n` | BSV fork-id flag (required post-fork) |
| `SigHash.ANYONECANPAY` | `0x80n` | Only sign the current input |

---

## Design Decisions

### Why No Decorators

TypeScript decorators are experimental metadata annotations with no standardized compile-time semantics. Using them for contract structure creates a dependency on non-standard tooling and obscures the actual contract structure from `tsc` and IDE tools.

Rúnar uses `readonly` for immutable properties and `public`/`private` for method visibility -- keywords that TypeScript already understands natively. This means:

- Standard `tsc` type-checking works without plugins.
- IDE refactoring, go-to-definition, and error reporting work out of the box.
- The contract structure is self-evident from the TypeScript syntax.

### Why Branded Types

TypeScript's structural type system means that `string` is `string` everywhere. Without branding, nothing prevents passing a SHA-256 hash where a public key is expected -- both are just hex strings.

Branded types use unique symbols to create nominal distinctions:

```typescript
type PubKey = string & { readonly [PubKeyBrand]: 'PubKey' };
```

This is erased at runtime (zero overhead) but enforced at compile time. The constructor functions (`PubKey(hex)`, `Sha256(hex)`, etc.) validate the actual byte content at the API boundary.
