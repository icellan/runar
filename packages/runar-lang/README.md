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

| Modifier | Semantics | Available On | Script Representation |
|---|---|---|---|
| `readonly` | Immutable. Set in constructor, embedded in locking script at deploy time. Cannot be reassigned. | `SmartContract`, `StatefulSmartContract` | Push data in the locking script |
| _(none)_ | Mutable (stateful). Can be reassigned in public methods. New values propagated via OP_PUSH_TX. | `StatefulSmartContract` only | State suffix in the locking script (after OP_RETURN) |

**Important:** Mutable (non-`readonly`) properties with state propagation via OP_PUSH_TX are only available on `StatefulSmartContract`. The base `SmartContract` class is stateless and all its properties should be declared `readonly`.

```typescript
// Stateless contract: all properties must be readonly
class P2PKH extends SmartContract {
  readonly pubKeyHash: Addr;     // immutable -- baked into the script
  // ...
}

// Stateful contract: mutable properties are carried across transactions
class Counter extends StatefulSmartContract {
  readonly owner: Addr;          // immutable -- baked into the script
  count: bigint;                 // mutable -- carried across transactions
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
| `Sig` | `string` | variable | `Sig(hex)` | DER prefix `30`, min 8 bytes |
| `Ripemd160` | `string` | 20 | `Ripemd160(hex)` | 40 hex chars |
| `Sha256` | `string` | 32 | `Sha256(hex)` | 64 hex chars |
| `Addr` | `string` | 20 | `Addr(hex)` | 40 hex chars (alias for Ripemd160) |
| `SigHashPreimage` | `string` | variable | `SigHashPreimage(hex)` | Valid hex |
| `OpCodeType` | `string` | variable | `OpCodeType(hex)` | Valid hex |
| `Point` | `string` | 64 | 128-char hex | Big-endian x[32] \|\| y[32], no prefix |
| `RabinSig` | `bigint` | variable | literal `bigint` | -- |
| `RabinPubKey` | `bigint` | variable | literal `bigint` | -- |
| `SigHashType` | `bigint` | variable | `SigHash.ALL` etc. | -- |

**Note on `Sig` size**: ECDSA DER signatures are typically 71-73 bytes, but this is not enforced as a hard upper bound at the type level. The `Sig` constructor only validates a minimum of 8 bytes and a DER prefix of `0x30`. Variable-length signatures (e.g. from different signing schemes) are accepted as long as they meet these minimal requirements.

### Type Hierarchy

```
        ByteString
       /    |     \      \         \            \           \         \
   PubKey  Sig  Sha256  Ripemd160  Addr  SigHashPreimage  OpCodeType  Point
                                    ^
                                    | (alias)
                                 Ripemd160

        bigint
       /      \       \
  RabinSig  RabinPubKey  SigHashType
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
| `checkMultiSig` | `(sigs: Sig[], pubKeys: PubKey[]) => boolean` | Multi-signature verification |
| `hash256` | `(data: ByteString) => Sha256` | Double SHA-256 |
| `hash160` | `(data: ByteString) => Ripemd160` | SHA-256 then RIPEMD-160 |
| `sha256` | `(data: ByteString) => Sha256` | Single SHA-256 |
| `ripemd160` | `(data: ByteString) => Ripemd160` | Single RIPEMD-160 |

### Data Manipulation

| Function | Signature | Description |
|---|---|---|
| `toByteString` | `(hex: string) => ByteString` | Construct a byte string from hex |
| `len` | `(data: ByteString) => bigint` | Byte length |
| `cat` | `(a: ByteString, b: ByteString) => ByteString` | Concatenate two byte strings |
| `substr` | `(data: ByteString, start: bigint, len: bigint) => ByteString` | Extract a substring |
| `left` | `(data: ByteString, len: bigint) => ByteString` | Take the leftmost `len` bytes |
| `right` | `(data: ByteString, len: bigint) => ByteString` | Take the rightmost `len` bytes |
| `split` | `(data: ByteString, index: bigint) => [ByteString, ByteString]` | Split at position into two parts |
| `reverseBytes` | `(data: ByteString) => ByteString` | Reverse byte order |
| `num2bin` | `(n: bigint, size: bigint) => ByteString` | Encode integer with fixed byte width |
| `bin2num` | `(data: ByteString) => bigint` | Decode byte string to script number |
| `int2str` | `(n: bigint, size: bigint) => ByteString` | Encode integer as byte string (alias for num2bin) |

### Arithmetic

| Function | Signature | Description |
|---|---|---|
| `abs` | `(n: bigint) => bigint` | Absolute value |
| `min` | `(a: bigint, b: bigint) => bigint` | Minimum |
| `max` | `(a: bigint, b: bigint) => bigint` | Maximum |
| `within` | `(x: bigint, lo: bigint, hi: bigint) => boolean` | Range check: lo <= x < hi |
| `safediv` | `(a: bigint, b: bigint) => bigint` | Safe division (asserts divisor non-zero) |
| `safemod` | `(a: bigint, b: bigint) => bigint` | Safe modulo (asserts divisor non-zero) |
| `clamp` | `(value: bigint, lo: bigint, hi: bigint) => bigint` | Clamp value to range [lo, hi] |
| `sign` | `(value: bigint) => bigint` | Sign of a number: returns -1, 0, or 1 |
| `pow` | `(base: bigint, exp: bigint) => bigint` | Exponentiation |
| `mulDiv` | `(a: bigint, b: bigint, c: bigint) => bigint` | Multiply then divide: (a * b) / c |
| `percentOf` | `(amount: bigint, bps: bigint) => bigint` | Percentage in basis points: (amount * bps) / 10000 |
| `sqrt` | `(n: bigint) => bigint` | Integer square root |
| `gcd` | `(a: bigint, b: bigint) => bigint` | Greatest common divisor |
| `divmod` | `(a: bigint, b: bigint) => bigint` | Division returning quotient |
| `log2` | `(n: bigint) => bigint` | Approximate floor(log2(n)) |
| `bool` | `(n: bigint) => boolean` | Convert integer to boolean (0 is false, non-zero is true) |

### Control

| Function | Signature | Description |
|---|---|---|
| `assert` | `(cond: boolean, msg?: string) => asserts cond` | Verify condition or fail script |

### Compiler Intrinsics (Class Methods)

These are methods on the base classes that the compiler maps to inline Bitcoin Script. They cannot be called at runtime -- they only work inside compiled contracts.

| Method | Available On | Signature | Description |
|---|---|---|---|
| `this.getStateScript()` | `SmartContract`, `StatefulSmartContract` | `() => ByteString` | Returns the serialized locking script with current state values. Used to construct expected outputs for state continuation. |
| `this.buildP2PKH(addr)` | `SmartContract`, `StatefulSmartContract` | `(addr: Addr) => ByteString` | Builds a standard P2PKH output script (OP_DUP OP_HASH160 \<addr\> OP_EQUALVERIFY OP_CHECKSIG). Useful for enforcing payment to a specific address. |
| `this.addOutput(satoshis, ...stateValues)` | `StatefulSmartContract` | `(satoshis: bigint, ...stateValues: unknown[]) => void` | Registers a transaction output with the given satoshi amount and state values. State values correspond to mutable properties in declaration order. At method exit, the compiler verifies all registered outputs match the transaction's hashOutputs. |

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
| `checkPreimage` | `(preimage: SigHashPreimage) => boolean` | Verify the sighash preimage is valid |
| `extractVersion` | `(preimage: SigHashPreimage) => bigint` | Extract 4-byte tx version (nVersion) |
| `extractHashPrevouts` | `(preimage: SigHashPreimage) => Sha256` | Extract 32-byte hashPrevouts |
| `extractHashSequence` | `(preimage: SigHashPreimage) => Sha256` | Extract 32-byte hashSequence |
| `extractOutpoint` | `(preimage: SigHashPreimage) => ByteString` | Extract 36-byte outpoint (txid + vout) |
| `extractInputIndex` | `(preimage: SigHashPreimage) => bigint` | Extract the input vout index |
| `extractScriptCode` | `(preimage: SigHashPreimage) => ByteString` | Extract the scriptCode field |
| `extractAmount` | `(preimage: SigHashPreimage) => bigint` | Extract 8-byte input amount (satoshis) |
| `extractSequence` | `(preimage: SigHashPreimage) => bigint` | Extract 4-byte nSequence |
| `extractOutputHash` | `(preimage: SigHashPreimage) => Sha256` | Extract 32-byte hashOutputs |
| `extractOutputs` | `(preimage: SigHashPreimage) => Sha256` | Extract hashOutputs (alias) |
| `extractLocktime` | `(preimage: SigHashPreimage) => bigint` | Extract 4-byte nLocktime |
| `extractSigHashType` | `(preimage: SigHashPreimage) => bigint` | Extract 4-byte sighash type |

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

`FungibleToken` provides `transfer`, `merge`, and `split` methods. `NonFungibleToken` provides `transfer` and `burn` methods. Your contract extends the appropriate base and adds custom logic.

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

## Post-Quantum Signature Verification

Hash-based signature schemes for quantum-resistant contract security. These are also exported from the main `runar-lang` entry point.

### WOTS+ (Winternitz One-Time Signature)

| Function | Signature | Description |
|---|---|---|
| `verifyWOTS` | `(msg: ByteString, sig: ByteString, pubkey: ByteString) => boolean` | WOTS+ signature verification (SHA-256, w=16, n=32) |

One-time use: each keypair can securely sign only one message. This is a natural fit for Bitcoin's UTXO model where each output is spent exactly once. Estimated script size: ~12 KB.

### SLH-DSA (SPHINCS+, FIPS 205)

Stateless hash-based signatures supporting multiple signings per keypair. Six parameter sets are available, trading off between signature size and verification speed:

| Function | Security | Variant | Signature Size |
|---|---|---|---|
| `verifySLHDSA_SHA2_128s` | 128-bit | small | 7,856 bytes |
| `verifySLHDSA_SHA2_128f` | 128-bit | fast | 17,088 bytes |
| `verifySLHDSA_SHA2_192s` | 192-bit | small | 16,224 bytes |
| `verifySLHDSA_SHA2_192f` | 192-bit | fast | 35,664 bytes |
| `verifySLHDSA_SHA2_256s` | 256-bit | small | 29,792 bytes |
| `verifySLHDSA_SHA2_256f` | 256-bit | fast | 48,736 bytes |

All SLH-DSA functions share the same signature: `(msg: ByteString, sig: ByteString, pubkey: ByteString) => boolean`.

---

## Elliptic Curve (secp256k1)

On-chain elliptic curve arithmetic over the secp256k1 curve. All operations are synthesized from base Bitcoin Script opcodes. Also exported from the main `runar-lang` entry point.

### EC Built-in Functions

| Function | Signature | Description |
|---|---|---|
| `ecAdd` | `(a: Point, b: Point) => Point` | Affine point addition |
| `ecMul` | `(p: Point, k: bigint) => Point` | Scalar multiplication (256-iteration double-and-add) |
| `ecMulGen` | `(k: bigint) => Point` | Scalar mult by hardcoded generator G |
| `ecNegate` | `(p: Point) => Point` | Point negation: (x, p - y) |
| `ecOnCurve` | `(p: Point) => boolean` | Verify y^2 === x^3 + 7 (mod p) |
| `ecModReduce` | `(value: bigint, mod: bigint) => bigint` | Modular reduction: ((value % mod) + mod) % mod |
| `ecEncodeCompressed` | `(p: Point) => ByteString` | Point to 33-byte compressed pubkey |
| `ecMakePoint` | `(x: bigint, y: bigint) => Point` | Construct 64-byte Point from coordinates |
| `ecPointX` | `(p: Point) => bigint` | Extract x-coordinate |
| `ecPointY` | `(p: Point) => bigint` | Extract y-coordinate |

### EC Constants

| Constant | Type | Description |
|---|---|---|
| `EC_P` | `bigint` | secp256k1 field prime: 2^256 - 2^32 - 977 |
| `EC_N` | `bigint` | secp256k1 group order |
| `EC_G` | `Point` | Generator point (64 bytes: x[32] \|\| y[32], big-endian) |

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
