# TypeScript Contract Format

**Status:** Stable (canonical)
**File extension:** `.runar.ts`
**Supported compilers:** TypeScript, Go, Rust, Python, Zig, Ruby, Java (all seven)

---

## Overview

TypeScript is Rúnar's canonical input format. Every other surface (`.runar.sol`, `.runar.move`, `.runar.go`, `.runar.rs`, `.runar.py`, `.runar.zig`, `.runar.rb`, `.runar.java`) lowers to the same `ContractNode` AST that the TypeScript parser produces, then runs through the identical validate / typecheck / ANF / stack / emit pipeline. When a peer format guide references "TypeScript Rúnar," it means the surface defined here.

A Rúnar contract is a TypeScript class extending `SmartContract` (stateless) or `StatefulSmartContract` (stateful). The compiler reads it with `ts-morph`, produces Bitcoin SV Script, and rejects anything outside the supported subset.

This document is the surface reference. The full grammar and semantics live in `spec/`.

---

## File Structure

```typescript
import { SmartContract, assert, checkSig, hash160 } from 'runar-lang';
import type { Addr, PubKey, Sig } from 'runar-lang';

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

- Exactly one contract class per source file.
- Imports come from `runar-lang` (the developer-facing package). The compiler does not load the runtime; it only parses the import to validate names.
- The class must extend `SmartContract` or `StatefulSmartContract`.
- Constructors must call `super(...)` as the first statement, passing every property in declaration order.

---

## Contract Declaration

```typescript
export class Name extends SmartContract { ... }            // stateless
export class Name extends StatefulSmartContract { ... }    // stateful
```

The `parentClass` field on the AST `ContractNode` discriminates the two base classes. `StatefulSmartContract` causes the compiler to auto-inject `checkPreimage` at method entry and a state-continuation output at exit; you do not write either by hand.

---

## Properties

```typescript
readonly pubKeyHash: Addr;       // immutable contract parameter
count: bigint;                   // mutable state field (stateful only)
```

- `readonly` properties are immutable contract parameters fixed at deploy time.
- Properties without `readonly` are mutable and only valid in `StatefulSmartContract`.
- A `SmartContract` whose properties are all `readonly` is stateless — the compiler emits a single locking script with no continuation.

### Property Initializers

Properties can carry a literal default:

```typescript
export class GameBoard extends StatefulSmartContract {
  count: bigint = 0n;
  readonly active: boolean = true;
  readonly owner: PubKey;

  constructor(owner: PubKey) {
    super(owner);
    this.owner = owner;
  }
}
```

- Initializers must be literals: `BigIntLiteral` (`0n`), `BoolLiteral` (`true`/`false`), or `ByteStringLiteral` (`'0xdeadbeef'`).
- Initialized properties are excluded from the constructor parameter list — only un-initialized properties are passed in.
- The AST `PropertyNode` carries an optional `initializer`; the ANF lowering populates `initialValue` from it.

---

## Methods

```typescript
public unlock(sig: Sig, pubKey: PubKey): void { ... }
private helper(amount: bigint): bigint { ... }
```

- `public` methods are spending entry points. They return `void` and contain the contract's spend conditions.
- `private` methods are inlined helpers. They may return a value and are folded into their callers during ANF lowering.
- Method bodies execute top-to-bottom; control flow drops to the next statement on success.

The script "succeeds" if no `assert` fires. There is no explicit return.

---

## `assert`

```typescript
assert(condition);
```

`assert(expr)` is the primary control mechanism. It compiles to an `OP_VERIFY` against the predicate and aborts the script (locking the UTXO unspendable for that path) if `expr` is false.

There is no `revert`, no `throw`, no `require`. Other format frontends accept `require(...)` as a synonym; TypeScript Rúnar uses `assert` exclusively.

---

## Operators

| TypeScript | Rúnar lowering | Notes |
|------------|---------------|-------|
| `===`, `!==` | Equality / inequality | No `==` / `!=`. |
| `+`, `-`, `*`, `/`, `%` | Arithmetic on `bigint` | Division is integer; see also `safediv`. |
| `<`, `<=`, `>`, `>=` | Comparison | `bigint` only. |
| `&&`, `\|\|`, `!` | Boolean logic | Both branches evaluated; no short-circuit script-level. |
| `<<`, `>>` | `OP_LSHIFT` / `OP_RSHIFT` | Bitwise shifts on `bigint`. |
| `&`, `\|`, `^`, `~` | Bitwise on `bigint` and `ByteString` | Operand types must match. |
| `condition ? a : b` | Ternary | Compiles to `OP_IF`/`OP_ELSE`/`OP_ENDIF`. |

---

## Property Access

```typescript
this.pubKeyHash    // required — bare identifier is rejected
```

Unlike the Solidity-like and Move-like surfaces (which allow bare property names), TypeScript Rúnar requires the explicit `this.` prefix. The validator rejects bare property identifiers inside method bodies.

---

## State Mutation

Stateful contracts mutate properties directly:

```typescript
this.count += 1n;
this.count -= 1n;
this.count = newValue;
this.highestBidder = bidder;
```

- `++` and `--` are not accepted; use `+= 1n` / `-= 1n`.
- The compiler tracks which properties were assigned in each control-flow path and emits the corresponding state continuation at method exit.

---

## `addOutput` and `addRawOutput`

```typescript
this.addOutput(satoshis, owner, balance, 0n);
this.addRawOutput(satoshis, scriptBytes);
```

- `this.addOutput(satoshis, ...values)` — multi-output intrinsic. The first argument is the output amount in satoshis; subsequent arguments are values matching the contract's mutable properties in declaration order. The compiler synthesises an output whose locking script is the contract's own `codePart` parameterised with those values.
- `this.addRawOutput(satoshis, scriptBytes)` — emits an output with caller-supplied locking script bytes (not a stateful continuation). Use this when the next-state output is an unrelated script (P2PKH, OP_RETURN, etc.).

---

## Control Flow

```typescript
for (let i = 0n; i < 10n; i++) {       // bound must be a compile-time constant
  // body — unrolled at compile time
}

if (amount > threshold) {
  // ...
} else if (amount === 0n) {
  // ...
} else {
  // ...
}
```

- `for` loops require a compile-time constant bound and are fully unrolled. There is no runtime iteration.
- `while`, `do/while`, recursion, and unbounded loops are rejected by the validator.

---

## Type System

### Primitives

| Rúnar type | TypeScript surface | Description |
|-----------|-------------------|-------------|
| `bigint` | `bigint` | 32-byte signed integer; literals require the `n` suffix. |
| `boolean` | `boolean` | True / false. Compiles to a 1-byte 0x01 / OP_FALSE. |
| `ByteString` | `ByteString` | Variable-length byte buffer. Hex literal: `'0xdeadbeef'`. |

### Crypto Subtypes

All of these are `ByteString` subtypes with declared length and semantics:

| Type | Bytes | Description |
|------|-------|-------------|
| `Sig` | 71–73 | DER-encoded ECDSA signature with 1-byte sighash type appended. |
| `PubKey` | 33 | SEC1 compressed secp256k1 public key. |
| `Sha256` | 32 | SHA-256 digest. |
| `Ripemd160` | 20 | RIPEMD-160 digest. |
| `Addr` | 20 | RIPEMD-160(SHA-256(pubkey)) — Bitcoin pay-to-pubkey-hash. |
| `SigHashPreimage` | variable | BIP-143 sighash preimage. |
| `RabinSig`, `RabinPubKey` | variable | Rabin signature primitives. |
| `Point` | 64 | secp256k1 affine point (x[32] \|\| y[32], no prefix byte). |

`Point` is used by the EC built-ins (`ecAdd`, `ecMul`, etc.) and is not interchangeable with `PubKey` (which is the compressed encoding).

---

## Built-in Functions

Built-ins are imported from `runar-lang`. The type checker rejects calls to anything that is not a built-in or a method on the contract class — `Math.floor`, `console.log`, `JSON.stringify`, etc. all fail typecheck.

### Cryptographic Verification

| Function | Signature | Description |
|----------|-----------|-------------|
| `assert` | `(cond: boolean) => void` | Fail script if false. |
| `checkSig` | `(sig: Sig, pk: PubKey) => boolean` | ECDSA signature verification. |
| `checkMultiSig` | `(sigs: Sig[], pks: PubKey[]) => boolean` | Multi-sig verification. |
| `checkPreimage` | `(pre: SigHashPreimage) => boolean` | BIP-143 preimage check (auto-injected for stateful). |
| `verifyRabinSig` | `(msg, sig, pad, pk) => boolean` | Rabin signature verification. |
| `verifyWOTS` | `(msg, sig, pubkey) => boolean` | WOTS+ one-time signature (~10 KB script). |
| `verifySLHDSA_SHA2_{128,192,256}{s,f}` | `(msg, sig, pubkey) => boolean` | SLH-DSA / FIPS 205 (200–900 KB scripts). |

### Hashing

| Function | Signature |
|----------|-----------|
| `sha256` | `(data: ByteString) => Sha256` |
| `hash256` | `(data: ByteString) => Sha256` (double SHA-256) |
| `ripemd160` | `(data: ByteString) => Ripemd160` |
| `hash160` | `(data: ByteString) => Addr` (RIPEMD-160 of SHA-256) |
| `blake3` | `(data: ByteString) => ByteString` |
| `sha256Compress` | `(state: ByteString, block: ByteString) => ByteString` |
| `sha256Finalize` | `(state, remaining, msgBitLen) => Sha256` |

### Byte Manipulation

| Function | Signature |
|----------|-----------|
| `cat` | `(a, b: ByteString) => ByteString` |
| `substr` | `(data: ByteString, start: bigint, len: bigint) => ByteString` |
| `split` | `(data: ByteString, index: bigint) => [ByteString, ByteString]` |
| `left`, `right` | `(data, len) => ByteString` |
| `reverseBytes` | `(data: ByteString) => ByteString` |
| `len` | `(data: ByteString) => bigint` |
| `num2bin`, `bin2num` | bigint ↔ ByteString conversion |
| `pack`, `unpack` | minimal-encoding bigint ↔ ByteString |
| `int2str`, `toByteString` | numeric / hex helpers |

### Math

`abs`, `min`, `max`, `within`, `safediv`, `safemod`, `clamp`, `sign`, `pow`, `mulDiv`, `percentOf`, `sqrt`, `gcd`, `divmod`, `log2`, `bool`.

### Sighash Preimage Extraction

`extractLocktime`, `extractOutputHash`, `extractAmount`, `extractVersion`, `extractHashPrevouts`, `extractHashSequence`, `extractOutpoint`, `extractScriptCode`, `extractSequence`, `extractSigHashType`, `extractInputIndex`, `extractOutputs`.

### Elliptic Curve (secp256k1)

| Function | Signature | Description |
|----------|-----------|-------------|
| `ecAdd` | `(a: Point, b: Point) => Point` | Point addition. |
| `ecMul` | `(p: Point, k: bigint) => Point` | Scalar multiplication. |
| `ecMulGen` | `(k: bigint) => Point` | Generator multiplication. |
| `ecNegate` | `(p: Point) => Point` | Point negation. |
| `ecOnCurve` | `(p: Point) => boolean` | Curve membership check. |
| `ecModReduce` | `(value: bigint, mod: bigint) => bigint` | Modular reduction. |
| `ecEncodeCompressed` | `(p: Point) => ByteString` | Compress to 33-byte SEC1 pubkey. |
| `ecMakePoint` | `(x: bigint, y: bigint) => Point` | Construct from coordinates. |
| `ecPointX`, `ecPointY` | `(p: Point) => bigint` | Coordinate extractors. |

EC constants: `EC_P` (field prime), `EC_N` (group order), `EC_G` (generator point) from `runar-lang/src/ec.ts`.

NIST P-256 / P-384 verification is also available through dedicated built-ins; see the `p256-primitives` and `p384-primitives` conformance fixtures for the full set.

---

## Examples

### P2PKH (stateless)

```typescript
import { SmartContract, assert, checkSig, hash160 } from 'runar-lang';
import type { Addr, PubKey, Sig } from 'runar-lang';

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

### Counter (stateful)

```typescript
import { StatefulSmartContract, assert } from 'runar-lang';

export class Counter extends StatefulSmartContract {
  count: bigint;

  constructor(count: bigint) {
    super(count);
    this.count = count;
  }

  public increment(): void {
    this.count += 1n;
  }

  public decrement(): void {
    assert(this.count > 0n);
    this.count -= 1n;
  }
}
```

The compiler auto-injects `checkPreimage` at method entry and emits a state-continuation output containing the new `count` at method exit. Developers do not write either.

### Escrow

```typescript
import { SmartContract, assert, checkSig } from 'runar-lang';
import type { PubKey, Sig } from 'runar-lang';

export class Escrow extends SmartContract {
  readonly buyer: PubKey;
  readonly seller: PubKey;
  readonly arbiter: PubKey;

  constructor(buyer: PubKey, seller: PubKey, arbiter: PubKey) {
    super(buyer, seller, arbiter);
    this.buyer = buyer;
    this.seller = seller;
    this.arbiter = arbiter;
  }

  public release(sellerSig: Sig, arbiterSig: Sig): void {
    assert(checkSig(sellerSig, this.seller));
    assert(checkSig(arbiterSig, this.arbiter));
  }

  public refund(buyerSig: Sig, arbiterSig: Sig): void {
    assert(checkSig(buyerSig, this.buyer));
    assert(checkSig(arbiterSig, this.arbiter));
  }
}
```

### Covenant Vault

```typescript
import { SmartContract, assert, checkSig, checkPreimage, cat, num2bin, hash256, extractOutputHash } from 'runar-lang';
import type { Addr, PubKey, Sig, SigHashPreimage } from 'runar-lang';

export class CovenantVault extends SmartContract {
  readonly owner: PubKey;
  readonly recipient: Addr;
  readonly minAmount: bigint;

  constructor(owner: PubKey, recipient: Addr, minAmount: bigint) {
    super(owner, recipient, minAmount);
    this.owner = owner;
    this.recipient = recipient;
    this.minAmount = minAmount;
  }

  public spend(sig: Sig, txPreimage: SigHashPreimage): void {
    assert(checkSig(sig, this.owner));
    assert(checkPreimage(txPreimage));

    const p2pkhScript: ByteString = cat(cat('0x1976a914', this.recipient), '0x88ac');
    const expectedOutput: ByteString = cat(num2bin(this.minAmount, 8n), p2pkhScript);
    assert(hash256(expectedOutput) === extractOutputHash(txPreimage));
  }
}
```

This demonstrates the covenant pattern: the locking script constrains not just *who* can spend the funds but *how* — it constructs the expected next-output script on-chain and verifies its hash against the BIP-143 `hashOutputs` field.

---

## Testing

```typescript
import { TestContract } from 'runar-testing';
import { describe, it, expect } from 'vitest';

const source = `
  import { StatefulSmartContract } from 'runar-lang';
  export class Counter extends StatefulSmartContract {
    count: bigint;
    constructor(count: bigint) { super(count); this.count = count; }
    public increment(): void { this.count += 1n; }
  }
`;

describe('Counter', () => {
  it('increments', () => {
    const counter = TestContract.fromSource(source, { count: 0n });
    counter.call('increment');
    expect(counter.state.count).toBe(1n);
  });
});
```

`TestContract` runs the contract through the ANF interpreter (not the BSV Script VM) with mocked crypto: `checkSig` and `checkPreimage` always return true. It tests business logic, not signature flows. For real-crypto coverage use the cross-tier ANF parity suite or `RunarContract` end-to-end.

---

## Compiler Support

Every Rúnar compiler parses `.runar.ts` natively. Cross-tier conformance (Stack IR + hex byte equality) is gated by `conformance/runner/runner.ts --multi-format` for the fixtures that do not carry a per-fixture `compilers` allowlist. See [`docs/formats/README.md`](./README.md) for the format compatibility matrix and the [conformance README](../../conformance/README.md) for fixture-level opt-outs.

---

## Style

- No decorators — TypeScript's own `public`, `private`, `readonly` keywords cover all expressiveness Rúnar needs.
- Constructor must call `super(...)` as the first statement and pass every property in declaration order.
- `assert()` is the only control-flow primitive; there is no `revert` or `throw`.
- Only `runar-lang` built-ins and contract methods may be called. Any other identifier (`Math.floor`, `console.log`, third-party imports) fails typecheck.
- Single-file contracts: one class per `.runar.ts` source.
