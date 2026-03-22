# Zig Contract Format

**Status:** Experimental
**File extension:** `.runar.zig`
**Supported compilers:** TypeScript, Zig

---

## Overview

The Zig format lets you write Rúnar contracts as native Zig structs with explicit types, a constructor-style `init` function, and `runar.*` builtins. It is the native frontend for the Zig compiler in `compilers/zig`, and the TypeScript compiler also parses `.runar.zig` so Zig sources can participate in shared AST and script conformance tests.

Use this format when you want Zig-native authoring, the `packages/runar-zig` helper/runtime package, `cd examples/zig && zig build test`, or the Zig benchmark harness while keeping the same contract model as the other Rúnar frontends.

---

## Syntax

### Import

```zig
const runar = @import("runar");
```

The import line is required by the parser. It establishes the `runar.` namespace used for contract types and builtins.

In the native Zig example/test setup, that module is provided by `packages/runar-zig`.

### Contract Declaration

```zig
pub const P2PKH = struct {
    pub const Contract = runar.SmartContract;

    pub_key_hash: runar.Addr,

    pub fn init(pub_key_hash: runar.Addr) P2PKH {
        return .{ .pub_key_hash = pub_key_hash };
    }

    pub fn unlock(self: *const P2PKH, sig: runar.Sig, pub_key: runar.PubKey) void {
        runar.assert(runar.hash160(pub_key) == self.pub_key_hash);
        runar.assert(runar.checkSig(sig, pub_key));
    }
};
```

- Use `pub const Name = struct { ... };` for the contract container.
- Set `pub const Contract = runar.SmartContract;` for stateless contracts.
- Set `pub const Contract = runar.StatefulSmartContract;` for stateful contracts.
- Contract properties are plain Zig struct fields.

### Properties

```zig
pub const Counter = struct {
    pub const Contract = runar.StatefulSmartContract;

    count: i64 = 0,
    owner: runar.PubKey,
};
```

- In `runar.SmartContract`, fields are treated as readonly contract properties.
- In `runar.StatefulSmartContract`, fields with defaults are mutable state fields.
- Use `runar.Readonly(T)` to mark a stateful field readonly explicitly, with or without a default initializer.
- Fields without defaults still become constructor parameters unless `init` assigns them explicitly.

### Constructor

```zig
pub fn init(owner: runar.PubKey) Counter {
    return .{
        .count = 0,
        .owner = owner,
    };
}
```

- `init` is the constructor entrypoint.
- Return the contract struct using Zig's struct literal form.
- The parser converts the returned field assignments into the standard Rúnar constructor AST.

### Public and Private Methods

```zig
pub fn unlock(self: *const P2PKH, sig: runar.Sig, pub_key: runar.PubKey) void {
    runar.assert(runar.checkSig(sig, pub_key));
}

fn helper(self: *const Counter, amount: i64) i64 {
    return amount + self.count;
}
```

- `pub fn` creates a public spending method.
- `fn` creates a private helper.
- The first parameter is the receiver, usually `self: *const Name` or `self: *Name`.
- The receiver is stripped from the Rúnar AST, so method params begin after `self`.

### Builtins

Builtins are called through the `runar` namespace:

```zig
runar.assert(condition);
runar.hash160(pub_key);
runar.checkSig(sig, pub_key);
runar.addOutput(satoshis, owner, balance);
```

The parser strips the namespace and lowers these to the standard builtin names used by the rest of the pipeline.

### Control Flow

Supported:

- `if { ... } else { ... }`
- bounded `for` loops in the supported compiler subset
- local `const` and `var`
- assignments and compound assignments

Unsupported or intentionally narrow:

- arbitrary Zig metaprogramming
- `while` loops for contracts
- general-purpose library imports
- unrestricted pointer manipulation

---

## Type Mapping

| Zig type | Rúnar type |
|----------|-----------|
| `i8`, `i16`, `i32`, `i64`, `i128` | `bigint` |
| `u8`, `u16`, `u32`, `u64`, `u128` | `bigint` |
| `bool` | `boolean` |
| `runar.ByteString` | `ByteString` |
| `runar.PubKey` | `PubKey` |
| `runar.Sig` | `Sig` |
| `runar.Sha256` | `Sha256` |
| `runar.Ripemd160` | `Ripemd160` |
| `runar.Addr` | `Addr` |
| `runar.SigHashPreimage` | `SigHashPreimage` |
| `runar.RabinSig` | `RabinSig` |
| `runar.RabinPubKey` | `RabinPubKey` |
| `runar.Point` | `Point` |
| `[N]runar.ByteString` | fixed-size array |

---

## Conventions

| Concept | Zig syntax |
|---------|-----------|
| Stateless contract | `pub const Contract = runar.SmartContract;` |
| Stateful contract | `pub const Contract = runar.StatefulSmartContract;` |
| Constructor | `pub fn init(...) Name { return .{ ... }; }` |
| Public method | `pub fn name(self: *const Name, ...) void { ... }` |
| Private method | `fn name(self: *const Name, ...) Type { ... }` |
| Readonly field | plain field in `SmartContract`, or `runar.Readonly(T)` in `StatefulSmartContract` |
| Mutable/defaulted field | `field: i64 = 0,` in `StatefulSmartContract` |

---

## Example Files

See the repo examples under:

- `examples/zig/p2pkh/P2PKH.runar.zig`
- `examples/zig/stateful-counter/Counter.runar.zig`
- `examples/zig/post-quantum-wallet/PostQuantumWallet.runar.zig`
- `examples/zig/sphincs-wallet/SPHINCSWallet.runar.zig`

Compiler-specific notes and benchmark commands live in `compilers/zig/README.md`.

Native Zig testing commands:

```bash
cd packages/runar-zig && zig build test
cd ../../examples/zig && zig build test
cd ../../compilers/zig && zig build test && zig build conformance
```
