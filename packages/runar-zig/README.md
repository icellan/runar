# runar-zig

Native Zig SDK for the Rúnar TypeScript-to-Bitcoin Script compiler. Compile,
deploy, and call Rúnar smart contracts from Zig.

`packages/runar-zig` ships:

- the contract-author runtime (`SmartContract`, `StatefulSmartContract`,
  `assert`, mock crypto, real hashes, EC/secp256k1, Rabin/WOTS/SLH-DSA verifiers,
  Baby Bear field arithmetic);
- a deployment SDK with five Provider implementations (Mock, RPC,
  WhatsOnChain, GorillaPool, Wallet) and four Signer implementations (Local,
  Mock, External, Wallet);
- a `RunarContract` wrapper that handles deploy → call → state-chained call
  with two-pass OP_PUSH_TX preimage convergence;
- an ANF interpreter for off-chain state simulation and auto-state
  computation between calls;
- BRC-100 wallet integration (`WalletProvider`, `WalletSigner`,
  `MockWalletClient`);
- 1sat ordinals envelope construction plus BSV-20 / BSV-21 helpers;
- a typed-binding generator (`generateZig`);
- frontend wrappers (`compileCheckSource`, `compileCheckFile`).

It is the seventh tier of the Rúnar SDK alongside TypeScript, Go, Rust,
Python, Ruby, and Java. All seven SDKs produce byte-identical deployed
locking scripts for the same artifact and constructor arguments — see
Section 13b for the conformance proof.

---

## Table of contents

1. [Title and overview](#runar-zig)
2. [Table of contents](#table-of-contents)
3. [Installation](#3-installation)
4. [Quick start](#4-quick-start)
5. [Core concepts](#5-core-concepts)
6. [Writing a contract](#6-writing-a-contract)
7. [Compiling](#7-compiling)
8. [Deploying contracts](#8-deploying-contracts)
9. [Calling contract methods](#9-calling-contract-methods)
   - [9a. Single-signer call](#9a-single-signer-call)
   - [9b. Multi-signer prepareCall / finalizeCall](#9b-multi-signer-preparecall--finalizecall)
   - [9c. BRC-100 wallet signing](#9c-brc-100-wallet-signing)
10. [Stateful contracts](#10-stateful-contracts)
11. [UTXO and fee management](#11-utxo-and-fee-management)
12. [Typed contract bindings](#12-typed-contract-bindings)
13. [Testing](#13-testing)
    - [13a. Off-chain testing](#13a-off-chain-testing)
    - [13b. Integration testing](#13b-integration-testing)
14. [Provider configuration](#14-provider-configuration)
15. [Full API reference](#15-full-api-reference)
16. [Error handling](#16-error-handling)
17. [Troubleshooting / FAQ](#17-troubleshooting--faq)
18. [Versioning and stability](#18-versioning-and-stability)
19. [Links](#19-links)

---

## 3. Installation

`runar-zig` is published as a Zig package. Add it to your project's
`build.zig.zon`:

```zig
.{
    .name = .my_app,
    .version = "0.1.0",
    .fingerprint = 0x1234567890abcdef,
    .dependencies = .{
        .runar_zig = .{
            .url = "https://github.com/icellan/runar/archive/refs/tags/runar-zig-v0.4.4.tar.gz",
            // After fetching once, `zig fetch --save` writes the hash here.
            .hash = "<filled in by `zig fetch --save`>",
        },
    },
    .paths = .{
        "build.zig",
        "build.zig.zon",
        "src",
    },
}
```

Wire the module into `build.zig`:

```zig
const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const runar_dep = b.dependency("runar_zig", .{
        .target = target,
        .optimize = optimize,
    });
    const runar_module = runar_dep.module("runar");

    const exe = b.addExecutable(.{
        .name = "my-app",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/main.zig"),
            .target = target,
            .optimize = optimize,
        }),
    });
    exe.root_module.addImport("runar", runar_module);
    b.installArtifact(exe);

    const tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/main_test.zig"),
            .target = target,
            .optimize = optimize,
        }),
    });
    tests.root_module.addImport("runar", runar_module);
    const run_tests = b.addRunArtifact(tests);
    const test_step = b.step("test", "Run tests");
    test_step.dependOn(&run_tests.step);
}
```

The package depends on
[bsvz](https://github.com/b-open-io/bsvz) for ECDSA, BIP-143 sighash, address
encoding, and transaction parsing. `bsvz` is declared as a transitive
dependency of `runar-zig` and is fetched automatically.

Zig version: 0.16 or newer is required.

After installation, contract sources import the SDK as:

```zig
const runar = @import("runar");
```

---

## 4. Quick start

The `Counter` contract — stateful, single `bigint` field, two methods
(`increment`, `decrement`) — is the canonical first-flight example.

`src/Counter.runar.zig`:

```zig
const runar = @import("runar");

pub const Counter = struct {
    pub const Contract = runar.StatefulSmartContract;

    count: i64 = 0,

    pub fn init(count: i64) Counter {
        return .{ .count = count };
    }

    pub fn increment(self: *Counter) void {
        self.count += 1;
    }

    pub fn decrement(self: *Counter) void {
        runar.assert(self.count > 0);
        self.count -= 1;
    }
};
```

Deploy it and call `increment` against a mock provider. The compiled
artifact JSON would normally come from your build; for the Quick Start
load it from disk.

```zig
const std = @import("std");
const runar = @import("runar");

pub fn main() !void {
    var gpa: std.heap.GeneralPurposeAllocator(.{}) = .{};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const artifact_json = try std.fs.cwd().readFileAlloc(
        allocator,
        "build/Counter.runar.json",
        16 * 1024 * 1024,
    );
    defer allocator.free(artifact_json);

    var artifact = try runar.RunarArtifact.fromJson(allocator, artifact_json);
    defer artifact.deinit();

    var contract = try runar.RunarContract.init(
        allocator,
        &artifact,
        &[_]runar.StateValue{.{ .int = 0 }},
    );
    defer contract.deinit();

    var mock_provider = runar.MockProvider.init(allocator, "testnet");
    defer mock_provider.deinit();

    try mock_provider.addUtxo("anyaddress", .{
        .txid = "11" ** 32,
        .output_index = 0,
        .satoshis = 100_000,
        .script = "76a914" ++ "00" ** 20 ++ "88ac",
    });

    var signer = runar.MockSigner.init(null, "anyaddress");

    const deploy_txid = try contract.deploy(
        mock_provider.provider(),
        signer.signer(),
        .{ .satoshis = 5000 },
    );
    defer allocator.free(deploy_txid);
    std.log.info("deployed: {s}", .{deploy_txid});

    const call_txid = try contract.call(
        "increment",
        &.{},
        mock_provider.provider(),
        signer.signer(),
        null,
    );
    defer allocator.free(call_txid);
    std.log.info("incremented: {s} (count={d})", .{ call_txid, contract.state[0].int });
}
```

Replace `MockProvider`/`MockSigner` with `RPCProvider`+`LocalSigner`,
`WhatsOnChainProvider`, or `WalletProvider`+`WalletSigner` to talk to a
real network. The `RunarContract` API is identical across providers and
signers because both are vtable-based interfaces.

The Counter source lives at
[examples/zig/stateful-counter/Counter.runar.zig](../../examples/zig/stateful-counter/Counter.runar.zig);
the integration test that flows through `Increment`, chained
increment, decrement, wrong-state rejection, and underflow rejection
lives at
[integration/zig/src/counter_test.zig](../../integration/zig/src/counter_test.zig).

---

## 5. Core concepts

The SDK has nine top-level concepts. Every concept is named here once and
referenced by that name throughout the rest of this README.

| Concept | Zig type | Source |
|---------|----------|--------|
| **Artifact** | `RunarArtifact` | [src/sdk_types.zig](src/sdk_types.zig) |
| **Contract** | `RunarContract` | [src/sdk_contract.zig](src/sdk_contract.zig) |
| **Provider** | `Provider` (vtable) | [src/sdk_provider.zig](src/sdk_provider.zig) |
| **Signer** | `Signer` (vtable) | [src/sdk_signer.zig](src/sdk_signer.zig) |
| **WalletClient** | `WalletClient` (vtable) | [src/sdk_wallet.zig](src/sdk_wallet.zig) |
| **HttpTransport** | per-provider struct | [src/sdk_http_client.zig](src/sdk_http_client.zig) |
| **Call / DeployOptions / CallOptions** | structs | [src/sdk_types.zig](src/sdk_types.zig) |
| **State** | `[]StateValue`, encoded after `OP_RETURN` | [src/sdk_state.zig](src/sdk_state.zig) |
| **UTXO** | `UTXO` | [src/sdk_types.zig](src/sdk_types.zig) |

**Artifact.** The compiled output of the Rúnar compiler: a script
template (with `OP_0` placeholders for constructor args), an ABI, a state
schema, constructor / code-separator slot tables, and the ANF IR. Loaded
from JSON via `RunarArtifact.fromJson`. Immutable. Owns its allocations
and is freed via `artifact.deinit()`.

**Contract.** A `RunarContract` wraps an `*RunarArtifact` plus the
constructor arguments and tracks current `state` (for stateful contracts)
and `current_utxo` across deploy → call → call. It knows how to build
its own locking script, sign Sig parameters, run the OP_PUSH_TX two-pass
convergence for stateful continuations, and broadcast.

**Provider.** A `Provider` is the read/write blockchain interface
(vtable struct). Implementations: `MockProvider`, `RPCProvider`,
`WhatsOnChainProvider`, `GorillaPoolProvider`, `WalletProvider`. Custom
providers implement the seven-method `Provider.VTable`.

**Signer.** A `Signer` is the key-management interface (vtable struct).
Implementations: `LocalSigner` (raw key in memory), `MockSigner`
(deterministic placeholder), `ExternalSigner` (callback-driven),
`WalletSigner` (delegates to a BRC-100 wallet). Custom signers implement
the three-method `Signer.VTable`.

**WalletClient.** A BRC-100 wallet client (vtable struct). Backs both
`WalletProvider` (for UTXO lookup and broadcast) and `WalletSigner` (for
key derivation and signing). `MockWalletClient` is shipped for tests.

**HttpTransport.** The HTTP-using providers (`WhatsOnChainProvider`,
`GorillaPoolProvider`, `RPCProvider`) each declare an `HttpTransport`
struct in their own module. `CurlHttpTransport` (curl subprocess) and
`StdHttpTransport` (`std.http.Client`) ship in
[src/sdk_http_client.zig](src/sdk_http_client.zig); both expose
`wocTransport()`, `gorillaTransport()`, and `rpcTransport()` adapters.

**DeployOptions / CallOptions.** Plain structs passed by value. Both
allow optional `change_address`. `CallOptions` additionally allows
`new_state` (override the auto-computed continuation) and `data_outputs`
(override `addDataOutput` resolution).

**State.** The contract's mutable, Bitcoin-Script-encoded payload after
the locking script's last `OP_RETURN` opcode. Encoded as Script number
push-data via `serializeState`; decoded via `deserializeState` /
`extractStateFromScript`. Held on the `RunarContract` as
`state: []StateValue`.

**UTXO.** `{ txid, output_index, satoshis, script }`. The
`current_utxo` field on a `RunarContract` tracks the single output that
holds the contract on-chain.

**Allocator-passing convention.** The SDK is allocator-explicit
throughout. Every function that returns owned memory takes an
`allocator: std.mem.Allocator` parameter. Caller owns returned slices
and is responsible for `allocator.free(...)` (or calling the type's
`deinit(...)` method when one exists). The convention matches `std`:
errors propagate via `try`, cleanup runs via `defer`. `RunarContract`,
`RunarArtifact`, `MockProvider`, and similar long-lived objects each
own their own allocator and expose `deinit(self: *Self)`.

**Vtable polymorphism.** `Provider`, `Signer`, `WalletClient`, and
`HttpTransport` are vtable structs (`{ ptr: *anyopaque, vtable: *const
VTable }`). Each concrete implementation exposes a method like
`provider()` / `signer()` / `walletClient()` that constructs the vtable
struct pointing back at itself. Section 14 shows how to implement a
custom Provider end to end.

---

## 6. Writing a contract

Contracts live in `*.runar.zig` files and import the SDK module as
`runar`. Two base classes:

| Base class | When to use | Compiler behaviour |
|------------|-------------|--------------------|
| `runar.SmartContract` | Stateless, all properties `readonly`. Developer writes full unlock logic. | No automatic preimage check, no continuation. |
| `runar.StatefulSmartContract` | Mutable state, methods produce a continuation UTXO. | Compiler injects `checkPreimage` at method entry and a state-output continuation at exit. |

The base class is selected via `pub const Contract = ...`:

```zig
const runar = @import("runar");

pub const P2PKH = struct {
    pub const Contract = runar.SmartContract;

    pubKeyHash: runar.Addr,

    pub fn init(pubKeyHash: runar.Addr) P2PKH {
        return .{ .pubKeyHash = pubKeyHash };
    }

    pub fn unlock(self: *const P2PKH, sig: runar.Sig, pubKey: runar.PubKey) void {
        runar.assert(runar.bytesEq(runar.hash160(pubKey), self.pubKeyHash));
        runar.assert(runar.checkSig(sig, pubKey));
    }
};
```

A stateful counter:

```zig
const runar = @import("runar");

pub const Counter = struct {
    pub const Contract = runar.StatefulSmartContract;

    count: i64 = 0,

    pub fn init(count: i64) Counter {
        return .{ .count = count };
    }

    pub fn increment(self: *Counter) void {
        self.count += 1;
    }

    pub fn decrement(self: *Counter) void {
        runar.assert(self.count > 0);
        self.count -= 1;
    }
};
```

Rules enforced by the validator:

- One contract struct per `.runar.zig` file.
- `init` is the constructor. Every property must be assigned in `init`
  (either positionally or via a `= default` initializer at declaration).
- `pub` methods are spending entry points. Non-`pub` methods are inlined
  helpers.
- Only Rúnar built-ins, methods on `self`, and operations on Rúnar types
  are allowed inside method bodies. Calls like `std.debug.print` or
  `@import("std")` are rejected by the typecheck pass.
- `runar.assert(expr)` is the failure mechanism — a script is invalid if
  any `assert` is false.

Type aliases provided in `src/base.zig` and re-exported from
`src/root.zig`:

| Zig name | Underlying type | Meaning |
|----------|-----------------|---------|
| `Int`, `Bigint` | `i64` | Script integer |
| `PubKey`, `Sig`, `Addr`, `ByteString` | `[]const u8` | Length-prefix-free byte string |
| `Sha256`, `Sha256Digest`, `Ripemd160` | `[]const u8` | Hash digests |
| `SigHashPreimage` | `[]const u8` | BIP-143 preimage |
| `RabinSig`, `RabinPubKey` | `[]const u8` | Rabin signature material |
| `Point` | `[]const u8` (64 bytes) | secp256k1 point (`x \|\| y`) |
| `Readonly(T)` | `T` (alias) | Marks readonly stateful properties |

Built-ins are documented in Section 15; see the `runar.<fn>` re-exports.

---

## 7. Compiling

The compiler is invoked from the `runar-compiler` package (TypeScript) or
the standalone Zig compiler (`compilers/zig/`). The Zig SDK ships only
the **frontend wrapper** that runs parse → validate → typecheck and
returns whether the contract is acceptable Rúnar. It does not produce
hex script — for that, run the Rúnar CLI or one of the language compilers
and load the resulting JSON via `RunarArtifact.fromJson`.

Two helpers are exported:

```zig
pub fn compileCheckSource(
    allocator: std.mem.Allocator,
    source: []const u8,
    file_name: []const u8,
) !CompileCheckResult;

pub fn compileCheckFile(
    allocator: std.mem.Allocator,
    file_path: []const u8,
) !CompileCheckResult;
```

`CompileCheckResult` is

```zig
pub const CompileCheckResult = struct {
    stage: ?CompileCheckStage, // null when ok
    messages: []const []const u8,

    pub fn ok(self: CompileCheckResult) bool;
    pub fn deinit(self: CompileCheckResult, allocator: std.mem.Allocator) void;
};

pub const CompileCheckStage = enum { parse, validate, typecheck };
```

Typical use inside a unit test:

```zig
test "Counter compiles" {
    const src = @embedFile("Counter.runar.zig");
    const result = try runar.compileCheckSource(
        std.testing.allocator,
        src,
        "Counter.runar.zig",
    );
    defer result.deinit(std.testing.allocator);
    try std.testing.expect(result.ok());
}
```

To produce a deployable artifact, run the TypeScript compiler against
the same source:

```bash
npx runar compile examples/zig/stateful-counter/Counter.runar.zig --out build/Counter.runar.json
```

Then load it from Zig with `RunarArtifact.fromJson`. The seven-compiler
conformance suite (see Section 13b) guarantees the resulting hex matches
what any of the seven compilers would produce.

---

## 8. Deploying contracts

`RunarContract.deploy` is the one-shot deployment path:

```zig
pub fn deploy(
    self: *RunarContract,
    provider: ?Provider,
    signer: ?Signer,
    options: DeployOptions,
) ContractError![]u8;
```

`DeployOptions`:

```zig
pub const DeployOptions = struct {
    satoshis: i64,             // amount locked into the contract output
    change_address: ?[]const u8 = null, // defaults to the signer's address
};
```

The call returns the broadcast txid (caller owns). It also stores
`current_utxo` on the contract so subsequent calls know where the output
lives.

What `deploy` does end to end:

1. Resolves the provider/signer (uses arguments, falls back to values
   stashed by `connect()`).
2. Builds the locking script: substitutes constructor-arg slots and
   code-separator-index slots in the artifact's template; appends
   `OP_RETURN <state-bytes>` for stateful contracts; splices in the
   inscription envelope when one is attached.
3. Fetches the signer's funding UTXOs from the provider.
4. Selects funding UTXOs largest-first via
   [`selectUtxos`](src/sdk_deploy.zig).
5. Builds an unsigned tx via
   [`buildDeployTransaction`](src/sdk_deploy.zig) with one
   contract-bearing output and an optional change output.
6. Signs each P2PKH input (BIP-143 sighash + ECDSA via the signer).
7. Broadcasts via `provider.broadcast`.

```zig
var artifact = try runar.RunarArtifact.fromJson(allocator, artifact_json);
defer artifact.deinit();

var contract = try runar.RunarContract.init(
    allocator,
    &artifact,
    &[_]runar.StateValue{.{ .int = 0 }},
);
defer contract.deinit();

var rpc = runar.RPCProvider.initRegtest(
    allocator,
    "http://localhost:18332",
    "user",
    "pass",
);
defer rpc.deinit();
var transport = try runar.CurlHttpTransport.init(allocator);
defer transport.deinit();
rpc.setTransport(transport.rpcTransport());

var signer = try runar.LocalSigner.fromHex(
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
);

const deploy_txid = try contract.deploy(
    rpc.provider(),
    signer.signer(),
    .{ .satoshis = 5000 },
);
defer allocator.free(deploy_txid);
```

Optional pattern: pre-bind provider/signer with `contract.connect(p, s)`
and pass `null` to `deploy` / `call`.

---

## 9. Calling contract methods

### 9a. Single-signer call

```zig
pub fn call(
    self: *RunarContract,
    method_name: []const u8,
    args: []const StateValue,
    provider: ?Provider,
    signer: ?Signer,
    options: ?CallOptions,
) ContractError![]u8;
```

`CallOptions`:

```zig
pub const CallOptions = struct {
    satoshis: i64 = 0,                        // override continuation amount
    change_address: ?[]const u8 = null,
    new_state: ?[]const StateValue = null,    // skip ANF auto-state
    data_outputs: ?[]const ContractOutput = null, // skip addDataOutput resolution
};
```

`args` is a slice of `StateValue` — the user-visible parameters in the
order declared on the public method. Auto-injected stateful parameters
(`SigHashPreimage`, `_changePKH`, `_changeAmount`, `_newAmount`) are
filled by the SDK and must NOT be passed by the caller.

`StateValue` is a tagged union:

```zig
pub const StateValue = union(enum) {
    int: i64,
    big_int: []const u8,    // decimal string for values outside i64
    boolean: bool,
    bytes: []const u8,      // hex-encoded
    array_value: []const StateValue,
};
```

Sig and PubKey arguments are auto-resolved when passed as
`.{ .int = 0 }`: Sig becomes a 72-byte zero placeholder during the
preimage convergence and is replaced with a real ECDSA signature in the
final pass; PubKey is filled from `signer.getPublicKey`.

```zig
const txid = try contract.call(
    "increment",
    &.{}, // no user-visible parameters on increment()
    provider,
    signer,
    null,
);
defer allocator.free(txid);
```

For a method that takes a `bigint` argument:

```zig
const txid = try contract.call(
    "deposit",
    &.{ .{ .int = 1500 } },
    provider,
    signer,
    null,
);
```

For a method that takes a `Sig`-typed parameter (one element of the
contract API), pass `.{ .int = 0 }` as the placeholder; the SDK fills the
real signature in pass two of the convergence loop.

What `call` does for a **stateful** contract:

1. Resolves args, computes the new state (via the embedded ANF
   interpreter unless `options.new_state` is supplied), and figures out
   any `addDataOutput` continuations.
2. Builds the new locking script (`getLockingScript`) for the
   continuation output.
3. First pass: builds the call transaction with placeholder unlocking
   script (72 zero bytes for the OP_PUSH_TX sig, 181 zero bytes for the
   preimage) and runs `computeOpPushTx` to get the real BIP-143 preimage
   and OP_PUSH_TX signature.
4. Re-signs the funding inputs.
5. Second pass: re-runs `computeOpPushTx` against the resigned tx
   (preimage size depends on tx size) and rebuilds the unlocking script.
6. Signs the contract's own Sig parameters (if any) against the now-final
   transaction.
7. Splices the final unlocking script in, re-signs the funding inputs
   one last time, broadcasts.
8. Updates `current_utxo` to the new continuation output so the next
   `call` chains naturally.

For a **stateless** contract, the call is simpler: build the unlocking
script, sign Sig params, broadcast. After the call `current_utxo`
becomes `null` because the script was spent without continuation.

### 9b. Multi-signer prepareCall / finalizeCall

**Not yet exposed in the Zig SDK.**

The other six SDK tiers (TypeScript, Go, Rust, Python, Java, Ruby) ship a
two-step calling flow for hardware wallets and multi-party signing:
`prepareCall(...) → PreparedCall { tx_hex, sighashes }` followed by
`finalizeCall(prepared, signatures)`. This API is on the Rúnar roadmap
for the Zig SDK; until it lands, use one of the workarounds below.

**Workaround 1 — implement a custom `Signer` vtable** that proxies the
sighash digest out to your hardware wallet, prompts the user, and
returns the DER signature. Because the contract `call` flow signs each
Sig parameter independently, an `ExternalSigner` that blocks on a UI
prompt is functionally equivalent to a `prepareCall` / `finalizeCall`
round-trip — the difference is only that the prompt happens inside
`call()` instead of between two SDK calls.

```zig
fn promptHardwareWallet(
    allocator: std.mem.Allocator,
    tx_hex: []const u8,
    input_index: usize,
    subscript: []const u8,
    satoshis: i64,
    sighash_type: ?u32,
) runar.sdk_signer.SignerError![]u8 {
    // Emit tx_hex + (input_index, subscript, satoshis) to your device,
    // wait for the user to approve, return DER||sighash_byte hex.
    _ = sighash_type;
    return device.sign(allocator, tx_hex, input_index, subscript, satoshis);
}

var signer_state = runar.ExternalSigner{
    .pub_key = device_pubkey_hex,
    .address = device_address_str,
    .sign_fn = promptHardwareWallet,
};
const txid = try contract.call(
    "increment", &.{},
    provider,
    signer_state.signer(),
    null,
);
```

**Workaround 2 — manually drive the building blocks.** `RunarContract`
exposes `getLockingScript`, `getCodePartHex`, `getCodeSepIndex`,
`buildUnlockingScript`, and `adjustCodeSepOffset`; together with
[`buildCallTransaction`](src/sdk_call.zig),
[`computeOpPushTx`](src/sdk_oppushtx.zig), and
[`insertUnlockingScript`](src/sdk_contract.zig) you can replicate the
two-pass convergence by hand and hand the unsigned tx + computed sighash
to an off-line signer.

Track the planned `prepareCall` / `finalizeCall` API at the project
issue tracker
(<https://github.com/icellan/runar/issues>); when it ships, the surface
will mirror the Go and Rust shapes:

```zig
// Planned, not yet implemented:
//
// var prepared = try contract.prepareCall(method, args, provider, signer, options);
// defer prepared.deinit(allocator);
// const sigs = try external_device.signEach(prepared.sighashes);
// const txid = try contract.finalizeCall(prepared, sigs);
```

### 9c. BRC-100 wallet signing

When the SDK can't hold raw private keys (browser extensions, OS
keychains, hardware wallets exposing a BRC-100 surface), use
`WalletProvider` + `WalletSigner` to delegate UTXO management and
signing to the wallet. Both are backed by a `WalletClient` vtable struct.

```zig
pub const WalletClient = struct {
    ptr: *anyopaque,
    vtable: *const VTable,

    pub const VTable = struct {
        getPublicKey: *const fn (
            ctx: *anyopaque,
            allocator: std.mem.Allocator,
            protocol_id: ProtocolID,
            key_id: []const u8,
        ) WalletError![]u8,

        createSignature: *const fn (
            ctx: *anyopaque,
            allocator: std.mem.Allocator,
            hash: []const u8,
            protocol_id: ProtocolID,
            key_id: []const u8,
        ) WalletError![]u8,

        createAction: *const fn (
            ctx: *anyopaque,
            allocator: std.mem.Allocator,
            description: []const u8,
            outputs: []const WalletActionOutput,
        ) WalletError!WalletActionResult,

        listOutputs: *const fn (
            ctx: *anyopaque,
            allocator: std.mem.Allocator,
            basket: []const u8,
            tags: []const []const u8,
            limit: usize,
        ) WalletError![]WalletOutput,
    };
    // ... convenience methods (getPublicKey, createSignature, ...) that
    // forward through the vtable.
};
```

`MockWalletClient` is the reference implementation; production callers
implement the four-method vtable wrapping their wallet's transport.

```zig
var mock = runar.MockWalletClient.init(allocator);
defer mock.deinit();
try mock.addOutput(.{
    .outpoint = "aabb" ++ "00" ** 30 ++ ".0",
    .satoshis = 50_000,
    .locking_script = "76a914" ++ "00" ** 20 ++ "88ac",
    .spendable = true,
});

const wallet = mock.walletClient();

const protocol = runar.ProtocolID{ .level = 2, .name = "runar-counter" };
const key_id = "1";

var wallet_provider = runar.WalletProvider.init(
    allocator,
    wallet,
    "runar-funding",        // wallet basket name
    .{
        .funding_tag = "funding",
        .network = "testnet",
        .fee_rate = 50,
    },
);
defer wallet_provider.deinit();

var wallet_signer = runar.WalletSigner.init(allocator, wallet, protocol, key_id);
defer wallet_signer.deinit();

// One-shot deploy convenience that sets up the expected-script filter
// for funding UTXOs and forwards everything to contract.deploy().
const deploy_txid = try runar.deployWithWallet(&contract, wallet, .{
    .satoshis = 5000,
    .basket = "runar-funding",
    .protocol_id = protocol,
    .key_id = key_id,
});
defer allocator.free(deploy_txid);

// Subsequent calls go through the same vtables — call() doesn't care
// where the keys live.
const inc_txid = try contract.call(
    "increment",
    &.{},
    wallet_provider.provider(),
    wallet_signer.signer(),
    null,
);
defer allocator.free(inc_txid);
```

`WalletProvider.setExpectedScript` lets you scope `getUtxos` to outputs
whose locking script matches a specific P2PKH template (used internally
by `deployWithWallet` to filter the wallet basket down to funding
UTXOs).

A custom `WalletClient` implementation is wired exactly the same way as
a custom `Provider` (Section 14): write a struct, declare a `vtable`
constant pointing at impl functions, return a `WalletClient` from a
`walletClient()` method.

---

## 10. Stateful contracts

`StatefulSmartContract` is the base class that produces a continuation
UTXO. Two compiler-injected primitives drive the on-chain semantics:

- **`checkPreimage(preimage)`** at method entry — proves the spending
  transaction matches the BIP-143 preimage the contract was given.
- **OP_PUSH_TX** (private key k=1, public key = secp256k1 generator G)
  is the on-chain signature scheme used for `checkPreimage`. The SDK
  computes both halves: see
  [`opPushTxPubKeyHex`](src/sdk_oppushtx.zig) and
  [`computeOpPushTx`](src/sdk_oppushtx.zig).

The SDK `call` flow runs **two-pass OP_PUSH_TX convergence** for
stateful contracts. The size of the transaction influences the BIP-143
preimage; the preimage is part of the unlocking script; the unlocking
script's size influences the transaction size. Two passes are enough in
practice because the per-pass deltas are bounded by the small DER
signature width (70–72 bytes):

```
pass 1: build tx with placeholder sig + placeholder preimage
        → sign funding inputs
        → compute real preimage and OP_PUSH_TX sig
        → rebuild tx with real unlock (size may differ)
        → re-sign funding inputs
pass 2: recompute OP_PUSH_TX against the rebuilt tx
        → sign Sig parameters
        → splice final unlock in
        → re-sign funding inputs
        → broadcast
```

State serialization layout for the continuation output:

```
<code-template-with-substituted-args>
  [<inscription-envelope-if-any>]
6a                                            ; OP_RETURN
<encoded-state-field-0> <encoded-state-field-1> ...
```

Each state field is encoded as a Bitcoin Script number push (small
opcodes for `-1..16`, push-data for larger ints) or a hex-prefixed
push-data for byte fields. Encoding is implemented by
[`serializeState`](src/sdk_state.zig). Decoding is symmetric via
[`deserializeState`](src/sdk_state.zig) and
[`extractStateFromScript`](src/sdk_state.zig).

**ANF interpreter for auto-state.** The artifact carries the contract's
A-Normal Form IR (the `anf_json` field). On each `call()` the SDK runs
[`computeNewStateAndDataOutputs`](src/sdk_anf_interpreter.zig) over the
current state plus the user args to predict what the on-chain method
would assign. This is what makes `contract.call("increment", &.{}, ...)`
work without you having to pass the new value of `count` — the
interpreter figures out `count + 1` and writes it back into
`contract.state` after broadcast.

Override the interpreter when you need to test rejection paths:

```zig
const txid = try contract.call(
    "increment",
    &.{},
    provider,
    signer,
    &runar.CallOptions{
        .new_state = &.{ .{ .int = 99 } }, // wrong! script will reject
    },
);
```

The wrong-state and underflow rejection cases in
[integration/zig/src/counter_test.zig](../../integration/zig/src/counter_test.zig)
use exactly this pattern.

**Reconnecting to a deployed contract.**
[`RunarContract.fromUtxo`](src/sdk_contract.zig) reconstructs a contract
from an on-chain UTXO. It parses the locking script, separates the code
portion from the state portion at the last `OP_RETURN`, deserializes
state, and detects an attached inscription envelope.

```zig
var contract = try runar.RunarContract.fromUtxo(allocator, &artifact, utxo);
defer contract.deinit();
contract.connect(provider, signer);
const txid = try contract.call("increment", &.{}, null, null, null);
```

There is no `fromTxId` helper in the Zig SDK today (the TS, Go, Rust,
and Python SDKs ship one). To reconnect from a txid, fetch the
transaction via the provider and construct the UTXO yourself before
calling `fromUtxo`.

---

## 11. UTXO and fee management

`UTXO`:

```zig
pub const UTXO = struct {
    txid: []const u8,        // 64-char hex
    output_index: i32,
    satoshis: i64,
    script: []const u8,      // hex-encoded locking script

    pub fn clone(self: UTXO, allocator: std.mem.Allocator) !UTXO;
    pub fn deinit(self: *UTXO, allocator: std.mem.Allocator) void;
};
```

The fee model uses real script sizes throughout (it does not assume P2PKH
shapes for non-P2PKH outputs):

- **`estimateDeployFee(num_inputs, locking_script_byte_len, fee_rate)`**
  ([src/sdk_deploy.zig](src/sdk_deploy.zig)) — used by deploy for fee
  estimation. P2PKH input is sized at 148 bytes; the contract output
  uses the real locking script length plus its varint header.
- **`estimateCallFee`** ([src/sdk_call.zig](src/sdk_call.zig)) — same
  shape for the call path: real unlocking-script length for input 0,
  real continuation-script length for output 0.
- **`selectUtxos(allocator, utxos, target_satoshis,
  locking_script_byte_len, fee_rate)`** ([src/sdk_deploy.zig](src/sdk_deploy.zig))
  — largest-first selection that re-estimates fees as it iterates so it
  stops as soon as `total >= target + fee`.

Fee rate is satoshis per KB (the SDK divides by 1000 internally). Pass
`0` to fall back to the default of `100`.

`MockProvider.fee_rate` defaults to `100` and is exposed as a public
field for tests that want to model rate spikes.

---

## 12. Typed contract bindings

`generateZig(allocator, &artifact)` produces a typed Zig wrapper around
a compiled artifact: a constructor-args struct plus one method stub per
public ABI entry.

```zig
const wrapper_src = try runar.generateZig(allocator, &artifact);
defer allocator.free(wrapper_src);
try std.fs.cwd().writeFile(.{
    .sub_path = "src/CounterWrapper.zig",
    .data = wrapper_src,
});
```

For the Counter contract the generated source looks like:

```zig
// GENERATED — do not edit by hand.
const std = @import("std");

pub const CounterArgs = struct {
    count: i64,
};

pub const Counter = struct {
    args: CounterArgs,

    pub fn init(args: CounterArgs) Counter { return .{ .args = args }; }

    /// ABI method `increment`.
    pub fn increment(self: *Counter) void { _ = self; }

    /// ABI method `decrement`.
    pub fn decrement(self: *Counter) void { _ = self; }
};
```

Today the wrapper is a typed shell over the constructor args plus
method-name stubs; it is intended to be wired to your own `RunarContract`
instance in glue code. ABI types map to Zig as follows (see
[src/sdk_codegen.zig](src/sdk_codegen.zig)):

| ABI type | Zig type |
|----------|----------|
| `bigint` | `i64` |
| `boolean` | `bool` |
| `Sig`, `PubKey`, `Addr`, `ByteString`, `Ripemd160`, `Sha256`, `Point`, `SigHashPreimage` | `[]const u8` (hex) |
| anything else | `[]const u8` (hex) |

---

## 13. Testing

### 13a. Off-chain testing

Native Zig unit tests use `zig build test`. The SDK ships a custom test
runner at [src/test_runner.zig](src/test_runner.zig) that initializes
`std.testing.environ` (so tests can read env vars without linking libc)
and prints a compact summary. The build wires it in automatically.

Mock crypto fixtures (matching the cross-SDK conventions in the concept
inventory):

| Fixture | Origin | Purpose |
|---------|--------|---------|
| `runar.ALICE`, `runar.BOB`, `runar.CHARLIE` | [src/test_keys.zig](src/test_keys.zig) | Deterministic 32-byte private keys with their compressed pubkeys and hash160 addresses precomputed. |
| `runar.signTestMessage(pair)` | [src/builtins.zig](src/builtins.zig) | Real ECDSA signature of `"runar-test-message-v1"` under the test key — `checkSig` returns true against the matching pubkey. |
| `runar.mockPreimage(parts)` | [src/builtins.zig](src/builtins.zig) | Deterministic 181-byte SigHashPreimage; `checkPreimage` always returns true off-chain. |
| `runar.MockSigner` | [src/sdk_signer.zig](src/sdk_signer.zig) | 72-byte zero-DER signature; deterministic 33-byte placeholder pubkey. |
| `runar.MockProvider` | [src/sdk_provider.zig](src/sdk_provider.zig) | In-memory UTXO store + fake-txid broadcaster. |
| `runar.MockWalletClient` | [src/sdk_wallet.zig](src/sdk_wallet.zig) | Deterministic BRC-100 wallet for `WalletProvider`/`WalletSigner` tests. |

Real hashes (`sha256`, `hash160`, `hash256`, `ripemd160`, `blake3Hash`)
and post-quantum verifiers (`verifyRabinSig`, `verifyWOTS`,
`verifySLHDSA_SHA2_*`) always run real math, even in mocked tests.

A typical contract unit test:

```zig
const std = @import("std");
const runar = @import("runar");
const Counter = @import("Counter.runar.zig").Counter;

test "increment moves count up" {
    var c = Counter.init(0);
    c.increment();
    try std.testing.expectEqual(@as(i64, 1), c.count);
}

test "decrement at zero traps the assertion" {
    // The compile-check route runs the source through the Rúnar frontend
    // so failed asserts surface here as well.
    const result = try runar.compileCheckSource(
        std.testing.allocator,
        @embedFile("Counter.runar.zig"),
        "Counter.runar.zig",
    );
    defer result.deinit(std.testing.allocator);
    try std.testing.expect(result.ok());
}
```

To run only the SDK tests:

```bash
cd packages/runar-zig
zig build test
```

### 13b. Integration testing

[src/script_integration_test.zig](src/script_integration_test.zig) is
gated behind the optional `bsvz_runar_harness` build option. When the
harness is present the test set wires up:

1. The TypeScript compiler (`packages/runar-compiler/dist/index.js`) to
   compile a Rúnar source string into hex.
2. The bsvz Script VM with the Rúnar harness shim to execute the
   compiled hex against a constructed unlocking script.
3. End-to-end assertions like "P2PKH unlock with the correct sig
   succeeds and with a wrong sig fails".

Tests skip cleanly with `error.SkipZigTest` when either the Node-built
compiler dist or the bsvz harness file isn't present, so `zig build
test` does not require a Node toolchain.

The on-chain integration suite that exercises real BSV regtest lives
outside this package at [integration/zig/](../../integration/zig/) and
has its own `build.zig`. It hits a Bitcoin regtest RPC over curl and
runs deploy → call → call flows through the real script interpreter:

```bash
cd integration/zig
zig build test
```

The Counter integration test there mirrors the Go reference at
[integration/go/counter_test.go](../../integration/go/counter_test.go).

**Cross-SDK byte-identity proof.** All seven SDKs are required to emit
byte-identical deployed locking scripts for the same artifact and
constructor arguments. The conformance fixture set lives at
[conformance/sdk-output/tests/](../../conformance/sdk-output/tests/) and
includes a dedicated `stateful-counter/` case
([input.json](../../conformance/sdk-output/tests/stateful-counter/input.json),
[expected-locking.hex](../../conformance/sdk-output/tests/stateful-counter/expected-locking.hex))
that the Zig SDK's deployed output is checked against in CI.

---

## 14. Provider configuration

Five concrete providers ship in this package. All five implement
`Provider` via `provider()` and can be passed interchangeably to
`RunarContract.deploy` / `.call`.

### MockProvider

```zig
var mock = runar.MockProvider.init(allocator, "testnet");
defer mock.deinit();
try mock.addUtxo("addr", .{
    .txid = "11" ** 32, .output_index = 0,
    .satoshis = 10_000, .script = "76a914...88ac",
});
mock.fee_rate = 50;             // optional override
const prov = mock.provider();
```

In-memory. `broadcast` returns a deterministic fake txid generated from
a content-addressed hash and stores the raw hex (`getRawTransaction`
returns it back). `getTransaction` always returns
`ProviderError.NotFound` because the mock doesn't parse tx bytes.
`getContractUtxo` returns `null`.

### RPCProvider

```zig
var rpc = runar.RPCProvider.initRegtest(
    allocator, "http://localhost:18332", "user", "pass",
);
defer rpc.deinit();
var http = try runar.CurlHttpTransport.init(allocator);
defer http.deinit();
rpc.setTransport(http.rpcTransport());
const prov = rpc.provider();
```

`initRegtest` enables `auto_mine` so a `generatetoaddress` 1 block
follows every broadcast. Use `RPCProvider.init` for testnet/mainnet
nodes that already have a confirmation path.

`HttpTransport` is a small struct with one `post` callback:

```zig
pub const HttpTransport = struct {
    ctx: *anyopaque,
    post: *const fn (
        ctx: *anyopaque,
        allocator: std.mem.Allocator,
        url: []const u8,
        user: []const u8,
        pass: []const u8,
        body: []const u8,
    ) RPCError![]u8,
};
```

A custom transport is just a struct with a `post` impl plus an adapter
constructor.

### WhatsOnChainProvider

```zig
var woc = runar.WhatsOnChainProvider.init(allocator, .testnet);
defer woc.deinit();
var http = try runar.CurlHttpTransport.init(allocator);
defer http.deinit();
woc.setTransport(http.wocTransport());
const prov = woc.provider();
```

Talks to <https://api.whatsonchain.com>. Network options: `.mainnet` /
`.testnet`. The HTTP transport callback shape is:

```zig
pub const HttpTransport = struct {
    ctx: *anyopaque,
    get: *const fn (
        ctx: *anyopaque,
        allocator: std.mem.Allocator,
        url: []const u8,
    ) ProviderError![]u8,
    post: *const fn (
        ctx: *anyopaque,
        allocator: std.mem.Allocator,
        url: []const u8,
        content_type: []const u8,
        body: []const u8,
    ) ProviderError![]u8,
};
```

### GorillaPoolProvider

```zig
var gp = runar.GorillaPoolProvider.init(allocator, .mainnet);
defer gp.deinit();
var http = try runar.StdHttpTransport.init(allocator);
defer http.deinit();
gp.setTransport(http.gorillaTransport());
const prov = gp.provider();
```

1sat-ordinals-aware. Talks to <https://ordinals.gorillapool.io/api> /
<https://testnet.ordinals.gorillapool.io/api>. Same `HttpTransport`
shape as WoC.

### WalletProvider

See Section 9c for the full BRC-100 walkthrough.

### Implementing a custom Provider

Vtable polymorphism: write a struct, declare a `vtable` constant
pointing at impl functions, return a `Provider` from a `provider()`
method. Skeleton:

```zig
const std = @import("std");
const runar = @import("runar");

pub const MyCachedProvider = struct {
    allocator: std.mem.Allocator,
    inner: runar.Provider,
    cache: std.StringHashMap([]u8),

    pub fn init(allocator: std.mem.Allocator, inner: runar.Provider) MyCachedProvider {
        return .{
            .allocator = allocator,
            .inner = inner,
            .cache = std.StringHashMap([]u8).init(allocator),
        };
    }

    pub fn deinit(self: *MyCachedProvider) void {
        var it = self.cache.iterator();
        while (it.next()) |e| {
            self.allocator.free(e.key_ptr.*);
            self.allocator.free(e.value_ptr.*);
        }
        self.cache.deinit();
    }

    pub fn provider(self: *MyCachedProvider) runar.Provider {
        return .{ .ptr = @ptrCast(self), .vtable = &vtable };
    }

    const vtable = runar.sdk_provider.Provider.VTable{
        .getTransaction = getTransactionImpl,
        .broadcast = broadcastImpl,
        .getUtxos = getUtxosImpl,
        .getContractUtxo = getContractUtxoImpl,
        .getNetwork = getNetworkImpl,
        .getFeeRate = getFeeRateImpl,
        .getRawTransaction = getRawTransactionImpl,
    };

    fn getRawTransactionImpl(
        ctx: *anyopaque,
        allocator: std.mem.Allocator,
        txid: []const u8,
    ) runar.sdk_provider.ProviderError![]u8 {
        const self: *MyCachedProvider = @ptrCast(@alignCast(ctx));
        if (self.cache.get(txid)) |cached| {
            return allocator.dupe(u8, cached) catch return error.OutOfMemory;
        }
        const fresh = try self.inner.getRawTransaction(allocator, txid);
        // Cache and return
        const key = self.allocator.dupe(u8, txid) catch return error.OutOfMemory;
        const val = self.allocator.dupe(u8, fresh) catch {
            self.allocator.free(key);
            return error.OutOfMemory;
        };
        self.cache.put(key, val) catch {};
        return fresh;
    }

    // ... impl the other six vtable methods, forwarding to self.inner
};
```

The same pattern works for custom `Signer` and `WalletClient`
implementations — implement the vtable, return the interface struct
from a constructor method.

---

## 15. Full API reference

Every public symbol exported from
[src/root.zig](src/root.zig). Grouped by subsystem; alphabetical within
each group.

### 15.1 Compilation

```zig
pub const CompileCheckStage = enum { parse, validate, typecheck };

pub const CompileCheckResult = struct {
    stage: ?CompileCheckStage,         // null when ok()
    messages: []const []const u8,

    pub fn ok(self: CompileCheckResult) bool;
    pub fn deinit(self: CompileCheckResult, allocator: std.mem.Allocator) void;
};

pub fn compileCheckSource(
    allocator: std.mem.Allocator,
    source: []const u8,
    file_name: []const u8,
) !CompileCheckResult;

pub fn compileCheckFile(
    allocator: std.mem.Allocator,
    file_path: []const u8,
) !CompileCheckResult;
```

[src/compile_check.zig](src/compile_check.zig).

### 15.2 Artifact types

```zig
pub const RunarArtifact = struct {
    allocator: std.mem.Allocator,
    version: []const u8,
    compiler_version: []const u8,
    contract_name: []const u8,
    abi: ABI,
    script: []const u8,                // template hex
    asm_text: []const u8,
    state_fields: []StateField,
    constructor_slots: []ConstructorSlot,
    code_sep_index_slots: []CodeSepIndexSlot,
    build_timestamp: []const u8,
    code_separator_index: ?i32,
    code_separator_indices: []i32,
    anf_json: ?[]const u8,             // raw ANF IR JSON

    pub fn isStateful(self: *const RunarArtifact) bool;
    pub fn deinit(self: *RunarArtifact) void;
    pub fn fromJson(allocator: std.mem.Allocator, json_text: []const u8) !RunarArtifact;
};

pub const ABI = struct {
    constructor: ABIConstructor,
    methods: []ABIMethod,

    pub fn deinit(self: *ABI, allocator: std.mem.Allocator) void;
    pub fn fromJsonValue(allocator: std.mem.Allocator, obj: std.json.ObjectMap) !ABI;
};

pub const ABIMethod = struct {
    name: []const u8,
    params: []ABIParam,
    is_public: bool,
    is_terminal: ?bool,

    pub fn deinit(self: *ABIMethod, allocator: std.mem.Allocator) void;
};

pub const ABIParam = struct {
    name: []const u8,
    type_name: []const u8,
};

pub const StateField = struct {
    name: []const u8,
    type_name: []const u8,
    index: i32,
    initial_value: ?[]const u8,
    fixed_array: ?FixedArrayInfo,
};

pub const ConstructorSlot = struct {
    param_index: i32,
    byte_offset: i32,
};
```

[src/sdk_types.zig](src/sdk_types.zig).

### 15.3 RunarContract

```zig
pub const ContractError = error{
    NotDeployed,
    MethodNotFound,
    ArgCountMismatch,
    NoProviderOrSigner,
    DeployFailed,
    CallFailed,
    OutOfMemory,
    InsufficientFunds,
};

pub const RunarContract = struct {
    allocator: std.mem.Allocator,
    artifact: *RunarArtifact,
    constructor_args: []StateValue,
    state: []StateValue,
    code_script: ?[]u8,
    inscription: ?Inscription,
    current_utxo: ?UTXO,
    provider: ?Provider,
    signer: ?Signer,

    pub fn init(
        allocator: std.mem.Allocator,
        artifact: *RunarArtifact,
        constructor_args: []const StateValue,
    ) !RunarContract;
    pub fn deinit(self: *RunarContract) void;

    pub fn connect(self: *RunarContract, provider: Provider, signer: Signer) void;

    pub fn deploy(
        self: *RunarContract,
        provider: ?Provider,
        signer: ?Signer,
        options: DeployOptions,
    ) ContractError![]u8;

    pub fn call(
        self: *RunarContract,
        method_name: []const u8,
        args: []const StateValue,
        provider: ?Provider,
        signer: ?Signer,
        options: ?CallOptions,
    ) ContractError![]u8;

    pub fn fromUtxo(
        allocator: std.mem.Allocator,
        artifact: *RunarArtifact,
        utxo: UTXO,
    ) !RunarContract;

    pub fn withInscription(self: *RunarContract, insc: Inscription) !void;
    pub fn getInscription(self: *const RunarContract) ?Inscription;

    pub fn getLockingScript(self: *const RunarContract) ![]u8;
    pub fn getCodePartHex(self: *const RunarContract) ![]u8;
    pub fn getCodeSepIndex(self: *const RunarContract, method_index: usize) !?i32;
    pub fn adjustCodeSepOffset(self: *const RunarContract, base_offset: i32) !i32;
    pub fn buildUnlockingScript(
        self: *const RunarContract,
        method_name: []const u8,
        args: []const StateValue,
    ) ![]u8;

    pub fn getState(self: *const RunarContract) ![]StateValue;
    pub fn setState(self: *RunarContract, new_state: []const StateValue) !void;
    pub fn getCurrentUtxo(self: *const RunarContract) ?UTXO;
    pub fn setCurrentUtxo(self: *RunarContract, utxo: ?UTXO) !void;
};

pub fn insertUnlockingScript(
    allocator: std.mem.Allocator,
    tx_hex: []const u8,
    input_index: usize,
    unlock_script_hex: []const u8,
) ![]u8;
```

[src/sdk_contract.zig](src/sdk_contract.zig).

### 15.4 Provider

```zig
pub const ProviderError = error{
    NotFound,
    BroadcastFailed,
    NetworkError,
    OutOfMemory,
};

pub const Provider = struct {
    ptr: *anyopaque,
    vtable: *const VTable,

    pub const VTable = struct {
        getTransaction: *const fn (
            ctx: *anyopaque,
            allocator: std.mem.Allocator,
            txid: []const u8,
        ) ProviderError!TransactionData,
        broadcast: *const fn (
            ctx: *anyopaque,
            allocator: std.mem.Allocator,
            tx_hex: []const u8,
        ) ProviderError![]u8,
        getUtxos: *const fn (
            ctx: *anyopaque,
            allocator: std.mem.Allocator,
            address: []const u8,
        ) ProviderError![]UTXO,
        getContractUtxo: *const fn (
            ctx: *anyopaque,
            allocator: std.mem.Allocator,
            script_hash: []const u8,
        ) ProviderError!?UTXO,
        getNetwork: *const fn (ctx: *anyopaque) []const u8,
        getFeeRate: *const fn (ctx: *anyopaque) ProviderError!i64,
        getRawTransaction: *const fn (
            ctx: *anyopaque,
            allocator: std.mem.Allocator,
            txid: []const u8,
        ) ProviderError![]u8,
    };

    // Convenience methods that forward through the vtable:
    pub fn getTransaction(self: Provider, allocator: std.mem.Allocator, txid: []const u8) ProviderError!TransactionData;
    pub fn broadcast(self: Provider, allocator: std.mem.Allocator, tx_hex: []const u8) ProviderError![]u8;
    pub fn getUtxos(self: Provider, allocator: std.mem.Allocator, address: []const u8) ProviderError![]UTXO;
    pub fn getContractUtxo(self: Provider, allocator: std.mem.Allocator, script_hash: []const u8) ProviderError!?UTXO;
    pub fn getNetwork(self: Provider) []const u8;
    pub fn getFeeRate(self: Provider) ProviderError!i64;
    pub fn getRawTransaction(self: Provider, allocator: std.mem.Allocator, txid: []const u8) ProviderError![]u8;
};

pub const MockProvider = struct {
    allocator: std.mem.Allocator,
    network: []const u8,
    fee_rate: i64,
    broadcast_count: u32,

    pub fn init(allocator: std.mem.Allocator, network: []const u8) MockProvider;
    pub fn deinit(self: *MockProvider) void;
    pub fn addUtxo(self: *MockProvider, address: []const u8, utxo: UTXO) !void;
    pub fn addRawTransaction(self: *MockProvider, txid: []const u8, raw_hex: []const u8) !void;
    pub fn getBroadcastedTxs(self: *const MockProvider) []const []const u8;
    pub fn provider(self: *MockProvider) Provider;
};

pub const RPCProvider = struct {
    pub fn init(allocator: std.mem.Allocator, url: []const u8, user: []const u8, pass: []const u8) RPCProvider;
    pub fn initRegtest(allocator: std.mem.Allocator, url: []const u8, user: []const u8, pass: []const u8) RPCProvider;
    pub fn setTransport(self: *RPCProvider, transport: RPCHttpTransport) void;
    pub fn buildRequestBody(self: *RPCProvider, allocator: std.mem.Allocator, method: []const u8, params_json: []const u8) RPCError![]u8;
    pub fn rpcCall(self: *RPCProvider, allocator: std.mem.Allocator, method: []const u8, params_json: []const u8) RPCError![]u8;
    pub fn broadcast(self: *RPCProvider, allocator: std.mem.Allocator, tx_hex: []const u8) RPCError![]u8;
    pub fn deinit(_: *RPCProvider) void;
};

pub const RPCError = error{ TransportError, ProtocolError, RPCError, OutOfMemory, InvalidResponse };

pub const WhatsOnChainProvider = struct {
    pub const Network = enum { mainnet, testnet };
    pub fn init(allocator: std.mem.Allocator, network: Network) WhatsOnChainProvider;
    pub fn deinit(self: *WhatsOnChainProvider) void;
    pub fn setTransport(self: *WhatsOnChainProvider, transport: WhatsOnChainHttpTransport) void;
    pub fn provider(self: *WhatsOnChainProvider) Provider;
};

pub const GorillaPoolProvider = struct {
    pub const Network = enum { mainnet, testnet };
    pub fn init(allocator: std.mem.Allocator, network: Network) GorillaPoolProvider;
    pub fn deinit(self: *GorillaPoolProvider) void;
    pub fn setTransport(self: *GorillaPoolProvider, transport: GorillaPoolHttpTransport) void;
    pub fn provider(self: *GorillaPoolProvider) Provider;
};
```

Per-provider HTTP transport structs are exposed from `root.zig` as
`WhatsOnChainHttpTransport`, `GorillaPoolHttpTransport`, and
`RPCHttpTransport`.

### 15.5 Signer

```zig
pub const SignerError = error{
    InvalidKey,
    SigningFailed,
    OutOfMemory,
    InvalidEncoding,
    InvalidLength,
    InvalidTransaction,
};

pub const Signer = struct {
    ptr: *anyopaque,
    vtable: *const VTable,

    pub const VTable = struct {
        getPublicKey: *const fn (ctx: *anyopaque, allocator: std.mem.Allocator) SignerError![]u8,
        getAddress: *const fn (ctx: *anyopaque, allocator: std.mem.Allocator) SignerError![]u8,
        sign: *const fn (
            ctx: *anyopaque,
            allocator: std.mem.Allocator,
            tx_hex: []const u8,
            input_index: usize,
            subscript_hex: []const u8,
            satoshis: i64,
            sighash_type: ?u32,
        ) SignerError![]u8,
    };

    pub fn getPublicKey(self: Signer, allocator: std.mem.Allocator) SignerError![]u8;
    pub fn getAddress(self: Signer, allocator: std.mem.Allocator) SignerError![]u8;
    pub fn sign(self: Signer, allocator: std.mem.Allocator, tx_hex: []const u8, input_index: usize, subscript_hex: []const u8, satoshis: i64, sighash_type: ?u32) SignerError![]u8;
};

pub const LocalSigner = struct {
    private_key: bsvz.crypto.PrivateKey,
    network: bsvz.primitives.network.Network,

    pub fn fromBytes(key_bytes: [32]u8) !LocalSigner;
    pub fn fromHex(hex_key: []const u8) !LocalSigner;
    pub fn signer(self: *LocalSigner) Signer;
};

pub const MockSigner = struct {
    pub_key: []const u8,
    address: []const u8,

    pub fn init(pub_key_hex: ?[]const u8, address: ?[]const u8) MockSigner;
    pub fn signer(self: *MockSigner) Signer;
};

pub const ExternalSigner = struct {
    pub_key: []const u8,
    address: []const u8,
    sign_fn: *const fn (
        allocator: std.mem.Allocator,
        tx_hex: []const u8,
        input_index: usize,
        subscript: []const u8,
        satoshis: i64,
        sighash_type: ?u32,
    ) SignerError![]u8,

    pub fn signer(self: *ExternalSigner) Signer;
};
```

[src/sdk_signer.zig](src/sdk_signer.zig).

### 15.6 BRC-100 wallet

```zig
pub const WalletError = error{
    WalletUnavailable,
    ActionFailed,
    SigningFailed,
    KeyDerivationFailed,
    InsufficientFunds,
    OutOfMemory,
    InvalidOutpoint,
};

pub const ProtocolID = struct {
    level: u8,
    name: []const u8,
};

pub const WalletActionOutput = struct {
    locking_script: []const u8,
    satoshis: i64,
    description: []const u8,
    basket: []const u8,
    tags: []const []const u8,
};

pub const WalletActionResult = struct {
    txid: []const u8,
    tx_hex: []const u8,
    pub fn deinit(self: *WalletActionResult, allocator: std.mem.Allocator) void;
};

pub const WalletOutput = struct {
    outpoint: []const u8,        // "txid.vout"
    satoshis: i64,
    locking_script: []const u8,
    spendable: bool,

    pub fn clone(self: WalletOutput, allocator: std.mem.Allocator) !WalletOutput;
    pub fn deinit(self: *WalletOutput, allocator: std.mem.Allocator) void;
};

pub const WalletClient = struct {
    ptr: *anyopaque,
    vtable: *const VTable,
    pub const VTable = struct {
        getPublicKey: *const fn (ctx: *anyopaque, allocator: std.mem.Allocator, protocol_id: ProtocolID, key_id: []const u8) WalletError![]u8,
        createSignature: *const fn (ctx: *anyopaque, allocator: std.mem.Allocator, hash: []const u8, protocol_id: ProtocolID, key_id: []const u8) WalletError![]u8,
        createAction: *const fn (ctx: *anyopaque, allocator: std.mem.Allocator, description: []const u8, outputs: []const WalletActionOutput) WalletError!WalletActionResult,
        listOutputs: *const fn (ctx: *anyopaque, allocator: std.mem.Allocator, basket: []const u8, tags: []const []const u8, limit: usize) WalletError![]WalletOutput,
    };
    // forwarding methods elided
};

pub const MockWalletClient = struct {
    pub fn init(allocator: std.mem.Allocator) MockWalletClient;
    pub fn deinit(self: *MockWalletClient) void;
    pub fn addOutput(self: *MockWalletClient, output: WalletOutput) !void;
    pub fn walletClient(self: *MockWalletClient) WalletClient;
};

pub const WalletProvider = struct {
    pub fn init(
        allocator: std.mem.Allocator,
        wallet: WalletClient,
        basket: []const u8,
        options: struct {
            funding_tag: ?[]const u8 = null,
            network: ?[]const u8 = null,
            fee_rate: ?i64 = null,
        },
    ) WalletProvider;
    pub fn deinit(self: *WalletProvider) void;
    pub fn setExpectedScript(self: *WalletProvider, script_hex: []const u8) !void;
    pub fn provider(self: *WalletProvider) Provider;
};

pub const WalletSigner = struct {
    pub fn init(
        allocator: std.mem.Allocator,
        wallet: WalletClient,
        protocol_id: ProtocolID,
        key_id: []const u8,
    ) WalletSigner;
    pub fn deinit(self: *WalletSigner) void;
    pub fn signer(self: *WalletSigner) Signer;
};

pub fn deployWithWallet(
    contract: *RunarContract,
    wallet: WalletClient,
    options: struct {
        satoshis: i64,
        basket: []const u8,
        protocol_id: ProtocolID,
        key_id: []const u8,
        funding_tag: ?[]const u8 = null,
        network: ?[]const u8 = null,
        fee_rate: ?i64 = null,
    },
) ![]u8;
```

[src/sdk_wallet.zig](src/sdk_wallet.zig).

### 15.7 HTTP transports

```zig
pub const CurlHttpTransport = struct {
    pub fn init(allocator: std.mem.Allocator) !*CurlHttpTransport;
    pub fn deinit(self: *CurlHttpTransport) void;
    pub fn wocTransport(self: *CurlHttpTransport) WhatsOnChainHttpTransport;
    pub fn gorillaTransport(self: *CurlHttpTransport) GorillaPoolHttpTransport;
    pub fn rpcTransport(self: *CurlHttpTransport) RPCHttpTransport;
};

pub const StdHttpTransport = struct {
    pub fn init(allocator: std.mem.Allocator) !*StdHttpTransport;
    pub fn deinit(self: *StdHttpTransport) void;
    pub fn wocTransport(self: *StdHttpTransport) WhatsOnChainHttpTransport;
    pub fn gorillaTransport(self: *StdHttpTransport) GorillaPoolHttpTransport;
    pub fn rpcTransport(self: *StdHttpTransport) RPCHttpTransport;
};
```

`CurlHttpTransport` shells out to the system `curl` binary (most robust
TLS path on macOS today). `StdHttpTransport` uses
`std.http.Client` (pure Zig, requires a working
`std.crypto.Certificate.Bundle`).

[src/sdk_http_client.zig](src/sdk_http_client.zig).

### 15.8 OP_PUSH_TX

```zig
pub const OpPushTxError = error{
    InvalidKey,
    InvalidTransaction,
    SigningFailed,
    InvalidEncoding,
    OutOfMemory,
};

pub const OpPushTxResult = struct {
    sig_hex: []u8,        // DER + sighash byte
    preimage_hex: []u8,
    pub fn deinit(self: *OpPushTxResult, allocator: std.mem.Allocator) void;
};

pub fn computeOpPushTx(
    allocator: std.mem.Allocator,
    tx_hex: []const u8,
    input_index: usize,
    subscript_hex: []const u8,
    satoshis: i64,
    code_separator_index: i32,
) OpPushTxError!OpPushTxResult;

pub fn opPushTxPubKeyHex(allocator: std.mem.Allocator) ![]u8;
```

[src/sdk_oppushtx.zig](src/sdk_oppushtx.zig).

### 15.9 Deploy / call helpers

```zig
pub const DeployError = error{
    InsufficientFunds, NoUtxos, InvalidScript, OutOfMemory, BuildFailed,
};

pub const DeployResult = struct { tx_hex: []u8, input_count: usize, pub fn deinit(self: *DeployResult, allocator: std.mem.Allocator) void; };

pub fn buildDeployTransaction(
    allocator: std.mem.Allocator,
    locking_script_hex: []const u8,
    utxos: []const UTXO,
    satoshis: i64,
    change_address: ?[]const u8,
    fee_rate: i64,
) !DeployResult;

pub fn selectUtxos(
    allocator: std.mem.Allocator,
    utxos: []const UTXO,
    target_satoshis: i64,
    locking_script_byte_len: usize,
    fee_rate: i64,
) ![]UTXO;

pub fn buildP2PKHScript(allocator: std.mem.Allocator, address: []const u8) ![]u8;
pub fn estimateDeployFee(num_inputs: usize, locking_script_byte_len: usize, fee_rate: i64) i64;

pub fn buildCallTransaction(
    allocator: std.mem.Allocator,
    current_utxo: UTXO,
    unlocking_script_hex: []const u8,
    new_locking_script_hex: []const u8,
    new_satoshis: i64,
    change_address: ?[]const u8,
    additional_utxos: []const UTXO,
    fee_rate_in: i64,
    opts: ?*const CallBuildOptions,
) !CallResult;

pub fn estimateCallFee(...) i64;   // see src/sdk_call.zig
```

[src/sdk_deploy.zig](src/sdk_deploy.zig),
[src/sdk_call.zig](src/sdk_call.zig).

### 15.10 State serialization

```zig
pub fn serializeState(allocator: std.mem.Allocator, fields: []const StateField, values: []const StateValue) ![]u8;
pub fn deserializeState(allocator: std.mem.Allocator, fields: []const StateField, script_hex: []const u8) ![]StateValue;
pub fn extractStateFromScript(allocator: std.mem.Allocator, artifact: *const RunarArtifact, script_hex: []const u8) !?[]StateValue;
pub fn findLastOpReturn(script_hex: []const u8) ?usize;

pub fn encodePushData(allocator: std.mem.Allocator, data_hex: []const u8) ![]u8;
pub fn encodeScriptNumber(allocator: std.mem.Allocator, n: i64) ![]u8;
pub fn encodeBigScriptNumber(allocator: std.mem.Allocator, decimal_str: []const u8) ![]u8;
pub fn encodeScriptInt(allocator: std.mem.Allocator, n: i64) ![]u8;
pub fn encodeArg(allocator: std.mem.Allocator, value: StateValue) ![]u8;

pub fn decodePushData(hex: []const u8, offset: usize) PushDataResult;
pub fn decodeNum2Bin(hex: []const u8) i64;

pub fn encodeNum2Bin(allocator: std.mem.Allocator, n: i64, width: usize) ![]u8;
pub fn encodeBigNum2Bin(allocator: std.mem.Allocator, decimal_str: []const u8, width: usize) ![]u8;

pub fn flattenStateValue(allocator: std.mem.Allocator, out: *std.ArrayListUnmanaged(StateValue), value: StateValue) !void;
pub fn regroupStateValues(allocator: std.mem.Allocator, flat: []const StateValue, shape: []const u32) !StateValue;

pub fn bytesToHex(allocator: std.mem.Allocator, bytes: []const u8) ![]u8;
pub fn hexToBytes(allocator: std.mem.Allocator, hex: []const u8) ![]u8;
```

[src/sdk_state.zig](src/sdk_state.zig).

### 15.11 ANF interpreter

```zig
pub const InterpreterError = error{ MethodNotFound, OutOfMemory };

pub const ANFProgram = struct { /* ... */ };
pub const ANFProperty = struct { /* ... */ };
pub const ANFMethod = struct { /* ... */ };
pub const ANFParam = struct { /* ... */ };
pub const ANFBinding = struct { /* ... */ };
pub const ANFValue = union(enum) { int: i64, boolean: bool, bytes: []const u8, none: void };
pub const ANFNode = union(enum) { /* see src/sdk_anf_interpreter.zig */ };

pub const DataOutputEntry = struct { satoshis: i64, script: []u8 };
pub const NewStateResult = struct {
    state: std.StringHashMap(ANFValue),
    data_outputs: []DataOutputEntry,
};

pub fn parseANFFromJson(allocator: std.mem.Allocator, json_text: []const u8) !ANFProgram;
pub fn computeNewState(allocator: std.mem.Allocator, anf: *const ANFProgram, method_name: []const u8, current_state: std.StringHashMap(ANFValue), args: std.StringHashMap(ANFValue), constructor_args: []const ANFValue) !std.StringHashMap(ANFValue);
pub fn computeNewStateAndDataOutputs(allocator: std.mem.Allocator, anf: *const ANFProgram, method_name: []const u8, current_state: std.StringHashMap(ANFValue), args: std.StringHashMap(ANFValue), constructor_args: []const ANFValue) !NewStateResult;
```

These are exposed under `runar.sdk_anf_interpreter` (re-exported as
`sdk_anf_interpreter` from `root.zig`). Most users do not call them
directly — `RunarContract.call` runs the interpreter automatically when
the artifact ships ANF JSON.

[src/sdk_anf_interpreter.zig](src/sdk_anf_interpreter.zig).

### 15.12 Inscriptions + ordinals

```zig
pub const Inscription = struct {
    content_type: []const u8,
    data: []const u8,             // hex-encoded
    pub fn clone(self: Inscription, allocator: std.mem.Allocator) !Inscription;
    pub fn deinit(self: *Inscription, allocator: std.mem.Allocator) void;
};

pub const EnvelopeBounds = struct { start_hex: usize, end_hex: usize };

pub fn buildInscriptionEnvelope(allocator: std.mem.Allocator, content_type: []const u8, data: []const u8) ![]u8;
pub fn parseInscriptionEnvelope(allocator: std.mem.Allocator, script_hex: []const u8) !?Inscription;
pub fn findInscriptionEnvelope(script_hex: []const u8) ?EnvelopeBounds;
pub fn stripInscriptionEnvelope(allocator: std.mem.Allocator, script_hex: []const u8) ![]u8;

pub fn bsv20Deploy(allocator: std.mem.Allocator, tick: []const u8, max: []const u8, lim: ?[]const u8, dec: ?[]const u8) !Inscription;
pub fn bsv20Mint(allocator: std.mem.Allocator, tick: []const u8, amt: []const u8) !Inscription;
pub fn bsv20Transfer(allocator: std.mem.Allocator, tick: []const u8, amt: []const u8) !Inscription;
pub fn bsv21DeployMint(allocator: std.mem.Allocator, amt: []const u8, dec: ?[]const u8, sym: ?[]const u8, icon: ?[]const u8) !Inscription;
pub fn bsv21Transfer(allocator: std.mem.Allocator, id: []const u8, amt: []const u8) !Inscription;
```

[src/sdk_ordinals.zig](src/sdk_ordinals.zig).

### 15.13 TokenWallet

```zig
pub const TokenWalletError = error{
    NoUtxos, ProviderError, SignerError, OutOfMemory, InsufficientBalance,
};

pub const TokenWallet = struct {
    pub fn init(
        allocator: std.mem.Allocator,
        artifact: *const RunarArtifact,
        provider: Provider,
        signer: Signer,
    ) TokenWallet;
    pub fn getUtxos(self: *TokenWallet, allocator: std.mem.Allocator) TokenWalletError![]UTXO;
    pub fn pickCandidate(candidates: []const UTXO) TokenWalletError!UTXO;
};
```

[src/sdk_token_wallet.zig](src/sdk_token_wallet.zig).

### 15.14 Codegen

```zig
pub fn generateZig(allocator: std.mem.Allocator, artifact: *const RunarArtifact) ![]u8;
```

[src/sdk_codegen.zig](src/sdk_codegen.zig).

### 15.15 Contract author runtime

```zig
// Type aliases
pub const Int = i64;
pub const Bigint = i64;
pub const PubKey = []const u8;
pub const Sig = []const u8;
pub const Addr = []const u8;
pub const ByteString = []const u8;
pub const Sha256 = []const u8;
pub const Sha256Digest = Sha256;
pub const Ripemd160 = []const u8;
pub const SigHashPreimage = []const u8;
pub const RabinSig = []const u8;
pub const RabinPubKey = []const u8;
pub const Point = []const u8;

pub fn Readonly(comptime T: type) type;

// Base classes
pub const SmartContract = struct {};
pub const StatefulSmartContract = struct { /* ... */ };
pub const StatefulContext = struct { /* ... */ };
pub const StatefulSmartContractError = error{ UnsupportedOutputValue };

// Test fixtures
pub const TestKeyPair = struct { name, privKey, pubKey, pubKeyHash };
pub const ALICE: TestKeyPair;
pub const BOB: TestKeyPair;
pub const CHARLIE: TestKeyPair;

// Helpers
pub const SignedBigint = builtins.SignedBigint;
pub fn bigint(value: anytype) SignedBigint;       // alias for SignedBigint.from
pub fn assert(condition: bool) void;
pub const assertFailureMessage: []const u8;
```

### 15.16 Built-in crypto and math

The `runar` module re-exports about 70 contract built-ins. These are
the **ONLY** functions that may be called inside a contract method —
the typecheck pass rejects calls to anything else. Listed by category;
detailed signatures live in [src/builtins.zig](src/builtins.zig).

**Hashing.** `sha256`, `ripemd160`, `hash160`, `hash256`,
`sha256Compress`, `sha256Finalize`, `blake3Compress`, `blake3Hash`.

**Bytes.** `bytesEq`, `bytesConcat`, `cat`, `substr`, `num2bin`,
`bin2num`, `hexToBytes`.

**Math.** `clamp`, `safediv`, `safemod`, `sign`, `pow`, `mulDiv`,
`percentOf`, `sqrt`, `gcd`, `log2`.

**Signature verification.** `checkSig`, `checkMultiSig`,
`checkPreimage`, `verifyRabinSig`, `verifyWOTS`,
`verifySLHDSA_SHA2_128s`, `verifySLHDSA_SHA2_128f`,
`verifySLHDSA_SHA2_192s`, `verifySLHDSA_SHA2_192f`,
`verifySLHDSA_SHA2_256s`, `verifySLHDSA_SHA2_256f`.

**EC (secp256k1).** `ecAdd`, `ecMul`, `ecMulGen`, `ecNegate`,
`ecOnCurve`, `ecModReduce`, `ecEncodeCompressed`, `ecMakePoint`,
`ecPointX`, `ecPointY`.

**Baby Bear field arithmetic.** `bbFieldAdd`, `bbFieldSub`, `bbFieldMul`,
`bbFieldInv`, `bbExt4Mul0..3`, `bbExt4Inv0..3`.

**Merkle.** `merkleRootSha256`, `merkleRootHash256`.

**Preimage helpers.** `mockPreimage`, `mockPreimageChecked`,
`extractHashPrevouts`, `extractOutpoint`, `extractOutputHash`,
`extractLocktime`, `buildChangeOutput`, `buildChangeOutputChecked`.

**Test helpers.** `signTestMessage`, `signTestMessageChecked` (real
ECDSA against the project test message digest, used by
`checkSig` in unit tests against `ALICE`/`BOB`/`CHARLIE`).

### 15.17 Common types

```zig
pub const UTXO = struct { txid, output_index, satoshis, script;  clone, deinit };
pub const TransactionData = struct { txid, version, inputs, outputs, locktime, raw;  deinit };
pub const TxInput = struct { txid, output_index, script, sequence };
pub const TxOutput = struct { satoshis, script };
pub const DeployOptions = struct { satoshis, change_address };
pub const CallOptions = struct { satoshis, change_address, new_state, data_outputs };
pub const ContractOutput = struct { script, satoshis };
pub const StateValue = union(enum) { int, big_int, boolean, bytes, array_value;  clone, deinit };
```

[src/sdk_types.zig](src/sdk_types.zig).

---

## 16. Error handling

The Zig SDK uses **typed error sets per subsystem**. Each error set is
narrow enough that `try` propagation forces callers to handle real
failure modes without a catch-all.

| Error set | Source | Variants |
|-----------|--------|----------|
| `ProviderError` | [src/sdk_provider.zig](src/sdk_provider.zig) | `NotFound`, `BroadcastFailed`, `NetworkError`, `OutOfMemory` |
| `SignerError` | [src/sdk_signer.zig](src/sdk_signer.zig) | `InvalidKey`, `SigningFailed`, `OutOfMemory`, `InvalidEncoding`, `InvalidLength`, `InvalidTransaction` |
| `ContractError` | [src/sdk_contract.zig](src/sdk_contract.zig) | `NotDeployed`, `MethodNotFound`, `ArgCountMismatch`, `NoProviderOrSigner`, `DeployFailed`, `CallFailed`, `OutOfMemory`, `InsufficientFunds` |
| `OpPushTxError` | [src/sdk_oppushtx.zig](src/sdk_oppushtx.zig) | `InvalidKey`, `InvalidTransaction`, `SigningFailed`, `InvalidEncoding`, `OutOfMemory` |
| `WalletError` | [src/sdk_wallet.zig](src/sdk_wallet.zig) | `WalletUnavailable`, `ActionFailed`, `SigningFailed`, `KeyDerivationFailed`, `InsufficientFunds`, `OutOfMemory`, `InvalidOutpoint` |
| `DeployError` | [src/sdk_deploy.zig](src/sdk_deploy.zig) | `InsufficientFunds`, `NoUtxos`, `InvalidScript`, `OutOfMemory`, `BuildFailed` |
| `RPCError` | [src/sdk_rpc_provider.zig](src/sdk_rpc_provider.zig) | `TransportError`, `ProtocolError`, `RPCError`, `OutOfMemory`, `InvalidResponse` |
| `InterpreterError` | [src/sdk_anf_interpreter.zig](src/sdk_anf_interpreter.zig) | `MethodNotFound`, `OutOfMemory` |
| `TokenWalletError` | [src/sdk_token_wallet.zig](src/sdk_token_wallet.zig) | `NoUtxos`, `ProviderError`, `SignerError`, `OutOfMemory`, `InsufficientBalance` |

`RunarContract.call` and `.deploy` collapse provider/signer/build
failures into the broader `ContractError` variants (`DeployFailed`,
`CallFailed`, `InsufficientFunds`, ...) so callers can switch on a small
shape:

```zig
const txid = contract.call("increment", &.{}, prov, signer, null) catch |err| switch (err) {
    error.NotDeployed => return runFirstDeploy(),
    error.InsufficientFunds => return promptForFunding(),
    error.CallFailed => return logAndExit(err),
    else => return err,
};
```

When you need finer detail (which provider call failed, what RPC
error was returned), build the call manually with
`buildCallTransaction` + `computeOpPushTx` + `provider.broadcast` and
pattern-match on the underlying error set.

---

## 17. Troubleshooting / FAQ

**`error.ContractError.NoProviderOrSigner`.** A `deploy` / `call` was
made without a provider or signer in either the function arguments or
on the contract via `connect()`. Either pass them explicitly or call
`contract.connect(provider, signer)` once after `init`.

**`error.ContractError.NotDeployed`.** `call` was invoked before `deploy`
or after a stateless call consumed the UTXO. For a fresh deploy, call
`.deploy` first; for a contract that's already on-chain, reconstruct it
with `RunarContract.fromUtxo(allocator, &artifact, utxo)`.

**`error.ContractError.ArgCountMismatch`.** The user-arg count didn't
match the public method's signature minus the auto-injected stateful
parameters (`SigHashPreimage`, `_changePKH`, `_changeAmount`,
`_newAmount`). Inspect `artifact.abi.methods[i].params` — the SDK
expects you to pass values for every param whose `name` is not one of
the four reserved names and whose `type_name` is not `SigHashPreimage`.

**`error.ContractError.InsufficientFunds`.** The signer's address has
no funding UTXOs or not enough satoshis to cover `options.satoshis`
plus the estimated fee. Add UTXOs via `MockProvider.addUtxo`, fund the
real address on regtest, or lower `options.satoshis`.

**`error.ProviderError.NetworkError` from `WhatsOnChainProvider` /
`GorillaPoolProvider` / `RPCProvider`.** No `HttpTransport` was
injected, or the underlying request failed. Initialise a transport
(`CurlHttpTransport` for curl, `StdHttpTransport` for `std.http.Client`)
and call `provider.setTransport(transport.wocTransport())` before any
network-touching method.

**`error.SignerError.InvalidTransaction` from `LocalSigner.sign`.** The
`tx_hex` failed to parse. Confirm the bytes round-trip through `bsvz`'s
`Transaction.parse` — typically the cause is a mismatch between the
varint input/output count headers and the actual element counts.

**Stateful call broadcasts but on-chain validation fails.** Almost
always one of: (1) the artifact's `state_fields` order doesn't match the
runtime contract — re-run the compiler; (2) you supplied
`options.new_state` whose hash doesn't match what the contract method
would compute; (3) the contract uses `addDataOutput` and the SDK's
auto-resolution didn't fire because the artifact was built without ANF
JSON. The wrong-state and underflow tests in
[integration/zig/src/counter_test.zig](../../integration/zig/src/counter_test.zig)
exercise the rejection path explicitly.

**`compileCheckSource` reports `validate` errors.** Common causes: a
property is not assigned in `init`; a non-Rúnar function (e.g.
`std.debug.print`) was called inside a method body; a public method
parameter type isn't a Rúnar primitive. The `messages` slice on the
result names the precise failing property or call.

**`std.testing.environ` undefined when importing the SDK.** The Zig SDK
test runner ([src/test_runner.zig](src/test_runner.zig)) initializes
`std.testing.environ` for you. If you're hosting tests in your own
build, copy that test runner into your project — without it,
`liveHttpEnabled()`-style env-var checks will trap at runtime under Zig
0.16.

**`HttpTransport` fails on macOS with `error.NetworkError`.**
`CurlHttpTransport` shells out to the system `curl` binary, which is
present on all macOS installs. `StdHttpTransport` requires a working
`std.crypto.Certificate.Bundle` — on some macOS versions the system
cert store is harder to enumerate from Zig 0.16. When in doubt, use
`CurlHttpTransport`.

---

## 18. Versioning and stability

This SDK is at **v0.4.4** (see [build.zig.zon](build.zig.zon)). Status
of the surface area:

| Surface | Status |
|---------|--------|
| `RunarContract.init` / `.deploy` / `.call` / `.fromUtxo` / `.connect` | **stable** — the on-chain semantics are pinned by the cross-SDK conformance suite |
| `Provider` / `Signer` / `WalletClient` vtables | **stable** — adding methods is a breaking change |
| `MockProvider`, `MockSigner`, `MockWalletClient` | **stable** for tests |
| `WhatsOnChainProvider`, `GorillaPoolProvider`, `RPCProvider`, `WalletProvider` | **stable** API; HTTP transport plumbing may evolve as `std.http.Client` matures |
| `RunarArtifact.fromJson` | **stable** — the JSON schema is shared across all seven SDKs |
| Built-in math / EC / Baby Bear / SLH-DSA / WOTS / Rabin / Blake3 | **stable** for the subset compiled today; new built-ins land additively |
| `prepareCall` / `finalizeCall` (multi-signer) | **not yet shipped** — see Section 9b |
| `RunarContract.fromTxId` convenience | **not shipped** — `fromUtxo` works today |
| `generateZig` typed bindings | **stable** but minimal — wrapper today is name-only |
| `sdk_anf_interpreter.*` low-level API | **public but not pinned** — schema may evolve with the IR |
| `ContractSimulator` (Java SDK feature) | not applicable to Zig — use the off-chain unit-test path in Section 13 instead |

Cross-SDK byte-identity is verified by
[conformance/sdk-output/](../../conformance/sdk-output/) for every
release. Any change that breaks byte-identity is an SDK bug, not an
intentional update.

Zig itself is pre-1.0 and `std` rearranges across releases. This SDK
targets Zig 0.16 and is updated promptly when the language ships
breaking changes; track the project for the supported version when
upgrading.

---

## 19. Links

- Rúnar repository — <https://github.com/icellan/runar>
- Cross-SDK parity matrix — [`RUNAR-SDK-PARITY.md`](../../RUNAR-SDK-PARITY.md)
- Cross-SDK conformance fixtures —
  [conformance/sdk-output/](../../conformance/sdk-output/)
- Sibling SDKs: `packages/runar-sdk` (TypeScript),
  `packages/runar-go`, `packages/runar-rs`, `packages/runar-py`,
  `packages/runar-rb`, `packages/runar-java`
- Zig compiler: `compilers/zig/`
- Zig contract examples: `examples/zig/`
- Zig integration tests: `integration/zig/`
- Counter contract (this README's running example):
  [examples/zig/stateful-counter/Counter.runar.zig](../../examples/zig/stateful-counter/Counter.runar.zig)
- `bsvz` (Bitcoin SV crypto and transaction primitives):
  <https://github.com/b-open-io/bsvz>
- BRC-100 wallet specification:
  <https://brc.dev/100>
- Issues and roadmap: <https://github.com/icellan/runar/issues>
