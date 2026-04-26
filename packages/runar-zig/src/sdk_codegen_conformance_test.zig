// Cross-SDK codegen conformance runner — Zig side.
//
// Asserts the typed wrapper this SDK generates contains every structural
// element required by `conformance/sdk-codegen/MANIFEST.md`. Sibling
// runners:
//   • packages/runar-java/src/test/java/runar/lang/sdk/codegen/CodegenConformanceTest.java
//   • packages/runar-rb/spec/sdk/codegen_conformance_spec.rb
//
// **Fixture sync invariant.** Zig refuses `@embedFile` outside the
// package boundary, and Zig 0.16's `std.fs.cwd()` API moved under
// `std.Io.Dir` requiring an `Io` parameter that test runners do not
// thread through. We work around this by inlining the JSON fixtures
// here as comptime string literals. **They MUST byte-equal the files
// at `conformance/sdk-codegen/fixtures/*.json` in the repo root** —
// CI's other SDK runners (Java, Ruby) read the canonical files, so any
// drift surfaces immediately.

const std = @import("std");
const types = @import("sdk_types.zig");
const codegen = @import("sdk_codegen.zig");

const P2PKH_JSON =
    \\{
    \\  "version": "runar-v0.1.0",
    \\  "compilerVersion": "0.1.0",
    \\  "contractName": "P2PKH",
    \\  "abi": {
    \\    "constructor": {
    \\      "params": [
    \\        { "name": "pubKeyHash", "type": "Addr" }
    \\      ]
    \\    },
    \\    "methods": [
    \\      {
    \\        "name": "unlock",
    \\        "params": [
    \\          { "name": "sig", "type": "Sig" },
    \\          { "name": "pubKey", "type": "PubKey" }
    \\        ],
    \\        "isPublic": true
    \\      }
    \\    ]
    \\  },
    \\  "script": "76a9007c7c9c69007c7cac",
    \\  "asm": "OP_DUP OP_HASH160 OP_0 OP_SWAP OP_SWAP OP_NUMEQUAL OP_VERIFY OP_0 OP_SWAP OP_SWAP OP_CHECKSIG",
    \\  "buildTimestamp": "2026-04-26T00:00:00Z",
    \\  "stateFields": [],
    \\  "constructorSlots": [{ "paramIndex": 0, "byteOffset": 3 }]
    \\}
;

const COUNTER_JSON =
    \\{
    \\  "version": "runar-v0.1.0",
    \\  "compilerVersion": "0.1.0",
    \\  "contractName": "Counter",
    \\  "abi": {
    \\    "constructor": {
    \\      "params": [
    \\        { "name": "count", "type": "bigint" }
    \\      ]
    \\    },
    \\    "methods": [
    \\      {
    \\        "name": "increment",
    \\        "params": [
    \\          { "name": "amount", "type": "bigint" },
    \\          { "name": "txPreimage", "type": "SigHashPreimage" },
    \\          { "name": "_changePKH", "type": "ByteString" },
    \\          { "name": "_changeAmount", "type": "bigint" }
    \\        ],
    \\        "isPublic": true,
    \\        "isTerminal": false
    \\      },
    \\      {
    \\        "name": "reset",
    \\        "params": [
    \\          { "name": "txPreimage", "type": "SigHashPreimage" }
    \\        ],
    \\        "isPublic": true,
    \\        "isTerminal": true
    \\      }
    \\    ]
    \\  },
    \\  "script": "76009c63",
    \\  "asm": "OP_DUP OP_0 OP_NUMEQUAL OP_IF",
    \\  "buildTimestamp": "2026-04-26T00:00:00Z",
    \\  "stateFields": [
    \\    { "name": "count", "type": "bigint", "index": 0 }
    \\  ],
    \\  "constructorSlots": [],
    \\  "codeSeparatorIndex": 4
    \\}
;

const SIMPLE_JSON =
    \\{
    \\  "version": "runar-v0.1.0",
    \\  "compilerVersion": "0.1.0",
    \\  "contractName": "Simple",
    \\  "abi": {
    \\    "constructor": { "params": [] },
    \\    "methods": [
    \\      {
    \\        "name": "execute",
    \\        "params": [],
    \\        "isPublic": true
    \\      }
    \\    ]
    \\  },
    \\  "script": "00",
    \\  "asm": "OP_0",
    \\  "buildTimestamp": "2026-04-26T00:00:00Z",
    \\  "stateFields": [],
    \\  "constructorSlots": []
    \\}
;

const STATEFUL_ESCROW_JSON =
    \\{
    \\  "version": "runar-v0.1.0",
    \\  "compilerVersion": "0.1.0",
    \\  "contractName": "Escrow",
    \\  "abi": {
    \\    "constructor": {
    \\      "params": [
    \\        { "name": "buyer", "type": "PubKey" },
    \\        { "name": "seller", "type": "PubKey" },
    \\        { "name": "amount", "type": "bigint" }
    \\      ]
    \\    },
    \\    "methods": [
    \\      {
    \\        "name": "claim",
    \\        "params": [
    \\          { "name": "amountToClaim", "type": "bigint" },
    \\          { "name": "buyerSig", "type": "Sig" },
    \\          { "name": "txPreimage", "type": "SigHashPreimage" },
    \\          { "name": "_changePKH", "type": "ByteString" },
    \\          { "name": "_changeAmount", "type": "bigint" }
    \\        ],
    \\        "isPublic": true,
    \\        "isTerminal": false
    \\      },
    \\      {
    \\        "name": "release",
    \\        "params": [
    \\          { "name": "buyerSig", "type": "Sig" },
    \\          { "name": "sellerSig", "type": "Sig" },
    \\          { "name": "txPreimage", "type": "SigHashPreimage" }
    \\        ],
    \\        "isPublic": true,
    \\        "isTerminal": true
    \\      }
    \\    ]
    \\  },
    \\  "script": "76a9007c7c9c697c7cac",
    \\  "asm": "OP_DUP OP_HASH160 OP_0 OP_SWAP OP_SWAP OP_NUMEQUAL OP_VERIFY OP_SWAP OP_SWAP OP_CHECKSIG",
    \\  "buildTimestamp": "2026-04-26T00:00:00Z",
    \\  "stateFields": [
    \\    { "name": "amount", "type": "bigint", "index": 2 }
    \\  ],
    \\  "constructorSlots": [],
    \\  "codeSeparatorIndex": 4
    \\}
;

const INSCRIBED_JSON =
    \\{
    \\  "version": "runar-v0.1.0",
    \\  "compilerVersion": "0.1.0",
    \\  "contractName": "InscribedHolder",
    \\  "abi": {
    \\    "constructor": {
    \\      "params": [
    \\        { "name": "owner", "type": "Addr" }
    \\      ]
    \\    },
    \\    "methods": [
    \\      {
    \\        "name": "transfer",
    \\        "params": [
    \\          { "name": "sig", "type": "Sig" },
    \\          { "name": "pubKey", "type": "PubKey" },
    \\          { "name": "newOwner", "type": "Addr" }
    \\        ],
    \\        "isPublic": true
    \\      }
    \\    ]
    \\  },
    \\  "script": "76a9007c7c9c69007c7cac",
    \\  "asm": "OP_DUP OP_HASH160 OP_0 OP_SWAP OP_SWAP OP_NUMEQUAL OP_VERIFY OP_0 OP_SWAP OP_SWAP OP_CHECKSIG",
    \\  "buildTimestamp": "2026-04-26T00:00:00Z",
    \\  "stateFields": [],
    \\  "constructorSlots": [{ "paramIndex": 0, "byteOffset": 3 }]
    \\}
;

fn assertContains(haystack: []const u8, needle: []const u8) !void {
    if (std.mem.indexOf(u8, haystack, needle) == null) {
        std.debug.print("\nconformance: missing required element\n--- needle ---\n{s}\n--- got ---\n{s}\n", .{ needle, haystack });
        return error.ConformanceMismatch;
    }
}

fn assertNotContains(haystack: []const u8, needle: []const u8, why: []const u8) !void {
    if (std.mem.indexOf(u8, haystack, needle) != null) {
        std.debug.print("\nconformance: forbidden element present ({s})\n--- needle ---\n{s}\n--- got ---\n{s}\n",
            .{ why, needle, haystack });
        return error.ConformanceMismatch;
    }
}

test "conformance: p2pkh.json — stateless + Sig param" {
    const allocator = std.testing.allocator;
    var artifact = try types.RunarArtifact.fromJson(allocator, P2PKH_JSON);
    defer artifact.deinit();

    const src = try codegen.generateZig(allocator, &artifact);
    defer allocator.free(src);

    try assertContains(src, "pub const P2PKHConstructorArgs = struct");
    try assertContains(src, "pub const P2PKHContract = struct");
    try assertContains(src, "pub fn fromUtxo(");
    try assertContains(src, "pub fn fromTxId(");
    try assertContains(src, "pub fn connect(");
    try assertContains(src, "pub fn attachInscription(");
    try assertContains(src, "pub fn getLockingScript(");
    try assertContains(src, "pub fn deploy(");
    try assertContains(src, "pub fn unlock(");
    try assertContains(src, "pub fn prepareUnlock(");
    try assertContains(src, "pub fn finalizeUnlock(");
    try assertContains(src, "pub const TerminalOutput = struct");
    try assertNotContains(src, "StatefulCallOptions", "stateless contract must not emit options struct");
}

test "conformance: counter.json — stateful, mixed terminal/non-terminal" {
    const allocator = std.testing.allocator;
    var artifact = try types.RunarArtifact.fromJson(allocator, COUNTER_JSON);
    defer artifact.deinit();

    const src = try codegen.generateZig(allocator, &artifact);
    defer allocator.free(src);

    try assertContains(src, "pub const CounterConstructorArgs = struct");
    try assertContains(src, "count: i64");
    try assertContains(src, "pub const CounterStatefulCallOptions = struct");
    try assertContains(src, "satoshis: ?i64");
    try assertContains(src, "change_address: ?[]const u8");
    try assertContains(src, "change_pub_key: ?[]const u8");
    try assertContains(src, "new_state: ?[]const sdk.StateValue");
    try assertContains(src, "outputs: ?[]const OutputSpec");
    try assertContains(src, "pub const OutputSpec = struct");
    try assertContains(src, "pub const TerminalOutput = struct");
    try assertContains(src, "pub const CounterContract = struct");
    try assertContains(src, "pub fn increment(");
    try assertContains(src, "pub fn reset(");
    try assertContains(src, "pub fn count(self: *const CounterContract)");
}

test "conformance: simple.json — no constructor params" {
    const allocator = std.testing.allocator;
    var artifact = try types.RunarArtifact.fromJson(allocator, SIMPLE_JSON);
    defer artifact.deinit();

    const src = try codegen.generateZig(allocator, &artifact);
    defer allocator.free(src);

    try assertNotContains(src, "SimpleConstructorArgs", "no-args contract must not emit ConstructorArgs record");
    try assertContains(src, "pub const SimpleContract = struct");
    try assertContains(src, "pub fn execute(");
}

test "conformance: stateful-escrow.json — stateful + multi-Sig" {
    const allocator = std.testing.allocator;
    var artifact = try types.RunarArtifact.fromJson(allocator, STATEFUL_ESCROW_JSON);
    defer artifact.deinit();

    const src = try codegen.generateZig(allocator, &artifact);
    defer allocator.free(src);

    try assertContains(src, "pub const EscrowConstructorArgs = struct");
    try assertContains(src, "buyer: []const u8");
    try assertContains(src, "seller: []const u8");
    try assertContains(src, "amount: i64");
    try assertContains(src, "pub const EscrowStatefulCallOptions = struct");
    try assertContains(src, "pub const OutputSpec = struct");
    try assertContains(src, "pub const TerminalOutput = struct");
    try assertContains(src, "pub const EscrowContract = struct");
    // Non-terminal stateful with single Sig: claim
    try assertContains(src, "pub fn claim(");
    try assertContains(src, "pub fn prepareClaim(");
    try assertContains(src, "pub fn finalizeClaim(");
    try assertContains(src, "sig0: []const u8");
    // Terminal stateful with two Sigs: release
    try assertContains(src, "pub fn release(");
    try assertContains(src, "pub fn prepareRelease(");
    try assertContains(src, "pub fn finalizeRelease(");
    // sig0 and sig1 both present (multi-Sig finalize)
    try assertContains(src, "sig1: []const u8");
    // State accessor
    try assertContains(src, "pub fn amount(self: *const EscrowContract)");
}

test "conformance: inscribed.json — attachInscription path" {
    const allocator = std.testing.allocator;
    var artifact = try types.RunarArtifact.fromJson(allocator, INSCRIBED_JSON);
    defer artifact.deinit();

    const src = try codegen.generateZig(allocator, &artifact);
    defer allocator.free(src);

    try assertContains(src, "pub const InscribedHolderConstructorArgs = struct");
    try assertContains(src, "owner: []const u8");
    try assertContains(src, "pub const InscribedHolderContract = struct");
    try assertContains(src, "pub fn attachInscription(self: *InscribedHolderContract, insc: sdk.Inscription)");
    try assertContains(src, "try self.inner.withInscription(insc);");
    // Sig-bearing transfer + companions
    try assertContains(src, "pub fn transfer(");
    try assertContains(src, "pub fn prepareTransfer(");
    try assertContains(src, "pub fn finalizeTransfer(");
}
