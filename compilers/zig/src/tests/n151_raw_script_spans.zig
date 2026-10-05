//! N-151 — the artifact carries rawScriptSpans exactly as the TS reference
//! does. Port of the reference tier's cases in
//! packages/runar-compiler/src/__tests__/raw-script-spans.test.ts.
//!
//! The emitter always recorded one span per asm() raw-bytes op, but
//! emitArtifact never serialized them, so the analyzer and SDKs lost the span
//! metadata for every Zig-built raw-script contract.
//!
//! Proves: for the single-span, consecutive-span, non-default-arity and
//! multi-byte-body shapes the artifact JSON's rawScriptSpans array equals the
//! TS values (offset, length, inArity, outArity), and the key is omitted for a
//! contract with no asm(). Does NOT prove how an SDK or analyzer consumes the
//! spans; cross-tier value parity is
//! conformance/negatives/artifact-flag-parity.test.ts.

const std = @import("std");
const compiler_api = @import("../compiler_api.zig");

fn artifactOf(allocator: std.mem.Allocator, source: []const u8) ![]const u8 {
    const result = try compiler_api.compileSource(allocator, source, "WithAsm.runar.ts");
    allocator.free(result.script_hex);
    return result.artifact_json.?;
}

fn expectSpans(source: []const u8, expected: []const u8) !void {
    const allocator = std.testing.allocator;
    const json = try artifactOf(allocator, source);
    defer allocator.free(json);
    var parsed = try std.json.parseFromSlice(std.json.Value, allocator, json, .{});
    defer parsed.deinit();
    const spans = parsed.value.object.get("rawScriptSpans") orelse {
        std.debug.print("artifact has no rawScriptSpans key; want {s}\n", .{expected});
        return error.MissingRawScriptSpans;
    };
    var out: std.ArrayListUnmanaged(u8) = .empty;
    defer out.deinit(allocator);
    for (spans.array.items, 0..) |s, i| {
        if (i > 0) try out.append(allocator, ',');
        const line = try std.fmt.allocPrint(allocator, "{d}/{d}/{d}/{d}", .{
            s.object.get("offset").?.integer,
            s.object.get("length").?.integer,
            s.object.get("inArity").?.integer,
            s.object.get("outArity").?.integer,
        });
        defer allocator.free(line);
        try out.appendSlice(allocator, line);
    }
    try std.testing.expectEqualStrings(expected, out.items);
}

test "N-151: single asm() span" {
    try expectSpans(
        \\import { UnsafeSmartContract, asm } from 'runar-lang';
        \\class WithAsm extends UnsafeSmartContract {
        \\  constructor() { super(); }
        \\  public unlock() {
        \\    asm({ body: '51', in_arity: 0, out_arity: 1 });
        \\  }
        \\}
    , "0/1/0/1");
}

test "N-151: consecutive asm() spans" {
    try expectSpans(
        \\import { UnsafeSmartContract, asm } from 'runar-lang';
        \\class WithAsm extends UnsafeSmartContract {
        \\  constructor() { super(); }
        \\  public unlock() {
        \\    asm({ body: '51', in_arity: 0, out_arity: 1 });
        \\    asm({ body: '6151', in_arity: 1, out_arity: 1 });
        \\  }
        \\}
    , "0/1/0/1,1/2/1/1");
}

test "N-151: non-default arities" {
    try expectSpans(
        \\import { UnsafeSmartContract, asm } from 'runar-lang';
        \\class WithAsm extends UnsafeSmartContract {
        \\  constructor() { super(); }
        \\  public unlock(a: bigint, b: bigint) {
        \\    asm({ body: '87', in_arity: 2, out_arity: 1 });
        \\  }
        \\}
    , "0/1/2/1");
}

test "N-151: multi-byte body" {
    try expectSpans(
        \\import { UnsafeSmartContract, asm } from 'runar-lang';
        \\class WithAsm extends UnsafeSmartContract {
        \\  constructor() { super(); }
        \\  public unlock() {
        \\    asm({ body: '76a90051', in_arity: 0, out_arity: 1 });
        \\  }
        \\}
    , "0/4/0/1");
}

test "N-151: rawScriptSpans omitted without asm()" {
    const allocator = std.testing.allocator;
    const json = try artifactOf(allocator,
        \\import { SmartContract, assert } from 'runar-lang';
        \\class Always extends SmartContract {
        \\  constructor() { super(); }
        \\  public unlock(): void {
        \\    assert(1n === 1n);
        \\  }
        \\}
    );
    defer allocator.free(json);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"rawScriptSpans\"") == null);
}
