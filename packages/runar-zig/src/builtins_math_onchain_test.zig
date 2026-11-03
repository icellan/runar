//! F-033 (CL-BUG-104) — native math builtins must return what the compiled
//! script returns.
//!
//! `builtins.zig` is the runtime every native `.runar.zig` contract test links
//! against (re-exported as the public `runar` namespace in root.zig). Its
//! `percentOf` divided by 100 while the script divides by 10000 (basis points),
//! so a native test passed on a fee 100x the one the deployed contract charges.
//!
//! The vectors in fixtures/f033-math-builtins-onchain.json are pinned against
//! the EXECUTED SCRIPT on @bsv/sdk Spend.validate by
//! packages/runar-testing/src/__tests__/f033-zig-native-math-onchain.test.ts
//! (accept at `expect`, reject at `expect + 1`). This file replays the same
//! JSON through the native runtime, so native == JSON == on-chain.
//!
//! Proves: for every non-abort vector, the native builtin returns the on-chain
//! value, including truncation toward zero for negative operands, the lo > hi
//! clamp order, and sqrt's exact floor.
//! Does NOT prove: native aborts. An `abort` vector ends in a Zig panic, which
//! a test cannot observe in-process; those are replayed out-of-process through
//! the examples/zig assert_probe (MathDemo_test.zig / FunctionPatterns_test.zig).
//! Values are limited to i64, the native Bigint.

const std = @import("std");
const builtins = @import("builtins.zig");

const vectors_json = @embedFile("fixtures/f033-math-builtins-onchain.json");

test "F-033: percentOf is basis points (10000 * 250 / 10000 == 250)" {
    try std.testing.expectEqual(@as(i64, 250), builtins.percentOf(10000, 250));
}

const Outcome = union(enum) { int: i64, boolean: bool, missing };

fn call(name: []const u8, a: []const i64) Outcome {
    const B = builtins;
    const eq = std.mem.eql;
    if (eq(u8, name, "percentOf")) return .{ .int = B.percentOf(a[0], a[1]) };
    if (eq(u8, name, "mulDiv")) return .{ .int = B.mulDiv(a[0], a[1], a[2]) };
    if (eq(u8, name, "safediv")) return .{ .int = B.safediv(a[0], a[1]) };
    if (eq(u8, name, "safemod")) return .{ .int = B.safemod(a[0], a[1]) };
    if (eq(u8, name, "sqrt")) return .{ .int = B.sqrt(a[0]) };
    if (eq(u8, name, "log2")) return .{ .int = B.log2(a[0]) };
    if (eq(u8, name, "pow")) return .{ .int = B.pow(a[0], a[1]) };
    if (eq(u8, name, "clamp")) return .{ .int = B.clamp(a[0], a[1], a[2]) };
    if (eq(u8, name, "within")) return .{ .boolean = B.within(a[0], a[1], a[2]) };
    if (eq(u8, name, "sign")) return .{ .int = B.sign(a[0]) };
    if (eq(u8, name, "gcd")) return .{ .int = B.gcd(a[0], a[1]) };
    // Builtins the compiler accepts from a .runar.zig source that the native
    // runtime may not export; a missing one is reported, not a compile error,
    // so one run shows every divergence.
    if (eq(u8, name, "divmod")) return if (@hasDecl(B, "divmod")) .{ .int = B.divmod(a[0], a[1]) } else .missing;
    if (eq(u8, name, "abs")) return if (@hasDecl(B, "abs")) .{ .int = B.abs(a[0]) } else .missing;
    if (eq(u8, name, "min")) return if (@hasDecl(B, "min")) .{ .int = B.min(a[0], a[1]) } else .missing;
    if (eq(u8, name, "max")) return if (@hasDecl(B, "max")) .{ .int = B.max(a[0], a[1]) } else .missing;
    if (eq(u8, name, "bool")) return if (@hasDecl(B, "boolCast")) .{ .boolean = B.boolCast(a[0]) } else .missing;
    std.debug.panic("f033 vectors: unknown builtin {s}", .{name});
}

test "F-033: every native math builtin returns the on-chain value for every vector" {
    const allocator = std.testing.allocator;
    var parsed = try std.json.parseFromSlice(std.json.Value, allocator, vectors_json, .{});
    defer parsed.deinit();

    const cases = parsed.value.object.get("cases").?.array.items;
    try std.testing.expect(cases.len > 0);

    var checked: usize = 0;
    var mismatches: usize = 0;
    for (cases) |c| {
        const obj = c.object;
        const name = obj.get("fn").?.string;
        const expect = obj.get("expect").?;
        // Native aborts are panics — covered out-of-process (see header).
        if (expect == .string) {
            try std.testing.expectEqualStrings("abort", expect.string);
            continue;
        }

        var args: [3]i64 = undefined;
        const arr = obj.get("args").?.array.items;
        for (arr, 0..) |v, i| args[i] = v.integer;

        const got = call(name, args[0..arr.len]);
        const ok = switch (got) {
            .missing => false,
            .int => |v| expect == .integer and v == expect.integer,
            .boolean => |v| expect == .bool and v == expect.bool,
        };
        checked += 1;
        if (!ok) {
            mismatches += 1;
            std.debug.print("F-033 native/on-chain mismatch: {s}({any}) native={any} on-chain={any}\n", .{
                name, args[0..arr.len], got, expect,
            });
        }
    }
    try std.testing.expect(checked > 0);
    try std.testing.expectEqual(@as(usize, 0), mismatches);
}
