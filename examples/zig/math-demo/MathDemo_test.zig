const std = @import("std");

const root = @import("../examples_test.zig");
const MathDemo = @import("MathDemo.runar.zig").MathDemo;
const onchain_vectors = @import("onchain_vectors.zig");

fn contractPath(comptime basename: []const u8) []const u8 {
    return "math-demo/" ++ basename;
}

fn runCompileChecks(comptime basename: []const u8) !void {
    try root.runar.compileCheckSource(std.testing.allocator, @embedFile(basename), basename);
    try root.runar.compileCheckFile(std.testing.allocator, contractPath(basename));
}

test "compile-check MathDemo.runar.zig" {
    try runCompileChecks("MathDemo.runar.zig");
}

test "MathDemo executes division, fee withdrawal, clamp, and normalize directly" {
    var demo = MathDemo.init(1000);

    demo.divideBy(4);
    try std.testing.expectEqual(@as(i64, 250), demo.value);

    // F-033: feeBps is basis points — 100 * 5 / 10000 = 0 on-chain, so the
    // total is 100 (this used to expect 145, the native /100 result).
    demo.withdrawWithFee(100, 5);
    try std.testing.expectEqual(@as(i64, 150), demo.value);

    demo.clampValue(-10, 120);
    try std.testing.expectEqual(@as(i64, 120), demo.value);

    demo.normalize();
    try std.testing.expectEqual(@as(i64, 1), demo.value);
}

test "MathDemo normalize handles positive negative and zero values directly" {
    var positive = MathDemo.init(42);
    positive.normalize();
    try std.testing.expectEqual(@as(i64, 1), positive.value);

    var negative = MathDemo.init(-7);
    negative.normalize();
    try std.testing.expectEqual(@as(i64, -1), negative.value);

    var zero = MathDemo.init(0);
    zero.normalize();
    try std.testing.expectEqual(@as(i64, 0), zero.value);
}

test "MathDemo executes pow sqrt gcd ratio and log2 directly" {
    var demo = MathDemo.init(3);

    demo.exponentiate(4);
    try std.testing.expectEqual(@as(i64, 81), demo.value);

    demo.squareRoot();
    try std.testing.expectEqual(@as(i64, 9), demo.value);

    demo.reduceGcd(6);
    try std.testing.expectEqual(@as(i64, 3), demo.value);

    demo.scaleByRatio(10, 3);
    try std.testing.expectEqual(@as(i64, 10), demo.value);

    demo.computeLog2();
    try std.testing.expectEqual(@as(i64, 3), demo.value);
}

test "MathDemo rejects fee withdrawals that exceed balance" {
    try root.expectAssertFailure("math-demo-overdraw");
}

// F-033: every vector in onchain-vectors.json carries the verdict of the
// COMPILED script on @bsv/sdk Spend.validate, asserted by
// packages/runar-testing/src/__tests__/f033-zig-native-math-onchain.test.ts.
// Proves: the native MathDemo lands on the on-chain value for each value
// vector and aborts for each abort vector (out-of-process, via assert_probe).
// Does not prove: anything outside i64, or that the vectors are exhaustive.
test "F-033: MathDemo native run matches the on-chain verdict for every vector" {
    const allocator = std.testing.allocator;
    var parsed = try std.json.parseFromSlice(std.json.Value, allocator, onchain_vectors.json, .{});
    defer parsed.deinit();
    const cases = parsed.value.object.get("cases").?.array.items;
    try std.testing.expect(cases.len > 0);

    var aborts: usize = 0;
    for (cases, 0..) |c, i| {
        const expect = c.object.get("expect").?;
        if (expect == .string) {
            try std.testing.expectEqualStrings("abort", expect.string);
            var buf: [64]u8 = undefined;
            try root.expectVectorAbort(try std.fmt.bufPrint(&buf, "math-demo-vector:{d}", .{i}));
            aborts += 1;
            continue;
        }
        const got = try onchain_vectors.run(allocator, i, false);
        if (got != expect.integer) {
            std.debug.print("math-demo vector {d} ({s}): native={d} on-chain={d}\n", .{
                i, c.object.get("method").?.string, got, expect.integer,
            });
            return error.TestExpectedEqual;
        }
    }
    try std.testing.expect(aborts > 0);
}
