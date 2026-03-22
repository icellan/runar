const std = @import("std");

const root = @import("../examples_test.zig");
const MathDemo = @import("MathDemo.runar.zig").MathDemo;

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

    demo.withdrawWithFee(100, 5);
    try std.testing.expectEqual(@as(i64, 145), demo.value);

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
