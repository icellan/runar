const std = @import("std");
const root = @import("../examples_test.zig");
const runar = @import("runar");
const BabyBearExt4Demo = @import("BabyBearExt4Demo.runar.zig").BabyBearExt4Demo;

fn contractPath(comptime basename: []const u8) []const u8 {
    return "babybear-ext4/" ++ basename;
}

fn runCompileChecks(comptime basename: []const u8) !void {
    try root.runar.compileCheckSource(std.testing.allocator, @embedFile(basename), basename);
    try root.runar.compileCheckFile(std.testing.allocator, contractPath(basename));
}

test "compile-check BabyBearExt4Demo.runar.zig" {
    try runCompileChecks("BabyBearExt4Demo.runar.zig");
}

test "checkMul identity: (a) * (1,0,0,0) = a" {
    const c = BabyBearExt4Demo.init();
    const a0: i64 = 7;
    const a1: i64 = 11;
    const a2: i64 = 13;
    const a3: i64 = 17;
    const e0 = runar.bbExt4Mul0(a0, a1, a2, a3, 1, 0, 0, 0);
    const e1 = runar.bbExt4Mul1(a0, a1, a2, a3, 1, 0, 0, 0);
    const e2 = runar.bbExt4Mul2(a0, a1, a2, a3, 1, 0, 0, 0);
    const e3 = runar.bbExt4Mul3(a0, a1, a2, a3, 1, 0, 0, 0);
    try std.testing.expectEqual(@as(i64, 7), e0);
    try std.testing.expectEqual(@as(i64, 11), e1);
    try std.testing.expectEqual(@as(i64, 13), e2);
    try std.testing.expectEqual(@as(i64, 17), e3);
    c.checkMul(a0, a1, a2, a3, 1, 0, 0, 0, e0, e1, e2, e3);
}

test "checkInv: x * inv(x) = (1,0,0,0)" {
    const c = BabyBearExt4Demo.init();
    const x0: i64 = 100;
    const x1: i64 = 200;
    const x2: i64 = 300;
    const x3: i64 = 400;
    const inv0 = runar.bbExt4Inv0(x0, x1, x2, x3);
    const inv1 = runar.bbExt4Inv1(x0, x1, x2, x3);
    const inv2 = runar.bbExt4Inv2(x0, x1, x2, x3);
    const inv3 = runar.bbExt4Inv3(x0, x1, x2, x3);
    const p0 = runar.bbExt4Mul0(x0, x1, x2, x3, inv0, inv1, inv2, inv3);
    const p1 = runar.bbExt4Mul1(x0, x1, x2, x3, inv0, inv1, inv2, inv3);
    const p2 = runar.bbExt4Mul2(x0, x1, x2, x3, inv0, inv1, inv2, inv3);
    const p3 = runar.bbExt4Mul3(x0, x1, x2, x3, inv0, inv1, inv2, inv3);
    try std.testing.expectEqual(@as(i64, 1), p0);
    try std.testing.expectEqual(@as(i64, 0), p1);
    try std.testing.expectEqual(@as(i64, 0), p2);
    try std.testing.expectEqual(@as(i64, 0), p3);
    c.checkInv(x0, x1, x2, x3, inv0, inv1, inv2, inv3);
}
