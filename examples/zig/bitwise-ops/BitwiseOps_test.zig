const std = @import("std");
const root = @import("../examples_test.zig");
const runar = @import("runar");
const BitwiseOps = @import("BitwiseOps.runar.zig").BitwiseOps;

fn contractPath(comptime basename: []const u8) []const u8 {
    return "bitwise-ops/" ++ basename;
}

fn runCompileChecks(comptime basename: []const u8) !void {
    try root.runar.compileCheckSource(std.testing.allocator, @embedFile(basename), basename);
    try root.runar.compileCheckFile(std.testing.allocator, contractPath(basename));
}

test "compile-check BitwiseOps.runar.zig" {
    try runCompileChecks("BitwiseOps.runar.zig");
}

test "BitwiseOps.testShift runs on positive values" {
    const c = BitwiseOps.init(42, 17);
    c.testShift();
}

test "BitwiseOps.testBitwise runs on positive values" {
    const c = BitwiseOps.init(42, 17);
    c.testBitwise();
}

test "BitwiseOps.testBitwise runs on zero" {
    const c = BitwiseOps.init(0, 0);
    c.testBitwise();
}
