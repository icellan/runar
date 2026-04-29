const std = @import("std");
const root = @import("../examples_test.zig");
const ShiftOps = @import("ShiftOps.runar.zig").ShiftOps;

fn contractPath(comptime basename: []const u8) []const u8 {
    return "shift-ops/" ++ basename;
}

fn runCompileChecks(comptime basename: []const u8) !void {
    try root.runar.compileCheckSource(std.testing.allocator, @embedFile(basename), basename);
    try root.runar.compileCheckFile(std.testing.allocator, contractPath(basename));
}

test "compile-check ShiftOps.runar.zig" {
    try runCompileChecks("ShiftOps.runar.zig");
}

test "ShiftOps.testShift runs on a positive value" {
    const c = ShiftOps.init(42);
    c.testShift();
}

test "ShiftOps.testShift runs on zero" {
    const c = ShiftOps.init(0);
    c.testShift();
}
