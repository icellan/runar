const std = @import("std");
const root = @import("../examples_test.zig");
const Arithmetic = @import("Arithmetic.runar.zig").Arithmetic;

fn contractPath(comptime basename: []const u8) []const u8 {
    return "arithmetic/" ++ basename;
}

fn runCompileChecks(comptime basename: []const u8) !void {
    try root.runar.compileCheckSource(std.testing.allocator, @embedFile(basename), basename);
    try root.runar.compileCheckFile(std.testing.allocator, contractPath(basename));
}

test "compile-check Arithmetic.runar.zig" {
    try runCompileChecks("Arithmetic.runar.zig");
}

test "Arithmetic.verify accepts the matching target value" {
    // For a=10, b=2: sum=12, diff=8, prod=20, quot=5, total=45.
    const c = Arithmetic.init(45);
    c.verify(10, 2);
}

test "Arithmetic.verify accepts another consistent target" {
    // For a=4, b=2: sum=6, diff=2, prod=8, quot=2, total=18.
    const c = Arithmetic.init(18);
    c.verify(4, 2);
}
