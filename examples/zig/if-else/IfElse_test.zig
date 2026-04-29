const std = @import("std");
const root = @import("../examples_test.zig");
const IfElse = @import("IfElse.runar.zig").IfElse;

fn contractPath(comptime basename: []const u8) []const u8 {
    return "if-else/" ++ basename;
}

fn runCompileChecks(comptime basename: []const u8) !void {
    try root.runar.compileCheckSource(std.testing.allocator, @embedFile(basename), basename);
    try root.runar.compileCheckFile(std.testing.allocator, contractPath(basename));
}

test "compile-check IfElse.runar.zig" {
    try runCompileChecks("IfElse.runar.zig");
}

test "IfElse.check passes on the true branch when value+limit is positive" {
    const c = IfElse.init(5);
    c.check(3, true);
}

test "IfElse.check passes on the false branch when value-limit is positive" {
    const c = IfElse.init(5);
    c.check(20, false);
}
