const std = @import("std");
const root = @import("../examples_test.zig");
const BooleanLogic = @import("BooleanLogic.runar.zig").BooleanLogic;

fn contractPath(comptime basename: []const u8) []const u8 {
    return "boolean-logic/" ++ basename;
}

fn runCompileChecks(comptime basename: []const u8) !void {
    try root.runar.compileCheckSource(std.testing.allocator, @embedFile(basename), basename);
    try root.runar.compileCheckFile(std.testing.allocator, contractPath(basename));
}

test "compile-check BooleanLogic.runar.zig" {
    try runCompileChecks("BooleanLogic.runar.zig");
}

test "BooleanLogic.verify passes when both inputs are above the threshold" {
    const c = BooleanLogic.init(10);
    c.verify(20, 30, true);
}

test "BooleanLogic.verify passes when one input is above and flag is false" {
    const c = BooleanLogic.init(10);
    c.verify(20, 5, false);
}
