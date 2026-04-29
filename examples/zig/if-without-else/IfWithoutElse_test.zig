const std = @import("std");
const root = @import("../examples_test.zig");
const IfWithoutElse = @import("IfWithoutElse.runar.zig").IfWithoutElse;

fn contractPath(comptime basename: []const u8) []const u8 {
    return "if-without-else/" ++ basename;
}

fn runCompileChecks(comptime basename: []const u8) !void {
    try root.runar.compileCheckSource(std.testing.allocator, @embedFile(basename), basename);
    try root.runar.compileCheckFile(std.testing.allocator, contractPath(basename));
}

test "compile-check IfWithoutElse.runar.zig" {
    try runCompileChecks("IfWithoutElse.runar.zig");
}

test "IfWithoutElse.check passes when one input is above the threshold" {
    const c = IfWithoutElse.init(10);
    c.check(15, 5);
}

test "IfWithoutElse.check passes when both inputs are above the threshold" {
    const c = IfWithoutElse.init(10);
    c.check(15, 20);
}
