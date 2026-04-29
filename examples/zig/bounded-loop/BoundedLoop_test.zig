const std = @import("std");
const root = @import("../examples_test.zig");
const BoundedLoop = @import("BoundedLoop.runar.zig").BoundedLoop;

fn contractPath(comptime basename: []const u8) []const u8 {
    return "bounded-loop/" ++ basename;
}

fn runCompileChecks(comptime basename: []const u8) !void {
    try root.runar.compileCheckSource(std.testing.allocator, @embedFile(basename), basename);
    try root.runar.compileCheckFile(std.testing.allocator, contractPath(basename));
}

test "compile-check BoundedLoop.runar.zig" {
    try runCompileChecks("BoundedLoop.runar.zig");
}

test "BoundedLoop.verify accepts the expected sum from start=0" {
    // Loop: 0+0 + 0+1 + 0+2 + 0+3 + 0+4 = 10.
    const c = BoundedLoop.init(10);
    c.verify(0);
}

test "BoundedLoop.verify accepts the expected sum from start=2" {
    // Loop: (2+0) + (2+1) + (2+2) + (2+3) + (2+4) = 5*2 + 10 = 20.
    const c = BoundedLoop.init(20);
    c.verify(2);
}
