const std = @import("std");
const root = @import("../examples_test.zig");
const Selector = @import("Selector.runar.zig").Selector;

fn contractPath(comptime basename: []const u8) []const u8 {
    return "selector/" ++ basename;
}

fn runCompileChecks(comptime basename: []const u8) !void {
    try root.runar.compileCheckSource(std.testing.allocator, @embedFile(basename), basename);
    try root.runar.compileCheckFile(std.testing.allocator, contractPath(basename));
}

test "compile-check Selector.runar.zig" {
    try runCompileChecks("Selector.runar.zig");
}

// Proves: set() routes i=0 to a and i=1 to b without touching the other, and the terminal `else` assert(false) aborts for any other selector (C20).
// Does not prove: that the abort survives ANF lowering in the compiled script (the C20 regression itself is a conformance/on-chain property).

test "Selector set routes each selector to its own field" {
    var c = Selector.init(1, 2);
    c.set(0, 7);
    try std.testing.expectEqual(@as(i64, 7), c.a);
    try std.testing.expectEqual(@as(i64, 2), c.b);
    c.set(1, 9);
    try std.testing.expectEqual(@as(i64, 7), c.a);
    try std.testing.expectEqual(@as(i64, 9), c.b);
}

test "Selector set aborts for an out-of-range selector" {
    try root.expectAssertFailure("selector-out-of-range");
}
