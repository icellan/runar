const std = @import("std");
const root = @import("../examples_test.zig");
const Stateful = @import("Stateful.runar.zig").Stateful;

fn contractPath(comptime basename: []const u8) []const u8 {
    return "stateful/" ++ basename;
}

fn runCompileChecks(comptime basename: []const u8) !void {
    try root.runar.compileCheckSource(std.testing.allocator, @embedFile(basename), basename);
    try root.runar.compileCheckFile(std.testing.allocator, contractPath(basename));
}

test "compile-check Stateful.runar.zig" {
    try runCompileChecks("Stateful.runar.zig");
}

test "Stateful.increment advances count up to the maximum" {
    var c = Stateful.init(0, 10);
    c.increment(3);
    try std.testing.expectEqual(@as(i64, 3), c.count);
    c.increment(7);
    try std.testing.expectEqual(@as(i64, 10), c.count);
}

test "Stateful.reset clears count back to zero" {
    var c = Stateful.init(5, 10);
    c.reset();
    try std.testing.expectEqual(@as(i64, 0), c.count);
}
