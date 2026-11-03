const std = @import("std");
const root = @import("../examples_test.zig");
const PropertyShadow = @import("PropertyShadow.runar.zig").PropertyShadow;

fn contractPath(comptime basename: []const u8) []const u8 {
    return "property-shadow/" ++ basename;
}

fn runCompileChecks(comptime basename: []const u8) !void {
    try root.runar.compileCheckSource(std.testing.allocator, @embedFile(basename), basename);
    try root.runar.compileCheckFile(std.testing.allocator, contractPath(basename));
}

test "compile-check PropertyShadow.runar.zig" {
    try runCompileChecks("PropertyShadow.runar.zig");
}

// Proves: bump() compares the LOCAL (n + 1) against the target field and accumulates the local into count; both asserts abort independently.
// Does not prove: that every compiler keeps the local distinct from `self.<field>` (N-016 is a conformance property; Zig fields are never in scope by bare name).

test "PropertyShadow bump accepts the matching target and accumulates count" {
    var c = PropertyShadow.init(6, 1);
    c.bump(5);
    try std.testing.expectEqual(@as(i64, 6), c.count);
    try std.testing.expectEqual(@as(i64, 6), c.target);
}

test "PropertyShadow bump rejects a local that misses the target" {
    try root.expectAssertFailure("property-shadow-wrong-target");
}

test "PropertyShadow bump rejects when count does not grow past the local" {
    try root.expectAssertFailure("property-shadow-count-not-greater");
}
