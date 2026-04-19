const std = @import("std");
const root = @import("../examples_test.zig");

fn contractPath(comptime basename: []const u8) []const u8 {
    return "fixed-array-nested/" ++ basename;
}

test "compile-check Grid2x2.v2.runar.zig (source)" {
    try root.runar.compileCheckSource(
        std.testing.allocator,
        @embedFile("Grid2x2.v2.runar.zig"),
        "Grid2x2.v2.runar.zig",
    );
}

test "compile-check Grid2x2.v2.runar.zig (file)" {
    try root.runar.compileCheckFile(
        std.testing.allocator,
        contractPath("Grid2x2.v2.runar.zig"),
    );
}
