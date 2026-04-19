const std = @import("std");
const root = @import("../examples_test.zig");

fn contractPath(comptime basename: []const u8) []const u8 {
    return "ec-unit/" ++ basename;
}

test "compile-check ECUnit.runar.zig (source)" {
    try root.runar.compileCheckSource(
        std.testing.allocator,
        @embedFile("ECUnit.runar.zig"),
        "ECUnit.runar.zig",
    );
}

test "compile-check ECUnit.runar.zig (file)" {
    try root.runar.compileCheckFile(
        std.testing.allocator,
        contractPath("ECUnit.runar.zig"),
    );
}
