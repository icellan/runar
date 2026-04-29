const std = @import("std");
const root = @import("../examples_test.zig");

// ECPrimitives.runar.zig exercises EC builtins (`ecAdd`, `ecMul`, ...) on
// `runar.Point` operands. Constructing real secp256k1 points from native Zig
// in the test harness duplicates the work covered by ECDemo's tests, so for
// this fixture we focus on Rúnar frontend coverage.

fn contractPath(comptime basename: []const u8) []const u8 {
    return "ec-primitives/" ++ basename;
}

test "compile-check ECPrimitives.runar.zig (source)" {
    try root.runar.compileCheckSource(
        std.testing.allocator,
        @embedFile("ECPrimitives.runar.zig"),
        "ECPrimitives.runar.zig",
    );
}

test "compile-check ECPrimitives.runar.zig (file)" {
    try root.runar.compileCheckFile(
        std.testing.allocator,
        contractPath("ECPrimitives.runar.zig"),
    );
}
