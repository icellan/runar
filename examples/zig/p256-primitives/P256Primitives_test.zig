const std = @import("std");
const root = @import("../examples_test.zig");

// P256Primitives.runar.zig exercises NIST P-256 builtins (`p256Mul`,
// `p256Add`, `p256MulGen`). Constructing real P-256 points from native Zig
// duplicates work that lives in the runar-zig SDK tier, so for this fixture
// we focus on Rúnar frontend coverage (parse → validate → typecheck).

fn contractPath(comptime basename: []const u8) []const u8 {
    return "p256-primitives/" ++ basename;
}

test "compile-check P256Primitives.runar.zig (source)" {
    try root.runar.compileCheckSource(
        std.testing.allocator,
        @embedFile("P256Primitives.runar.zig"),
        "P256Primitives.runar.zig",
    );
}

test "compile-check P256Primitives.runar.zig (file)" {
    try root.runar.compileCheckFile(
        std.testing.allocator,
        contractPath("P256Primitives.runar.zig"),
    );
}
