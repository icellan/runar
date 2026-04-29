const std = @import("std");
const root = @import("../examples_test.zig");

// P384Primitives.runar.zig exercises NIST P-384 builtins (`p384Mul`,
// `p384Add`, `p384MulGen`). Constructing real P-384 points from native Zig
// duplicates work that lives in the runar-zig SDK tier, so for this fixture
// we focus on Rúnar frontend coverage (parse → validate → typecheck).

fn contractPath(comptime basename: []const u8) []const u8 {
    return "p384-primitives/" ++ basename;
}

test "compile-check P384Primitives.runar.zig (source)" {
    try root.runar.compileCheckSource(
        std.testing.allocator,
        @embedFile("P384Primitives.runar.zig"),
        "P384Primitives.runar.zig",
    );
}

test "compile-check P384Primitives.runar.zig (file)" {
    try root.runar.compileCheckFile(
        std.testing.allocator,
        contractPath("P384Primitives.runar.zig"),
    );
}
