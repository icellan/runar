const std = @import("std");
const root = @import("../examples_test.zig");

// PrivateHelperOutputs.runar.zig calls self.addDataOutput / self.addOutput —
// Rúnar intrinsics that the compiler materialises into emitted Bitcoin
// Script. We exercise the Rúnar frontend (parse → validate → typecheck) via
// compileCheck.

fn contractPath(comptime basename: []const u8) []const u8 {
    return "private-helper-outputs/" ++ basename;
}

test "compile-check PrivateHelperOutputs.runar.zig (source)" {
    try root.runar.compileCheckSource(
        std.testing.allocator,
        @embedFile("PrivateHelperOutputs.runar.zig"),
        "PrivateHelperOutputs.runar.zig",
    );
}

test "compile-check PrivateHelperOutputs.runar.zig (file)" {
    try root.runar.compileCheckFile(
        std.testing.allocator,
        contractPath("PrivateHelperOutputs.runar.zig"),
    );
}
