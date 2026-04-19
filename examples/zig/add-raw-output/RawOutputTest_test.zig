const std = @import("std");
const root = @import("../examples_test.zig");

// RawOutputTest.runar.zig calls self.addRawOutput / self.addOutput —
// Rúnar intrinsics that the compiler materialises into the emitted Bitcoin
// Script, not real Zig methods. So we only exercise the Rúnar frontend
// (parse → validate → typecheck) via compileCheck.

fn contractPath(comptime basename: []const u8) []const u8 {
    return "add-raw-output/" ++ basename;
}

test "compile-check RawOutputTest.runar.zig (source)" {
    try root.runar.compileCheckSource(
        std.testing.allocator,
        @embedFile("RawOutputTest.runar.zig"),
        "RawOutputTest.runar.zig",
    );
}

test "compile-check RawOutputTest.runar.zig (file)" {
    try root.runar.compileCheckFile(
        std.testing.allocator,
        contractPath("RawOutputTest.runar.zig"),
    );
}
