const std = @import("std");
const root = @import("../examples_test.zig");

// DataOutputTest.runar.zig calls self.addDataOutput — a Rúnar intrinsic that
// the compiler materialises into the emitted Bitcoin Script, not a real Zig
// method on the contract struct. So we only exercise the Rúnar frontend
// (parse → validate → typecheck) via compileCheck.

fn contractPath(comptime basename: []const u8) []const u8 {
    return "add-data-output/" ++ basename;
}

test "compile-check DataOutputTest.runar.zig (source)" {
    try root.runar.compileCheckSource(
        std.testing.allocator,
        @embedFile("DataOutputTest.runar.zig"),
        "DataOutputTest.runar.zig",
    );
}

test "compile-check DataOutputTest.runar.zig (file)" {
    try root.runar.compileCheckFile(
        std.testing.allocator,
        contractPath("DataOutputTest.runar.zig"),
    );
}
