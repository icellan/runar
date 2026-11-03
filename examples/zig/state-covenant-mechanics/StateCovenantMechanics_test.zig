const std = @import("std");
const root = @import("../examples_test.zig");

fn contractPath(comptime basename: []const u8) []const u8 {
    return "state-covenant-mechanics/" ++ basename;
}

fn runCompileChecks(comptime basename: []const u8) !void {
    try root.runar.compileCheckSource(std.testing.allocator, @embedFile(basename), basename);
    try root.runar.compileCheckFile(std.testing.allocator, contractPath(basename));
}

test "compile-check StateCovenantMechanics.runar.zig" {
    try runCompileChecks("StateCovenantMechanics.runar.zig");
}

// Proves: the contract parses, validates and typechecks in the Rúnar frontend.
// Does not prove: any business logic. advanceState() compares ByteStrings with `==` (preStateRoot == self.stateRoot); Zig does not compare slices with ==, so the body does not compile natively (state-covenant uses bytesEq). Frontend compile check only.
