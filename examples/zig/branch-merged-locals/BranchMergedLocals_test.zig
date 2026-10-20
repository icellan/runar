const std = @import("std");
const root = @import("../examples_test.zig");

fn contractPath(comptime basename: []const u8) []const u8 {
    return "branch-merged-locals/" ++ basename;
}

fn runCompileChecks(comptime basename: []const u8) !void {
    try root.runar.compileCheckSource(std.testing.allocator, @embedFile(basename), basename);
    try root.runar.compileCheckFile(std.testing.allocator, contractPath(basename));
}

test "compile-check BranchMergedLocals.runar.zig" {
    try runCompileChecks("BranchMergedLocals.runar.zig");
}

// Proves: the contract parses, validates and typechecks in the Rúnar frontend.
// Does not prove: any business logic. bid() calls self.addOutput, a Runar intrinsic the compiler materialises into the script rather than a method of the Zig struct (see add-data-output). Frontend compile check only.
