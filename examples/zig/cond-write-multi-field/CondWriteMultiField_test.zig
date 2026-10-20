const std = @import("std");
const root = @import("../examples_test.zig");

fn contractPath(comptime basename: []const u8) []const u8 {
    return "cond-write-multi-field/" ++ basename;
}

fn runCompileChecks(comptime basename: []const u8) !void {
    try root.runar.compileCheckSource(std.testing.allocator, @embedFile(basename), basename);
    try root.runar.compileCheckFile(std.testing.allocator, contractPath(basename));
}

test "compile-check CondWriteMultiField.runar.zig" {
    try runCompileChecks("CondWriteMultiField.runar.zig");
}

// Proves: the contract parses, validates and typechecks in the Rúnar frontend.
// Does not prove: any business logic. bump() calls self.addOutput, a Runar compile-time intrinsic with no native method. Frontend compile check only.
