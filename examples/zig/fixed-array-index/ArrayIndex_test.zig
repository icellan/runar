const std = @import("std");
const root = @import("../examples_test.zig");

fn contractPath(comptime basename: []const u8) []const u8 {
    return "fixed-array-index/" ++ basename;
}

fn runCompileChecks(comptime basename: []const u8) !void {
    try root.runar.compileCheckSource(std.testing.allocator, @embedFile(basename), basename);
    try root.runar.compileCheckFile(std.testing.allocator, contractPath(basename));
}

test "compile-check ArrayIndex.runar.zig" {
    try runCompileChecks("ArrayIndex.runar.zig");
}

// Proves: the contract parses, validates and typechecks in the Rúnar frontend.
// Does not prove: any business logic. lookup() indexes a [4]i64 with an i64 (self.table[i]); Zig only indexes arrays with usize, so the body does not compile natively. Frontend compile check only.
