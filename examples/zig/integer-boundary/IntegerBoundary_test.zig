const std = @import("std");
const root = @import("../examples_test.zig");

fn contractPath(comptime basename: []const u8) []const u8 {
    return "integer-boundary/" ++ basename;
}

fn runCompileChecks(comptime basename: []const u8) !void {
    try root.runar.compileCheckSource(std.testing.allocator, @embedFile(basename), basename);
    try root.runar.compileCheckFile(std.testing.allocator, contractPath(basename));
}

test "compile-check IntegerBoundary.runar.zig" {
    try runCompileChecks("IntegerBoundary.runar.zig");
}

// Proves: the contract parses, validates and typechecks in the Rúnar frontend.
// Does not prove: any business logic. verify() folds literals past the signed 64-bit range (comptime_int) and adds a runtime i64 to the result; Zig rejects that at compile time, which is the point of the fixture (arbitrary-precision script integers). Frontend compile check only.
