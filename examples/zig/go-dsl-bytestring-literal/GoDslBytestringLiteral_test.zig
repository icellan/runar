const std = @import("std");
const root = @import("../examples_test.zig");

fn contractPath(comptime basename: []const u8) []const u8 {
    return "go-dsl-bytestring-literal/" ++ basename;
}

fn runCompileChecks(comptime basename: []const u8) !void {
    try root.runar.compileCheckSource(std.testing.allocator, @embedFile(basename), basename);
    try root.runar.compileCheckFile(std.testing.allocator, contractPath(basename));
}

test "compile-check GoDslBytestringLiteral.runar.zig" {
    try runCompileChecks("GoDslBytestringLiteral.runar.zig");
}

// Proves: the contract parses, validates and typechecks in the Rúnar frontend.
// Does not prove: any business logic. runar.Bigint is the multi-limb builtins.SignedBigint struct in the Zig package, so `a + b == self.target` does not compile natively (the struct has no + or ==). Frontend compile check only.
