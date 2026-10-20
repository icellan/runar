const std = @import("std");
const root = @import("../examples_test.zig");

fn contractPath(comptime basename: []const u8) []const u8 {
    return "byte-builtins/" ++ basename;
}

fn runCompileChecks(comptime basename: []const u8) !void {
    try root.runar.compileCheckSource(std.testing.allocator, @embedFile(basename), basename);
    try root.runar.compileCheckFile(std.testing.allocator, contractPath(basename));
}

test "compile-check ByteBuiltins.runar.zig" {
    try runCompileChecks("ByteBuiltins.runar.zig");
}

// Proves: the contract parses, validates and typechecks in the Rúnar frontend.
// Does not prove: any business logic. The file cannot be imported as Zig: checkSplit / checkInt2Str / checkReverse carry an unused `self` parameter (a file-wide AstGen error) and call runar.split / int2str / reverseBytes, which the runar Zig package does not implement. The SHA-256 / RIPEMD-160 checks therefore have no native path either. Frontend compile check only.
