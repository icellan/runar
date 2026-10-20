const std = @import("std");
const root = @import("../examples_test.zig");

fn contractPath(comptime basename: []const u8) []const u8 {
    return "p256-encode-negate/" ++ basename;
}

fn runCompileChecks(comptime basename: []const u8) !void {
    try root.runar.compileCheckSource(std.testing.allocator, @embedFile(basename), basename);
    try root.runar.compileCheckFile(std.testing.allocator, contractPath(basename));
}

test "compile-check P256EncodeNegate.runar.zig" {
    try runCompileChecks("P256EncodeNegate.runar.zig");
}

// Proves: the contract parses, validates and typechecks in the Rúnar frontend.
// Does not prove: any business logic. runar.p256Negate / runar.p256EncodeCompressed have no native implementation in the runar Zig package (see p256-primitives). Frontend compile check only.
