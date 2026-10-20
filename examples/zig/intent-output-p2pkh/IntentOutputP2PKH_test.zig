const std = @import("std");
const root = @import("../examples_test.zig");

fn contractPath(comptime basename: []const u8) []const u8 {
    return "intent-output-p2pkh/" ++ basename;
}

fn runCompileChecks(comptime basename: []const u8) !void {
    try root.runar.compileCheckSource(std.testing.allocator, @embedFile(basename), basename);
    try root.runar.compileCheckFile(std.testing.allocator, contractPath(basename));
}

test "compile-check IntentOutputP2PKH.runar.zig" {
    try runCompileChecks("IntentOutputP2PKH.runar.zig");
}

// Proves: the contract parses, validates and typechecks in the Rúnar frontend.
// Does not prove: any business logic. runar.requireOutputP2PKH is defined in packages/runar-zig/src/builtins.zig but not re-exported from root.zig, so the body does not compile natively (logged as a package gap). It is a no-op stub off-chain in any case. Frontend compile check only.
