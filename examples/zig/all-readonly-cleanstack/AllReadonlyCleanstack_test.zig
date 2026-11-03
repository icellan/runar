const std = @import("std");
const root = @import("../examples_test.zig");

fn contractPath(comptime basename: []const u8) []const u8 {
    return "all-readonly-cleanstack/" ++ basename;
}

fn runCompileChecks(comptime basename: []const u8) !void {
    try root.runar.compileCheckSource(std.testing.allocator, @embedFile(basename), basename);
    try root.runar.compileCheckFile(std.testing.allocator, contractPath(basename));
}

test "compile-check AllReadonlyCleanstack.runar.zig" {
    try runCompileChecks("AllReadonlyCleanstack.runar.zig");
}

// Proves: the contract parses, validates and typechecks in the Rúnar frontend.
// Does not prove: any business logic. AllReadonlyCleanstack declares `const ownerCopy = self.owner;` and never reads it. Zig rejects an unused local constant, so the claim() body cannot be analysed natively; the issue-44 clean-stack behaviour is an on-chain script property covered by the conformance fixture. Frontend compile check only.
