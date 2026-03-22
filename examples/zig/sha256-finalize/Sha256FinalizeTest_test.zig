const std = @import("std");
const root = @import("../examples_test.zig");
const runar = @import("runar");
const Sha256FinalizeTest = @import("Sha256FinalizeTest.runar.zig").Sha256FinalizeTest;

fn contractPath(comptime basename: []const u8) []const u8 {
    return "sha256-finalize/" ++ basename;
}

fn runCompileChecks(comptime basename: []const u8) !void {
    try root.runar.compileCheckSource(std.testing.allocator, @embedFile(basename), basename);
    try root.runar.compileCheckFile(std.testing.allocator, contractPath(basename));
}

test "compile-check Sha256FinalizeTest.runar.zig" {
    try runCompileChecks("Sha256FinalizeTest.runar.zig");
}

test "Sha256FinalizeTest stores expected digest" {
    const state = runar.sha256("state");
    const expected = runar.sha256Finalize(state, "abc", 24);
    const contract = Sha256FinalizeTest.init(expected);
    try std.testing.expectEqualSlices(u8, expected, contract.expected);
}

test "Sha256FinalizeTest verify checks the real finalized digest" {
    const state = runar.sha256("state");
    const contract = Sha256FinalizeTest.init(runar.sha256Finalize(state, "abc", 24));
    contract.verify(state, "abc", 24);
}

test "Sha256FinalizeTest verify rejects mismatched digest bytes through the real assertion path" {
    try root.runar.expectAssertFailure(std.testing.allocator, "sha256-finalize-mismatch");
}
