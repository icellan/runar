const std = @import("std");
const root = @import("../examples_test.zig");
const runar = @import("runar");
const Sha256CompressTest = @import("Sha256CompressTest.runar.zig").Sha256CompressTest;

fn contractPath(comptime basename: []const u8) []const u8 {
    return "sha256-compress/" ++ basename;
}

fn runCompileChecks(comptime basename: []const u8) !void {
    try root.runar.compileCheckSource(std.testing.allocator, @embedFile(basename), basename);
    try root.runar.compileCheckFile(std.testing.allocator, contractPath(basename));
}

test "compile-check Sha256CompressTest.runar.zig" {
    try runCompileChecks("Sha256CompressTest.runar.zig");
}

test "Sha256CompressTest stores expected compressed state" {
    const state = runar.sha256("state");
    const block = [_]u8{'a'} ** 64;
    const expected = runar.sha256Compress(state, &block);
    const contract = Sha256CompressTest.init(expected);
    try std.testing.expectEqualSlices(u8, expected, contract.expected);
}

test "Sha256CompressTest verify compares the real builtin output to expected bytes" {
    const state = runar.sha256("state");
    const block = [_]u8{'a'} ** 64;
    const contract = Sha256CompressTest.init(runar.sha256Compress(state, &block));
    contract.verify(state, &block);
}

test "Sha256CompressTest verify rejects mismatched compressed bytes through the real assertion path" {
    try root.runar.expectAssertFailure(std.testing.allocator, "sha256-compress-mismatch");
}
