const std = @import("std");
const root = @import("../examples_test.zig");
const runar = @import("runar");
const Blake3Test = @import("Blake3Test.runar.zig").Blake3Test;

fn contractPath(comptime basename: []const u8) []const u8 {
    return "blake3/" ++ basename;
}

fn runCompileChecks(comptime basename: []const u8) !void {
    try root.runar.compileCheckSource(std.testing.allocator, @embedFile(basename), basename);
    try root.runar.compileCheckFile(std.testing.allocator, contractPath(basename));
}

test "compile-check Blake3Test.runar.zig" {
    try runCompileChecks("Blake3Test.runar.zig");
}

test "Blake3Test verifyHash checks the real BLAKE3 helper" {
    const expected = runar.blake3Hash("abc");
    const contract = Blake3Test.init(expected);
    contract.verifyHash("abc");
}

test "Blake3Test verifyHash rejects mismatched digest bytes through the real assertion path" {
    try root.runar.expectAssertFailure(std.testing.allocator, "blake3-hash-mismatch");
}

test "Blake3Test verifyCompress checks the real compression helper" {
    const state = runar.sha256("state");
    const block = [_]u8{'a'} ** 64;
    const expected = runar.blake3Compress(state, &block);
    const contract = Blake3Test.init(expected);
    contract.verifyCompress(state, &block);
}

test "Blake3Test verifyCompress rejects mismatched compressed bytes through the real assertion path" {
    try root.runar.expectAssertFailure(std.testing.allocator, "blake3-compress-mismatch");
}
