const std = @import("std");
const root = @import("../examples_test.zig");
const runar = @import("runar");
const BSV21Token = @import("BSV21Token.runar.zig").BSV21Token;

fn contractPath(comptime basename: []const u8) []const u8 {
    return "bsv21-token/" ++ basename;
}

fn runCompileChecks(comptime basename: []const u8) !void {
    try root.runar.compileCheckSource(std.testing.allocator, @embedFile(basename), basename);
    try root.runar.compileCheckFile(std.testing.allocator, contractPath(basename));
}

test "compile-check BSV21Token.runar.zig" {
    try runCompileChecks("BSV21Token.runar.zig");
}

test "BSV21Token init stores pubKeyHash" {
    const expected = runar.hash160(runar.ALICE.pubKey);
    const contract = BSV21Token.init(expected);
    try std.testing.expectEqualSlices(u8, expected, contract.pubKeyHash);
}

test "BSV21Token unlock succeeds with the matching key and signature" {
    const contract = BSV21Token.init(runar.hash160(runar.ALICE.pubKey));
    contract.unlock(runar.signTestMessage(runar.ALICE), runar.ALICE.pubKey);
}

test "BSV21Token unlock rejects the wrong pubkey through the real contract assertion path" {
    try root.runar.expectAssertFailure(std.testing.allocator, "bsv21-token-wrong-pubkey");
}

test "BSV21Token unlock rejects the wrong signature through the real contract assertion path" {
    try root.runar.expectAssertFailure(std.testing.allocator, "bsv21-token-wrong-sig");
}
