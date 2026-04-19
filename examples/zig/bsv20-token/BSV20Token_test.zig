const std = @import("std");
const root = @import("../examples_test.zig");
const runar = @import("runar");
const BSV20Token = @import("BSV20Token.runar.zig").BSV20Token;

fn contractPath(comptime basename: []const u8) []const u8 {
    return "bsv20-token/" ++ basename;
}

fn runCompileChecks(comptime basename: []const u8) !void {
    try root.runar.compileCheckSource(std.testing.allocator, @embedFile(basename), basename);
    try root.runar.compileCheckFile(std.testing.allocator, contractPath(basename));
}

test "compile-check BSV20Token.runar.zig" {
    try runCompileChecks("BSV20Token.runar.zig");
}

test "BSV20Token init stores pubKeyHash" {
    const expected = runar.hash160(runar.ALICE.pubKey);
    const contract = BSV20Token.init(expected);
    try std.testing.expectEqualSlices(u8, expected, contract.pubKeyHash);
}

test "BSV20Token unlock succeeds with the matching key and signature" {
    const contract = BSV20Token.init(runar.hash160(runar.ALICE.pubKey));
    contract.unlock(runar.signTestMessage(runar.ALICE), runar.ALICE.pubKey);
}

test "BSV20Token unlock rejects the wrong pubkey through the real contract assertion path" {
    try root.runar.expectAssertFailure(std.testing.allocator, "bsv20-token-wrong-pubkey");
}

test "BSV20Token unlock rejects the wrong signature through the real contract assertion path" {
    try root.runar.expectAssertFailure(std.testing.allocator, "bsv20-token-wrong-sig");
}
