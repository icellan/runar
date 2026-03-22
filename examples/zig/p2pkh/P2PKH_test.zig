const std = @import("std");
const root = @import("../examples_test.zig");
const runar = @import("runar");
const P2PKH = @import("P2PKH.runar.zig").P2PKH;

fn contractPath(comptime basename: []const u8) []const u8 {
    return "p2pkh/" ++ basename;
}

fn runCompileChecks(comptime basename: []const u8) !void {
    try root.runar.compileCheckSource(std.testing.allocator, @embedFile(basename), basename);
    try root.runar.compileCheckFile(std.testing.allocator, contractPath(basename));
}

test "compile-check P2PKH.runar.zig" {
    try runCompileChecks("P2PKH.runar.zig");
}

test "P2PKH init stores pubKeyHash" {
    const expected = runar.hash160(runar.ALICE.pubKey);
    const contract = P2PKH.init(expected);
    try std.testing.expectEqualSlices(u8, expected, contract.pubKeyHash);
}

test "P2PKH unlock succeeds with the matching key and signature" {
    const contract = P2PKH.init(runar.hash160(runar.ALICE.pubKey));
    contract.unlock(runar.signTestMessage(runar.ALICE), runar.ALICE.pubKey);
}

test "P2PKH unlock rejects the wrong pubkey through the real contract assertion path" {
    try root.runar.expectAssertFailure(std.testing.allocator, "p2pkh-wrong-pubkey");
}

test "P2PKH unlock rejects the wrong signature through the real contract assertion path" {
    try root.runar.expectAssertFailure(std.testing.allocator, "p2pkh-wrong-sig");
}
