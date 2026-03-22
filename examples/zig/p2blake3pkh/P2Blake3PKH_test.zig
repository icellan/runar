const std = @import("std");
const root = @import("../examples_test.zig");
const runar = @import("runar");
const P2Blake3PKH = @import("P2Blake3PKH.runar.zig").P2Blake3PKH;

fn contractPath(comptime basename: []const u8) []const u8 {
    return "p2blake3pkh/" ++ basename;
}

fn runCompileChecks(comptime basename: []const u8) !void {
    try root.runar.compileCheckSource(std.testing.allocator, @embedFile(basename), basename);
    try root.runar.compileCheckFile(std.testing.allocator, contractPath(basename));
}

test "compile-check P2Blake3PKH.runar.zig" {
    try runCompileChecks("P2Blake3PKH.runar.zig");
}

test "P2Blake3PKH init stores pubKeyHash" {
    const expected = runar.blake3Hash(runar.ALICE.pubKey);
    const contract = P2Blake3PKH.init(expected);
    try std.testing.expectEqualSlices(u8, expected, contract.pubKeyHash);
}

test "P2Blake3PKH unlock succeeds with the matching key and signature" {
    const contract = P2Blake3PKH.init(runar.blake3Hash(runar.ALICE.pubKey));
    contract.unlock(runar.signTestMessage(runar.ALICE), runar.ALICE.pubKey);
}

test "P2Blake3PKH unlock rejects the wrong pubkey through the real contract assertion path" {
    try root.runar.expectAssertFailure(std.testing.allocator, "p2blake3pkh-wrong-pubkey");
}

test "P2Blake3PKH unlock rejects the wrong signature through the real contract assertion path" {
    try root.runar.expectAssertFailure(std.testing.allocator, "p2blake3pkh-wrong-sig");
}
