const std = @import("std");
const root = @import("../examples_test.zig");
const runar = @import("runar");
const OrdinalNFT = @import("OrdinalNFT.runar.zig").OrdinalNFT;

fn contractPath(comptime basename: []const u8) []const u8 {
    return "ordinal-nft/" ++ basename;
}

fn runCompileChecks(comptime basename: []const u8) !void {
    try root.runar.compileCheckSource(std.testing.allocator, @embedFile(basename), basename);
    try root.runar.compileCheckFile(std.testing.allocator, contractPath(basename));
}

test "compile-check OrdinalNFT.runar.zig" {
    try runCompileChecks("OrdinalNFT.runar.zig");
}

test "OrdinalNFT init stores pubKeyHash" {
    const expected = runar.hash160(runar.ALICE.pubKey);
    const contract = OrdinalNFT.init(expected);
    try std.testing.expectEqualSlices(u8, expected, contract.pubKeyHash);
}

test "OrdinalNFT unlock succeeds with the matching key and signature" {
    const contract = OrdinalNFT.init(runar.hash160(runar.ALICE.pubKey));
    contract.unlock(runar.signTestMessage(runar.ALICE), runar.ALICE.pubKey);
}

test "OrdinalNFT unlock rejects the wrong pubkey through the real contract assertion path" {
    try root.runar.expectAssertFailure(std.testing.allocator, "ordinal-nft-wrong-pubkey");
}

test "OrdinalNFT unlock rejects the wrong signature through the real contract assertion path" {
    try root.runar.expectAssertFailure(std.testing.allocator, "ordinal-nft-wrong-sig");
}
