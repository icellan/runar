const std = @import("std");
const root = @import("../examples_test.zig");
const runar = @import("runar");
const WalletToken = @import("WalletToken.runar.zig").WalletToken;

fn contractPath(comptime basename: []const u8) []const u8 {
    return "token-wallet-naive-INSECURE/" ++ basename;
}

fn runCompileChecks(comptime basename: []const u8) !void {
    try root.runar.compileCheckSource(std.testing.allocator, @embedFile(basename), basename);
    try root.runar.compileCheckFile(std.testing.allocator, contractPath(basename));
}

test "compile-check WalletToken.runar.zig" {
    try runCompileChecks("WalletToken.runar.zig");
}

// PEDAGOGY: naive-INSECURE. merge() cannot authenticate its companion input (see the contract header), so the tests below prove only what the contract does check: the holder's signature, the holder match, the 20-byte address and a non-negative supply.
// Does not prove: that a merge is bound to a real second input; natively it is not, which is the documented flaw.

test "WalletToken transfer accepts the holder signature and a 20-byte address" {
    const c = WalletToken.init(100, runar.ALICE.pubKey);
    c.transfer(runar.signTestMessage(runar.ALICE), runar.hash160(runar.BOB.pubKey));
}

test "WalletToken merge adds the other supply for the same holder" {
    var c = WalletToken.init(100, runar.ALICE.pubKey);
    c.merge(runar.signTestMessage(runar.ALICE), 50, runar.ALICE.pubKey);
    try std.testing.expectEqual(@as(i64, 150), c.supply);
}

test "WalletToken rejects transfer with the wrong signature" {
    try root.expectAssertFailure("token-wallet-transfer-wrong-sig");
}

test "WalletToken rejects transfer to a non-20-byte address" {
    try root.expectAssertFailure("token-wallet-transfer-short-addr");
}

test "WalletToken rejects merge with the wrong signature" {
    try root.expectAssertFailure("token-wallet-merge-wrong-sig");
}

test "WalletToken rejects merge with a different holder" {
    try root.expectAssertFailure("token-wallet-merge-other-holder");
}

test "WalletToken rejects merge with a negative other supply" {
    try root.expectAssertFailure("token-wallet-merge-negative-supply");
}
