const std = @import("std");
const root = @import("../examples_test.zig");
const runar = @import("runar");
const R1K1Wallet = @import("R1K1Wallet.runar.zig").R1K1Wallet;

fn contractPath(comptime basename: []const u8) []const u8 {
    return "r1-k1-wallet/" ++ basename;
}

fn runCompileChecks(comptime basename: []const u8) !void {
    try root.runar.compileCheckSource(std.testing.allocator, @embedFile(basename), basename);
    try root.runar.compileCheckFile(std.testing.allocator, contractPath(basename));
}

test "compile-check R1K1Wallet.runar.zig" {
    try runCompileChecks("R1K1Wallet.runar.zig");
}

// Proves: recoverK1() requires hash160(k1PubKey) == k1PubKeyHash AND a valid signature, and aborts on either mismatch.
// Does not prove: spendR1 (runar.verifyECDSA_P256 and the preimage plumbing have no native implementation) or the R1 salted-key path.

test "R1K1Wallet recoverK1 accepts the committed K1 key and its signature" {
    const c = R1K1Wallet.init(runar.hash160("r1"), runar.hash160(runar.ALICE.pubKey));
    c.recoverK1(runar.signTestMessage(runar.ALICE), runar.ALICE.pubKey);
}

test "R1K1Wallet recoverK1 rejects a key that does not hash to the commitment" {
    try root.expectAssertFailure("r1-k1-wallet-wrong-k1-key");
}

test "R1K1Wallet recoverK1 rejects a bad signature" {
    try root.expectAssertFailure("r1-k1-wallet-wrong-k1-sig");
}
