const std = @import("std");
const root = @import("../examples_test.zig");
const runar = @import("runar");
const PostQuantumWallet = @import("PostQuantumWallet.runar.zig").PostQuantumWallet;

fn contractPath(comptime basename: []const u8) []const u8 {
    return "post-quantum-wallet/" ++ basename;
}

fn runCompileChecks(comptime basename: []const u8) !void {
    try root.runar.compileCheckSource(std.testing.allocator, @embedFile(basename), basename);
    try root.runar.compileCheckFile(std.testing.allocator, contractPath(basename));
}

test "compile-check PostQuantumWallet.runar.zig" {
    try runCompileChecks("PostQuantumWallet.runar.zig");
}

test "PostQuantumWallet init stores both authorization hashes" {
    const ecdsa_hash = runar.hash160(runar.ALICE.pubKey);
    const wots_pub_key = "wots-pub-key";
    const wots_hash = runar.hash160(wots_pub_key);
    const contract = PostQuantumWallet.init(ecdsa_hash, wots_hash);

    try std.testing.expectEqualSlices(u8, ecdsa_hash, contract.ecdsaPubKeyHash);
    try std.testing.expectEqualSlices(u8, wots_hash, contract.wotsPubKeyHash);
}

test "PostQuantumWallet spend accepts real ECDSA and WOTS authorization" {
    const ecdsa_sig = runar.signTestMessage(runar.ALICE);
    const seed = [_]u8{0x42} ** 32;
    const pub_seed = [_]u8{0x13} ** 32;
    const wots_pub_key = runar.testing.wotsPublicKeyFromSeed(&seed, &pub_seed);
    const wots_sig = runar.testing.wotsSignDeterministic(ecdsa_sig, &seed, &pub_seed);

    const contract = PostQuantumWallet.init(
        runar.hash160(runar.ALICE.pubKey),
        runar.hash160(&wots_pub_key),
    );

    contract.spend(&wots_sig, &wots_pub_key, ecdsa_sig, runar.ALICE.pubKey);
}

test "PostQuantumWallet rejects invalid authorization paths through the real contract" {
    try root.expectAssertFailure("post-quantum-wallet-wrong-ecdsa-pubkey");
    try root.expectAssertFailure("post-quantum-wallet-wrong-ecdsa-sig");
    try root.expectAssertFailure("post-quantum-wallet-wrong-wots-key");
    try root.expectAssertFailure("post-quantum-wallet-invalid-wots-proof");
}
