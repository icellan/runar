const std = @import("std");
const root = @import("../examples_test.zig");
const runar = @import("runar");
const fixtures = @import("fixtures.zig");
const SPHINCSWallet = @import("SPHINCSWallet.runar.zig").SPHINCSWallet;

fn contractPath(comptime basename: []const u8) []const u8 {
    return "sphincs-wallet/" ++ basename;
}

fn runCompileChecks(comptime basename: []const u8) !void {
    try root.runar.compileCheckSource(std.testing.allocator, @embedFile(basename), basename);
    try root.runar.compileCheckFile(std.testing.allocator, contractPath(basename));
}

test "compile-check SPHINCSWallet.runar.zig" {
    try runCompileChecks("SPHINCSWallet.runar.zig");
}

test "SPHINCSWallet init stores both authorization hashes" {
    const ecdsa_hash = runar.hash160(runar.ALICE.pubKey);
    const slhdsa_hash = runar.hash160(&fixtures.slhdsa_pub_key);
    const contract = SPHINCSWallet.init(ecdsa_hash, slhdsa_hash);

    try std.testing.expectEqualSlices(u8, ecdsa_hash, contract.ecdsaPubKeyHash);
    try std.testing.expectEqualSlices(u8, slhdsa_hash, contract.slhdsaPubKeyHash);
    try std.testing.expectEqualSlices(u8, &fixtures.slhdsa_pub_key_hash, contract.slhdsaPubKeyHash);
}

test "SPHINCSWallet spend accepts real ECDSA and SLH-DSA authorization" {
    const ecdsa_sig = runar.signTestMessage(runar.ALICE);
    const slhdsa_sig = try runar.hex.decodeAlloc(std.testing.allocator, fixtures.slhdsa_sig_hex);
    const slhdsa_pub_key = try runar.hex.decodeAlloc(std.testing.allocator, fixtures.slhdsa_pub_key_hex);
    defer std.testing.allocator.free(slhdsa_sig);
    defer std.testing.allocator.free(slhdsa_pub_key);

    try std.testing.expectEqualSlices(u8, &[_]u8{
        0x30, 0x45, 0x02, 0x21, 0x00, 0xe2, 0xaa, 0x12,
        0x65, 0xce, 0x57, 0xf5, 0x4b, 0x98, 0x1f, 0xfc,
        0x6a, 0x5f, 0x3d, 0x22, 0x9e, 0x90, 0x8d, 0x77,
        0x72, 0xfc, 0xeb, 0x75, 0xa5, 0x0c, 0x8c, 0x2d,
        0x60, 0x76, 0x31, 0x3d, 0xf0, 0x02, 0x20, 0x60,
        0x7d, 0xbc, 0xa2, 0xf9, 0xf6, 0x95, 0x43, 0x8b,
        0x49, 0xee, 0xfe, 0xa4, 0xe4, 0x45, 0x66, 0x4c,
        0x74, 0x01, 0x63, 0xaf, 0x8b, 0x62, 0xb1, 0x37,
        0x3f, 0x87, 0xd5, 0x0e, 0xb6, 0x44, 0x17,
    }, ecdsa_sig);

    try std.testing.expect(runar.verifySLHDSA_SHA2_128s(ecdsa_sig, slhdsa_sig, &fixtures.slhdsa_pub_key));
    try std.testing.expect(runar.verifySLHDSA_SHA2_128s(ecdsa_sig, slhdsa_sig, slhdsa_pub_key));

    const contract = SPHINCSWallet.init(
        runar.hash160(runar.ALICE.pubKey),
        runar.hash160(&fixtures.slhdsa_pub_key),
    );

    contract.spend(slhdsa_sig, &fixtures.slhdsa_pub_key, ecdsa_sig, runar.ALICE.pubKey);
}

test "SPHINCSWallet rejects invalid authorization paths through the real contract" {
    try root.expectAssertFailure("sphincs-wallet-wrong-ecdsa-pubkey");
    try root.expectAssertFailure("sphincs-wallet-wrong-ecdsa-sig");
    try root.expectAssertFailure("sphincs-wallet-wrong-slhdsa-key");
    try root.expectAssertFailure("sphincs-wallet-invalid-slhdsa-proof");
}
