const std = @import("std");
const runar = @import("runar");
const helpers = @import("helpers.zig");
const compile = @import("compile.zig");

// ---------------------------------------------------------------------------
// SLH-DSA integration: compile + (when regtest is up) deploy a contract that
// exposes verifySLHDSA_SHA2_128s as a spending condition. The Zig SDK does
// not currently expose an SLH-DSA keygen/sign helper, so this test covers
// the *deployment* path only — script-size sanity, IR integrity, and that a
// real BSV node accepts the locking script.
//
// Mirrors the Go `slhdsa_test.go` regtest cover; the spending half (which
// requires an SLH-DSA keypair) is exercised in the existing
// `sphincs_wallet_test.zig`, which uses the hybrid ECDSA+SLH-DSA wallet.
// ---------------------------------------------------------------------------

test "SLHDSA_Compile" {
    const allocator = std.testing.allocator;

    var artifact = try compile.compileContract(
        allocator,
        "examples/zig/post-quantum-slhdsa-naive-INSECURE/PostQuantumSLHDSANaiveInsecure.runar.zig",
    );
    defer artifact.deinit();

    try std.testing.expectEqualStrings("PostQuantumSLHDSANaiveInsecure", artifact.contract_name);
    const script_bytes = artifact.script.len / 2;
    // SLH-DSA-SHA2-128s inlined verifier is ~100-300 KB.
    try std.testing.expect(script_bytes > 50_000);
    std.log.info("PostQuantumSLHDSANaiveInsecure compiled: {d} bytes", .{script_bytes});
}

test "SLHDSA_Deploy" {
    const allocator = std.testing.allocator;

    helpers.requireNodeAvailable(allocator);

    var artifact = try compile.compileContract(
        allocator,
        "examples/zig/post-quantum-slhdsa-naive-INSECURE/PostQuantumSLHDSANaiveInsecure.runar.zig",
    );
    defer artifact.deinit();

    // Use a deterministic placeholder pubkey. Spending is not exercised
    // here (no keygen helper); see sphincs_wallet_test.zig for the
    // hybrid-wallet end-to-end path.
    const placeholder = "00".* ** 32;
    const pubkey_hex = try allocator.dupe(u8, &placeholder);
    defer allocator.free(pubkey_hex);

    var contract = try runar.RunarContract.init(allocator, &artifact, &[_]runar.StateValue{
        .{ .bytes = pubkey_hex },
    });
    defer contract.deinit();

    var wallet = try helpers.newWallet(allocator);
    defer wallet.deinit();
    const fund_txid = try helpers.fundWallet(allocator, &wallet, 1.0);
    defer allocator.free(fund_txid);

    var rpc_provider = helpers.RPCProvider.init(allocator);
    var local_signer = try wallet.localSigner();

    const deploy_txid = try contract.deploy(rpc_provider.provider(), local_signer.signer(), .{ .satoshis = 1_000_000 });
    defer allocator.free(deploy_txid);

    try std.testing.expectEqual(@as(usize, 64), deploy_txid.len);
    std.log.info("PostQuantumSLHDSANaiveInsecure deployed: {s}", .{deploy_txid});
}
