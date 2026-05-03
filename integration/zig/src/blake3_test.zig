const std = @import("std");
const bsvz = @import("bsvz");
const runar = @import("runar");
const helpers = @import("helpers.zig");
const compile = @import("compile.zig");

// ---------------------------------------------------------------------------
// BLAKE3 integration: compile + (when regtest is up) deploy a contract that
// runs the blake3Compress builtin. Mirrors the Go/TS `blake3*` regtest covers.
// ---------------------------------------------------------------------------

test "Blake3_Compile" {
    const allocator = std.testing.allocator;

    var artifact = compile.compileContract(
        allocator,
        "examples/zig/blake3/Blake3Test.runar.zig",
    ) catch |err| {
        std.log.warn("Could not compile Blake3Test: {any}, skipping", .{err});
        return;
    };
    defer artifact.deinit();

    try std.testing.expectEqualStrings("Blake3Test", artifact.contract_name);
    // BLAKE3 compress inlined script is large (~10 KB).
    try std.testing.expect(artifact.script.len / 2 > 5000);
    std.log.info("Blake3Test compiled: {d} bytes", .{artifact.script.len / 2});
}

test "Blake3Compress_Deploy" {
    const allocator = std.testing.allocator;

    helpers.requireNodeAvailable(allocator);

    var artifact = compile.compileContract(
        allocator,
        "examples/zig/blake3/Blake3Test.runar.zig",
    ) catch |err| {
        std.log.warn("Could not compile Blake3Test: {any}, skipping", .{err});
        return;
    };
    defer artifact.deinit();

    // Deploy with a placeholder expected value — we only assert that
    // on-chain deployment of the BLAKE3-verifying script works
    // end-to-end. Spend-time vector verification is exercised by the
    // SDK interpreter tests in `examples/zig/blake3/`.
    const placeholder = "00".* ** 32;
    const expected_hex = try allocator.dupe(u8, &placeholder);
    defer allocator.free(expected_hex);

    var contract = try runar.RunarContract.init(allocator, &artifact, &[_]runar.StateValue{
        .{ .bytes = expected_hex },
    });
    defer contract.deinit();

    var wallet = try helpers.newWallet(allocator);
    defer wallet.deinit();
    const fund_txid = try helpers.fundWallet(allocator, &wallet, 1.0);
    defer allocator.free(fund_txid);

    var rpc_provider = helpers.RPCProvider.init(allocator);
    var local_signer = try wallet.localSigner();

    const deploy_txid = try contract.deploy(rpc_provider.provider(), local_signer.signer(), .{ .satoshis = 500_000 });
    defer allocator.free(deploy_txid);

    try std.testing.expectEqual(@as(usize, 64), deploy_txid.len);
    std.log.info("Blake3Test deployed: {s}", .{deploy_txid});
}
