const std = @import("std");
const runar = @import("runar");
const helpers = @import("helpers.zig");
const compile = @import("compile.zig");

// ---------------------------------------------------------------------------
// sha256Finalize integration: compile + (when regtest is up) deploy a
// contract that runs the sha256Finalize builtin. Mirrors the Go/TS
// `sha256-finalize` regtest covers.
// ---------------------------------------------------------------------------

test "Sha256Finalize_Compile" {
    const allocator = std.testing.allocator;

    var artifact = try compile.compileContract(
        allocator,
        "examples/zig/sha256-finalize/Sha256FinalizeTest.runar.zig",
    );
    defer artifact.deinit();

    try std.testing.expectEqualStrings("Sha256FinalizeTest", artifact.contract_name);
    std.log.info("Sha256FinalizeTest compiled: {d} bytes", .{artifact.script.len / 2});
}

test "Sha256Finalize_Deploy" {
    const allocator = std.testing.allocator;

    helpers.requireNodeAvailable(allocator);

    var artifact = try compile.compileContract(
        allocator,
        "examples/zig/sha256-finalize/Sha256FinalizeTest.runar.zig",
    );
    defer artifact.deinit();

    // Construct with an arbitrary expected — we only assert deployment
    // succeeds end-to-end here. A spending test would require computing
    // sha256 of a specific message, supplying the post-block-N state,
    // remaining tail bytes, and message bit length; that flow is
    // exercised in `examples/zig/sha256-finalize/` interpreter tests.
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

    const deploy_txid = try contract.deploy(rpc_provider.provider(), local_signer.signer(), .{ .satoshis = 200_000 });
    defer allocator.free(deploy_txid);

    try std.testing.expectEqual(@as(usize, 64), deploy_txid.len);
    std.log.info("Sha256FinalizeTest deployed: {s}", .{deploy_txid});
}
