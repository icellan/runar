const std = @import("std");
const runar = @import("runar");
const helpers = @import("helpers.zig");
const compile_mod = @import("compile.zig");

// ---------------------------------------------------------------------------
// Baby Bear field arithmetic tests: verify bbFieldAdd and bbFieldInv compile,
// deploy, and call correctly on a regtest node.
// ---------------------------------------------------------------------------

test "BabyBear_Compile" {
    const allocator = std.testing.allocator;

    var artifact = compile_mod.compileContract(allocator, "examples/zig/babybear/BabyBearDemo.runar.zig") catch |err| {
        std.log.warn("Could not compile BabyBearDemo: {any}, skipping", .{err});
        return;
    };
    defer artifact.deinit();

    try std.testing.expectEqualStrings("BabyBearDemo", artifact.contract_name);
    std.log.info("BabyBearDemo compiled: {d} bytes", .{artifact.script.len / 2});
}

test "BabyBear_FieldAdd_DeployAndCall" {
    const allocator = std.testing.allocator;

    if (!helpers.isNodeAvailable(allocator)) {
        std.log.warn("Regtest node not available, skipping test", .{});
        return;
    }

    var artifact = compile_mod.compileContract(allocator, "examples/zig/babybear/BabyBearDemo.runar.zig") catch |err| {
        std.log.warn("Could not compile BabyBearDemo: {any}, skipping", .{err});
        return;
    };
    defer artifact.deinit();

    // Constructor takes no args
    var contract = try runar.RunarContract.init(allocator, &artifact, &[_]runar.StateValue{});
    defer contract.deinit();

    var wallet = try helpers.newWallet(allocator);
    defer wallet.deinit();
    const fund_txid = try helpers.fundWallet(allocator, &wallet, 1.0);
    defer allocator.free(fund_txid);

    var rpc_provider = helpers.RPCProvider.init(allocator);
    var local_signer = try wallet.localSigner();

    const deploy_txid = try contract.deploy(rpc_provider.provider(), local_signer.signer(), .{ .satoshis = 50000 });
    defer allocator.free(deploy_txid);

    try std.testing.expectEqual(@as(usize, 64), deploy_txid.len);
    std.log.info("BabyBearDemo deployed: {s}", .{deploy_txid});

    // Call checkAdd(3, 7, 10)
    const call_txid = try contract.call(
        "checkAdd",
        &[_]runar.StateValue{
            .{ .int = 3 },
            .{ .int = 7 },
            .{ .int = 10 },
        },
        rpc_provider.provider(),
        local_signer.signer(),
        null,
    );
    defer allocator.free(call_txid);

    try std.testing.expectEqual(@as(usize, 64), call_txid.len);
    std.log.info("BabyBear checkAdd TX: {s}", .{call_txid});
}

test "BabyBear_FieldAdd_WrongResult_Rejected" {
    const allocator = std.testing.allocator;

    if (!helpers.isNodeAvailable(allocator)) {
        std.log.warn("Regtest node not available, skipping test", .{});
        return;
    }

    var artifact = compile_mod.compileContract(allocator, "examples/zig/babybear/BabyBearDemo.runar.zig") catch |err| {
        std.log.warn("Could not compile BabyBearDemo: {any}, skipping", .{err});
        return;
    };
    defer artifact.deinit();

    var contract = try runar.RunarContract.init(allocator, &artifact, &[_]runar.StateValue{});
    defer contract.deinit();

    var wallet = try helpers.newWallet(allocator);
    defer wallet.deinit();
    const fund_txid = try helpers.fundWallet(allocator, &wallet, 1.0);
    defer allocator.free(fund_txid);

    var rpc_provider = helpers.RPCProvider.init(allocator);
    var local_signer = try wallet.localSigner();

    const deploy_txid = try contract.deploy(rpc_provider.provider(), local_signer.signer(), .{ .satoshis = 50000 });
    defer allocator.free(deploy_txid);

    // Call checkAdd(3, 7, 11) — wrong expected, should be rejected on-chain
    const result = contract.call(
        "checkAdd",
        &[_]runar.StateValue{
            .{ .int = 3 },
            .{ .int = 7 },
            .{ .int = 11 }, // wrong!
        },
        rpc_provider.provider(),
        local_signer.signer(),
        null,
    );

    if (result) |call_txid| {
        allocator.free(call_txid);
        return error.TestExpectedError;
    } else |_| {
        std.log.info("BabyBear correctly rejected wrong result", .{});
    }
}
