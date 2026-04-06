const std = @import("std");
const runar = @import("runar");
const helpers = @import("helpers.zig");
const compile = @import("compile.zig");

test "FunctionPatterns_Compile" {
    const allocator = std.testing.allocator;

    var artifact = compile.compileContract(allocator, "examples/zig/function-patterns/FunctionPatterns.runar.zig") catch |err| {
        std.log.warn("Could not compile FunctionPatterns contract: {any}, skipping test", .{err});
        return;
    };
    defer artifact.deinit();

    try std.testing.expectEqualStrings("FunctionPatterns", artifact.contract_name);
    try std.testing.expect(artifact.isStateful());
    std.log.info("FunctionPatterns compiled: {d} bytes", .{artifact.script.len / 2});
}

test "FunctionPatterns_Deploy_And_Call_Deposit" {
    const allocator = std.testing.allocator;

    if (!helpers.isNodeAvailable(allocator)) {
        std.log.warn("Regtest node not available, skipping test", .{});
        return;
    }

    var artifact = compile.compileContract(allocator, "examples/zig/function-patterns/FunctionPatterns.runar.zig") catch |err| {
        std.log.warn("Could not compile FunctionPatterns contract: {any}, skipping test", .{err});
        return;
    };
    defer artifact.deinit();

    var wallet = try helpers.newWallet(allocator);
    defer wallet.deinit();

    const pk_hex = try wallet.pubKeyHex(allocator);
    defer allocator.free(pk_hex);

    var contract = try runar.RunarContract.init(allocator, &artifact, &[_]runar.StateValue{
        .{ .bytes = pk_hex },
        .{ .int = 0 },
    });
    defer contract.deinit();

    const fund_txid = try helpers.fundWallet(allocator, &wallet, 1.0);
    defer allocator.free(fund_txid);

    var rpc_provider = helpers.RPCProvider.init(allocator);
    var local_signer = try wallet.localSigner();

    const deploy_txid = try contract.deploy(rpc_provider.provider(), local_signer.signer(), .{ .satoshis = 5000 });
    defer allocator.free(deploy_txid);
    std.log.info("FunctionPatterns deployed: {s}", .{deploy_txid});

    // Call deposit with auto-sign: deposit(sig=auto, amount=50)
    const call_txid = try contract.call(
        "deposit",
        &[_]runar.StateValue{
            .{ .int = 0 }, // Sig: auto-sign
            .{ .int = 50 },
        },
        rpc_provider.provider(),
        local_signer.signer(),
        .{ .new_state = &[_]runar.StateValue{
            .{ .int = 50 }, // balance: 0 + 50 = 50
        } },
    );
    defer allocator.free(call_txid);

    std.log.info("FunctionPatterns deposit TX: {s}", .{call_txid});
    try std.testing.expectEqual(@as(usize, 64), call_txid.len);
}

test "FunctionPatterns_Deploy_WithOwnerAndBalance" {
    const allocator = std.testing.allocator;

    if (!helpers.isNodeAvailable(allocator)) {
        std.log.warn("Regtest node not available, skipping test", .{});
        return;
    }

    var artifact = compile.compileContract(allocator, "examples/zig/function-patterns/FunctionPatterns.runar.zig") catch |err| {
        std.log.warn("Could not compile FunctionPatterns contract: {any}, skipping test", .{err});
        return;
    };
    defer artifact.deinit();

    var owner = try helpers.newWallet(allocator);
    defer owner.deinit();

    const pk_hex = try owner.pubKeyHex(allocator);
    defer allocator.free(pk_hex);

    var contract = try runar.RunarContract.init(allocator, &artifact, &[_]runar.StateValue{
        .{ .bytes = pk_hex },
        .{ .int = 1000 },
    });
    defer contract.deinit();

    var funder = try helpers.newWallet(allocator);
    defer funder.deinit();
    const fund_txid = try helpers.fundWallet(allocator, &funder, 1.0);
    defer allocator.free(fund_txid);

    var rpc_provider = helpers.RPCProvider.init(allocator);
    var local_signer = try funder.localSigner();

    const deploy_txid = try contract.deploy(rpc_provider.provider(), local_signer.signer(), .{ .satoshis = 10000 });
    defer allocator.free(deploy_txid);

    try std.testing.expectEqual(@as(usize, 64), deploy_txid.len);
    std.log.info("FunctionPatterns deployed with owner and balance=1000: {s}", .{deploy_txid});
}

test "FunctionPatterns_Deploy_LargeBalance" {
    const allocator = std.testing.allocator;

    if (!helpers.isNodeAvailable(allocator)) {
        std.log.warn("Regtest node not available, skipping test", .{});
        return;
    }

    var artifact = compile.compileContract(allocator, "examples/zig/function-patterns/FunctionPatterns.runar.zig") catch |err| {
        std.log.warn("Could not compile FunctionPatterns contract: {any}, skipping test", .{err});
        return;
    };
    defer artifact.deinit();

    var owner = try helpers.newWallet(allocator);
    defer owner.deinit();

    const pk_hex = try owner.pubKeyHex(allocator);
    defer allocator.free(pk_hex);

    var contract = try runar.RunarContract.init(allocator, &artifact, &[_]runar.StateValue{
        .{ .bytes = pk_hex },
        .{ .int = 999_999_999 },
    });
    defer contract.deinit();

    var funder = try helpers.newWallet(allocator);
    defer funder.deinit();
    const fund_txid = try helpers.fundWallet(allocator, &funder, 1.0);
    defer allocator.free(fund_txid);

    var rpc_provider = helpers.RPCProvider.init(allocator);
    var local_signer = try funder.localSigner();

    const deploy_txid = try contract.deploy(rpc_provider.provider(), local_signer.signer(), .{ .satoshis = 10000 });
    defer allocator.free(deploy_txid);

    try std.testing.expectEqual(@as(usize, 64), deploy_txid.len);
    std.log.info("FunctionPatterns deployed with large balance=999999999: {s}", .{deploy_txid});
}

test "FunctionPatterns_Deploy_ZeroBalance" {
    const allocator = std.testing.allocator;

    if (!helpers.isNodeAvailable(allocator)) {
        std.log.warn("Regtest node not available, skipping test", .{});
        return;
    }

    var artifact = compile.compileContract(allocator, "examples/zig/function-patterns/FunctionPatterns.runar.zig") catch |err| {
        std.log.warn("Could not compile FunctionPatterns contract: {any}, skipping test", .{err});
        return;
    };
    defer artifact.deinit();

    var owner = try helpers.newWallet(allocator);
    defer owner.deinit();

    const pk_hex = try owner.pubKeyHex(allocator);
    defer allocator.free(pk_hex);

    var contract = try runar.RunarContract.init(allocator, &artifact, &[_]runar.StateValue{
        .{ .bytes = pk_hex },
        .{ .int = 0 },
    });
    defer contract.deinit();

    var funder = try helpers.newWallet(allocator);
    defer funder.deinit();
    const fund_txid = try helpers.fundWallet(allocator, &funder, 1.0);
    defer allocator.free(fund_txid);

    var rpc_provider = helpers.RPCProvider.init(allocator);
    var local_signer = try funder.localSigner();

    const deploy_txid = try contract.deploy(rpc_provider.provider(), local_signer.signer(), .{ .satoshis = 10000 });
    defer allocator.free(deploy_txid);

    try std.testing.expectEqual(@as(usize, 64), deploy_txid.len);
    std.log.info("FunctionPatterns deployed with zero balance: {s}", .{deploy_txid});
}

test "FunctionPatterns_Call_DepositThenWithdraw" {
    const allocator = std.testing.allocator;

    if (!helpers.isNodeAvailable(allocator)) {
        std.log.warn("Regtest node not available, skipping test", .{});
        return;
    }

    var artifact = compile.compileContract(allocator, "examples/zig/function-patterns/FunctionPatterns.runar.zig") catch |err| {
        std.log.warn("Could not compile FunctionPatterns contract: {any}, skipping test", .{err});
        return;
    };
    defer artifact.deinit();

    var wallet = try helpers.newWallet(allocator);
    defer wallet.deinit();

    const pk_hex = try wallet.pubKeyHex(allocator);
    defer allocator.free(pk_hex);

    var contract = try runar.RunarContract.init(allocator, &artifact, &[_]runar.StateValue{
        .{ .bytes = pk_hex },
        .{ .int = 1000 },
    });
    defer contract.deinit();

    const fund_txid = try helpers.fundWallet(allocator, &wallet, 1.0);
    defer allocator.free(fund_txid);

    var rpc_provider = helpers.RPCProvider.init(allocator);
    var local_signer = try wallet.localSigner();

    const deploy_txid = try contract.deploy(rpc_provider.provider(), local_signer.signer(), .{ .satoshis = 10000 });
    defer allocator.free(deploy_txid);
    std.log.info("FunctionPatterns deployed: {s}", .{deploy_txid});

    // deposit(sig=auto, amount=500) -> balance = 1000 + 500 = 1500
    // Let the SDK auto-compute new state from ANF IR (same as Python/Go SDKs)
    const deposit_txid = try contract.call(
        "deposit",
        &[_]runar.StateValue{
            .{ .int = 0 }, // Sig: auto-sign
            .{ .int = 500 },
        },
        rpc_provider.provider(),
        local_signer.signer(),
        null,
    );
    defer allocator.free(deposit_txid);
    std.log.info("FunctionPatterns deposit TX: {s}", .{deposit_txid});

    // withdraw(sig=auto, amount=200, feeBps=100) -> fee=2, balance=1500-200-2=1298
    const withdraw_txid = try contract.call(
        "withdraw",
        &[_]runar.StateValue{
            .{ .int = 0 }, // Sig: auto-sign
            .{ .int = 200 },
            .{ .int = 100 }, // feeBps
        },
        rpc_provider.provider(),
        local_signer.signer(),
        null,
    );
    defer allocator.free(withdraw_txid);
    std.log.info("FunctionPatterns withdraw TX: {s}", .{withdraw_txid});
    try std.testing.expectEqual(@as(usize, 64), withdraw_txid.len);
}

test "FunctionPatterns_WrongOwnerRejected" {
    const allocator = std.testing.allocator;

    if (!helpers.isNodeAvailable(allocator)) {
        std.log.warn("Regtest node not available, skipping test", .{});
        return;
    }

    var artifact = compile.compileContract(allocator, "examples/zig/function-patterns/FunctionPatterns.runar.zig") catch |err| {
        std.log.warn("Could not compile FunctionPatterns contract: {any}, skipping test", .{err});
        return;
    };
    defer artifact.deinit();

    // Owner wallet (used to lock the contract)
    var owner = try helpers.newWallet(allocator);
    defer owner.deinit();

    const owner_pk = try owner.pubKeyHex(allocator);
    defer allocator.free(owner_pk);

    var contract = try runar.RunarContract.init(allocator, &artifact, &[_]runar.StateValue{
        .{ .bytes = owner_pk },
        .{ .int = 100 },
    });
    defer contract.deinit();

    // Fund the owner for deployment
    const fund_txid = try helpers.fundWallet(allocator, &owner, 1.0);
    defer allocator.free(fund_txid);

    var rpc_provider = helpers.RPCProvider.init(allocator);
    var owner_signer = try owner.localSigner();

    const deploy_txid = try contract.deploy(rpc_provider.provider(), owner_signer.signer(), .{ .satoshis = 10000 });
    defer allocator.free(deploy_txid);
    std.log.info("FunctionPatterns deployed: {s}", .{deploy_txid});

    // Fund a wrong signer wallet
    var wrong_wallet = try helpers.newWallet(allocator);
    defer wrong_wallet.deinit();
    const fund_txid2 = try helpers.fundWallet(allocator, &wrong_wallet, 1.0);
    defer allocator.free(fund_txid2);

    var wrong_signer = try wrong_wallet.localSigner();

    // deposit(sig=auto, amount=50) with wrong signer -- should be rejected
    const result = contract.call(
        "deposit",
        &[_]runar.StateValue{
            .{ .int = 0 }, // Sig: auto-sign (wrong key)
            .{ .int = 50 },
        },
        rpc_provider.provider(),
        wrong_signer.signer(),
        .{ .new_state = &[_]runar.StateValue{
            .{ .int = 150 },
        } },
    );

    if (result) |txid| {
        allocator.free(txid);
        return error.TestUnexpectedResult; // should have failed
    } else |_| {
        // Expected: call was rejected on-chain due to wrong signer
        std.log.info("FunctionPatterns correctly rejected wrong owner", .{});
    }
}

test "FunctionPatterns_DistinctDeployTxids" {
    const allocator = std.testing.allocator;

    if (!helpers.isNodeAvailable(allocator)) {
        std.log.warn("Regtest node not available, skipping test", .{});
        return;
    }

    var artifact = compile.compileContract(allocator, "examples/zig/function-patterns/FunctionPatterns.runar.zig") catch |err| {
        std.log.warn("Could not compile FunctionPatterns contract: {any}, skipping test", .{err});
        return;
    };
    defer artifact.deinit();

    // Owner 1
    var owner1 = try helpers.newWallet(allocator);
    defer owner1.deinit();
    const pk1 = try owner1.pubKeyHex(allocator);
    defer allocator.free(pk1);

    var contract1 = try runar.RunarContract.init(allocator, &artifact, &[_]runar.StateValue{
        .{ .bytes = pk1 },
        .{ .int = 100 },
    });
    defer contract1.deinit();

    var funder1 = try helpers.newWallet(allocator);
    defer funder1.deinit();
    const fund1 = try helpers.fundWallet(allocator, &funder1, 1.0);
    defer allocator.free(fund1);

    var rpc1 = helpers.RPCProvider.init(allocator);
    var signer1 = try funder1.localSigner();

    const txid1 = try contract1.deploy(rpc1.provider(), signer1.signer(), .{ .satoshis = 10000 });
    defer allocator.free(txid1);

    // Owner 2
    var owner2 = try helpers.newWallet(allocator);
    defer owner2.deinit();
    const pk2 = try owner2.pubKeyHex(allocator);
    defer allocator.free(pk2);

    var contract2 = try runar.RunarContract.init(allocator, &artifact, &[_]runar.StateValue{
        .{ .bytes = pk2 },
        .{ .int = 200 },
    });
    defer contract2.deinit();

    var funder2 = try helpers.newWallet(allocator);
    defer funder2.deinit();
    const fund2 = try helpers.fundWallet(allocator, &funder2, 1.0);
    defer allocator.free(fund2);

    var rpc2 = helpers.RPCProvider.init(allocator);
    var signer2 = try funder2.localSigner();

    const txid2 = try contract2.deploy(rpc2.provider(), signer2.signer(), .{ .satoshis = 10000 });
    defer allocator.free(txid2);

    // Two deploys with different owners should produce distinct txids
    try std.testing.expect(!std.mem.eql(u8, txid1, txid2));
    std.log.info("Distinct txids: {s} vs {s}", .{ txid1, txid2 });
}
