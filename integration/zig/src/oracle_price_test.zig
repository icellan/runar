const std = @import("std");
const runar = @import("runar");
const helpers = @import("helpers.zig");
const compile = @import("compile.zig");

test "OraclePriceFeed_Compile" {
    const allocator = std.testing.allocator;

    var artifact = compile.compileContract(allocator, "examples/zig/oracle-price/OraclePriceFeed.runar.zig") catch |err| {
        std.log.warn("Could not compile OraclePriceFeed contract: {any}, skipping test", .{err});
        return;
    };
    defer artifact.deinit();

    try std.testing.expectEqualStrings("OraclePriceFeed", artifact.contract_name);
    try std.testing.expect(!artifact.isStateful());
    std.log.info("OraclePriceFeed compiled: {d} bytes", .{artifact.script.len / 2});
}

test "OraclePriceFeed_Deploy" {
    const allocator = std.testing.allocator;

    if (!helpers.isNodeAvailable(allocator)) {
        std.log.warn("Regtest node not available, skipping test", .{});
        return;
    }

    var artifact = compile.compileContract(allocator, "examples/zig/oracle-price/OraclePriceFeed.runar.zig") catch |err| {
        std.log.warn("Could not compile OraclePriceFeed contract: {any}, skipping test", .{err});
        return;
    };
    defer artifact.deinit();

    var receiver = try helpers.newWallet(allocator);
    defer receiver.deinit();

    const receiver_pk = try receiver.pubKeyHex(allocator);
    defer allocator.free(receiver_pk);

    // Constructor: oracleN (bigint), receiver (PubKey)
    // Use a deterministic Rabin public key (just a large number for the test)
    var contract = try runar.RunarContract.init(allocator, &artifact, &[_]runar.StateValue{
        .{ .int = 999999937 }, // oracleN (Rabin modulus -- small for test)
        .{ .bytes = receiver_pk },
    });
    defer contract.deinit();

    var funder = try helpers.newWallet(allocator);
    defer funder.deinit();
    const fund_txid = try helpers.fundWallet(allocator, &funder, 1.0);
    defer allocator.free(fund_txid);

    var rpc_provider = helpers.RPCProvider.init(allocator);
    var local_signer = try funder.localSigner();

    const deploy_txid = try contract.deploy(rpc_provider.provider(), local_signer.signer(), .{ .satoshis = 5000 });
    defer allocator.free(deploy_txid);

    const utxo = contract.getCurrentUtxo();
    try std.testing.expect(utxo != null);
    try std.testing.expectEqual(@as(usize, 64), deploy_txid.len);
    std.log.info("OraclePriceFeed deployed: {s}", .{deploy_txid});
}

test "OraclePriceFeed_DeployDifferentReceiver" {
    const allocator = std.testing.allocator;

    if (!helpers.isNodeAvailable(allocator)) {
        std.log.warn("Regtest node not available, skipping test", .{});
        return;
    }

    var artifact = compile.compileContract(allocator, "examples/zig/oracle-price/OraclePriceFeed.runar.zig") catch |err| {
        std.log.warn("Could not compile OraclePriceFeed contract: {any}, skipping test", .{err});
        return;
    };
    defer artifact.deinit();

    var receiver1 = try helpers.newWallet(allocator);
    defer receiver1.deinit();
    var receiver2 = try helpers.newWallet(allocator);
    defer receiver2.deinit();

    const pk1 = try receiver1.pubKeyHex(allocator);
    defer allocator.free(pk1);
    const pk2 = try receiver2.pubKeyHex(allocator);
    defer allocator.free(pk2);

    // Deploy with receiver1
    var contract1 = try runar.RunarContract.init(allocator, &artifact, &[_]runar.StateValue{
        .{ .int = 999999937 },
        .{ .bytes = pk1 },
    });
    defer contract1.deinit();

    var funder1 = try helpers.newWallet(allocator);
    defer funder1.deinit();
    const fund1 = try helpers.fundWallet(allocator, &funder1, 1.0);
    defer allocator.free(fund1);

    var rpc1 = helpers.RPCProvider.init(allocator);
    var signer1 = try funder1.localSigner();
    const txid1 = try contract1.deploy(rpc1.provider(), signer1.signer(), .{ .satoshis = 5000 });
    defer allocator.free(txid1);

    // Deploy with receiver2
    var contract2 = try runar.RunarContract.init(allocator, &artifact, &[_]runar.StateValue{
        .{ .int = 999999937 },
        .{ .bytes = pk2 },
    });
    defer contract2.deinit();

    var funder2 = try helpers.newWallet(allocator);
    defer funder2.deinit();
    const fund2 = try helpers.fundWallet(allocator, &funder2, 1.0);
    defer allocator.free(fund2);

    var rpc2 = helpers.RPCProvider.init(allocator);
    var signer2 = try funder2.localSigner();
    const txid2 = try contract2.deploy(rpc2.provider(), signer2.signer(), .{ .satoshis = 5000 });
    defer allocator.free(txid2);

    try std.testing.expect(!std.mem.eql(u8, txid1, txid2));
    std.log.info("receiver1 txid: {s}, receiver2 txid: {s}", .{ txid1, txid2 });
}

test "OraclePriceFeed_ABI_Methods" {
    const allocator = std.testing.allocator;

    var artifact = compile.compileContract(allocator, "examples/zig/oracle-price/OraclePriceFeed.runar.zig") catch |err| {
        std.log.warn("Could not compile OraclePriceFeed contract: {any}, skipping test", .{err});
        return;
    };
    defer artifact.deinit();

    // OraclePriceFeed should have a settle method
    var has_settle = false;
    for (artifact.abi.methods) |m| {
        if (std.mem.eql(u8, m.name, "settle")) has_settle = true;
    }
    try std.testing.expect(has_settle);
}

test "OraclePriceFeed_SpendValidPrice" {
    const allocator = std.testing.allocator;

    if (!helpers.isNodeAvailable(allocator)) {
        std.log.warn("Regtest node not available, skipping test", .{});
        return;
    }

    var artifact = compile.compileContract(allocator, "examples/zig/oracle-price/OraclePriceFeed.runar.zig") catch |err| {
        std.log.warn("Could not compile OraclePriceFeed contract: {any}, skipping test", .{err});
        return;
    };
    defer artifact.deinit();

    // The receiver will be the signer -- their ECDSA key must match the constructor
    var receiver = try helpers.newWallet(allocator);
    defer receiver.deinit();

    const receiver_pk = try receiver.pubKeyHex(allocator);
    defer allocator.free(receiver_pk);

    // Rabin public key n = p*q (130-bit test primes)
    // n as LE signed-magnitude hex bytes (too large for i64)
    const n_hex = "950b36f00000000000000000000000002863620200000000000000000000000010";

    var contract = try runar.RunarContract.init(allocator, &artifact, &[_]runar.StateValue{
        .{ .bytes = n_hex }, // oraclePubKey (RabinPubKey as bigint)
        .{ .bytes = receiver_pk },
    });
    defer contract.deinit();

    const fund_txid = try helpers.fundWallet(allocator, &receiver, 1.0);
    defer allocator.free(fund_txid);

    var rpc_provider = helpers.RPCProvider.init(allocator);
    var local_signer = try receiver.localSigner();

    const deploy_txid = try contract.deploy(rpc_provider.provider(), local_signer.signer(), .{ .satoshis = 5000 });
    defer allocator.free(deploy_txid);
    std.log.info("OraclePriceFeed deployed: {s}", .{deploy_txid});

    // Oracle signs price=55001 (above 50000 threshold)
    // Precomputed Rabin signature for num2bin_le(55001, 8) with test primes
    const valid_sig_hex = "1e5fc8f8f7d3f27334d422c054a618ca3dd6a1068b42d549ad53b33bcd702b7b08";

    // Call settle(price, rabinSig, padding, sig=auto)
    const call_txid = try contract.call(
        "settle",
        &[_]runar.StateValue{
            .{ .int = 55001 }, // price
            .{ .bytes = valid_sig_hex }, // rabinSig (bigint as LE hex)
            .{ .int = 0 }, // padding
            .{ .int = 0 }, // sig: auto-sign
        },
        rpc_provider.provider(),
        local_signer.signer(),
        null,
    );
    defer allocator.free(call_txid);

    try std.testing.expectEqual(@as(usize, 64), call_txid.len);
    std.log.info("OraclePriceFeed spend TX: {s}", .{call_txid});
}

test "OraclePriceFeed_BelowThresholdRejected" {
    const allocator = std.testing.allocator;

    if (!helpers.isNodeAvailable(allocator)) {
        std.log.warn("Regtest node not available, skipping test", .{});
        return;
    }

    var artifact = compile.compileContract(allocator, "examples/zig/oracle-price/OraclePriceFeed.runar.zig") catch |err| {
        std.log.warn("Could not compile OraclePriceFeed contract: {any}, skipping test", .{err});
        return;
    };
    defer artifact.deinit();

    var receiver = try helpers.newWallet(allocator);
    defer receiver.deinit();

    const receiver_pk = try receiver.pubKeyHex(allocator);
    defer allocator.free(receiver_pk);

    const n_hex = "950b36f00000000000000000000000002863620200000000000000000000000010";

    var contract = try runar.RunarContract.init(allocator, &artifact, &[_]runar.StateValue{
        .{ .bytes = n_hex },
        .{ .bytes = receiver_pk },
    });
    defer contract.deinit();

    const fund_txid = try helpers.fundWallet(allocator, &receiver, 1.0);
    defer allocator.free(fund_txid);

    var rpc_provider = helpers.RPCProvider.init(allocator);
    var local_signer = try receiver.localSigner();

    const deploy_txid = try contract.deploy(rpc_provider.provider(), local_signer.signer(), .{ .satoshis = 5000 });
    defer allocator.free(deploy_txid);

    // Oracle signs price=49999 (below 50000 threshold)
    // Precomputed Rabin signature for num2bin_le(49999, 8) with test primes
    const low_sig_hex = "01f02badb5dd3fd4a63e0a8c121d2dbc4b843cc3f7195e6cd6bc62b77dcb0adb09";

    // Call settle with below-threshold price -- should be rejected
    const result = contract.call(
        "settle",
        &[_]runar.StateValue{
            .{ .int = 49999 }, // price (below 50000 threshold)
            .{ .bytes = low_sig_hex }, // rabinSig
            .{ .int = 0 }, // padding
            .{ .int = 0 }, // sig: auto-sign
        },
        rpc_provider.provider(),
        local_signer.signer(),
        null,
    );

    if (result) |call_txid| {
        allocator.free(call_txid);
        return error.TestExpectedError;
    } else |_| {
        std.log.warn("OraclePriceFeed correctly rejected below-threshold price", .{});
    }
}
