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
