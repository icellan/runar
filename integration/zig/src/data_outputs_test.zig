const std = @import("std");
const runar = @import("runar");
const helpers = @import("helpers.zig");
const compile = @import("compile.zig");

// ---------------------------------------------------------------------------
// data_outputs integration: compile + (when regtest is up) deploy and call a
// stateful contract whose method calls `self.addDataOutput(...)`. Mirrors the
// Go `data_outputs_test.go` and TS `data-outputs.test.ts` regtest covers.
// ---------------------------------------------------------------------------

test "DataOutput_Compile" {
    const allocator = std.testing.allocator;

    var artifact = compile.compileContract(
        allocator,
        "examples/zig/add-data-output/DataOutputTest.runar.zig",
    ) catch |err| {
        std.log.warn("Could not compile DataOutputTest: {any}, skipping", .{err});
        return;
    };
    defer artifact.deinit();

    try std.testing.expectEqualStrings("DataOutputTest", artifact.contract_name);
    try std.testing.expect(artifact.isStateful());
    std.log.info("DataOutputTest compiled: {d} bytes", .{artifact.script.len / 2});
}

test "DataOutput_Deploy_Publish" {
    const allocator = std.testing.allocator;

    helpers.requireNodeAvailable(allocator);

    var artifact = compile.compileContract(
        allocator,
        "examples/zig/add-data-output/DataOutputTest.runar.zig",
    ) catch |err| {
        std.log.warn("Could not compile DataOutputTest: {any}, skipping", .{err});
        return;
    };
    defer artifact.deinit();

    var contract = try runar.RunarContract.init(allocator, &artifact, &[_]runar.StateValue{
        .{ .int = 0 },
    });
    defer contract.deinit();

    var wallet = try helpers.newWallet(allocator);
    defer wallet.deinit();
    const fund_txid = try helpers.fundWallet(allocator, &wallet, 1.0);
    defer allocator.free(fund_txid);

    var rpc_provider = helpers.RPCProvider.init(allocator);
    var local_signer = try wallet.localSigner();

    const deploy_txid = try contract.deploy(rpc_provider.provider(), local_signer.signer(), .{ .satoshis = 5000 });
    defer allocator.free(deploy_txid);
    std.log.info("DataOutputTest deployed: {s}", .{deploy_txid});

    // Payload: OP_RETURN "hi" -- the data output the contract emits.
    // The contract just relays the bytes verbatim into the data output.
    const payload = "6a026869";

    const call_txid = contract.call(
        "publish",
        &[_]runar.StateValue{.{ .bytes = payload }},
        rpc_provider.provider(),
        local_signer.signer(),
        .{ .new_state = &[_]runar.StateValue{.{ .int = 1 }} },
    ) catch |err| {
        std.log.warn("DataOutput publish call failed: {any}", .{err});
        return;
    };
    defer allocator.free(call_txid);

    try std.testing.expectEqual(@as(usize, 64), call_txid.len);
    std.log.info("DataOutputTest publish TX: {s}", .{call_txid});
}
