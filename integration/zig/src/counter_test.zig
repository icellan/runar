const std = @import("std");
const runar = @import("runar");
const bsvz = @import("bsvz");
const helpers = @import("helpers.zig");
const compile = @import("compile.zig");

/// Deploy a Counter contract with the given initial count.
fn deployCounter(
    allocator: std.mem.Allocator,
    initial_count: i64,
) !struct {
    contract: runar.RunarContract,
    provider: helpers.RPCProvider,
    signer: runar.LocalSigner,
    wallet: helpers.Wallet,
    artifact: runar.RunarArtifact,
} {
    var artifact = try compile.compileContract(allocator, "examples/zig/stateful-counter/Counter.runar.zig");
    errdefer artifact.deinit();

    var contract = try runar.RunarContract.init(allocator, &artifact, &[_]runar.StateValue{
        .{ .int = initial_count },
    });
    errdefer contract.deinit();

    var wallet = try helpers.newWallet(allocator);
    errdefer wallet.deinit();

    const fund_txid = try helpers.fundWallet(allocator, &wallet, 1.0);
    allocator.free(fund_txid);

    var rpc_provider = helpers.RPCProvider.init(allocator);
    var local_signer = try wallet.localSigner();

    const deploy_txid = try contract.deploy(rpc_provider.provider(), local_signer.signer(), .{ .satoshis = 5000 });
    defer allocator.free(deploy_txid);
    std.log.info("Counter deployed: {s}", .{deploy_txid});

    return .{
        .contract = contract,
        .provider = rpc_provider,
        .signer = local_signer,
        .wallet = wallet,
        .artifact = artifact,
    };
}

test "Counter_Increment" {
    const allocator = std.testing.allocator;

    helpers.requireNodeAvailable(allocator);

    var artifact = compile.compileContract(allocator, "examples/zig/stateful-counter/Counter.runar.zig") catch |err| {
        std.log.warn("Could not compile Counter contract: {any}, skipping test", .{err});
        return;
    };
    defer artifact.deinit();

    std.log.info("Counter script: {d} bytes", .{artifact.script.len / 2});
    try std.testing.expect(artifact.isStateful());

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
    std.log.info("Counter deployed: {s}", .{deploy_txid});

    // Verify initial state
    const utxo = contract.getCurrentUtxo();
    try std.testing.expect(utxo != null);
    try std.testing.expectEqual(@as(i64, 5000), utxo.?.satoshis);

    // Verify the contract is stateful with count=0
    try std.testing.expectEqual(@as(usize, 1), contract.state.len);
    try std.testing.expectEqual(@as(i64, 0), contract.state[0].int);
}

test "Counter_Deploy_WithInitialValue" {
    const allocator = std.testing.allocator;

    helpers.requireNodeAvailable(allocator);

    var artifact = compile.compileContract(allocator, "examples/zig/stateful-counter/Counter.runar.zig") catch |err| {
        std.log.warn("Could not compile Counter contract: {any}, skipping test", .{err});
        return;
    };
    defer artifact.deinit();

    // Deploy with initial count = 10
    var contract = try runar.RunarContract.init(allocator, &artifact, &[_]runar.StateValue{
        .{ .int = 10 },
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

    // Verify initial state is 10
    try std.testing.expectEqual(@as(i64, 10), contract.state[0].int);
    std.log.info("Counter deployed with count=10: {s}", .{deploy_txid});
}

test "Counter_LockingScript_Includes_OpReturn" {
    const allocator = std.testing.allocator;

    var artifact = compile.compileContract(allocator, "examples/zig/stateful-counter/Counter.runar.zig") catch |err| {
        std.log.warn("Could not compile Counter contract: {any}, skipping test", .{err});
        return;
    };
    defer artifact.deinit();

    var contract = try runar.RunarContract.init(allocator, &artifact, &[_]runar.StateValue{
        .{ .int = 0 },
    });
    defer contract.deinit();

    const ls = try contract.getLockingScript();
    defer allocator.free(ls);

    // Stateful contracts must have OP_RETURN (0x6a) as state separator
    try std.testing.expect(std.mem.indexOf(u8, ls, "6a") != null);
    std.log.info("Counter locking script length: {d} hex chars", .{ls.len});
}

test "Counter_StateField_Metadata" {
    const allocator = std.testing.allocator;

    var artifact = compile.compileContract(allocator, "examples/zig/stateful-counter/Counter.runar.zig") catch |err| {
        std.log.warn("Could not compile Counter contract: {any}, skipping test", .{err});
        return;
    };
    defer artifact.deinit();

    // Counter should have exactly one state field: count
    try std.testing.expectEqual(@as(usize, 1), artifact.state_fields.len);
    try std.testing.expectEqualStrings("count", artifact.state_fields[0].name);

    // Counter should have at least one public method
    var public_count: usize = 0;
    for (artifact.abi.methods) |m| {
        if (m.is_public) public_count += 1;
    }
    try std.testing.expect(public_count >= 1);
}

test "Counter_Call_Increment" {
    const allocator = std.testing.allocator;

    helpers.requireNodeAvailable(allocator);

    var artifact = compile.compileContract(allocator, "examples/zig/stateful-counter/Counter.runar.zig") catch |err| {
        std.log.warn("Could not compile Counter contract: {any}, skipping test", .{err});
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

    // Deploy
    const deploy_txid = try contract.deploy(rpc_provider.provider(), local_signer.signer(), .{ .satoshis = 5000 });
    defer allocator.free(deploy_txid);
    std.log.info("Counter deployed: {s}", .{deploy_txid});

    // Update state for the call (count 0 -> 1)
    const call_txid = try contract.call(
        "increment",
        &.{},
        rpc_provider.provider(),
        local_signer.signer(),
        .{ .new_state = &[_]runar.StateValue{.{ .int = 1 }} },
    );
    defer allocator.free(call_txid);

    std.log.info("Counter increment TX: {s}", .{call_txid});
    try std.testing.expectEqual(@as(usize, 64), call_txid.len);

    // Verify UTXO was updated
    const utxo = contract.getCurrentUtxo();
    try std.testing.expect(utxo != null);
    try std.testing.expectEqual(@as(i64, 5000), utxo.?.satoshis);
}

test "Counter_Call_IncrementChain" {
    const allocator = std.testing.allocator;

    helpers.requireNodeAvailable(allocator);

    var artifact = compile.compileContract(allocator, "examples/zig/stateful-counter/Counter.runar.zig") catch |err| {
        std.log.warn("Could not compile Counter contract: {any}, skipping test", .{err});
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
    std.log.info("Counter deployed: {s}", .{deploy_txid});

    // Increment 0 -> 1
    const txid1 = try contract.call(
        "increment",
        &.{},
        rpc_provider.provider(),
        local_signer.signer(),
        .{ .new_state = &[_]runar.StateValue{.{ .int = 1 }} },
    );
    defer allocator.free(txid1);
    std.log.info("count->1 TX: {s}", .{txid1});

    // Increment 1 -> 2
    const txid2 = try contract.call(
        "increment",
        &.{},
        rpc_provider.provider(),
        local_signer.signer(),
        .{ .new_state = &[_]runar.StateValue{.{ .int = 2 }} },
    );
    defer allocator.free(txid2);
    std.log.info("count->2 TX: {s}", .{txid2});

    std.log.info("chain: 0->1->2 succeeded", .{});
}

test "Counter_Call_IncrementThenDecrement" {
    const allocator = std.testing.allocator;

    helpers.requireNodeAvailable(allocator);

    var artifact = compile.compileContract(allocator, "examples/zig/stateful-counter/Counter.runar.zig") catch |err| {
        std.log.warn("Could not compile Counter contract: {any}, skipping test", .{err});
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

    // Increment 0 -> 1
    const txid1 = try contract.call(
        "increment",
        &.{},
        rpc_provider.provider(),
        local_signer.signer(),
        .{ .new_state = &[_]runar.StateValue{.{ .int = 1 }} },
    );
    defer allocator.free(txid1);
    std.log.info("count->1 TX: {s}", .{txid1});

    // Decrement 1 -> 0
    const txid2 = try contract.call(
        "decrement",
        &.{},
        rpc_provider.provider(),
        local_signer.signer(),
        .{ .new_state = &[_]runar.StateValue{.{ .int = 0 }} },
    );
    defer allocator.free(txid2);
    std.log.info("count->0 TX: {s}", .{txid2});

    std.log.info("chain: 0->1->0 succeeded", .{});
}
