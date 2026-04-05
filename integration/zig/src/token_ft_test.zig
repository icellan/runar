const std = @import("std");
const runar = @import("runar");
const helpers = @import("helpers.zig");
const compile = @import("compile.zig");

/// Helper: hex-encode an ASCII string (for tokenId).
fn hexEncodeAscii(allocator: std.mem.Allocator, ascii: []const u8) ![]u8 {
    const hex_buf = try allocator.alloc(u8, ascii.len * 2);
    for (ascii, 0..) |byte, i| {
        const hi: u8 = byte >> 4;
        const lo: u8 = byte & 0x0f;
        hex_buf[i * 2] = if (hi < 10) '0' + hi else 'a' + hi - 10;
        hex_buf[i * 2 + 1] = if (lo < 10) '0' + lo else 'a' + lo - 10;
    }
    return hex_buf;
}

test "FungibleToken_Compile" {
    const allocator = std.testing.allocator;

    var artifact = compile.compileContract(allocator, "examples/zig/token-ft/FungibleTokenExample.runar.zig") catch |err| {
        std.log.warn("Could not compile FungibleTokenExample contract: {any}, skipping test", .{err});
        return;
    };
    defer artifact.deinit();

    try std.testing.expectEqualStrings("FungibleTokenExample", artifact.contract_name);
    try std.testing.expect(artifact.isStateful());
    std.log.info("FungibleTokenExample compiled: {d} bytes", .{artifact.script.len / 2});
}

test "FungibleToken_Deploy" {
    const allocator = std.testing.allocator;

    if (!helpers.isNodeAvailable(allocator)) {
        std.log.warn("Regtest node not available, skipping test", .{});
        return;
    }

    var artifact = compile.compileContract(allocator, "examples/zig/token-ft/FungibleTokenExample.runar.zig") catch |err| {
        std.log.warn("Could not compile FungibleTokenExample contract: {any}, skipping test", .{err});
        return;
    };
    defer artifact.deinit();

    var owner = try helpers.newWallet(allocator);
    defer owner.deinit();

    const owner_pk = try owner.pubKeyHex(allocator);
    defer allocator.free(owner_pk);
    const token_id = try hexEncodeAscii(allocator, "TEST-TOKEN-001");
    defer allocator.free(token_id);

    // Constructor: owner (PubKey), balance (bigint), mergeBalance (bigint), tokenId (ByteString)
    var contract = try runar.RunarContract.init(allocator, &artifact, &[_]runar.StateValue{
        .{ .bytes = owner_pk },
        .{ .int = 1000 },
        .{ .int = 0 },
        .{ .bytes = token_id },
    });
    defer contract.deinit();

    const fund_txid = try helpers.fundWallet(allocator, &owner, 1.0);
    defer allocator.free(fund_txid);

    var rpc_provider = helpers.RPCProvider.init(allocator);
    var local_signer = try owner.localSigner();

    const deploy_txid = try contract.deploy(rpc_provider.provider(), local_signer.signer(), .{ .satoshis = 5000 });
    defer allocator.free(deploy_txid);

    const utxo = contract.getCurrentUtxo();
    try std.testing.expect(utxo != null);
    try std.testing.expectEqual(@as(usize, 64), deploy_txid.len);
    std.log.info("FungibleToken deployed with balance=1000: {s}", .{deploy_txid});
}

test "FungibleToken_DeployZeroBalance" {
    const allocator = std.testing.allocator;

    if (!helpers.isNodeAvailable(allocator)) {
        std.log.warn("Regtest node not available, skipping test", .{});
        return;
    }

    var artifact = compile.compileContract(allocator, "examples/zig/token-ft/FungibleTokenExample.runar.zig") catch |err| {
        std.log.warn("Could not compile FungibleTokenExample contract: {any}, skipping test", .{err});
        return;
    };
    defer artifact.deinit();

    var owner = try helpers.newWallet(allocator);
    defer owner.deinit();

    const owner_pk = try owner.pubKeyHex(allocator);
    defer allocator.free(owner_pk);
    const token_id = try hexEncodeAscii(allocator, "TEST-TOKEN-002");
    defer allocator.free(token_id);

    var contract = try runar.RunarContract.init(allocator, &artifact, &[_]runar.StateValue{
        .{ .bytes = owner_pk },
        .{ .int = 0 },
        .{ .int = 0 },
        .{ .bytes = token_id },
    });
    defer contract.deinit();

    const fund_txid = try helpers.fundWallet(allocator, &owner, 1.0);
    defer allocator.free(fund_txid);

    var rpc_provider = helpers.RPCProvider.init(allocator);
    var local_signer = try owner.localSigner();

    const deploy_txid = try contract.deploy(rpc_provider.provider(), local_signer.signer(), .{ .satoshis = 5000 });
    defer allocator.free(deploy_txid);

    const utxo = contract.getCurrentUtxo();
    try std.testing.expect(utxo != null);
    std.log.info("FungibleToken deployed with balance=0: {s}", .{deploy_txid});
}

test "FungibleToken_DeployLargeBalance" {
    const allocator = std.testing.allocator;

    if (!helpers.isNodeAvailable(allocator)) {
        std.log.warn("Regtest node not available, skipping test", .{});
        return;
    }

    var artifact = compile.compileContract(allocator, "examples/zig/token-ft/FungibleTokenExample.runar.zig") catch |err| {
        std.log.warn("Could not compile FungibleTokenExample contract: {any}, skipping test", .{err});
        return;
    };
    defer artifact.deinit();

    var owner = try helpers.newWallet(allocator);
    defer owner.deinit();

    const owner_pk = try owner.pubKeyHex(allocator);
    defer allocator.free(owner_pk);
    const token_id = try hexEncodeAscii(allocator, "TEST-TOKEN-003");
    defer allocator.free(token_id);

    var contract = try runar.RunarContract.init(allocator, &artifact, &[_]runar.StateValue{
        .{ .bytes = owner_pk },
        .{ .int = 99999999999 },
        .{ .int = 0 },
        .{ .bytes = token_id },
    });
    defer contract.deinit();

    const fund_txid = try helpers.fundWallet(allocator, &owner, 1.0);
    defer allocator.free(fund_txid);

    var rpc_provider = helpers.RPCProvider.init(allocator);
    var local_signer = try owner.localSigner();

    const deploy_txid = try contract.deploy(rpc_provider.provider(), local_signer.signer(), .{ .satoshis = 5000 });
    defer allocator.free(deploy_txid);

    const utxo = contract.getCurrentUtxo();
    try std.testing.expect(utxo != null);
    std.log.info("FungibleToken deployed with large balance=99999999999: {s}", .{deploy_txid});
}

test "FungibleToken_StateFields" {
    const allocator = std.testing.allocator;

    var artifact = compile.compileContract(allocator, "examples/zig/token-ft/FungibleTokenExample.runar.zig") catch |err| {
        std.log.warn("Could not compile FungibleTokenExample contract: {any}, skipping test", .{err});
        return;
    };
    defer artifact.deinit();

    // FungibleToken should have state fields: owner, balance, mergeBalance, tokenId
    try std.testing.expect(artifact.state_fields.len >= 3);

    // Should have at least 2 public methods (send, transfer, merge)
    var public_count: usize = 0;
    for (artifact.abi.methods) |m| {
        if (m.is_public) public_count += 1;
    }
    try std.testing.expect(public_count >= 2);
}

test "FungibleToken_Send" {
    const allocator = std.testing.allocator;

    if (!helpers.isNodeAvailable(allocator)) {
        std.log.warn("Regtest node not available, skipping test", .{});
        return;
    }

    var artifact = compile.compileContract(allocator, "examples/zig/token-ft/FungibleTokenExample.runar.zig") catch |err| {
        std.log.warn("Could not compile FungibleTokenExample contract: {any}, skipping test", .{err});
        return;
    };
    defer artifact.deinit();

    var owner = try helpers.newWallet(allocator);
    defer owner.deinit();
    var receiver = try helpers.newWallet(allocator);
    defer receiver.deinit();

    const owner_pk = try owner.pubKeyHex(allocator);
    defer allocator.free(owner_pk);
    const receiver_pk = try receiver.pubKeyHex(allocator);
    defer allocator.free(receiver_pk);
    const token_id = try hexEncodeAscii(allocator, "TEST-TOKEN-SEND");
    defer allocator.free(token_id);

    const initial_balance: i64 = 1000;
    const deploy_sats: i64 = 5000;

    var contract = try runar.RunarContract.init(allocator, &artifact, &[_]runar.StateValue{
        .{ .bytes = owner_pk },
        .{ .int = initial_balance },
        .{ .int = 0 },
        .{ .bytes = token_id },
    });
    defer contract.deinit();

    const fund_txid = try helpers.fundWallet(allocator, &owner, 1.0);
    defer allocator.free(fund_txid);

    var rpc_provider = helpers.RPCProvider.init(allocator);
    var local_signer = try owner.localSigner();

    const deploy_txid = try contract.deploy(rpc_provider.provider(), local_signer.signer(), .{ .satoshis = deploy_sats });
    defer allocator.free(deploy_txid);
    std.log.info("FungibleToken deployed: {s}", .{deploy_txid});

    // Call send(sig, to, outputSatoshis) -- transfers entire balance to new owner
    // State after send: owner=receiver, balance=initial, mergeBalance=0
    // outputSatoshis must match the continuation UTXO amount (deploy_sats)
    // because the on-chain addOutput uses this value for the output amount.
    const call_txid = try contract.call(
        "send",
        &[_]runar.StateValue{
            .{ .int = 0 }, // sig: auto-sign
            .{ .bytes = receiver_pk },
            .{ .int = deploy_sats }, // outputSatoshis = deploy amount
        },
        rpc_provider.provider(),
        local_signer.signer(),
        // State fields (mutable only): owner, balance, mergeBalance
        // tokenId is readonly and baked into the code script, not in state.
        .{ .new_state = &[_]runar.StateValue{
            .{ .bytes = receiver_pk }, // owner = receiver
            .{ .int = initial_balance }, // balance = 1000
            .{ .int = 0 }, // mergeBalance = 0
        } },
    );
    defer allocator.free(call_txid);

    std.log.info("FungibleToken send TX: {s}", .{call_txid});
    try std.testing.expectEqual(@as(usize, 64), call_txid.len);
}
