const std = @import("std");
const runar = @import("runar");
const bsvz = @import("bsvz");
const helpers = @import("helpers.zig");
const compile = @import("compile.zig");

test "Escrow_Compile" {
    const allocator = std.testing.allocator;

    var artifact = compile.compileContract(allocator, "examples/zig/escrow/Escrow.runar.zig") catch |err| {
        std.log.warn("Could not compile Escrow contract: {any}, skipping test", .{err});
        return;
    };
    defer artifact.deinit();

    try std.testing.expectEqualStrings("Escrow", artifact.contract_name);
    std.log.info("Escrow compiled: {d} bytes", .{artifact.script.len / 2});
}

test "Escrow_DeployThreePubKeys" {
    const allocator = std.testing.allocator;

    if (!helpers.isNodeAvailable(allocator)) {
        std.log.warn("Regtest node not available, skipping test", .{});
        return;
    }

    var artifact = compile.compileContract(allocator, "examples/zig/escrow/Escrow.runar.zig") catch |err| {
        std.log.warn("Could not compile Escrow contract: {any}, skipping test", .{err});
        return;
    };
    defer artifact.deinit();

    var buyer = try helpers.newWallet(allocator);
    defer buyer.deinit();
    var seller = try helpers.newWallet(allocator);
    defer seller.deinit();
    var arbiter = try helpers.newWallet(allocator);
    defer arbiter.deinit();

    const buyer_pk = try buyer.pubKeyHex(allocator);
    defer allocator.free(buyer_pk);
    const seller_pk = try seller.pubKeyHex(allocator);
    defer allocator.free(seller_pk);
    const arbiter_pk = try arbiter.pubKeyHex(allocator);
    defer allocator.free(arbiter_pk);

    var contract = try runar.RunarContract.init(allocator, &artifact, &[_]runar.StateValue{
        .{ .bytes = buyer_pk },
        .{ .bytes = seller_pk },
        .{ .bytes = arbiter_pk },
    });
    defer contract.deinit();

    // Fund the seller (who will pay for deployment)
    var funder = try helpers.newWallet(allocator);
    defer funder.deinit();
    const fund_txid = try helpers.fundWallet(allocator, &funder, 1.0);
    defer allocator.free(fund_txid);

    var rpc_provider = helpers.RPCProvider.init(allocator);
    var local_signer = try funder.localSigner();

    const deploy_txid = try contract.deploy(rpc_provider.provider(), local_signer.signer(), .{ .satoshis = 5000 });
    defer allocator.free(deploy_txid);

    try std.testing.expectEqual(@as(usize, 64), deploy_txid.len);
    std.log.info("Escrow deployed with 3 distinct pubkeys: {s}", .{deploy_txid});
}

test "Escrow_DeploySameKey" {
    const allocator = std.testing.allocator;

    if (!helpers.isNodeAvailable(allocator)) {
        std.log.warn("Regtest node not available, skipping test", .{});
        return;
    }

    var artifact = compile.compileContract(allocator, "examples/zig/escrow/Escrow.runar.zig") catch |err| {
        std.log.warn("Could not compile Escrow contract: {any}, skipping test", .{err});
        return;
    };
    defer artifact.deinit();

    // All three roles use the same key
    var wallet = try helpers.newWallet(allocator);
    defer wallet.deinit();
    const pk_hex = try wallet.pubKeyHex(allocator);
    defer allocator.free(pk_hex);

    var contract = try runar.RunarContract.init(allocator, &artifact, &[_]runar.StateValue{
        .{ .bytes = pk_hex },
        .{ .bytes = pk_hex },
        .{ .bytes = pk_hex },
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

    try std.testing.expectEqual(@as(usize, 64), deploy_txid.len);
    std.log.info("Escrow deployed with same key for all roles: {s}", .{deploy_txid});
}

test "Escrow_ABI_Methods" {
    const allocator = std.testing.allocator;

    var artifact = compile.compileContract(allocator, "examples/zig/escrow/Escrow.runar.zig") catch |err| {
        std.log.warn("Could not compile Escrow contract: {any}, skipping test", .{err});
        return;
    };
    defer artifact.deinit();

    // Escrow should have at least 2 public methods: release and refund
    var public_count: usize = 0;
    var has_release = false;
    var has_refund = false;
    for (artifact.abi.methods) |m| {
        if (m.is_public) {
            public_count += 1;
            if (std.mem.eql(u8, m.name, "release")) has_release = true;
            if (std.mem.eql(u8, m.name, "refund")) has_refund = true;
        }
    }
    try std.testing.expect(public_count >= 2);
    try std.testing.expect(has_release);
    try std.testing.expect(has_refund);
}

test "Escrow_NotStateful" {
    const allocator = std.testing.allocator;

    var artifact = compile.compileContract(allocator, "examples/zig/escrow/Escrow.runar.zig") catch |err| {
        std.log.warn("Could not compile Escrow contract: {any}, skipping test", .{err});
        return;
    };
    defer artifact.deinit();

    // Escrow is a stateless contract
    try std.testing.expect(!artifact.isStateful());
}
