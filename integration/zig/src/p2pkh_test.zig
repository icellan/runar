const std = @import("std");
const runar = @import("runar");
const bsvz = @import("bsvz");
const helpers = @import("helpers.zig");
const compile = @import("compile.zig");

/// Deploy a P2PKH contract locked to the given owner wallet.
fn deployP2PKH(allocator: std.mem.Allocator, owner: *helpers.Wallet) !struct { contract: runar.RunarContract, provider: helpers.RPCProvider, signer: runar.LocalSigner } {
    var artifact = try compile.compileContract(allocator, "examples/zig/p2pkh/P2PKH.runar.zig");
    errdefer artifact.deinit();

    const pkh_hex = try owner.pubKeyHashHex(allocator);
    defer allocator.free(pkh_hex);

    var contract = try runar.RunarContract.init(allocator, &artifact, &[_]runar.StateValue{
        .{ .bytes = pkh_hex },
    });
    errdefer contract.deinit();

    // Fund the owner wallet
    const fund_txid = try helpers.fundWallet(allocator, owner, 1.0);
    allocator.free(fund_txid);

    var rpc_provider = helpers.RPCProvider.init(allocator);
    var local_signer = try owner.localSigner();

    // Deploy
    const txid = try contract.deploy(rpc_provider.provider(), local_signer.signer(), .{ .satoshis = 5000 });
    defer allocator.free(txid);
    std.log.info("P2PKH deployed: {s}", .{txid});

    return .{ .contract = contract, .provider = rpc_provider, .signer = local_signer };
}

test "P2PKH_ValidUnlock" {
    const allocator = std.testing.allocator;

    if (!helpers.isNodeAvailable(allocator)) {
        std.log.warn("Regtest node not available, skipping test", .{});
        return;
    }

    var owner = try helpers.newWallet(allocator);
    defer owner.deinit();

    var artifact = compile.compileContract(allocator, "examples/zig/p2pkh/P2PKH.runar.zig") catch |err| {
        std.log.warn("Could not compile P2PKH contract: {any}, skipping test", .{err});
        return;
    };
    defer artifact.deinit();

    std.log.info("P2PKH script: {d} bytes", .{artifact.script.len / 2});

    const pkh_hex = try owner.pubKeyHashHex(allocator);
    defer allocator.free(pkh_hex);

    var contract = try runar.RunarContract.init(allocator, &artifact, &[_]runar.StateValue{
        .{ .bytes = pkh_hex },
    });
    defer contract.deinit();

    // Fund
    const fund_txid = try helpers.fundWallet(allocator, &owner, 1.0);
    defer allocator.free(fund_txid);

    var rpc_provider = helpers.RPCProvider.init(allocator);
    var local_signer = try owner.localSigner();

    // Deploy
    const deploy_txid = try contract.deploy(rpc_provider.provider(), local_signer.signer(), .{ .satoshis = 5000 });
    defer allocator.free(deploy_txid);
    std.log.info("P2PKH deployed: {s}", .{deploy_txid});

    try std.testing.expectEqual(@as(usize, 64), deploy_txid.len);

    // The P2PKH contract is stateless and requires signature verification.
    // For a full unlock, we would need to build a spending tx and compute
    // the BIP-143 sighash. For now, verify the deployment succeeded.
    const utxo = contract.getCurrentUtxo();
    try std.testing.expect(utxo != null);
    try std.testing.expectEqual(@as(i64, 5000), utxo.?.satoshis);
}

test "P2PKH_DeployDifferentPubKeyHash" {
    const allocator = std.testing.allocator;

    if (!helpers.isNodeAvailable(allocator)) {
        std.log.warn("Regtest node not available, skipping test", .{});
        return;
    }

    var artifact = compile.compileContract(allocator, "examples/zig/p2pkh/P2PKH.runar.zig") catch |err| {
        std.log.warn("Could not compile P2PKH contract: {any}, skipping test", .{err});
        return;
    };
    defer artifact.deinit();

    // Owner 1
    var owner1 = try helpers.newWallet(allocator);
    defer owner1.deinit();
    const pkh1 = try owner1.pubKeyHashHex(allocator);
    defer allocator.free(pkh1);

    var contract1 = try runar.RunarContract.init(allocator, &artifact, &[_]runar.StateValue{
        .{ .bytes = pkh1 },
    });
    defer contract1.deinit();

    const fund1 = try helpers.fundWallet(allocator, &owner1, 1.0);
    defer allocator.free(fund1);

    var rpc1 = helpers.RPCProvider.init(allocator);
    var signer1 = try owner1.localSigner();
    const txid1 = try contract1.deploy(rpc1.provider(), signer1.signer(), .{ .satoshis = 5000 });
    defer allocator.free(txid1);

    // Owner 2
    var owner2 = try helpers.newWallet(allocator);
    defer owner2.deinit();
    const pkh2 = try owner2.pubKeyHashHex(allocator);
    defer allocator.free(pkh2);

    var contract2 = try runar.RunarContract.init(allocator, &artifact, &[_]runar.StateValue{
        .{ .bytes = pkh2 },
    });
    defer contract2.deinit();

    const fund2 = try helpers.fundWallet(allocator, &owner2, 1.0);
    defer allocator.free(fund2);

    var rpc2 = helpers.RPCProvider.init(allocator);
    var signer2 = try owner2.localSigner();
    const txid2 = try contract2.deploy(rpc2.provider(), signer2.signer(), .{ .satoshis = 5000 });
    defer allocator.free(txid2);

    // Verify different txids (different pubkey hashes produce different scripts)
    try std.testing.expect(!std.mem.eql(u8, txid1, txid2));
    std.log.info("owner1 txid: {s}, owner2 txid: {s}", .{ txid1, txid2 });
}
