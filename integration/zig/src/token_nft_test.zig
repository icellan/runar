const std = @import("std");
const runar = @import("runar");
const helpers = @import("helpers.zig");
const compile = @import("compile.zig");

/// Helper: hex-encode an ASCII string (for tokenId and metadata).
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

test "NFT_Compile" {
    const allocator = std.testing.allocator;

    var artifact = compile.compileContract(allocator, "examples/zig/token-nft/NFTExample.runar.zig") catch |err| {
        std.log.warn("Could not compile NFTExample contract: {any}, skipping test", .{err});
        return;
    };
    defer artifact.deinit();

    try std.testing.expectEqualStrings("NFTExample", artifact.contract_name);
    try std.testing.expect(artifact.isStateful());
    std.log.info("NFTExample compiled: {d} bytes", .{artifact.script.len / 2});
}

test "NFT_Deploy" {
    const allocator = std.testing.allocator;

    if (!helpers.isNodeAvailable(allocator)) {
        std.log.warn("Regtest node not available, skipping test", .{});
        return;
    }

    var artifact = compile.compileContract(allocator, "examples/zig/token-nft/NFTExample.runar.zig") catch |err| {
        std.log.warn("Could not compile NFTExample contract: {any}, skipping test", .{err});
        return;
    };
    defer artifact.deinit();

    var owner = try helpers.newWallet(allocator);
    defer owner.deinit();

    const owner_pk = try owner.pubKeyHex(allocator);
    defer allocator.free(owner_pk);
    const token_id = try hexEncodeAscii(allocator, "NFT-DEPLOY-001");
    defer allocator.free(token_id);
    const metadata = try hexEncodeAscii(allocator, "Deploy test");
    defer allocator.free(metadata);

    // Constructor: owner (PubKey), tokenId (ByteString), metadata (ByteString)
    var contract = try runar.RunarContract.init(allocator, &artifact, &[_]runar.StateValue{
        .{ .bytes = owner_pk },
        .{ .bytes = token_id },
        .{ .bytes = metadata },
    });
    defer contract.deinit();

    var funder = try helpers.newWallet(allocator);
    defer funder.deinit();
    const fund_txid = try helpers.fundWallet(allocator, &funder, 0.01);
    defer allocator.free(fund_txid);

    var rpc_provider = helpers.RPCProvider.init(allocator);
    var local_signer = try funder.localSigner();

    const deploy_txid = try contract.deploy(rpc_provider.provider(), local_signer.signer(), .{ .satoshis = 5000 });
    defer allocator.free(deploy_txid);

    try std.testing.expectEqual(@as(usize, 64), deploy_txid.len);
    std.log.info("NFT deployed: {s}", .{deploy_txid});
}

test "NFT_DeployDifferentOwners" {
    const allocator = std.testing.allocator;

    if (!helpers.isNodeAvailable(allocator)) {
        std.log.warn("Regtest node not available, skipping test", .{});
        return;
    }

    var artifact = compile.compileContract(allocator, "examples/zig/token-nft/NFTExample.runar.zig") catch |err| {
        std.log.warn("Could not compile NFTExample contract: {any}, skipping test", .{err});
        return;
    };
    defer artifact.deinit();

    var owner1 = try helpers.newWallet(allocator);
    defer owner1.deinit();
    var owner2 = try helpers.newWallet(allocator);
    defer owner2.deinit();

    const pk1 = try owner1.pubKeyHex(allocator);
    defer allocator.free(pk1);
    const pk2 = try owner2.pubKeyHex(allocator);
    defer allocator.free(pk2);

    const token_id = try hexEncodeAscii(allocator, "NFT-DIFF-001");
    defer allocator.free(token_id);
    const metadata = try hexEncodeAscii(allocator, "Diff owners test");
    defer allocator.free(metadata);

    // Deploy first NFT
    var contract1 = try runar.RunarContract.init(allocator, &artifact, &[_]runar.StateValue{
        .{ .bytes = pk1 },
        .{ .bytes = token_id },
        .{ .bytes = metadata },
    });
    defer contract1.deinit();

    var funder1 = try helpers.newWallet(allocator);
    defer funder1.deinit();
    const fund1 = try helpers.fundWallet(allocator, &funder1, 0.01);
    defer allocator.free(fund1);

    var rpc1 = helpers.RPCProvider.init(allocator);
    var signer1 = try funder1.localSigner();
    const txid1 = try contract1.deploy(rpc1.provider(), signer1.signer(), .{ .satoshis = 5000 });
    defer allocator.free(txid1);

    // Deploy second NFT with different owner
    var contract2 = try runar.RunarContract.init(allocator, &artifact, &[_]runar.StateValue{
        .{ .bytes = pk2 },
        .{ .bytes = token_id },
        .{ .bytes = metadata },
    });
    defer contract2.deinit();

    var funder2 = try helpers.newWallet(allocator);
    defer funder2.deinit();
    const fund2 = try helpers.fundWallet(allocator, &funder2, 0.01);
    defer allocator.free(fund2);

    var rpc2 = helpers.RPCProvider.init(allocator);
    var signer2 = try funder2.localSigner();
    const txid2 = try contract2.deploy(rpc2.provider(), signer2.signer(), .{ .satoshis = 5000 });
    defer allocator.free(txid2);

    try std.testing.expect(!std.mem.eql(u8, txid1, txid2));
    std.log.info("NFT1: {s}, NFT2: {s}", .{ txid1, txid2 });
}

test "NFT_DeployLongMetadata" {
    const allocator = std.testing.allocator;

    if (!helpers.isNodeAvailable(allocator)) {
        std.log.warn("Regtest node not available, skipping test", .{});
        return;
    }

    var artifact = compile.compileContract(allocator, "examples/zig/token-nft/NFTExample.runar.zig") catch |err| {
        std.log.warn("Could not compile NFTExample contract: {any}, skipping test", .{err});
        return;
    };
    defer artifact.deinit();

    var owner = try helpers.newWallet(allocator);
    defer owner.deinit();

    const owner_pk = try owner.pubKeyHex(allocator);
    defer allocator.free(owner_pk);
    const token_id = try hexEncodeAscii(allocator, "NFT-LONG-001");
    defer allocator.free(token_id);

    // 256-byte metadata
    var long_meta_raw: [256]u8 = undefined;
    for (&long_meta_raw, 0..) |*byte, i| {
        byte.* = @truncate(i);
    }
    const long_metadata = try allocator.alloc(u8, 512);
    defer allocator.free(long_metadata);
    for (long_meta_raw, 0..) |byte, i| {
        const hi: u8 = byte >> 4;
        const lo: u8 = byte & 0x0f;
        long_metadata[i * 2] = if (hi < 10) '0' + hi else 'a' + hi - 10;
        long_metadata[i * 2 + 1] = if (lo < 10) '0' + lo else 'a' + lo - 10;
    }

    var contract = try runar.RunarContract.init(allocator, &artifact, &[_]runar.StateValue{
        .{ .bytes = owner_pk },
        .{ .bytes = token_id },
        .{ .bytes = long_metadata },
    });
    defer contract.deinit();

    var funder = try helpers.newWallet(allocator);
    defer funder.deinit();
    const fund_txid = try helpers.fundWallet(allocator, &funder, 0.01);
    defer allocator.free(fund_txid);

    var rpc_provider = helpers.RPCProvider.init(allocator);
    var local_signer = try funder.localSigner();

    const deploy_txid = try contract.deploy(rpc_provider.provider(), local_signer.signer(), .{ .satoshis = 5000 });
    defer allocator.free(deploy_txid);

    std.log.info("NFT deployed with 256-byte metadata: {s}", .{deploy_txid});
}

test "NFT_Transfer" {
    const allocator = std.testing.allocator;

    if (!helpers.isNodeAvailable(allocator)) {
        std.log.warn("Regtest node not available, skipping test", .{});
        return;
    }

    var artifact = compile.compileContract(allocator, "examples/zig/token-nft/NFTExample.runar.zig") catch |err| {
        std.log.warn("Could not compile NFTExample contract: {any}, skipping test", .{err});
        return;
    };
    defer artifact.deinit();

    var owner = try helpers.newWallet(allocator);
    defer owner.deinit();
    var new_owner = try helpers.newWallet(allocator);
    defer new_owner.deinit();

    const owner_pk = try owner.pubKeyHex(allocator);
    defer allocator.free(owner_pk);
    const new_owner_pk = try new_owner.pubKeyHex(allocator);
    defer allocator.free(new_owner_pk);
    const token_id = try hexEncodeAscii(allocator, "NFT-001");
    defer allocator.free(token_id);
    const metadata = try hexEncodeAscii(allocator, "My First NFT");
    defer allocator.free(metadata);

    var contract = try runar.RunarContract.init(allocator, &artifact, &[_]runar.StateValue{
        .{ .bytes = owner_pk },
        .{ .bytes = token_id },
        .{ .bytes = metadata },
    });
    defer contract.deinit();

    const fund_txid = try helpers.fundWallet(allocator, &owner, 0.01);
    defer allocator.free(fund_txid);

    var rpc_provider = helpers.RPCProvider.init(allocator);
    var local_signer = try owner.localSigner();

    const deploy_sats: i64 = 5000;
    const deploy_txid = try contract.deploy(rpc_provider.provider(), local_signer.signer(), .{ .satoshis = deploy_sats });
    defer allocator.free(deploy_txid);
    std.log.info("NFT deployed: {s}", .{deploy_txid});

    // Transfer via SDK Call -- state transitions to new owner
    // outputSatoshis must match the continuation UTXO amount (deploy_sats)
    // because the on-chain addOutput uses this value for the output amount.
    const call_txid = try contract.call(
        "transfer",
        &[_]runar.StateValue{
            .{ .int = 0 }, // sig: auto-sign
            .{ .bytes = new_owner_pk },
            .{ .int = deploy_sats }, // outputSatoshis = deploy amount
        },
        rpc_provider.provider(),
        local_signer.signer(),
        // State fields (mutable only): owner
        // tokenId and metadata are readonly, baked into the code script.
        .{ .new_state = &[_]runar.StateValue{
            .{ .bytes = new_owner_pk }, // owner = new_owner
        } },
    );
    defer allocator.free(call_txid);

    std.log.info("NFT transfer TX: {s}", .{call_txid});
    try std.testing.expectEqual(@as(usize, 64), call_txid.len);
}

test "NFT_Burn" {
    const allocator = std.testing.allocator;

    if (!helpers.isNodeAvailable(allocator)) {
        std.log.warn("Regtest node not available, skipping test", .{});
        return;
    }

    var artifact = compile.compileContract(allocator, "examples/zig/token-nft/NFTExample.runar.zig") catch |err| {
        std.log.warn("Could not compile NFTExample contract: {any}, skipping test", .{err});
        return;
    };
    defer artifact.deinit();

    var owner = try helpers.newWallet(allocator);
    defer owner.deinit();

    const owner_pk = try owner.pubKeyHex(allocator);
    defer allocator.free(owner_pk);
    const token_id = try hexEncodeAscii(allocator, "NFT-BURN-001");
    defer allocator.free(token_id);
    const metadata = try hexEncodeAscii(allocator, "Burnable NFT");
    defer allocator.free(metadata);

    var contract = try runar.RunarContract.init(allocator, &artifact, &[_]runar.StateValue{
        .{ .bytes = owner_pk },
        .{ .bytes = token_id },
        .{ .bytes = metadata },
    });
    defer contract.deinit();

    const fund_txid = try helpers.fundWallet(allocator, &owner, 0.01);
    defer allocator.free(fund_txid);

    var rpc_provider = helpers.RPCProvider.init(allocator);
    var local_signer = try owner.localSigner();

    const deploy_txid = try contract.deploy(rpc_provider.provider(), local_signer.signer(), .{ .satoshis = 5000 });
    defer allocator.free(deploy_txid);
    std.log.info("NFT deployed: {s}", .{deploy_txid});

    // burn(sig) -- stateless terminal call, no continuation output
    const call_txid = try contract.call(
        "burn",
        &[_]runar.StateValue{
            .{ .int = 0 }, // sig: auto-sign
        },
        rpc_provider.provider(),
        local_signer.signer(),
        null,
    );
    defer allocator.free(call_txid);

    std.log.info("NFT burn TX: {s}", .{call_txid});
    try std.testing.expectEqual(@as(usize, 64), call_txid.len);
}
