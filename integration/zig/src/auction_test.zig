const std = @import("std");
const runar = @import("runar");
const helpers = @import("helpers.zig");
const compile = @import("compile.zig");

test "Auction_Compile" {
    const allocator = std.testing.allocator;

    var artifact = try compile.compileContract(allocator, "examples/zig/auction/Auction.runar.zig");
    defer artifact.deinit();

    try std.testing.expectEqualStrings("Auction", artifact.contract_name);
    try std.testing.expect(artifact.isStateful());
    std.log.info("Auction compiled: {d} bytes", .{artifact.script.len / 2});
}

test "Auction_Deploy" {
    const allocator = std.testing.allocator;

    helpers.requireNodeAvailable(allocator);

    var artifact = try compile.compileContract(allocator, "examples/zig/auction/Auction.runar.zig");
    defer artifact.deinit();

    var auctioneer = try helpers.newWallet(allocator);
    defer auctioneer.deinit();
    var bidder = try helpers.newWallet(allocator);
    defer bidder.deinit();

    const auctioneer_pk = try auctioneer.pubKeyHex(allocator);
    defer allocator.free(auctioneer_pk);
    const bidder_pk = try bidder.pubKeyHex(allocator);
    defer allocator.free(bidder_pk);

    // Constructor params: auctioneer, highestBidder, highestBid, deadline
    var contract = try runar.RunarContract.init(allocator, &artifact, &[_]runar.StateValue{
        .{ .bytes = auctioneer_pk },
        .{ .bytes = bidder_pk },
        .{ .int = 1000 },
        .{ .int = 1000000 },
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
    std.log.info("Auction deployed: {s}", .{deploy_txid});
}

test "Auction_DeployZeroBid" {
    const allocator = std.testing.allocator;

    helpers.requireNodeAvailable(allocator);

    var artifact = try compile.compileContract(allocator, "examples/zig/auction/Auction.runar.zig");
    defer artifact.deinit();

    var auctioneer = try helpers.newWallet(allocator);
    defer auctioneer.deinit();
    var bidder = try helpers.newWallet(allocator);
    defer bidder.deinit();

    const auctioneer_pk = try auctioneer.pubKeyHex(allocator);
    defer allocator.free(auctioneer_pk);
    const bidder_pk = try bidder.pubKeyHex(allocator);
    defer allocator.free(bidder_pk);

    var contract = try runar.RunarContract.init(allocator, &artifact, &[_]runar.StateValue{
        .{ .bytes = auctioneer_pk },
        .{ .bytes = bidder_pk },
        .{ .int = 0 },
        .{ .int = 1000000 },
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
    std.log.info("Auction deployed with zero bid: {s}", .{deploy_txid});
}

test "Auction_DeploySameKey" {
    const allocator = std.testing.allocator;

    helpers.requireNodeAvailable(allocator);

    var artifact = try compile.compileContract(allocator, "examples/zig/auction/Auction.runar.zig");
    defer artifact.deinit();

    var wallet = try helpers.newWallet(allocator);
    defer wallet.deinit();

    const pk_hex = try wallet.pubKeyHex(allocator);
    defer allocator.free(pk_hex);

    // Same key as auctioneer and bidder
    var contract = try runar.RunarContract.init(allocator, &artifact, &[_]runar.StateValue{
        .{ .bytes = pk_hex },
        .{ .bytes = pk_hex },
        .{ .int = 1000 },
        .{ .int = 1000000 },
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
    std.log.info("Auction deployed with same key for auctioneer and bidder: {s}", .{deploy_txid});
}

test "Auction_ABI_Methods" {
    const allocator = std.testing.allocator;

    var artifact = try compile.compileContract(allocator, "examples/zig/auction/Auction.runar.zig");
    defer artifact.deinit();

    // Auction should have public methods including bid and close
    var public_count: usize = 0;
    for (artifact.abi.methods) |m| {
        if (m.is_public) public_count += 1;
    }
    try std.testing.expect(public_count >= 2);
}

test "Auction_Close" {
    const allocator = std.testing.allocator;

    helpers.requireNodeAvailable(allocator);

    var artifact = try compile.compileContract(allocator, "examples/zig/auction/Auction.runar.zig");
    defer artifact.deinit();

    var auctioneer = try helpers.newWallet(allocator);
    defer auctioneer.deinit();
    var bidder = try helpers.newWallet(allocator);
    defer bidder.deinit();

    const auctioneer_pk = try auctioneer.pubKeyHex(allocator);
    defer allocator.free(auctioneer_pk);
    const bidder_pk = try bidder.pubKeyHex(allocator);
    defer allocator.free(bidder_pk);

    // G5: this tier previously had NO successful-close test at all, so a
    // locktime regression could not be caught here even in principle. A REAL
    // non-zero block-height deadline paired with a matching CallOptions.locktime
    // (mirroring integration/rust/tests/auction.rs) makes
    // `extractLocktime(txPreimage) >= deadline` a live assertion: nLockTime=1 is
    // safely in the past so the tx is immediately mineable, but if the SDK
    // stopped writing the locktime into the preimage the preimage would carry 0
    // and `0 >= 1` would fail the spend.
    var contract = try runar.RunarContract.init(allocator, &artifact, &[_]runar.StateValue{
        .{ .bytes = auctioneer_pk },
        .{ .bytes = bidder_pk },
        .{ .int = 100 },
        .{ .int = 1 },
    });
    defer contract.deinit();

    const fund_auctioneer = try helpers.fundWallet(allocator, &auctioneer, 1.0);
    defer allocator.free(fund_auctioneer);

    var rpc_provider = helpers.RPCProvider.init(allocator);
    var auctioneer_signer = try auctioneer.localSigner();

    const deploy_txid = try contract.deploy(rpc_provider.provider(), auctioneer_signer.signer(), .{ .satoshis = 5000 });
    defer allocator.free(deploy_txid);

    // close: sig auto-signed by the auctioneer (the connected signer)
    const call_txid = try contract.call(
        "close",
        &[_]runar.StateValue{
            .{ .int = 0 }, // sig: auto-sign
        },
        rpc_provider.provider(),
        auctioneer_signer.signer(),
        .{ .locktime = 1 },
    );
    defer allocator.free(call_txid);
    try std.testing.expectEqual(@as(usize, 64), call_txid.len);
}

test "Auction_WrongSignerRejected" {
    const allocator = std.testing.allocator;

    helpers.requireNodeAvailable(allocator);

    var artifact = try compile.compileContract(allocator, "examples/zig/auction/Auction.runar.zig");
    defer artifact.deinit();

    // Auctioneer is the funded wallet that deploys
    var auctioneer = try helpers.newWallet(allocator);
    defer auctioneer.deinit();
    var wrong_signer = try helpers.newWallet(allocator);
    defer wrong_signer.deinit();
    var bidder = try helpers.newWallet(allocator);
    defer bidder.deinit();

    const auctioneer_pk = try auctioneer.pubKeyHex(allocator);
    defer allocator.free(auctioneer_pk);
    const bidder_pk = try bidder.pubKeyHex(allocator);
    defer allocator.free(bidder_pk);

    // G5: a REAL non-zero block-height deadline paired with a matching
    // CallOptions.locktime, mirroring integration/rust/tests/auction.rs. The old
    // deadline=0 + nLockTime=0 combination made
    // `extractLocktime(txPreimage) >= deadline` vacuously true, so the deadline
    // could never be the reason a spend failed. nLockTime=1 is safely in the
    // past, so here the ONLY reason for rejection is the wrong signer.
    var contract = try runar.RunarContract.init(allocator, &artifact, &[_]runar.StateValue{
        .{ .bytes = auctioneer_pk },
        .{ .bytes = bidder_pk },
        .{ .int = 100 },
        .{ .int = 1 },
    });
    defer contract.deinit();

    // Fund and deploy with auctioneer
    const fund_auctioneer = try helpers.fundWallet(allocator, &auctioneer, 1.0);
    defer allocator.free(fund_auctioneer);

    var rpc_provider = helpers.RPCProvider.init(allocator);
    var auctioneer_signer = try auctioneer.localSigner();

    const deploy_txid = try contract.deploy(rpc_provider.provider(), auctioneer_signer.signer(), .{ .satoshis = 5000 });
    defer allocator.free(deploy_txid);

    // Fund the wrong signer
    const fund_wrong = try helpers.fundWallet(allocator, &wrong_signer, 1.0);
    defer allocator.free(fund_wrong);

    var wrong_local_signer = try wrong_signer.localSigner();

    // Attempt to close with wrong signer -- should be rejected. locktime=1
    // satisfies the non-zero deadline, so the signature is the only failure.
    const broadcasts_before = rpc_provider.broadcast_attempts;
    const result = contract.call(
        "close",
        &[_]runar.StateValue{
            .{ .int = 0 }, // sig: auto-sign (wrong key)
        },
        rpc_provider.provider(),
        wrong_local_signer.signer(),
        .{ .locktime = 1 },
    );

    if (result) |call_txid| {
        allocator.free(call_txid);
        return error.TestExpectedError;
    } else |err| {
        // A negative test must prove CONSENSUS rejected the spend, not merely
        // that the call returned some error. `ContractError.CallFailed` is the
        // SDK's catch-all — it also covers a UTXO-fetch failure or a build-time
        // refusal — so assert the transaction actually reached the node.
        try std.testing.expectEqual(error.CallFailed, err);
        try std.testing.expect(rpc_provider.broadcast_attempts > broadcasts_before);
        std.log.warn("Auction correctly rejected close with wrong signer", .{});
    }
}
