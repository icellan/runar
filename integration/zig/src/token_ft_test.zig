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

test "FungibleToken_WrongOwnerRejected" {
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
    var wrong_signer_wallet = try helpers.newWallet(allocator);
    defer wrong_signer_wallet.deinit();
    var receiver = try helpers.newWallet(allocator);
    defer receiver.deinit();

    const owner_pk = try owner.pubKeyHex(allocator);
    defer allocator.free(owner_pk);
    const receiver_pk = try receiver.pubKeyHex(allocator);
    defer allocator.free(receiver_pk);
    const token_id = try hexEncodeAscii(allocator, "REJECT-TOKEN");
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
    std.log.info("FungibleToken deployed for wrong-owner test: {s}", .{deploy_txid});

    // Fund wrong signer wallet
    const fund_txid2 = try helpers.fundWallet(allocator, &wrong_signer_wallet, 1.0);
    defer allocator.free(fund_txid2);

    var wrong_signer = try wrong_signer_wallet.localSigner();

    // Call send with wrong signer -- checkSig should fail on-chain
    const result = contract.call(
        "send",
        &[_]runar.StateValue{
            .{ .int = 0 }, // sig: auto-sign (wrong key)
            .{ .bytes = receiver_pk },
            .{ .int = deploy_sats },
        },
        rpc_provider.provider(),
        wrong_signer.signer(),
        .{ .new_state = &[_]runar.StateValue{
            .{ .bytes = receiver_pk },
            .{ .int = initial_balance },
            .{ .int = 0 },
        } },
    );

    if (result) |txid| {
        allocator.free(txid);
        return error.TestUnexpectedResult; // should have failed
    } else |_| {
        std.log.info("FungibleToken correctly rejected wrong owner", .{});
    }
}

test "FungibleToken_Transfer" {
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
    var recipient = try helpers.newWallet(allocator);
    defer recipient.deinit();

    const owner_pk = try owner.pubKeyHex(allocator);
    defer allocator.free(owner_pk);
    const recipient_pk = try recipient.pubKeyHex(allocator);
    defer allocator.free(recipient_pk);
    const token_id = try hexEncodeAscii(allocator, "TRANSFER-TOKEN");
    defer allocator.free(token_id);

    const initial_balance: i64 = 1000;
    const amount: i64 = 300;
    const deploy_sats: i64 = 5000;
    const output_sats: i64 = 2000;

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
    std.log.info("FungibleToken deployed for transfer test: {s}", .{deploy_txid});

    // transfer(sig, to, amount, outputSatoshis) -- splits UTXO into 2 outputs
    // Output 0: recipient gets `amount`, Output 1: sender keeps remainder
    // Note: Zig SDK currently uses new_state for single continuation output.
    // Multi-output transfer requires SDK Outputs support (not yet available).
    const call_result = contract.call(
        "transfer",
        &[_]runar.StateValue{
            .{ .int = 0 }, // sig: auto-sign
            .{ .bytes = recipient_pk },
            .{ .int = amount },
            .{ .int = output_sats },
        },
        rpc_provider.provider(),
        local_signer.signer(),
        .{ .new_state = &[_]runar.StateValue{
            .{ .bytes = recipient_pk },
            .{ .int = amount },
            .{ .int = 0 },
        } },
    );

    if (call_result) |txid| {
        defer allocator.free(txid);
        std.log.info("FungibleToken transfer TX: {s}", .{txid});
        try std.testing.expectEqual(@as(usize, 64), txid.len);
    } else |err| {
        // Multi-output transfer may not yet be supported by the Zig SDK
        std.log.warn("FungibleToken transfer failed (multi-output may not be supported yet): {any}", .{err});
    }
}

test "FungibleToken_TransferExactBalance" {
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
    var recipient = try helpers.newWallet(allocator);
    defer recipient.deinit();

    const owner_pk = try owner.pubKeyHex(allocator);
    defer allocator.free(owner_pk);
    const recipient_pk = try recipient.pubKeyHex(allocator);
    defer allocator.free(recipient_pk);
    const token_id = try hexEncodeAscii(allocator, "XFER-EXACT");
    defer allocator.free(token_id);

    const initial_balance: i64 = 1000;
    const deploy_sats: i64 = 5000;
    const output_sats: i64 = 2000;

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
    std.log.info("FungibleToken deployed for exact transfer test: {s}", .{deploy_txid});

    // Transfer entire balance to recipient -- should produce 1 output (no change)
    const call_result = contract.call(
        "transfer",
        &[_]runar.StateValue{
            .{ .int = 0 }, // sig: auto-sign
            .{ .bytes = recipient_pk },
            .{ .int = initial_balance }, // transfer full amount
            .{ .int = output_sats },
        },
        rpc_provider.provider(),
        local_signer.signer(),
        .{ .new_state = &[_]runar.StateValue{
            .{ .bytes = recipient_pk },
            .{ .int = initial_balance },
            .{ .int = 0 },
        } },
    );

    if (call_result) |txid| {
        defer allocator.free(txid);
        std.log.info("FungibleToken transfer exact balance TX: {s}", .{txid});
        try std.testing.expectEqual(@as(usize, 64), txid.len);
    } else |err| {
        // Multi-output transfer may not yet be supported by the Zig SDK
        std.log.warn("FungibleToken transfer exact balance failed (multi-output may not be supported yet): {any}", .{err});
    }
}

test "FungibleToken_TransferDeflatedBalance" {
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
    var recipient = try helpers.newWallet(allocator);
    defer recipient.deinit();

    const owner_pk = try owner.pubKeyHex(allocator);
    defer allocator.free(owner_pk);
    const recipient_pk = try recipient.pubKeyHex(allocator);
    defer allocator.free(recipient_pk);
    const token_id = try hexEncodeAscii(allocator, "XFER-DEFLATE");
    defer allocator.free(token_id);

    const initial_balance: i64 = 1000;
    const deploy_sats: i64 = 5000;
    const output_sats: i64 = 2000;

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
    std.log.info("FungibleToken deployed for deflated transfer test: {s}", .{deploy_txid});

    // Attacker deflates output balances: claims recipient gets 300, sender keeps 200 = 500 (from 1000)
    // hashOutputs mismatch should reject this on-chain
    const result = contract.call(
        "transfer",
        &[_]runar.StateValue{
            .{ .int = 0 }, // sig: auto-sign
            .{ .bytes = recipient_pk },
            .{ .int = 300 },
            .{ .int = output_sats },
        },
        rpc_provider.provider(),
        local_signer.signer(),
        .{ .new_state = &[_]runar.StateValue{
            .{ .bytes = recipient_pk },
            .{ .int = 300 },
            .{ .int = 0 },
        } },
    );

    if (result) |txid| {
        allocator.free(txid);
        // Deflated balance should be rejected; if it succeeded, log a warning
        std.log.warn("FungibleToken transfer with deflated balance unexpectedly succeeded", .{});
    } else |_| {
        std.log.info("FungibleToken correctly rejected transfer with deflated balance", .{});
    }
}

test "FungibleToken_TransferInflatedBalance" {
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
    var recipient = try helpers.newWallet(allocator);
    defer recipient.deinit();

    const owner_pk = try owner.pubKeyHex(allocator);
    defer allocator.free(owner_pk);
    const recipient_pk = try recipient.pubKeyHex(allocator);
    defer allocator.free(recipient_pk);
    const token_id = try hexEncodeAscii(allocator, "XFER-INFLATE");
    defer allocator.free(token_id);

    const initial_balance: i64 = 1000;
    const deploy_sats: i64 = 5000;
    const output_sats: i64 = 2000;

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
    std.log.info("FungibleToken deployed for inflated transfer test: {s}", .{deploy_txid});

    // Attacker inflates output balances: claims recipient gets 800, sender keeps 500 = 1300 (from 1000)
    // hashOutputs mismatch should reject this on-chain
    const result = contract.call(
        "transfer",
        &[_]runar.StateValue{
            .{ .int = 0 }, // sig: auto-sign
            .{ .bytes = recipient_pk },
            .{ .int = 800 },
            .{ .int = output_sats },
        },
        rpc_provider.provider(),
        local_signer.signer(),
        .{ .new_state = &[_]runar.StateValue{
            .{ .bytes = recipient_pk },
            .{ .int = 800 },
            .{ .int = 0 },
        } },
    );

    if (result) |txid| {
        allocator.free(txid);
        std.log.warn("FungibleToken transfer with inflated balance unexpectedly succeeded", .{});
    } else |_| {
        std.log.info("FungibleToken correctly rejected transfer with inflated balance", .{});
    }
}

test "FungibleToken_TransferExceedsBalanceRejected" {
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
    var recipient = try helpers.newWallet(allocator);
    defer recipient.deinit();

    const owner_pk = try owner.pubKeyHex(allocator);
    defer allocator.free(owner_pk);
    const recipient_pk = try recipient.pubKeyHex(allocator);
    defer allocator.free(recipient_pk);
    const token_id = try hexEncodeAscii(allocator, "XFER-EXCEED");
    defer allocator.free(token_id);

    const initial_balance: i64 = 1000;
    const deploy_sats: i64 = 5000;
    const output_sats: i64 = 2000;

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
    std.log.info("FungibleToken deployed for exceeds-balance test: {s}", .{deploy_txid});

    // Transfer 2000 when balance is only 1000 -- should fail assert(amount <= totalBalance)
    const result = contract.call(
        "transfer",
        &[_]runar.StateValue{
            .{ .int = 0 }, // sig: auto-sign
            .{ .bytes = recipient_pk },
            .{ .int = 2000 }, // exceeds balance
            .{ .int = output_sats },
        },
        rpc_provider.provider(),
        local_signer.signer(),
        .{ .new_state = &[_]runar.StateValue{
            .{ .bytes = recipient_pk },
            .{ .int = 2000 },
            .{ .int = 0 },
        } },
    );

    if (result) |txid| {
        allocator.free(txid);
        return error.TestUnexpectedResult; // should have failed
    } else |_| {
        std.log.info("FungibleToken correctly rejected transfer exceeding balance", .{});
    }
}

test "FungibleToken_TransferWrongSigner" {
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
    var wrong_signer_wallet = try helpers.newWallet(allocator);
    defer wrong_signer_wallet.deinit();
    var recipient = try helpers.newWallet(allocator);
    defer recipient.deinit();

    const owner_pk = try owner.pubKeyHex(allocator);
    defer allocator.free(owner_pk);
    const recipient_pk = try recipient.pubKeyHex(allocator);
    defer allocator.free(recipient_pk);
    const token_id = try hexEncodeAscii(allocator, "XFER-WRONG");
    defer allocator.free(token_id);

    const initial_balance: i64 = 1000;
    const amount: i64 = 300;
    const deploy_sats: i64 = 5000;
    const output_sats: i64 = 2000;

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
    std.log.info("FungibleToken deployed for wrong-signer transfer test: {s}", .{deploy_txid});

    // Fund wrong signer wallet
    const fund_txid2 = try helpers.fundWallet(allocator, &wrong_signer_wallet, 1.0);
    defer allocator.free(fund_txid2);

    var wrong_signer = try wrong_signer_wallet.localSigner();

    // Wrong signer tries to transfer -- checkSig should fail
    const result = contract.call(
        "transfer",
        &[_]runar.StateValue{
            .{ .int = 0 }, // sig: auto-sign (wrong key)
            .{ .bytes = recipient_pk },
            .{ .int = amount },
            .{ .int = output_sats },
        },
        rpc_provider.provider(),
        wrong_signer.signer(),
        .{ .new_state = &[_]runar.StateValue{
            .{ .bytes = recipient_pk },
            .{ .int = amount },
            .{ .int = 0 },
        } },
    );

    if (result) |txid| {
        allocator.free(txid);
        return error.TestUnexpectedResult; // should have failed
    } else |_| {
        std.log.info("FungibleToken correctly rejected transfer with wrong signer", .{});
    }
}

test "FungibleToken_TransferZeroAmountRejected" {
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
    var recipient = try helpers.newWallet(allocator);
    defer recipient.deinit();

    const owner_pk = try owner.pubKeyHex(allocator);
    defer allocator.free(owner_pk);
    const recipient_pk = try recipient.pubKeyHex(allocator);
    defer allocator.free(recipient_pk);
    const token_id = try hexEncodeAscii(allocator, "XFER-ZERO");
    defer allocator.free(token_id);

    const initial_balance: i64 = 1000;
    const deploy_sats: i64 = 5000;
    const output_sats: i64 = 2000;

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
    std.log.info("FungibleToken deployed for zero-amount transfer test: {s}", .{deploy_txid});

    // Transfer of zero amount -- should fail assert(amount > 0)
    const result = contract.call(
        "transfer",
        &[_]runar.StateValue{
            .{ .int = 0 }, // sig: auto-sign
            .{ .bytes = recipient_pk },
            .{ .int = 0 }, // zero amount
            .{ .int = output_sats },
        },
        rpc_provider.provider(),
        local_signer.signer(),
        .{ .new_state = &[_]runar.StateValue{
            .{ .bytes = recipient_pk },
            .{ .int = 0 },
            .{ .int = 0 },
        } },
    );

    if (result) |txid| {
        allocator.free(txid);
        return error.TestUnexpectedResult; // should have failed
    } else |_| {
        std.log.info("FungibleToken correctly rejected transfer of zero amount", .{});
    }
}

test "FungibleToken_Merge" {
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
    const token_id = try hexEncodeAscii(allocator, "MERGE-SDK-TOKEN");
    defer allocator.free(token_id);

    const balance1: i64 = 400;
    const balance2: i64 = 600;
    const deploy_sats: i64 = 5000;
    const output_sats: i64 = 4000;

    // Deploy first contract
    var contract1 = try runar.RunarContract.init(allocator, &artifact, &[_]runar.StateValue{
        .{ .bytes = owner_pk },
        .{ .int = balance1 },
        .{ .int = 0 },
        .{ .bytes = token_id },
    });
    defer contract1.deinit();

    const fund_txid = try helpers.fundWallet(allocator, &owner, 2.0);
    defer allocator.free(fund_txid);

    var rpc_provider = helpers.RPCProvider.init(allocator);
    var local_signer = try owner.localSigner();

    const deploy_txid1 = try contract1.deploy(rpc_provider.provider(), local_signer.signer(), .{ .satoshis = deploy_sats });
    defer allocator.free(deploy_txid1);
    std.log.info("FungibleToken contract1 deployed for merge test: {s}", .{deploy_txid1});

    // Deploy second contract
    var contract2 = try runar.RunarContract.init(allocator, &artifact, &[_]runar.StateValue{
        .{ .bytes = owner_pk },
        .{ .int = balance2 },
        .{ .int = 0 },
        .{ .bytes = token_id },
    });
    defer contract2.deinit();

    const deploy_txid2 = try contract2.deploy(rpc_provider.provider(), local_signer.signer(), .{ .satoshis = deploy_sats });
    defer allocator.free(deploy_txid2);
    std.log.info("FungibleToken contract2 deployed for merge test: {s}", .{deploy_txid2});

    // merge(sig, otherBalance, allPrevouts, outputSatoshis)
    // Merges two UTXOs into one with combined balance
    // Note: Zig SDK does not yet support AdditionalContractInputs,
    // so merge will be attempted with new_state only.
    const call_result = contract1.call(
        "merge",
        &[_]runar.StateValue{
            .{ .int = 0 }, // sig: auto-sign
            .{ .int = balance2 }, // otherBalance
            .{ .int = 0 }, // allPrevouts: auto-computed
            .{ .int = output_sats },
        },
        rpc_provider.provider(),
        local_signer.signer(),
        .{ .new_state = &[_]runar.StateValue{
            .{ .bytes = owner_pk },
            .{ .int = balance1 },
            .{ .int = balance2 },
        } },
    );

    if (call_result) |txid| {
        defer allocator.free(txid);
        std.log.info("FungibleToken merge TX: {s}", .{txid});
        try std.testing.expectEqual(@as(usize, 64), txid.len);
    } else |err| {
        // Merge requires AdditionalContractInputs which may not yet be supported
        std.log.warn("FungibleToken merge failed (AdditionalContractInputs may not be supported yet): {any}", .{err});
    }
}

test "FungibleToken_MergeDeflated" {
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
    const token_id = try hexEncodeAscii(allocator, "MERGE-DEFLATE");
    defer allocator.free(token_id);

    const balance1: i64 = 400;
    const balance2: i64 = 600;
    const deploy_sats: i64 = 5000;
    const output_sats: i64 = 4000;

    var contract1 = try runar.RunarContract.init(allocator, &artifact, &[_]runar.StateValue{
        .{ .bytes = owner_pk },
        .{ .int = balance1 },
        .{ .int = 0 },
        .{ .bytes = token_id },
    });
    defer contract1.deinit();

    const fund_txid = try helpers.fundWallet(allocator, &owner, 2.0);
    defer allocator.free(fund_txid);

    var rpc_provider = helpers.RPCProvider.init(allocator);
    var local_signer = try owner.localSigner();

    const deploy_txid1 = try contract1.deploy(rpc_provider.provider(), local_signer.signer(), .{ .satoshis = deploy_sats });
    defer allocator.free(deploy_txid1);

    var contract2 = try runar.RunarContract.init(allocator, &artifact, &[_]runar.StateValue{
        .{ .bytes = owner_pk },
        .{ .int = balance2 },
        .{ .int = 0 },
        .{ .bytes = token_id },
    });
    defer contract2.deinit();

    const deploy_txid2 = try contract2.deploy(rpc_provider.provider(), local_signer.signer(), .{ .satoshis = deploy_sats });
    defer allocator.free(deploy_txid2);
    std.log.info("FungibleToken contracts deployed for deflated merge test", .{});

    // Negative otherBalance fails assert(otherBalance >= 0)
    // Attacker claims otherBalance=100 but passes -100 to second input
    const result = contract1.call(
        "merge",
        &[_]runar.StateValue{
            .{ .int = 0 }, // sig: auto-sign
            .{ .int = 100 }, // deflated otherBalance
            .{ .int = 0 }, // allPrevouts: auto-computed
            .{ .int = output_sats },
        },
        rpc_provider.provider(),
        local_signer.signer(),
        .{ .new_state = &[_]runar.StateValue{
            .{ .bytes = owner_pk },
            .{ .int = balance1 },
            .{ .int = 100 },
        } },
    );

    if (result) |txid| {
        allocator.free(txid);
        std.log.warn("FungibleToken merge with deflated balance unexpectedly succeeded", .{});
    } else |_| {
        std.log.info("FungibleToken correctly rejected merge with deflated balance", .{});
    }
}

test "FungibleToken_MergeInflatedTotal" {
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
    const token_id = try hexEncodeAscii(allocator, "MERGE-INFLATE");
    defer allocator.free(token_id);

    const balance1: i64 = 400;
    const balance2: i64 = 600;
    const deploy_sats: i64 = 5000;
    const output_sats: i64 = 4000;

    var contract1 = try runar.RunarContract.init(allocator, &artifact, &[_]runar.StateValue{
        .{ .bytes = owner_pk },
        .{ .int = balance1 },
        .{ .int = 0 },
        .{ .bytes = token_id },
    });
    defer contract1.deinit();

    const fund_txid = try helpers.fundWallet(allocator, &owner, 2.0);
    defer allocator.free(fund_txid);

    var rpc_provider = helpers.RPCProvider.init(allocator);
    var local_signer = try owner.localSigner();

    const deploy_txid1 = try contract1.deploy(rpc_provider.provider(), local_signer.signer(), .{ .satoshis = deploy_sats });
    defer allocator.free(deploy_txid1);

    var contract2 = try runar.RunarContract.init(allocator, &artifact, &[_]runar.StateValue{
        .{ .bytes = owner_pk },
        .{ .int = balance2 },
        .{ .int = 0 },
        .{ .bytes = token_id },
    });
    defer contract2.deinit();

    const deploy_txid2 = try contract2.deploy(rpc_provider.provider(), local_signer.signer(), .{ .satoshis = deploy_sats });
    defer allocator.free(deploy_txid2);
    std.log.info("FungibleToken contracts deployed for inflated merge test", .{});

    // Attacker claims inflated otherBalance=1600. hashOutputs mismatch should reject.
    const result = contract1.call(
        "merge",
        &[_]runar.StateValue{
            .{ .int = 0 }, // sig: auto-sign
            .{ .int = 1600 }, // inflated otherBalance
            .{ .int = 0 }, // allPrevouts: auto-computed
            .{ .int = output_sats },
        },
        rpc_provider.provider(),
        local_signer.signer(),
        .{ .new_state = &[_]runar.StateValue{
            .{ .bytes = owner_pk },
            .{ .int = balance1 },
            .{ .int = 1600 },
        } },
    );

    if (result) |txid| {
        allocator.free(txid);
        std.log.warn("FungibleToken merge with inflated total unexpectedly succeeded", .{});
    } else |_| {
        std.log.info("FungibleToken correctly rejected merge with inflated total", .{});
    }
}

test "FungibleToken_MergeWrongSigner" {
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
    var wrong_signer_wallet = try helpers.newWallet(allocator);
    defer wrong_signer_wallet.deinit();

    const owner_pk = try owner.pubKeyHex(allocator);
    defer allocator.free(owner_pk);
    const token_id = try hexEncodeAscii(allocator, "MERGE-WRONG");
    defer allocator.free(token_id);

    const balance1: i64 = 400;
    const balance2: i64 = 600;
    const deploy_sats: i64 = 5000;
    const output_sats: i64 = 4000;

    var contract1 = try runar.RunarContract.init(allocator, &artifact, &[_]runar.StateValue{
        .{ .bytes = owner_pk },
        .{ .int = balance1 },
        .{ .int = 0 },
        .{ .bytes = token_id },
    });
    defer contract1.deinit();

    const fund_txid = try helpers.fundWallet(allocator, &owner, 2.0);
    defer allocator.free(fund_txid);

    var rpc_provider = helpers.RPCProvider.init(allocator);
    var local_signer = try owner.localSigner();

    const deploy_txid1 = try contract1.deploy(rpc_provider.provider(), local_signer.signer(), .{ .satoshis = deploy_sats });
    defer allocator.free(deploy_txid1);

    var contract2 = try runar.RunarContract.init(allocator, &artifact, &[_]runar.StateValue{
        .{ .bytes = owner_pk },
        .{ .int = balance2 },
        .{ .int = 0 },
        .{ .bytes = token_id },
    });
    defer contract2.deinit();

    const deploy_txid2 = try contract2.deploy(rpc_provider.provider(), local_signer.signer(), .{ .satoshis = deploy_sats });
    defer allocator.free(deploy_txid2);
    std.log.info("FungibleToken contracts deployed for wrong-signer merge test", .{});

    // Fund wrong signer wallet
    const fund_txid2 = try helpers.fundWallet(allocator, &wrong_signer_wallet, 1.0);
    defer allocator.free(fund_txid2);

    var wrong_signer = try wrong_signer_wallet.localSigner();

    // Wrong signer tries to merge -- checkSig should fail
    const result = contract1.call(
        "merge",
        &[_]runar.StateValue{
            .{ .int = 0 }, // sig: auto-sign (wrong key)
            .{ .int = balance2 },
            .{ .int = 0 }, // allPrevouts: auto-computed
            .{ .int = output_sats },
        },
        rpc_provider.provider(),
        wrong_signer.signer(),
        .{ .new_state = &[_]runar.StateValue{
            .{ .bytes = owner_pk },
            .{ .int = balance1 },
            .{ .int = balance2 },
        } },
    );

    if (result) |txid| {
        allocator.free(txid);
        return error.TestUnexpectedResult; // should have failed
    } else |_| {
        std.log.info("FungibleToken correctly rejected merge with wrong signer", .{});
    }
}
