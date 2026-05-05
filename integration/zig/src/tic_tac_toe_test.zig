const std = @import("std");
const runar = @import("runar");
const helpers = @import("helpers.zig");
const compile = @import("compile.zig");

test "TicTacToe_Compile" {
    const allocator = std.testing.allocator;

    var artifact = try compile.compileContract(allocator, "examples/zig/tic-tac-toe/TicTacToe.runar.zig");
    defer artifact.deinit();

    try std.testing.expectEqualStrings("TicTacToe", artifact.contract_name);
    try std.testing.expect(artifact.isStateful());
    std.log.info("TicTacToe compiled: {d} bytes", .{artifact.script.len / 2});
}

test "TicTacToe_Deploy" {
    const allocator = std.testing.allocator;

    helpers.requireNodeAvailable(allocator);

    var artifact = try compile.compileContract(allocator, "examples/zig/tic-tac-toe/TicTacToe.runar.zig");
    defer artifact.deinit();

    var player_x = try helpers.newWallet(allocator);
    defer player_x.deinit();

    const px_hex = try player_x.pubKeyHex(allocator);
    defer allocator.free(px_hex);

    const bet_amount: i64 = 5000;

    // Constructor: playerX (PubKey), betAmount (bigint)
    var contract = try runar.RunarContract.init(allocator, &artifact, &[_]runar.StateValue{
        .{ .bytes = px_hex },
        .{ .int = bet_amount },
    });
    defer contract.deinit();

    const fund_txid = try helpers.fundWallet(allocator, &player_x, 1.0);
    defer allocator.free(fund_txid);

    var rpc_provider = helpers.RPCProvider.init(allocator);
    var local_signer = try player_x.localSigner();

    const deploy_txid = try contract.deploy(rpc_provider.provider(), local_signer.signer(), .{ .satoshis = bet_amount });
    defer allocator.free(deploy_txid);

    const utxo = contract.getCurrentUtxo();
    try std.testing.expect(utxo != null);
    try std.testing.expectEqual(@as(usize, 64), deploy_txid.len);
    std.log.info("TicTacToe deployed with betAmount={d}: {s}", .{ bet_amount, deploy_txid });
}

test "TicTacToe_Join" {
    const allocator = std.testing.allocator;

    helpers.requireNodeAvailable(allocator);

    var artifact = try compile.compileContract(allocator, "examples/zig/tic-tac-toe/TicTacToe.runar.zig");
    defer artifact.deinit();

    var player_x = try helpers.newWallet(allocator);
    defer player_x.deinit();
    var player_o = try helpers.newWallet(allocator);
    defer player_o.deinit();

    const px_hex = try player_x.pubKeyHex(allocator);
    defer allocator.free(px_hex);
    const po_hex = try player_o.pubKeyHex(allocator);
    defer allocator.free(po_hex);

    const bet_amount: i64 = 5000;

    var contract = try runar.RunarContract.init(allocator, &artifact, &[_]runar.StateValue{
        .{ .bytes = px_hex },
        .{ .int = bet_amount },
    });
    defer contract.deinit();

    const fund_x = try helpers.fundWallet(allocator, &player_x, 1.0);
    defer allocator.free(fund_x);

    var rpc_provider = helpers.RPCProvider.init(allocator);
    var signer_x = try player_x.localSigner();

    const deploy_txid = try contract.deploy(rpc_provider.provider(), signer_x.signer(), .{ .satoshis = bet_amount });
    defer allocator.free(deploy_txid);
    std.log.info("TicTacToe deployed: {s}", .{deploy_txid});

    // Fund playerO
    const fund_o = try helpers.fundWallet(allocator, &player_o, 1.0);
    defer allocator.free(fund_o);
    var signer_o = try player_o.localSigner();

    // join(opponentPK, sig) -- playerO joins. Pass null options so the
    // SDK auto-computes the new state via the ANF interpreter (matches the
    // Go integration test pattern). Explicit `new_state` worked in the
    // legacy SDK path but stops broadcasting once `playerO` (a PubKey) is
    // serialised through state_mod.serializeState — auto-compute is the
    // canonical path because it produces exactly the bytes the contract's
    // hashOutputs check expects.
    const join_txid = try contract.call(
        "join",
        &[_]runar.StateValue{
            .{ .bytes = po_hex },
            .{ .int = 0 }, // sig: auto-sign
        },
        rpc_provider.provider(),
        signer_o.signer(),
        null,
    );
    defer allocator.free(join_txid);
    std.log.info("TicTacToe join TX: {s}", .{join_txid});
    try std.testing.expectEqual(@as(usize, 64), join_txid.len);
}

test "TicTacToe_Move" {
    const allocator = std.testing.allocator;

    helpers.requireNodeAvailable(allocator);

    var artifact = try compile.compileContract(allocator, "examples/zig/tic-tac-toe/TicTacToe.runar.zig");
    defer artifact.deinit();

    var player_x = try helpers.newWallet(allocator);
    defer player_x.deinit();
    var player_o = try helpers.newWallet(allocator);
    defer player_o.deinit();

    const px_hex = try player_x.pubKeyHex(allocator);
    defer allocator.free(px_hex);
    const po_hex = try player_o.pubKeyHex(allocator);
    defer allocator.free(po_hex);

    const bet_amount: i64 = 5000;

    var contract = try runar.RunarContract.init(allocator, &artifact, &[_]runar.StateValue{
        .{ .bytes = px_hex },
        .{ .int = bet_amount },
    });
    defer contract.deinit();

    const fund_x = try helpers.fundWallet(allocator, &player_x, 1.0);
    defer allocator.free(fund_x);

    var rpc_provider = helpers.RPCProvider.init(allocator);
    var signer_x = try player_x.localSigner();

    const deploy_txid = try contract.deploy(rpc_provider.provider(), signer_x.signer(), .{ .satoshis = bet_amount });
    defer allocator.free(deploy_txid);

    // Fund playerO
    const fund_o = try helpers.fundWallet(allocator, &player_o, 1.0);
    defer allocator.free(fund_o);
    var signer_o = try player_o.localSigner();

    // Join — let the SDK auto-compute new state via the ANF interpreter.
    const join_txid = try contract.call(
        "join",
        &[_]runar.StateValue{
            .{ .bytes = po_hex },
            .{ .int = 0 },
        },
        rpc_provider.provider(),
        signer_o.signer(),
        null,
    );
    allocator.free(join_txid);

    // Move: player X plays position 4 (center). SDK auto-computes new
    // state — c4=1, turn flips from 1 to 2.
    const move_txid = try contract.call(
        "move",
        &[_]runar.StateValue{
            .{ .int = 4 }, // position
            .{ .bytes = px_hex }, // player
            .{ .int = 0 }, // sig: auto-sign
        },
        rpc_provider.provider(),
        signer_x.signer(),
        null,
    );
    defer allocator.free(move_txid);
    std.log.info("TicTacToe move TX: {s}", .{move_txid});
    try std.testing.expectEqual(@as(usize, 64), move_txid.len);
}

test "TicTacToe_StateFields" {
    const allocator = std.testing.allocator;

    var artifact = try compile.compileContract(allocator, "examples/zig/tic-tac-toe/TicTacToe.runar.zig");
    defer artifact.deinit();

    // TicTacToe should have multiple state fields (board, turn, status, etc.)
    try std.testing.expect(artifact.state_fields.len >= 3);

    // Should have public methods: join, move, moveAndWin
    var public_count: usize = 0;
    for (artifact.abi.methods) |m| {
        if (m.is_public) public_count += 1;
    }
    try std.testing.expect(public_count >= 2);
}

test "TicTacToe_WrongPlayerRejected" {
    const allocator = std.testing.allocator;

    helpers.requireNodeAvailable(allocator);

    var artifact = try compile.compileContract(allocator, "examples/zig/tic-tac-toe/TicTacToe.runar.zig");
    defer artifact.deinit();

    var player_x = try helpers.newWallet(allocator);
    defer player_x.deinit();
    var player_o = try helpers.newWallet(allocator);
    defer player_o.deinit();

    const px_hex = try player_x.pubKeyHex(allocator);
    defer allocator.free(px_hex);
    const po_hex = try player_o.pubKeyHex(allocator);
    defer allocator.free(po_hex);

    const bet_amount: i64 = 5000;

    var contract = try runar.RunarContract.init(allocator, &artifact, &[_]runar.StateValue{
        .{ .bytes = px_hex },
        .{ .int = bet_amount },
    });
    defer contract.deinit();

    const fund_x = try helpers.fundWallet(allocator, &player_x, 1.0);
    defer allocator.free(fund_x);

    var rpc_provider = helpers.RPCProvider.init(allocator);
    var signer_x = try player_x.localSigner();

    const deploy_txid = try contract.deploy(rpc_provider.provider(), signer_x.signer(), .{ .satoshis = bet_amount });
    defer allocator.free(deploy_txid);

    // Fund playerO
    const fund_o = try helpers.fundWallet(allocator, &player_o, 1.0);
    defer allocator.free(fund_o);
    var signer_o = try player_o.localSigner();

    // Join — let SDK auto-compute new state via ANF interpreter.
    const join_txid = try contract.call(
        "join",
        &[_]runar.StateValue{
            .{ .bytes = po_hex },
            .{ .int = 0 }, // sig: auto-sign
        },
        rpc_provider.provider(),
        signer_o.signer(),
        null,
    );
    allocator.free(join_txid);

    // After join, turn=1 (X's turn). Player O tries to move -- assertCorrectPlayer
    // checks player == playerX when turn==1, so this should be rejected.
    const move_result = contract.call(
        "move",
        &[_]runar.StateValue{
            .{ .int = 4 }, // position
            .{ .bytes = po_hex }, // player (wrong -- should be X)
            .{ .int = 0 }, // sig: auto-sign
        },
        rpc_provider.provider(),
        signer_o.signer(),
        null,
    );

    if (move_result) |move_txid| {
        allocator.free(move_txid);
        return error.TestUnexpectedResult; // should have been rejected
    } else |_| {
        // Expected: move was rejected because wrong player tried to move
        std.log.warn("TicTacToe correctly rejected wrong player move", .{});
    }
}

test "TicTacToe_JoinAfterPlayingRejected" {
    const allocator = std.testing.allocator;

    helpers.requireNodeAvailable(allocator);

    var artifact = try compile.compileContract(allocator, "examples/zig/tic-tac-toe/TicTacToe.runar.zig");
    defer artifact.deinit();

    var player_x = try helpers.newWallet(allocator);
    defer player_x.deinit();
    var player_o = try helpers.newWallet(allocator);
    defer player_o.deinit();
    var intruder = try helpers.newWallet(allocator);
    defer intruder.deinit();

    const px_hex = try player_x.pubKeyHex(allocator);
    defer allocator.free(px_hex);
    const po_hex = try player_o.pubKeyHex(allocator);
    defer allocator.free(po_hex);
    const intruder_hex = try intruder.pubKeyHex(allocator);
    defer allocator.free(intruder_hex);

    const bet_amount: i64 = 5000;

    var contract = try runar.RunarContract.init(allocator, &artifact, &[_]runar.StateValue{
        .{ .bytes = px_hex },
        .{ .int = bet_amount },
    });
    defer contract.deinit();

    const fund_x = try helpers.fundWallet(allocator, &player_x, 1.0);
    defer allocator.free(fund_x);

    var rpc_provider = helpers.RPCProvider.init(allocator);
    var signer_x = try player_x.localSigner();

    const deploy_txid = try contract.deploy(rpc_provider.provider(), signer_x.signer(), .{ .satoshis = bet_amount });
    defer allocator.free(deploy_txid);

    // Fund playerO
    const fund_o = try helpers.fundWallet(allocator, &player_o, 1.0);
    defer allocator.free(fund_o);
    var signer_o = try player_o.localSigner();

    // Fund intruder
    const fund_intruder = try helpers.fundWallet(allocator, &intruder, 1.0);
    defer allocator.free(fund_intruder);
    var signer_intruder = try intruder.localSigner();

    // Join — let SDK auto-compute new state via ANF interpreter.
    const join_txid = try contract.call(
        "join",
        &[_]runar.StateValue{
            .{ .bytes = po_hex },
            .{ .int = 0 }, // sig: auto-sign
        },
        rpc_provider.provider(),
        signer_o.signer(),
        null,
    );
    allocator.free(join_txid);

    // Try to join again with intruder -- status is now 1, assert(status==0) fails
    const second_join_result = contract.call(
        "join",
        &[_]runar.StateValue{
            .{ .bytes = intruder_hex },
            .{ .int = 0 }, // sig: auto-sign
        },
        rpc_provider.provider(),
        signer_intruder.signer(),
        null,
    );

    if (second_join_result) |txid| {
        allocator.free(txid);
        return error.TestUnexpectedResult; // should have been rejected
    } else |_| {
        // Expected: second join was rejected because status != 0
        std.log.warn("TicTacToe correctly rejected second join attempt", .{});
    }
}
