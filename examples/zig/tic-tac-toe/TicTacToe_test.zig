const std = @import("std");

const root = @import("../examples_test.zig");
const runar = @import("runar");
const TicTacToe = @import("TicTacToe.runar.zig").TicTacToe;

const contract_source = @embedFile("TicTacToe.runar.zig");

test "compile-check TicTacToe.runar.zig" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.writeFile(.{ .sub_path = "TicTacToe.runar.zig", .data = contract_source });

    const path = try std.fs.path.join(allocator, &.{ ".zig-cache", "tmp", tmp.sub_path[0..], "TicTacToe.runar.zig" });
    defer allocator.free(path);
    try root.runar.compileCheckFile(allocator, path);
    try root.runar.compileCheckSource(allocator, contract_source, "TicTacToe.runar.zig");
}

test "tic tac toe join and move update the real contract state" {
    var game = TicTacToe.init(runar.ALICE.pubKey, 100);

    game.join(runar.BOB.pubKey, runar.signTestMessage(runar.BOB));
    try std.testing.expectEqual(@as(i64, 1), game.status);
    try std.testing.expectEqual(@as(i64, 1), game.turn);
    try std.testing.expectEqualSlices(u8, runar.BOB.pubKey, game.playerO);

    game.move(0, runar.ALICE.pubKey, runar.signTestMessage(runar.ALICE));
    try std.testing.expectEqual(@as(i64, 1), game.c0);
    try std.testing.expectEqual(@as(i64, 2), game.turn);

    game.move(4, runar.BOB.pubKey, runar.signTestMessage(runar.BOB));
    try std.testing.expectEqual(@as(i64, 2), game.c4);
    try std.testing.expectEqual(@as(i64, 1), game.turn);
}

test "tic tac toe rejects invalid joins and moves through the real contract" {
    try root.expectAssertFailure("tictactoe-join-twice");
    try root.expectAssertFailure("tictactoe-move-wrong-player");
    try root.expectAssertFailure("tictactoe-move-occupied-cell");
}

test "tic tac toe cancelBeforeJoin validates the real payout output" {
    var runtime = runar.StatefulSmartContract.init(std.testing.allocator);
    defer runtime.deinit();
    const game = TicTacToe.init(runar.ALICE.pubKey, 100);
    const payout = runar.testing.buildP2pkhOutput(runar.hash160(runar.ALICE.pubKey), 100);
    defer std.heap.page_allocator.free(payout);
    const preimage = runar.testing.mockPreimageForOutputs(&.{payout});
    defer std.heap.page_allocator.free(preimage);
    const ctx = try runar.StatefulContext.init(&runtime, preimage);

    game.cancelBeforeJoin(ctx, runar.signTestMessage(runar.ALICE), runar.hash160(runar.BOB.pubKey), 0);
}

test "tic tac toe cancelBeforeJoin rejects invalid output or signature" {
    try root.expectAssertFailure("tictactoe-cancel-before-join-wrong-sig");
    try root.expectAssertFailure("tictactoe-cancel-before-join-wrong-output");
}

test "tic tac toe cancel validates the real dual-payout output" {
    var runtime = runar.StatefulSmartContract.init(std.testing.allocator);
    defer runtime.deinit();
    var game = TicTacToe.init(runar.ALICE.pubKey, 100);
    game.join(runar.BOB.pubKey, runar.signTestMessage(runar.BOB));

    const out1 = runar.testing.buildP2pkhOutput(runar.hash160(runar.ALICE.pubKey), 100);
    const out2 = runar.testing.buildP2pkhOutput(runar.hash160(runar.BOB.pubKey), 100);
    defer std.heap.page_allocator.free(out1);
    defer std.heap.page_allocator.free(out2);
    const preimage = runar.testing.mockPreimageForOutputs(&.{ out1, out2 });
    defer std.heap.page_allocator.free(preimage);
    const ctx = try runar.StatefulContext.init(&runtime, preimage);

    game.cancel(
        ctx,
        runar.signTestMessage(runar.ALICE),
        runar.signTestMessage(runar.BOB),
        runar.hash160(runar.CHARLIE.pubKey),
        0,
    );
}

test "tic tac toe cancel rejects invalid output or signatures" {
    try root.expectAssertFailure("tictactoe-cancel-wrong-sig-x");
    try root.expectAssertFailure("tictactoe-cancel-wrong-sig-o");
    try root.expectAssertFailure("tictactoe-cancel-wrong-output");
}

test "tic tac toe moveAndWin validates the real winner-take-all output" {
    var runtime = runar.StatefulSmartContract.init(std.testing.allocator);
    defer runtime.deinit();
    const game = TicTacToe{
        .playerX = runar.ALICE.pubKey,
        .betAmount = 100,
        .playerO = runar.BOB.pubKey,
        .c0 = 1,
        .c1 = 1,
        .c3 = 2,
        .c4 = 2,
        .turn = 1,
        .status = 1,
    };

    const payout = runar.testing.buildP2pkhOutput(runar.hash160(runar.ALICE.pubKey), 200);
    defer std.heap.page_allocator.free(payout);
    const preimage = runar.testing.mockPreimageForOutputs(&.{payout});
    defer std.heap.page_allocator.free(preimage);
    const ctx = try runar.StatefulContext.init(&runtime, preimage);

    game.moveAndWin(
        ctx,
        2,
        runar.ALICE.pubKey,
        runar.signTestMessage(runar.ALICE),
        runar.hash160(runar.CHARLIE.pubKey),
        0,
    );
}

test "tic tac toe moveAndWin rejects invalid output or signature" {
    try root.expectAssertFailure("tictactoe-move-and-win-wrong-sig");
    try root.expectAssertFailure("tictactoe-move-and-win-wrong-output");
}

test "tic tac toe moveAndTie validates the real split payout output" {
    var runtime = runar.StatefulSmartContract.init(std.testing.allocator);
    defer runtime.deinit();
    const game = TicTacToe{
        .playerX = runar.ALICE.pubKey,
        .betAmount = 100,
        .playerO = runar.BOB.pubKey,
        .c0 = 1,
        .c1 = 2,
        .c2 = 1,
        .c3 = 1,
        .c4 = 1,
        .c5 = 2,
        .c6 = 2,
        .c7 = 1,
        .turn = 2,
        .status = 1,
    };

    const out1 = runar.testing.buildP2pkhOutput(runar.hash160(runar.ALICE.pubKey), 100);
    const out2 = runar.testing.buildP2pkhOutput(runar.hash160(runar.BOB.pubKey), 100);
    defer std.heap.page_allocator.free(out1);
    defer std.heap.page_allocator.free(out2);
    const preimage = runar.testing.mockPreimageForOutputs(&.{ out1, out2 });
    defer std.heap.page_allocator.free(preimage);
    const ctx = try runar.StatefulContext.init(&runtime, preimage);

    game.moveAndTie(
        ctx,
        8,
        runar.BOB.pubKey,
        runar.signTestMessage(runar.BOB),
        runar.hash160(runar.CHARLIE.pubKey),
        0,
    );
}

test "tic tac toe moveAndTie rejects invalid output or signature" {
    try root.expectAssertFailure("tictactoe-move-and-tie-wrong-sig");
    try root.expectAssertFailure("tictactoe-move-and-tie-wrong-output");
}
