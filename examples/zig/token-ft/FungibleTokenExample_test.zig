const std = @import("std");

const root = @import("../examples_test.zig");
const runar = @import("runar");
const FungibleTokenExample = @import("FungibleTokenExample.runar.zig").FungibleTokenExample;

const contract_source = @embedFile("FungibleTokenExample.runar.zig");

test "compile-check FungibleTokenExample.runar.zig" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.writeFile(.{ .sub_path = "FungibleTokenExample.runar.zig", .data = contract_source });

    const path = try std.fs.path.join(allocator, &.{ ".zig-cache", "tmp", tmp.sub_path[0..], "FungibleTokenExample.runar.zig" });
    defer allocator.free(path);
    try root.runar.compileCheckFile(allocator, path);
    try root.runar.compileCheckSource(allocator, contract_source, "FungibleTokenExample.runar.zig");
}

fn expectBytes(value: runar.OutputValue, expected: []const u8) !void {
    switch (value) {
        .bytes => |bytes| try std.testing.expectEqualSlices(u8, expected, bytes),
        else => return error.TestUnexpectedResult,
    }
}

fn expectBigint(value: runar.OutputValue, expected: i64) !void {
    switch (value) {
        .bigint => |bigint| try std.testing.expectEqual(expected, bigint),
        else => return error.TestUnexpectedResult,
    }
}

fn expectContinuationOutput(
    output: runar.OutputSnapshot,
    prefix: []const u8,
    values: anytype,
    suffix: []const u8,
) !void {
    const expected_state = try runar.serializeTestStateValues(std.testing.allocator, values);
    defer std.testing.allocator.free(expected_state);
    const expected_continuation = try runar.wrapTestContinuationScript(std.testing.allocator, prefix, values, suffix);
    defer std.testing.allocator.free(expected_continuation);

    try std.testing.expectEqualSlices(u8, expected_state, output.stateScript);
    try std.testing.expectEqualSlices(u8, expected_continuation, output.continuationScript);
}

test "fungible token transfer records recipient and change outputs" {
    var runtime = runar.StatefulSmartContract.init(std.testing.allocator);
    defer runtime.deinit();
    try runtime.setContinuationEnvelope("ft:", ":script");
    var token = FungibleTokenExample.init(runar.ALICE.pubKey, 40, 10, "token");
    const ctx = try runar.StatefulContext.init(&runtime, runar.mockPreimage(.{}));

    token.transfer(ctx, runar.signTestMessage(runar.ALICE), runar.BOB.pubKey, 30, 1);

    try std.testing.expectEqual(@as(usize, 2), ctx.outputs().len);
    try std.testing.expectEqual(@as(i64, 1), ctx.outputs()[0].satoshis);
    try expectBytes(ctx.outputs()[0].values[0], runar.BOB.pubKey);
    try expectBigint(ctx.outputs()[0].values[1], 30);
    try expectBigint(ctx.outputs()[0].values[2], 0);
    try expectContinuationOutput(ctx.outputs()[0], "ft:", .{ runar.BOB.pubKey, @as(i64, 30), @as(i64, 0) }, ":script");
    try expectBytes(ctx.outputs()[1].values[0], runar.ALICE.pubKey);
    try expectBigint(ctx.outputs()[1].values[1], 20);
    try expectBigint(ctx.outputs()[1].values[2], 0);
    try expectContinuationOutput(ctx.outputs()[1], "ft:", .{ runar.ALICE.pubKey, @as(i64, 20), @as(i64, 0) }, ":script");
}

test "fungible token send records a single full-balance output" {
    var runtime = runar.StatefulSmartContract.init(std.testing.allocator);
    defer runtime.deinit();
    try runtime.setContinuationEnvelope("ft:", ":script");
    var token = FungibleTokenExample.init(runar.ALICE.pubKey, 25, 5, "token");
    const ctx = try runar.StatefulContext.init(&runtime, runar.mockPreimage(.{}));

    token.send(ctx, runar.signTestMessage(runar.ALICE), runar.BOB.pubKey, 1);

    try std.testing.expectEqual(@as(usize, 1), ctx.outputs().len);
    try expectBytes(ctx.outputs()[0].values[0], runar.BOB.pubKey);
    try expectBigint(ctx.outputs()[0].values[1], 30);
    try expectBigint(ctx.outputs()[0].values[2], 0);
    try expectContinuationOutput(ctx.outputs()[0], "ft:", .{ runar.BOB.pubKey, @as(i64, 30), @as(i64, 0) }, ":script");
}

test "fungible token merge preserves first-input ordering through the real contract" {
    var runtime = runar.StatefulSmartContract.init(std.testing.allocator);
    defer runtime.deinit();
    try runtime.setContinuationEnvelope("ft:", ":script");
    var token = FungibleTokenExample.init(runar.ALICE.pubKey, 25, 5, "token");
    const first = [_]u8{'a'} ** 36;
    const second = [_]u8{'b'} ** 36;
    const all_prevouts = first ++ second;
    const ctx = try runar.StatefulContext.init(&runtime, runar.mockPreimage(.{
        .hashPrevouts = runar.hash256(all_prevouts[0..]),
        .outpoint = first[0..],
    }));

    token.merge(ctx, runar.signTestMessage(runar.ALICE), 12, all_prevouts[0..], 1);

    try std.testing.expectEqual(@as(usize, 1), ctx.outputs().len);
    try expectBytes(ctx.outputs()[0].values[0], runar.ALICE.pubKey);
    try expectBigint(ctx.outputs()[0].values[1], 30);
    try expectBigint(ctx.outputs()[0].values[2], 12);
    try expectContinuationOutput(ctx.outputs()[0], "ft:", .{ runar.ALICE.pubKey, @as(i64, 30), @as(i64, 12) }, ":script");
}

test "fungible token rejects invalid transfers and prevout mismatches" {
    try root.expectAssertFailure("token-ft-transfer-too-much");
    try root.expectAssertFailure("token-ft-transfer-wrong-sig");
    try root.expectAssertFailure("token-ft-merge-prevouts-mismatch");
}
