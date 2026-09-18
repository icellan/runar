const std = @import("std");

const root = @import("../examples_test.zig");
const runar = @import("runar");
const FungibleTokenExample = @import("FungibleTokenExample.runar.zig").FungibleToken;

const contract_source = @embedFile("FungibleTokenExample.runar.zig");

test "compile-check FungibleTokenExample.runar.zig" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.writeFile(std.testing.io, .{ .sub_path = "FungibleTokenExample.runar.zig", .data = contract_source });

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
    // A 255-byte companion locking script: 2-byte prologue, 204-byte code
    // body, then the 49-byte (owner, balance, mergeBalance) state tail.
    var companion_script = [_]u8{0x51} ** 255;
    companion_script[0] = 0x61;
    companion_script[1] = 0xab;
    @memcpy(companion_script[206..239], runar.ALICE.pubKey);
    std.mem.writeInt(i64, companion_script[239..247], 7, .little);
    std.mem.writeInt(i64, companion_script[247..255], 5, .little);

    // version, one empty-script input, output-count fd/fd00, output zero,
    // 252 zero-value empty-script outputs, locktime.  This is a complete
    // 253-output serialization, so the authenticated txid and CompactSize
    // offsets are exercised together.
    var companion_parent = [_]u8{0} ** 2587;
    std.mem.writeInt(i32, companion_parent[0..4], 2, .little);
    companion_parent[4] = 1;
    @memset(companion_parent[42..46], 0xff);
    companion_parent[46] = 0xfd;
    companion_parent[47] = 0xfd;
    companion_parent[48] = 0x00;
    std.mem.writeInt(i64, companion_parent[49..57], 1, .little);
    companion_parent[57] = 0xfd;
    companion_parent[58] = 0xff;
    companion_parent[59] = 0x00;
    @memcpy(companion_parent[60..315], companion_script[0..]);

    const first = [_]u8{'a'} ** 36;
    var second = [_]u8{0} ** 36;
    @memcpy(second[0..32], runar.hash256(companion_parent[0..]));
    const all_prevouts = first ++ second;
    const ctx = try runar.StatefulContext.init(&runtime, runar.mockPreimage(.{
        .hashPrevouts = runar.hash256(all_prevouts[0..]),
        .outpoint = first[0..],
        .scriptCode = companion_script[2..],
    }));

    token.merge(ctx, runar.signTestMessage(runar.ALICE), 12, all_prevouts[0..], companion_parent[0..], 1);

    try std.testing.expectEqual(@as(usize, 1), ctx.outputs().len);
    try expectBytes(ctx.outputs()[0].values[0], runar.ALICE.pubKey);
    try expectBigint(ctx.outputs()[0].values[1], 30);
    try expectBigint(ctx.outputs()[0].values[2], 12);
    try expectContinuationOutput(ctx.outputs()[0], "ft:", .{ runar.ALICE.pubKey, @as(i64, 30), @as(i64, 12) }, ":script");
}

test "fungible token merge dummy companion parent is refused" {
    try root.expectAssertFailure("token-ft-merge-dummy-parent");
}

test "fungible token rejects invalid transfers and prevout mismatches" {
    try root.expectAssertFailure("token-ft-transfer-too-much");
    try root.expectAssertFailure("token-ft-transfer-wrong-sig");
    try root.expectAssertFailure("token-ft-merge-prevouts-mismatch");
}
