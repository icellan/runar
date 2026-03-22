const std = @import("std");

const root = @import("../examples_test.zig");
const runar = @import("runar");
const NFTExample = @import("NFTExample.runar.zig").NFTExample;

const contract_source = @embedFile("NFTExample.runar.zig");

test "compile-check NFTExample.runar.zig" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.writeFile(.{ .sub_path = "NFTExample.runar.zig", .data = contract_source });

    const path = try std.fs.path.join(allocator, &.{ ".zig-cache", "tmp", tmp.sub_path[0..], "NFTExample.runar.zig" });
    defer allocator.free(path);
    try root.runar.compileCheckFile(allocator, path);
    try root.runar.compileCheckSource(allocator, contract_source, "NFTExample.runar.zig");
}

fn expectBytes(value: runar.OutputValue, expected: []const u8) !void {
    switch (value) {
        .bytes => |bytes| try std.testing.expectEqualSlices(u8, expected, bytes),
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

test "nft transfer records a single new-owner output through the real contract" {
    var runtime = runar.StatefulSmartContract.init(std.testing.allocator);
    defer runtime.deinit();
    try runtime.setContinuationEnvelope("nft:", ":script");
    var nft = NFTExample.init(runar.ALICE.pubKey, "token", "metadata");
    const ctx = try runar.StatefulContext.init(&runtime, runar.mockPreimage(.{}));

    nft.transfer(ctx, runar.signTestMessage(runar.ALICE), runar.BOB.pubKey, 1);

    try std.testing.expectEqual(@as(usize, 1), ctx.outputs().len);
    try std.testing.expectEqual(@as(i64, 1), ctx.outputs()[0].satoshis);
    try expectBytes(ctx.outputs()[0].values[0], runar.BOB.pubKey);
    try expectContinuationOutput(ctx.outputs()[0], "nft:", .{runar.BOB.pubKey}, ":script");
}

test "nft burn authorizes the owner through the real contract" {
    const nft = NFTExample.init(runar.ALICE.pubKey, "token", "metadata");
    nft.burn(runar.signTestMessage(runar.ALICE));
}

test "nft transfer and burn reject invalid authorization or satoshis" {
    try root.expectAssertFailure("token-nft-transfer-wrong-sig");
    try root.expectAssertFailure("token-nft-transfer-invalid-satoshis");
    try root.expectAssertFailure("token-nft-burn-wrong-sig");
}
