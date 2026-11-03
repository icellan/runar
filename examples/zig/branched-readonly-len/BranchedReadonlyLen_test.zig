const std = @import("std");
const root = @import("../examples_test.zig");
const runar = @import("runar");
const BranchedReadonlyLen = @import("BranchedReadonlyLen.runar.zig").BranchedReadonlyLen;

fn contractPath(comptime basename: []const u8) []const u8 {
    return "branched-readonly-len/" ++ basename;
}

fn runCompileChecks(comptime basename: []const u8) !void {
    try root.runar.compileCheckSource(std.testing.allocator, @embedFile(basename), basename);
    try root.runar.compileCheckFile(std.testing.allocator, contractPath(basename));
}

test "compile-check BranchedReadonlyLen.runar.zig" {
    try runCompileChecks("BranchedReadonlyLen.runar.zig");
}

fn expectBigint(value: runar.OutputValue, expected: i64) !void {
    switch (value) {
        .bigint => |bigint| try std.testing.expectEqual(expected, bigint),
        else => return error.TestUnexpectedResult,
    }
}

fn expectBytes(value: runar.OutputValue, expected: []const u8) !void {
    switch (value) {
        .bytes => |bytes| try std.testing.expectEqualSlices(u8, expected, bytes),
        else => return error.TestUnexpectedResult,
    }
}

// Proves: the real contract struct runs natively. spend() branches on
// len(scratch): a non-empty scratch takes the increment arm and stores the
// scratch as the tag, an empty scratch takes the decrement arm and stores
// runar.hexToBytes("3030"); the recorded output carries the post-branch (count, tag), and
// the struct's own fields track it. Swapping the arms or the +1/-1 changes
// every assertion below.
// Does not prove: the compiled script (conformance fixture branched-readonly-len),
// that natively and in the compiler hexToBytes("3030") are the same two bytes
// 0x30 0x30 (N-448: the bare literal "3030" that used to be here was four ASCII
// bytes natively and two bytes in the compiler, and is now refused). The
// contract has no assert, so there is no rejecting input to feed it.
fn runSpend(scratch: []const u8, expect_count: i64, expect_tag: []const u8) !void {
    var runtime = runar.StatefulSmartContract.init(std.testing.allocator);
    defer runtime.deinit();
    var c = BranchedReadonlyLen.init(5, "aa");
    const ctx = try runar.StatefulContext.init(&runtime, runar.mockPreimage(.{}));

    c.spend(ctx, scratch);

    try std.testing.expectEqual(@as(usize, 1), ctx.outputs().len);
    try std.testing.expectEqual(@as(i64, 1000), ctx.outputs()[0].satoshis);
    try expectBigint(ctx.outputs()[0].values[0], expect_count);
    try expectBytes(ctx.outputs()[0].values[1], expect_tag);
    try std.testing.expectEqual(expect_count, c.count);
    try std.testing.expectEqualSlices(u8, expect_tag, c.tag);
}

test "spend with a non-empty scratch increments and adopts the scratch as tag" {
    try runSpend("beef", 6, "beef");
}

test "spend with an empty scratch decrements and resets the tag" {
    try runSpend("", 4, runar.hexToBytes("3030"));
}
