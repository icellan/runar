const std = @import("std");
const root = @import("../examples_test.zig");
const runar = @import("runar");
const BranchMergedLocals = @import("BranchMergedLocals.runar.zig").BranchMergedLocals;

fn contractPath(comptime basename: []const u8) []const u8 {
    return "branch-merged-locals/" ++ basename;
}

fn runCompileChecks(comptime basename: []const u8) !void {
    try root.runar.compileCheckSource(std.testing.allocator, @embedFile(basename), basename);
    try root.runar.compileCheckFile(std.testing.allocator, contractPath(basename));
}

test "compile-check BranchMergedLocals.runar.zig" {
    try runCompileChecks("BranchMergedLocals.runar.zig");
}

fn expectBigint(value: runar.OutputValue, expected: i64) !void {
    switch (value) {
        .bigint => |bigint| try std.testing.expectEqual(expected, bigint),
        else => return error.TestUnexpectedResult,
    }
}

// Proves: the real contract struct runs natively. bid() reassigns ONE of two
// state-derived locals per arm and feeds BOTH into the single recorded output,
// so each arm must yield the (touched, untouched) pair in property order, and a
// swapped arm (a<->b) or a stale pre-branch binding changes the recorded values.
// Does not prove: the compiled script's branch-merge handling (that is the
// conformance fixture branch-merged-locals), signatures, or the 1000-sat amount
// being enforced on chain. The contract has no assert, so there is no
// rejecting input to feed it.
fn runBid(a: i64, b: i64, amount: i64, toFirst: i64, expect_a: i64, expect_b: i64) !void {
    var runtime = runar.StatefulSmartContract.init(std.testing.allocator);
    defer runtime.deinit();
    var c = BranchMergedLocals.init(a, b);
    const ctx = try runar.StatefulContext.init(&runtime, runar.mockPreimage(.{}));

    c.bid(ctx, amount, toFirst);

    try std.testing.expectEqual(@as(usize, 1), ctx.outputs().len);
    try std.testing.expectEqual(@as(i64, 1000), ctx.outputs()[0].satoshis);
    try std.testing.expectEqual(@as(usize, 2), ctx.outputs()[0].values.len);
    try expectBigint(ctx.outputs()[0].values[0], expect_a);
    try expectBigint(ctx.outputs()[0].values[1], expect_b);
    // locals only: the struct's own fields are not written by bid().
    try std.testing.expectEqual(a, c.a);
    try std.testing.expectEqual(b, c.b);
}

test "bid with toFirst > 0 replaces a and keeps b" {
    try runBid(10, 20, 99, 1, 99, 20);
}

test "bid with toFirst <= 0 replaces b and keeps a" {
    try runBid(10, 20, 99, 0, 10, 99);
    try runBid(10, 20, 99, -5, 10, 99);
}
