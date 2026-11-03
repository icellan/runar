const std = @import("std");
const root = @import("../examples_test.zig");
const runar = @import("runar");
const CondWriteMultiField = @import("CondWriteMultiField.runar.zig").CondWriteMultiField;

fn contractPath(comptime basename: []const u8) []const u8 {
    return "cond-write-multi-field/" ++ basename;
}

fn runCompileChecks(comptime basename: []const u8) !void {
    try root.runar.compileCheckSource(std.testing.allocator, @embedFile(basename), basename);
    try root.runar.compileCheckFile(std.testing.allocator, contractPath(basename));
}

test "compile-check CondWriteMultiField.runar.zig" {
    try runCompileChecks("CondWriteMultiField.runar.zig");
}

fn expectBigint(value: runar.OutputValue, expected: i64) !void {
    switch (value) {
        .bigint => |bigint| try std.testing.expectEqual(expected, bigint),
        else => return error.TestUnexpectedResult,
    }
}

// Proves: the real contract struct runs natively. bump() writes BOTH fields
// (+1, +2) only when flag > 0 and always records the (a, b) pair, so a write that
// lands on one field only, or one that runs when flag <= 0, changes the output.
// Does not prove: the compiled script's conditional-write lowering (conformance
// fixture cond-write-multi-field). The contract has no assert, so there is no
// rejecting input to feed it.
fn runBump(flag: i64, expect_a: i64, expect_b: i64) !void {
    var runtime = runar.StatefulSmartContract.init(std.testing.allocator);
    defer runtime.deinit();
    var c = CondWriteMultiField.init(10, 20);
    const ctx = try runar.StatefulContext.init(&runtime, runar.mockPreimage(.{}));

    c.bump(ctx, flag);

    try std.testing.expectEqual(@as(usize, 1), ctx.outputs().len);
    try std.testing.expectEqual(@as(i64, 1000), ctx.outputs()[0].satoshis);
    try expectBigint(ctx.outputs()[0].values[0], expect_a);
    try expectBigint(ctx.outputs()[0].values[1], expect_b);
    try std.testing.expectEqual(expect_a, c.a);
    try std.testing.expectEqual(expect_b, c.b);
}

test "bump with flag > 0 advances both fields" {
    try runBump(1, 11, 22);
}

test "bump with flag <= 0 leaves both fields unchanged" {
    try runBump(0, 10, 20);
    try runBump(-1, 10, 20);
}
