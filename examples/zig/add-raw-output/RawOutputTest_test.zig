const std = @import("std");
const root = @import("../examples_test.zig");
const runar = @import("runar");
const RawOutputTest = @import("RawOutputTest.runar.zig").RawOutputTest;

fn contractPath(comptime basename: []const u8) []const u8 {
    return "add-raw-output/" ++ basename;
}

test "compile-check RawOutputTest.runar.zig (source)" {
    try root.runar.compileCheckSource(
        std.testing.allocator,
        @embedFile("RawOutputTest.runar.zig"),
        "RawOutputTest.runar.zig",
    );
}

test "compile-check RawOutputTest.runar.zig (file)" {
    try root.runar.compileCheckFile(
        std.testing.allocator,
        contractPath("RawOutputTest.runar.zig"),
    );
}

fn expectBigint(value: runar.OutputValue, expected: i64) !void {
    switch (value) {
        .bigint => |bigint| try std.testing.expectEqual(expected, bigint),
        else => return error.TestUnexpectedResult,
    }
}

// Proves: the real contract struct runs natively. sendToScript() records the
// raw output FIRST (1000 sats, caller bytes verbatim, no state script) and the
// state continuation SECOND (0 sats, the already-incremented count), in that
// order. Swapping the two calls, or reading count before the bump, fails.
// Does not prove: the compiled script's output interleaving (conformance fixture
// add-raw-output). The contract has no assert, so there is no rejecting input
// to feed it.
test "sendToScript records the raw output before the state continuation" {
    var runtime = runar.StatefulSmartContract.init(std.testing.allocator);
    defer runtime.deinit();
    var c = RawOutputTest.init(4);
    const ctx = try runar.StatefulContext.init(&runtime, runar.mockPreimage(.{}));

    c.sendToScript(ctx, "script-bytes");

    try std.testing.expectEqual(@as(i64, 5), c.count);
    try std.testing.expectEqual(@as(usize, 2), ctx.outputs().len);

    try std.testing.expectEqual(@as(i64, 1000), ctx.outputs()[0].satoshis);
    try std.testing.expectEqualSlices(u8, "script-bytes", ctx.outputs()[0].continuationScript);
    try std.testing.expectEqual(@as(usize, 0), ctx.outputs()[0].values.len);

    try std.testing.expectEqual(@as(i64, 0), ctx.outputs()[1].satoshis);
    try std.testing.expectEqual(@as(usize, 1), ctx.outputs()[1].values.len);
    try expectBigint(ctx.outputs()[1].values[0], 5);
}
