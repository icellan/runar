const std = @import("std");
const root = @import("../examples_test.zig");
const runar = @import("runar");
const DataOutputTest = @import("DataOutputTest.runar.zig").DataOutputTest;

fn contractPath(comptime basename: []const u8) []const u8 {
    return "add-data-output/" ++ basename;
}

test "compile-check DataOutputTest.runar.zig (source)" {
    try root.runar.compileCheckSource(
        std.testing.allocator,
        @embedFile("DataOutputTest.runar.zig"),
        "DataOutputTest.runar.zig",
    );
}

test "compile-check DataOutputTest.runar.zig (file)" {
    try root.runar.compileCheckFile(
        std.testing.allocator,
        contractPath("DataOutputTest.runar.zig"),
    );
}

// Proves: the real contract struct runs natively. publish() bumps count and
// records one data output (0 sats, payload bytes verbatim, no state script).
// Dropping the bump or the data output, or recording the payload elsewhere,
// fails these.
// Does not prove: the compiled continuation hash (conformance fixture
// add-data-output): natively a data output is recorded exactly like a raw
// output. The contract has no assert, so there is no rejecting input to feed it.
test "publish records the payload as a data output and bumps count" {
    var runtime = runar.StatefulSmartContract.init(std.testing.allocator);
    defer runtime.deinit();
    var c = DataOutputTest.init(0);
    const ctx = try runar.StatefulContext.init(&runtime, runar.mockPreimage(.{}));

    c.publish(ctx, "payload-1");

    try std.testing.expectEqual(@as(i64, 1), c.count);
    try std.testing.expectEqual(@as(usize, 1), ctx.outputs().len);
    try std.testing.expectEqual(@as(i64, 0), ctx.outputs()[0].satoshis);
    try std.testing.expectEqualSlices(u8, "payload-1", ctx.outputs()[0].continuationScript);
    try std.testing.expectEqual(@as(usize, 0), ctx.outputs()[0].stateScript.len);
}

test "publish twice accumulates count and keeps each payload in call order" {
    var runtime = runar.StatefulSmartContract.init(std.testing.allocator);
    defer runtime.deinit();
    var c = DataOutputTest.init(7);
    const ctx = try runar.StatefulContext.init(&runtime, runar.mockPreimage(.{}));

    c.publish(ctx, "first");
    c.publish(ctx, "second");

    try std.testing.expectEqual(@as(i64, 9), c.count);
    try std.testing.expectEqual(@as(usize, 2), ctx.outputs().len);
    try std.testing.expectEqualSlices(u8, "first", ctx.outputs()[0].continuationScript);
    try std.testing.expectEqualSlices(u8, "second", ctx.outputs()[1].continuationScript);
}
