const std = @import("std");
const root = @import("../examples_test.zig");
const runar = @import("runar");
const PrivateHelperOutputs = @import("PrivateHelperOutputs.runar.zig").PrivateHelperOutputs;

fn contractPath(comptime basename: []const u8) []const u8 {
    return "private-helper-outputs/" ++ basename;
}

test "compile-check PrivateHelperOutputs.runar.zig (source)" {
    try root.runar.compileCheckSource(
        std.testing.allocator,
        @embedFile("PrivateHelperOutputs.runar.zig"),
        "PrivateHelperOutputs.runar.zig",
    );
}

test "compile-check PrivateHelperOutputs.runar.zig (file)" {
    try root.runar.compileCheckFile(
        std.testing.allocator,
        contractPath("PrivateHelperOutputs.runar.zig"),
    );
}

fn expectBigint(value: runar.OutputValue, expected: i64) !void {
    switch (value) {
        .bigint => |bigint| try std.testing.expectEqual(expected, bigint),
        else => return error.TestUnexpectedResult,
    }
}

// Proves: the real contract struct runs natively. commit() really reaches its
// private helper bump() (counter 3 -> 4) and records nothing; a helper that is
// not called, or a second call, fails this.
// Does not prove: the compiled continuation hash (conformance fixture
// private-helper-outputs).
test "commit bumps counter through the private helper and records no output" {
    var runtime = runar.StatefulSmartContract.init(std.testing.allocator);
    defer runtime.deinit();
    var c = PrivateHelperOutputs.init(3);
    const ctx = try runar.StatefulContext.init(&runtime, runar.mockPreimage(.{}));

    c.commit();

    try std.testing.expectEqual(@as(i64, 4), c.counter);
    try std.testing.expectEqual(@as(usize, 0), ctx.outputs().len);

    c.commit();
    try std.testing.expectEqual(@as(i64, 5), c.counter);
    try std.testing.expectEqual(@as(usize, 0), ctx.outputs().len);
}

// Proves: log() reaches its private helper record() with the caller's context,
// which records exactly one data output (0 sats, payload bytes verbatim, no
// state script) and leaves counter alone. A helper that drops the output,
// records it twice or writes the payload elsewhere fails this.
// Does not prove: the compiled continuation hash (conformance fixture
// private-helper-outputs) or that the compiled script carries no ctx parameter
// (conformance/negatives/n453-zig-stateful-context-helper-parity.test.ts).
test "log records the payload as one data output through the private helper" {
    var runtime = runar.StatefulSmartContract.init(std.testing.allocator);
    defer runtime.deinit();
    var c = PrivateHelperOutputs.init(3);
    const ctx = try runar.StatefulContext.init(&runtime, runar.mockPreimage(.{}));

    c.log(ctx, "payload-1");

    try std.testing.expectEqual(@as(i64, 3), c.counter);
    try std.testing.expectEqual(@as(usize, 1), ctx.outputs().len);
    try std.testing.expectEqual(@as(i64, 0), ctx.outputs()[0].satoshis);
    try std.testing.expectEqualSlices(u8, "payload-1", ctx.outputs()[0].continuationScript);
    try std.testing.expectEqual(@as(usize, 0), ctx.outputs()[0].stateScript.len);
}

// Proves: partition() reaches its private helper forkOutput() with the caller's
// context, which records exactly one state output carrying `amount` satoshis and
// the single state value `leftover`; swapping the two, or recording no output,
// fails this.
// Does not prove: the compiled continuation hash or that the amounts are
// enforced on chain (conformance fixture private-helper-outputs). The contract
// has no assert that can fail, so there is no rejecting input to feed it.
test "partition records one state output through the private helper" {
    var runtime = runar.StatefulSmartContract.init(std.testing.allocator);
    defer runtime.deinit();
    var c = PrivateHelperOutputs.init(3);
    const ctx = try runar.StatefulContext.init(&runtime, runar.mockPreimage(.{}));

    c.partition(ctx, 700, 42);

    try std.testing.expectEqual(@as(i64, 3), c.counter);
    try std.testing.expectEqual(@as(usize, 1), ctx.outputs().len);
    try std.testing.expectEqual(@as(i64, 700), ctx.outputs()[0].satoshis);
    try std.testing.expectEqual(@as(usize, 1), ctx.outputs()[0].values.len);
    try expectBigint(ctx.outputs()[0].values[0], 42);
}
