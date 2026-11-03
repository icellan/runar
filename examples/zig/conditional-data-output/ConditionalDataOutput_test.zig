const std = @import("std");
const root = @import("../examples_test.zig");
const runar = @import("runar");
const ConditionalDataOutput = @import("ConditionalDataOutput.runar.zig").ConditionalDataOutput;

fn contractPath(comptime basename: []const u8) []const u8 {
    return "conditional-data-output/" ++ basename;
}

fn runCompileChecks(comptime basename: []const u8) !void {
    try root.runar.compileCheckSource(std.testing.allocator, @embedFile(basename), basename);
    try root.runar.compileCheckFile(std.testing.allocator, contractPath(basename));
}

test "compile-check ConditionalDataOutput.runar.zig" {
    try runCompileChecks("ConditionalDataOutput.runar.zig");
}

fn expectBigint(value: runar.OutputValue, expected: i64) !void {
    switch (value) {
        .bigint => |bigint| try std.testing.expectEqual(expected, bigint),
        else => return error.TestUnexpectedResult,
    }
}

// Proves: the real contract struct runs natively. pay() always bumps amount and
// records the data output (0 sats, payload bytes verbatim, no state script) only
// when flag is true; flag false records nothing. Dropping the branch guard or
// the amount bump fails these.
// Does not prove: the compiled continuation hash on the flag-true branch (that
// is conformance fixture conditional-data-output-stateful): natively a data
// output is recorded exactly like a raw output. The contract's only assert is
// assert(true), so there is no rejecting input to feed it.
test "pay with flag true records the data output and bumps amount" {
    var runtime = runar.StatefulSmartContract.init(std.testing.allocator);
    defer runtime.deinit();
    var c = ConditionalDataOutput.init(41);
    const ctx = try runar.StatefulContext.init(&runtime, runar.mockPreimage(.{}));

    c.pay(ctx, true, "receipt");

    try std.testing.expectEqual(@as(i64, 42), c.amount);
    try std.testing.expectEqual(@as(usize, 1), ctx.outputs().len);
    try std.testing.expectEqual(@as(i64, 0), ctx.outputs()[0].satoshis);
    try std.testing.expectEqualSlices(u8, "receipt", ctx.outputs()[0].continuationScript);
    try std.testing.expectEqual(@as(usize, 0), ctx.outputs()[0].stateScript.len);
}

test "pay with flag false bumps amount and records no output" {
    var runtime = runar.StatefulSmartContract.init(std.testing.allocator);
    defer runtime.deinit();
    var c = ConditionalDataOutput.init(41);
    const ctx = try runar.StatefulContext.init(&runtime, runar.mockPreimage(.{}));

    c.pay(ctx, false, "receipt");

    try std.testing.expectEqual(@as(i64, 42), c.amount);
    try std.testing.expectEqual(@as(usize, 0), ctx.outputs().len);
}
