const std = @import("std");
const root = @import("../examples_test.zig");
const runar = @import("runar");
const IntentCurrentBlockHeight = @import("IntentCurrentBlockHeight.runar.zig").IntentCurrentBlockHeight;

fn contractPath(comptime basename: []const u8) []const u8 {
    return "intent-current-block-height/" ++ basename;
}

fn runCompileChecks(comptime basename: []const u8) !void {
    try root.runar.compileCheckSource(std.testing.allocator, @embedFile(basename), basename);
    try root.runar.compileCheckFile(std.testing.allocator, contractPath(basename));
}

test "compile-check IntentCurrentBlockHeight.runar.zig" {
    try runCompileChecks("IntentCurrentBlockHeight.runar.zig");
}

// Proves: spend() reads the height the native mock reports (runar.setMockBlockHeight, the native counterpart of extractLocktime(txPreimage)): at or below the deadline it passes and bumps count; one above the deadline it aborts with the Runar assertion. Also pins that currentBlockHeight is reachable as runar.currentBlockHeight (N-375: it was defined in builtins.zig but never re-exported, so this file could not build natively).
// Does not prove: that the compiled script reads the preimage locktime (conformance / on-chain property), nor that a real transaction's nLockTime is what the mock reports.

test "IntentCurrentBlockHeight spend passes at and below the deadline" {
    const prev = runar.setMockBlockHeight(99);
    defer _ = runar.setMockBlockHeight(prev);
    var c = IntentCurrentBlockHeight.init(100, 0);
    c.spend();
    try std.testing.expectEqual(@as(i64, 1), c.count);
    _ = runar.setMockBlockHeight(100);
    c.spend();
    try std.testing.expectEqual(@as(i64, 2), c.count);
}

test "IntentCurrentBlockHeight spend aborts past the deadline" {
    try root.expectAssertFailure("intent-current-block-height-past-deadline");
}
