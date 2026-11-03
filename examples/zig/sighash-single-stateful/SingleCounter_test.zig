const std = @import("std");
const root = @import("../examples_test.zig");
const SingleCounter = @import("SingleCounter.runar.zig").SingleCounter;

fn contractPath(comptime basename: []const u8) []const u8 {
    return "sighash-single-stateful/" ++ basename;
}

fn runCompileChecks(comptime basename: []const u8) !void {
    try root.runar.compileCheckSource(std.testing.allocator, @embedFile(basename), basename);
    try root.runar.compileCheckFile(std.testing.allocator, contractPath(basename));
}

test "compile-check SingleCounter.runar.zig" {
    try runCompileChecks("SingleCounter.runar.zig");
}

// Proves: reset() requires count > 0 and zeroes it.
// Does not prove: bump() (it calls the self.addOutput intrinsic and extracts the amount from the preimage; there is no native method) or the SINGLE|FORKID continuation commitment, which are on-chain properties.

test "SingleCounter reset zeroes a positive count" {
    var c = SingleCounter.init(3);
    c.reset();
    try std.testing.expectEqual(@as(i64, 0), c.count);
}

test "SingleCounter reset rejects a zero count" {
    try root.expectAssertFailure("sighash-single-stateful-reset-zero");
}
