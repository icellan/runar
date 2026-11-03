const std = @import("std");
const root = @import("../examples_test.zig");
const CountdownLoop = @import("CountdownLoop.runar.zig").CountdownLoop;

fn contractPath(comptime basename: []const u8) []const u8 {
    return "countdown-loop/" ++ basename;
}

fn runCompileChecks(comptime basename: []const u8) !void {
    try root.runar.compileCheckSource(std.testing.allocator, @embedFile(basename), basename);
    try root.runar.compileCheckFile(std.testing.allocator, contractPath(basename));
}

test "compile-check CountdownLoop.runar.zig" {
    try runCompileChecks("CountdownLoop.runar.zig");
}

// Proves: the descending `while (i > 1) : (i -= 1)` loop runs five-to-two (seed + 5+4+3+2) natively, and a wrong target aborts.
// Does not prove: that the other six compilers unroll the same countdown (R-102 parity is a conformance property).

test "CountdownLoop verify accepts seed plus 5+4+3+2" {
    CountdownLoop.init(14).verify(0);
    CountdownLoop.init(24).verify(10);
}

test "CountdownLoop verify rejects a wrong target" {
    try root.expectAssertFailure("countdown-loop-wrong-target");
}
