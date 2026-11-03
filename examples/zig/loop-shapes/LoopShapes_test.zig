const std = @import("std");
const root = @import("../examples_test.zig");
const LoopShapes = @import("LoopShapes.runar.zig").LoopShapes;

fn contractPath(comptime basename: []const u8) []const u8 {
    return "loop-shapes/" ++ basename;
}

fn runCompileChecks(comptime basename: []const u8) !void {
    try root.runar.compileCheckSource(std.testing.allocator, @embedFile(basename), basename);
    try root.runar.compileCheckFile(std.testing.allocator, contractPath(basename));
}

test "compile-check LoopShapes.runar.zig" {
    try runCompileChecks("LoopShapes.runar.zig");
}

// Proves: the ascending loop starting at a non-zero bound runs three-to-six (seed + 3+4+5+6) natively, and a wrong target aborts.
// Does not prove: cross-tier unrolling parity (R-102 is a conformance property).

test "LoopShapes verify accepts seed plus 3+4+5+6" {
    LoopShapes.init(18).verify(0);
    LoopShapes.init(28).verify(10);
}

test "LoopShapes verify rejects a wrong target" {
    try root.expectAssertFailure("loop-shapes-wrong-target");
}
