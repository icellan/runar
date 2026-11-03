const std = @import("std");
const root = @import("../examples_test.zig");
const ShiftOps = @import("ShiftOps.runar.zig").ShiftOps;

fn contractPath(comptime basename: []const u8) []const u8 {
    return "shift-ops/" ++ basename;
}

fn runCompileChecks(comptime basename: []const u8) !void {
    try root.runar.compileCheckSource(std.testing.allocator, @embedFile(basename), basename);
    try root.runar.compileCheckFile(std.testing.allocator, contractPath(basename));
}

test "compile-check ShiftOps.runar.zig" {
    try runCompileChecks("ShiftOps.runar.zig");
}

// The caller supplies the expected shift results and the contract checks them
// (F-167: it used to assert only tautologies, so no input could fail). With
// a = 12 native Zig agrees with the on-chain OP_LSHIFT / OP_RSHIFT; the
// on-chain verdict is pinned by conformance/witnesses/real-crypto/shift-ops.json.

test "ShiftOps.testShift runs on a positive value" {
    const c = ShiftOps.init(12);
    c.testShift(96, 3);
}

test "ShiftOps.testShift rejects a wrong left-shift result" {
    try root.expectAssertFailure("shift-ops-wrong-left");
}

test "ShiftOps.testShift rejects a wrong right-shift result" {
    try root.expectAssertFailure("shift-ops-wrong-right");
}

test "ShiftOps.testShift runs on zero" {
    const c = ShiftOps.init(0);
    c.testShift(0, 0);
}
