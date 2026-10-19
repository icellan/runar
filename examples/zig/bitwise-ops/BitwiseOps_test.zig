const std = @import("std");
const root = @import("../examples_test.zig");
const runar = @import("runar");
const BitwiseOps = @import("BitwiseOps.runar.zig").BitwiseOps;

fn contractPath(comptime basename: []const u8) []const u8 {
    return "bitwise-ops/" ++ basename;
}

fn runCompileChecks(comptime basename: []const u8) !void {
    try root.runar.compileCheckSource(std.testing.allocator, @embedFile(basename), basename);
    try root.runar.compileCheckFile(std.testing.allocator, contractPath(basename));
}

test "compile-check BitwiseOps.runar.zig" {
    try runCompileChecks("BitwiseOps.runar.zig");
}

// The caller supplies the expected results and the contract checks them
// (F-167: it used to assert only tautologies, so no input could fail). a = 12,
// b = 10 are 1-byte operands whose results stay below 0x80, so native Zig
// agrees with the on-chain byte-array opcodes; the on-chain verdict for the
// same values is pinned by conformance/witnesses/real-crypto/bitwise-ops.json.

test "BitwiseOps.testShift runs on positive values" {
    const c = BitwiseOps.init(12, 10);
    c.testShift(48, 6);
}

test "BitwiseOps.testShift rejects a wrong shift result" {
    try root.expectAssertFailure("bitwise-ops-wrong-shift");
}

test "BitwiseOps.testBitwise runs on positive values" {
    const c = BitwiseOps.init(12, 10);
    c.testBitwise(8, 14, 6);
}

test "BitwiseOps.testBitwise rejects swapped AND / OR results" {
    try root.expectAssertFailure("bitwise-ops-wrong-bitwise");
}

test "BitwiseOps.testBitwise runs on zero" {
    const c = BitwiseOps.init(0, 0);
    c.testBitwise(0, 0, 0);
}
