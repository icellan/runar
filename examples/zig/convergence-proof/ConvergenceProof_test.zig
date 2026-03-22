const std = @import("std");

const root = @import("../examples_test.zig");
const runar = @import("runar");
const ConvergenceProof = @import("ConvergenceProof.runar.zig").ConvergenceProof;

fn contractPath(comptime basename: []const u8) []const u8 {
    return "convergence-proof/" ++ basename;
}

fn runCompileChecks(comptime basename: []const u8) !void {
    try root.runar.compileCheckSource(std.testing.allocator, @embedFile(basename), basename);
    try root.runar.compileCheckFile(std.testing.allocator, contractPath(basename));
}

test "compile-check ConvergenceProof.runar.zig" {
    try runCompileChecks("ConvergenceProof.runar.zig");
}

test "ConvergenceProof init stores both real points" {
    const r_a = runar.ecMulGen(5);
    const r_b = runar.ecMulGen(2);
    const contract = ConvergenceProof.init(r_a, r_b);
    try std.testing.expectEqualSlices(u8, runar.ecEncodeCompressed(r_a), runar.ecEncodeCompressed(contract.rA));
    try std.testing.expectEqualSlices(u8, runar.ecEncodeCompressed(r_b), runar.ecEncodeCompressed(contract.rB));
}

test "ConvergenceProof proveConvergence accepts a real point delta" {
    const contract = ConvergenceProof.init(runar.ecMulGen(5), runar.ecMulGen(2));
    contract.proveConvergence(3);
}

test "ConvergenceProof rejects invalid points and mismatched deltas" {
    try root.expectAssertFailure("convergence-proof-invalid-point");
    try root.expectAssertFailure("convergence-proof-wrong-delta");
}
