const std = @import("std");
const root = @import("../examples_test.zig");
const ParamShadowBranchArm = @import("ParamShadowBranchArm.runar.zig").ParamShadowBranchArm;

fn contractPath(comptime basename: []const u8) []const u8 {
    return "param-shadow-branch-arm/" ++ basename;
}

fn runCompileChecks(comptime basename: []const u8) !void {
    try root.runar.compileCheckSource(std.testing.allocator, @embedFile(basename), basename);
    try root.runar.compileCheckFile(std.testing.allocator, contractPath(basename));
}

test "compile-check ParamShadowBranchArm.runar.zig" {
    try runCompileChecks("ParamShadowBranchArm.runar.zig");
}

// Proves: the `count` parameter (not the field) is what the branch arm asserts on and what is stored; the assert aborts when the flagged arm sees count != 5.
// Does not prove: that every compiler resolves the shadowed name to the parameter (N-007 is a conformance property; Zig fields are never in scope by bare name, so this native test cannot reproduce the shadowing hazard).

test "ParamShadowBranchArm set stores the parameter when the arm holds" {
    var c = ParamShadowBranchArm.init(1);
    c.set(5, true);
    try std.testing.expectEqual(@as(i64, 5), c.count);
    c.set(9, false);
    try std.testing.expectEqual(@as(i64, 9), c.count);
}

test "ParamShadowBranchArm set rejects a flagged count other than 5" {
    try root.expectAssertFailure("param-shadow-branch-arm-flagged-wrong-count");
}
