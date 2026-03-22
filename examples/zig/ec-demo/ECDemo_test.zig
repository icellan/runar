const std = @import("std");

const root = @import("../examples_test.zig");
const runar = @import("runar");
const ECDemo = @import("ECDemo.runar.zig").ECDemo;

fn contractPath(comptime basename: []const u8) []const u8 {
    return "ec-demo/" ++ basename;
}

fn runCompileChecks(comptime basename: []const u8) !void {
    try root.runar.compileCheckSource(std.testing.allocator, @embedFile(basename), basename);
    try root.runar.compileCheckFile(std.testing.allocator, contractPath(basename));
}

test "compile-check ECDemo.runar.zig" {
    try runCompileChecks("ECDemo.runar.zig");
}

test "ECDemo init stores the real point" {
    const point = runar.ecMulGen(3);
    const contract = ECDemo.init(point);
    try std.testing.expectEqualSlices(u8, runar.ecEncodeCompressed(point), runar.ecEncodeCompressed(contract.pt));
}

test "ECDemo real contract covers the EC helper surface" {
    const point = runar.ecMulGen(3);
    const other = runar.ecMulGen(5);
    const contract = ECDemo.init(point);

    contract.checkX(runar.ecPointX(point));
    contract.checkY(runar.ecPointY(point));
    contract.checkMakePoint(7, 11, 7, 11);
    contract.checkOnCurve();

    const added = runar.ecAdd(point, other);
    contract.checkAdd(other, runar.ecPointX(added), runar.ecPointY(added));

    const doubled = runar.ecMul(point, 2);
    contract.checkMul(2, runar.ecPointX(doubled), runar.ecPointY(doubled));

    const mul_gen = runar.ecMulGen(9);
    contract.checkMulGen(9, runar.ecPointX(mul_gen), runar.ecPointY(mul_gen));

    const neg = runar.ecNegate(point);
    contract.checkNegate(runar.ecPointY(neg));
    contract.checkNegateRoundtrip();
    contract.checkModReduce(17, 5, 2);
    contract.checkEncodeCompressed(runar.ecEncodeCompressed(point));
    contract.checkMulIdentity();
    contract.checkAddOnCurve(other);
    contract.checkMulGenOnCurve(7);
}

test "ECDemo rejects mismatched scalar and encoding expectations" {
    try root.expectAssertFailure("ec-demo-wrong-x");
    try root.expectAssertFailure("ec-demo-wrong-encoding");
}
