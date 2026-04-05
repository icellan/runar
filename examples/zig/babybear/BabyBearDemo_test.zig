const std = @import("std");

const root = @import("../examples_test.zig");
const runar = @import("runar");
const BabyBearDemo = @import("BabyBearDemo.runar.zig").BabyBearDemo;

fn contractPath(comptime basename: []const u8) []const u8 {
    return "babybear/" ++ basename;
}

fn runCompileChecks(comptime basename: []const u8) !void {
    try root.runar.compileCheckSource(std.testing.allocator, @embedFile(basename), basename);
    try root.runar.compileCheckFile(std.testing.allocator, contractPath(basename));
}

test "compile-check BabyBearDemo.runar.zig" {
    try runCompileChecks("BabyBearDemo.runar.zig");
}

// Baby Bear field prime: p = 2^31 - 2^27 + 1 = 2013265921
const BB_P: i64 = 2013265921;

test "BabyBearDemo checkAdd adds two small values" {
    const contract = BabyBearDemo.init();
    contract.checkAdd(5, 7, 12);
}

test "BabyBearDemo checkAdd wraps around the field prime" {
    const contract = BabyBearDemo.init();
    contract.checkAdd(BB_P - 1, 1, 0);
}

test "BabyBearDemo checkAdd adds zero" {
    const contract = BabyBearDemo.init();
    contract.checkAdd(42, 0, 42);
}

test "BabyBearDemo checkSub subtracts two values" {
    const contract = BabyBearDemo.init();
    contract.checkSub(10, 3, 7);
}

test "BabyBearDemo checkSub wraps to field prime when result would be negative" {
    const contract = BabyBearDemo.init();
    // 0 - 1 = p - 1
    contract.checkSub(0, 1, BB_P - 1);
}

test "BabyBearDemo checkMul multiplies two values" {
    const contract = BabyBearDemo.init();
    contract.checkMul(6, 7, 42);
}

test "BabyBearDemo checkMul multiplies large values with wrap" {
    const contract = BabyBearDemo.init();
    // (p-1) * 2 mod p = p - 2
    contract.checkMul(BB_P - 1, 2, BB_P - 2);
}

test "BabyBearDemo checkMul multiplies by zero" {
    const contract = BabyBearDemo.init();
    contract.checkMul(12345, 0, 0);
}

test "BabyBearDemo checkInv inverts 1" {
    const contract = BabyBearDemo.init();
    contract.checkInv(1);
}

test "BabyBearDemo checkInv inverts 2" {
    const contract = BabyBearDemo.init();
    contract.checkInv(2);
}

test "BabyBearDemo checkAddSubRoundtrip verifies roundtrip" {
    const contract = BabyBearDemo.init();
    contract.checkAddSubRoundtrip(42, 99);
}

test "BabyBearDemo checkDistributive verifies distributive law" {
    const contract = BabyBearDemo.init();
    contract.checkDistributive(5, 7, 11);
}
