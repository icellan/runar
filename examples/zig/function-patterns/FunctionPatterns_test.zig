const std = @import("std");

const root = @import("../examples_test.zig");
const runar = @import("runar");
const FunctionPatterns = @import("FunctionPatterns.runar.zig").FunctionPatterns;

const contract_source = @embedFile("FunctionPatterns.runar.zig");

test "compile-check FunctionPatterns.runar.zig" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.writeFile(.{ .sub_path = "FunctionPatterns.runar.zig", .data = contract_source });

    const path = try std.fs.path.join(allocator, &.{ ".zig-cache", "tmp", tmp.sub_path[0..], "FunctionPatterns.runar.zig" });
    defer allocator.free(path);
    try root.runar.compileCheckFile(allocator, path);
    try root.runar.compileCheckSource(allocator, contract_source, "FunctionPatterns.runar.zig");
}

test "function patterns init stores owner and balance" {
    const contract = FunctionPatterns.init(runar.ALICE.pubKey, 1000);

    try std.testing.expectEqualSlices(u8, runar.ALICE.pubKey[0..], contract.owner[0..]);
    try std.testing.expectEqual(@as(i64, 1000), contract.balance);
}

test "function patterns executes deposit and withdraw through the real contract" {
    var contract = FunctionPatterns.init(runar.ALICE.pubKey, 1000);

    contract.deposit(runar.signTestMessage(runar.ALICE), 250);
    try std.testing.expectEqual(@as(i64, 1250), contract.balance);

    contract.withdraw(runar.signTestMessage(runar.ALICE), 400, 25);
    try std.testing.expectEqual(@as(i64, 750), contract.balance);
}

test "function patterns executes scale and normalize through the real contract" {
    var contract = FunctionPatterns.init(runar.ALICE.pubKey, 137);

    contract.scale(runar.signTestMessage(runar.ALICE), 3, 2);
    try std.testing.expectEqual(@as(i64, 205), contract.balance);

    contract.normalize(runar.signTestMessage(runar.ALICE), 0, 200, 16);
    try std.testing.expectEqual(@as(i64, 192), contract.balance);
}

test "function patterns rejects non-owner actions" {
    try root.expectAssertFailure("function-patterns-wrong-owner");
}

test "function patterns rejects overdraw" {
    try root.expectAssertFailure("function-patterns-overdraw");
}
