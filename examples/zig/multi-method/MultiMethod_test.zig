const std = @import("std");
const root = @import("../examples_test.zig");
const runar = @import("runar");
const MultiMethod = @import("MultiMethod.runar.zig").MultiMethod;

fn contractPath(comptime basename: []const u8) []const u8 {
    return "multi-method/" ++ basename;
}

fn runCompileChecks(comptime basename: []const u8) !void {
    try root.runar.compileCheckSource(std.testing.allocator, @embedFile(basename), basename);
    try root.runar.compileCheckFile(std.testing.allocator, contractPath(basename));
}

test "compile-check MultiMethod.runar.zig" {
    try runCompileChecks("MultiMethod.runar.zig");
}

test "MultiMethod.spendWithOwner succeeds when the owner signs and threshold is met" {
    const contract = MultiMethod.init(runar.ALICE.pubKey, runar.BOB.pubKey);
    contract.spendWithOwner(runar.signTestMessage(runar.ALICE), 6); // 6 * 2 + 1 = 13 > 10
}

test "MultiMethod.spendWithBackup succeeds when the backup signs" {
    const contract = MultiMethod.init(runar.ALICE.pubKey, runar.BOB.pubKey);
    contract.spendWithBackup(runar.signTestMessage(runar.BOB));
}
