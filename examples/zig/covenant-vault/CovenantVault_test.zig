const std = @import("std");

const root = @import("../examples_test.zig");
const runar = @import("runar");
const CovenantVault = @import("CovenantVault.runar.zig").CovenantVault;

fn contractPath(comptime basename: []const u8) []const u8 {
    return "covenant-vault/" ++ basename;
}

fn runCompileChecks(comptime basename: []const u8) !void {
    try root.runar.compileCheckSource(std.testing.allocator, @embedFile(basename), basename);
    try root.runar.compileCheckFile(std.testing.allocator, contractPath(basename));
}

test "compile-check CovenantVault.runar.zig" {
    try runCompileChecks("CovenantVault.runar.zig");
}

test "CovenantVault init stores owner recipient and amount" {
    const recipient = runar.BOB.pubKeyHash;
    const vault = CovenantVault.init(runar.ALICE.pubKey, recipient, 5000);

    try std.testing.expectEqualSlices(u8, runar.ALICE.pubKey, vault.owner);
    try std.testing.expectEqualSlices(u8, recipient, vault.recipient);
    try std.testing.expectEqual(@as(i64, 5000), vault.minAmount);
}

test "CovenantVault spend accepts the expected output hash and signature" {
    const recipient = runar.BOB.pubKeyHash;
    const vault = CovenantVault.init(runar.ALICE.pubKey, recipient, 5000);
    const expected_output = runar.testing.buildP2pkhOutput(recipient, 5000);
    defer std.heap.page_allocator.free(expected_output);
    const preimage = runar.testing.mockPreimageForOutputs(&.{expected_output});
    defer std.heap.page_allocator.free(preimage);

    vault.spend(runar.signTestMessage(runar.ALICE), preimage);
}

test "CovenantVault spend rejects the wrong output hash" {
    try root.expectAssertFailure("covenant-vault-wrong-output");
}

test "CovenantVault spend rejects the wrong signature" {
    try root.expectAssertFailure("covenant-vault-wrong-sig");
}
