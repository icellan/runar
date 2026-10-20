const std = @import("std");
const root = @import("../examples_test.zig");
const runar = @import("runar");
const AnnotatedVault = @import("AnnotatedVault.runar.zig").AnnotatedVault;

fn contractPath(comptime basename: []const u8) []const u8 {
    return "annotated-vault/" ++ basename;
}

fn runCompileChecks(comptime basename: []const u8) !void {
    try root.runar.compileCheckSource(std.testing.allocator, @embedFile(basename), basename);
    try root.runar.compileCheckFile(std.testing.allocator, contractPath(basename));
}

test "compile-check AnnotatedVault.runar.zig" {
    try runCompileChecks("AnnotatedVault.runar.zig");
}

// Proves: annotate() replaces only the memo; withdraw() accepts the owner's signature and rejects a foreign one via the real assert.
// Does not prove: that the memo-before-owner state layout serialises correctly on-chain (a conformance property).

test "AnnotatedVault annotate replaces the memo and nothing else" {
    var c = AnnotatedVault.init("old", runar.ALICE.pubKey, 5);
    c.annotate("new memo");
    try std.testing.expectEqualSlices(u8, "new memo", c.memo);
    try std.testing.expectEqualSlices(u8, runar.ALICE.pubKey, c.owner);
    try std.testing.expectEqual(@as(i64, 5), c.balance);
}

test "AnnotatedVault withdraw accepts the owner signature" {
    const c = AnnotatedVault.init("", runar.ALICE.pubKey, 5);
    c.withdraw(runar.signTestMessage(runar.ALICE));
}

test "AnnotatedVault withdraw rejects a non-owner signature" {
    try root.expectAssertFailure("annotated-vault-wrong-sig");
}
