const std = @import("std");
const root = @import("../examples_test.zig");
const runar = @import("runar");
const MultiSig2of3 = @import("MultiSig2of3.runar.zig").MultiSig2of3;

fn contractPath(comptime basename: []const u8) []const u8 {
    return "multisig-2of3/" ++ basename;
}

fn runCompileChecks(comptime basename: []const u8) !void {
    try root.runar.compileCheckSource(std.testing.allocator, @embedFile(basename), basename);
    try root.runar.compileCheckFile(std.testing.allocator, contractPath(basename));
}

test "compile-check MultiSig2of3.runar.zig" {
    try runCompileChecks("MultiSig2of3.runar.zig");
}

test "MultiSig2of3 init stores all three pubkeys" {
    const contract = MultiSig2of3.init(runar.ALICE.pubKey, runar.BOB.pubKey, runar.CHARLIE.pubKey);
    try std.testing.expectEqualSlices(u8, runar.ALICE.pubKey, contract.pk1);
    try std.testing.expectEqualSlices(u8, runar.BOB.pubKey, contract.pk2);
    try std.testing.expectEqualSlices(u8, runar.CHARLIE.pubKey, contract.pk3);
}

test "MultiSig2of3 unlock succeeds with first two committed signers" {
    const contract = MultiSig2of3.init(runar.ALICE.pubKey, runar.BOB.pubKey, runar.CHARLIE.pubKey);
    contract.unlock(
        runar.signTestMessage(runar.ALICE),
        runar.signTestMessage(runar.BOB),
    );
}

test "MultiSig2of3 unlock succeeds when signers skip pk2" {
    const contract = MultiSig2of3.init(runar.ALICE.pubKey, runar.BOB.pubKey, runar.CHARLIE.pubKey);
    contract.unlock(
        runar.signTestMessage(runar.ALICE),
        runar.signTestMessage(runar.CHARLIE),
    );
}

test "MultiSig2of3 unlock succeeds with last two committed signers" {
    const contract = MultiSig2of3.init(runar.ALICE.pubKey, runar.BOB.pubKey, runar.CHARLIE.pubKey);
    contract.unlock(
        runar.signTestMessage(runar.BOB),
        runar.signTestMessage(runar.CHARLIE),
    );
}
