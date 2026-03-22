const std = @import("std");
const root = @import("../examples_test.zig");
const runar = @import("runar");
const Escrow = @import("Escrow.runar.zig").Escrow;

fn contractPath(comptime basename: []const u8) []const u8 {
    return "escrow/" ++ basename;
}

fn runCompileChecks(comptime basename: []const u8) !void {
    try root.runar.compileCheckSource(std.testing.allocator, @embedFile(basename), basename);
    try root.runar.compileCheckFile(std.testing.allocator, contractPath(basename));
}

test "compile-check Escrow.runar.zig" {
    try runCompileChecks("Escrow.runar.zig");
}

test "Escrow init stores all parties" {
    const contract = Escrow.init(runar.ALICE.pubKey, runar.BOB.pubKey, runar.CHARLIE.pubKey);
    try std.testing.expectEqualSlices(u8, runar.ALICE.pubKey, contract.buyer);
    try std.testing.expectEqualSlices(u8, runar.BOB.pubKey, contract.seller);
    try std.testing.expectEqualSlices(u8, runar.CHARLIE.pubKey, contract.arbiter);
}

test "Escrow release and refund execute with matching fixture signatures" {
    const contract = Escrow.init(runar.ALICE.pubKey, runar.BOB.pubKey, runar.CHARLIE.pubKey);

    contract.release(
        runar.signTestMessage(runar.BOB),
        runar.signTestMessage(runar.CHARLIE),
    );
    contract.refund(
        runar.signTestMessage(runar.ALICE),
        runar.signTestMessage(runar.CHARLIE),
    );
}
