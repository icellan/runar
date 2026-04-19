const std = @import("std");
const runar = @import("runar");
const PriceBet = @import("PriceBet.runar.zig").PriceBet;

const contract_source = @embedFile("PriceBet.runar.zig");

test "PriceBet compiles through the Rúnar frontend" {
    const allocator = std.testing.allocator;
    const result = try runar.compileCheckSource(
        allocator,
        contract_source,
        "PriceBet.runar.zig",
    );
    defer result.deinit(allocator);
    if (!result.ok()) {
        for (result.messages) |m| std.debug.print("{s}\n", .{m});
    }
    try std.testing.expect(result.ok());
}

test "PriceBet.init stores all four constructor args" {
    const alice_pk = runar.ALICE.pubKey;
    const bob_pk = runar.BOB.pubKey;
    const oracle_pk: runar.RabinPubKey = &[_]u8{ 0xDE, 0xAD, 0xBE, 0xEF };
    const c = PriceBet.init(alice_pk, bob_pk, oracle_pk, 50_000);
    try std.testing.expectEqualSlices(u8, alice_pk, c.alicePubKey);
    try std.testing.expectEqualSlices(u8, bob_pk, c.bobPubKey);
    try std.testing.expectEqualSlices(u8, oracle_pk, c.oraclePubKey);
    try std.testing.expectEqual(@as(i64, 50_000), c.strikePrice);
}

test "PriceBet.cancel requires both signatures (check_sig mock always succeeds)" {
    const c = PriceBet.init(
        runar.ALICE.pubKey,
        runar.BOB.pubKey,
        &[_]u8{0},
        0,
    );
    c.cancel(runar.signTestMessage(runar.ALICE), runar.signTestMessage(runar.BOB));
}
