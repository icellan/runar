const std = @import("std");
const helpers = @import("helpers.zig");

// ---------------------------------------------------------------------------
// Guard: the negative tests must MEASURE the broadcast, not merely find the
// counter non-zero.
//
// Every negative test in this suite proves "consensus rejected the spend" by
// watching `helpers.RPCProvider.broadcast_attempts`. That counter is
// cumulative and is never reset, and each negative test deploys its fixture
// through the SAME provider instance before mounting the attack — so the deploy
// alone already drives it to >= 1. An ABSOLUTE assertion (`>= 1`) therefore
// holds whether or not the attacking transaction ever reached the node: it is
// satisfied before the call under test is even made.
//
// Only a DELTA taken around the attacking call measures what those comments
// claim. These tests need no node: the first two exercise the real counter on
// the real provider, the third is a source-level ratchet.
// ---------------------------------------------------------------------------

// Vacuity proof: with the fixture deployed and the attack failing INSIDE the
// SDK (no transaction ever handed to the node), the absolute assertion passes
// and the delta assertion does not.
test "NegativeAssertion_AbsoluteCounterIsVacuous" {
    const allocator = std.testing.allocator;
    var rpc_provider = helpers.RPCProvider.init(allocator);

    // Fixture setup: the deploy reached the node. (No node here, so the
    // broadcast errors — but the ATTEMPT is what the counter records, which is
    // exactly the deploy's contribution in a real run.)
    if (rpc_provider.provider().broadcast(allocator, "00")) |txid| {
        allocator.free(txid);
    } else |_| {}
    try std.testing.expectEqual(@as(usize, 1), rpc_provider.broadcast_attempts);

    // The attacking call now fails inside the SDK — a UTXO-fetch failure, a
    // build-time refusal, a bad argument — WITHOUT handing a transaction to the
    // node. The counter does not move.
    const broadcasts_before = rpc_provider.broadcast_attempts;

    // The absolute form passes anyway. It proves nothing about the attack.
    try std.testing.expect(rpc_provider.broadcast_attempts >= 1);

    // The delta form correctly refuses to call this a consensus rejection.
    try std.testing.expect(!(rpc_provider.broadcast_attempts > broadcasts_before));
}

// Control with teeth: a spend that genuinely reached the node and was rejected
// there must still satisfy the delta assertion.
test "NegativeAssertion_DeltaAcceptsAGenuineNodeRejection" {
    const allocator = std.testing.allocator;
    var rpc_provider = helpers.RPCProvider.init(allocator);

    if (rpc_provider.provider().broadcast(allocator, "00")) |txid| {
        allocator.free(txid);
    } else |_| {}

    const broadcasts_before = rpc_provider.broadcast_attempts;

    // The attack tx IS handed to the node, which rejects it.
    const result = rpc_provider.provider().broadcast(allocator, "00");
    if (result) |txid| {
        allocator.free(txid);
    } else |err| {
        try std.testing.expectEqual(error.BroadcastFailed, err);
    }

    try std.testing.expect(rpc_provider.broadcast_attempts > broadcasts_before);
}

/// Every test source that asserts on `broadcast_attempts` must do so as a
/// delta. Reverting any single site to the absolute form reddens this.
const negative_test_sources = [_]struct { name: []const u8, src: []const u8 }{
    .{ .name = "auction_test.zig", .src = @embedFile("auction_test.zig") },
    .{ .name = "babybear_test.zig", .src = @embedFile("babybear_test.zig") },
    .{ .name = "covenant_vault_test.zig", .src = @embedFile("covenant_vault_test.zig") },
    .{ .name = "function_patterns_test.zig", .src = @embedFile("function_patterns_test.zig") },
    .{ .name = "math_demo_test.zig", .src = @embedFile("math_demo_test.zig") },
    .{ .name = "merkle_proof_test.zig", .src = @embedFile("merkle_proof_test.zig") },
    .{ .name = "oracle_price_test.zig", .src = @embedFile("oracle_price_test.zig") },
    .{ .name = "p2pkh_test.zig", .src = @embedFile("p2pkh_test.zig") },
    .{ .name = "state_covenant_test.zig", .src = @embedFile("state_covenant_test.zig") },
    .{ .name = "tic_tac_toe_test.zig", .src = @embedFile("tic_tac_toe_test.zig") },
    .{ .name = "token_ft_test.zig", .src = @embedFile("token_ft_test.zig") },
    .{ .name = "token_nft_test.zig", .src = @embedFile("token_nft_test.zig") },
};

test "NegativeAssertion_NoAbsoluteBroadcastAssertionsRemain" {
    var absolute_sites: usize = 0;
    var delta_sites: usize = 0;

    for (negative_test_sources) |f| {
        var it = std.mem.splitScalar(u8, f.src, '\n');
        var line_no: usize = 0;
        while (it.next()) |line| {
            line_no += 1;
            if (std.mem.indexOf(u8, line, "broadcast_attempts >=") != null or
                std.mem.indexOf(u8, line, "broadcast_attempts >  ") != null)
            {
                absolute_sites += 1;
                std.log.err(
                    "{s}:{d}: absolute broadcast assertion — it is already satisfied by the fixture's deploy. Take a delta around the attacking call instead.",
                    .{ f.name, line_no },
                );
            }
            if (std.mem.indexOf(u8, line, "broadcast_attempts > broadcasts_before") != null) {
                delta_sites += 1;
            }
        }
    }

    try std.testing.expectEqual(@as(usize, 0), absolute_sites);
    // Falsification anchor: if the assertions are simply deleted rather than
    // converted, this reddens too.
    try std.testing.expectEqual(@as(usize, 24), delta_sites);
}
