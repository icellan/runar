const std = @import("std");

const root = @import("../examples_test.zig");
const runar = @import("runar");
const Auction = @import("Auction.runar.zig").Auction;

const contract_source = @embedFile("Auction.runar.zig");

test "compile-check Auction.runar.zig" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.writeFile(std.testing.io, .{ .sub_path = "Auction.runar.zig", .data = contract_source });

    const path = try std.fs.path.join(allocator, &.{ ".zig-cache", "tmp", tmp.sub_path[0..], "Auction.runar.zig" });
    defer allocator.free(path);
    try root.runar.compileCheckFile(allocator, path);
    try root.runar.compileCheckSource(allocator, contract_source, "Auction.runar.zig");
}

test "auction init stores constructor fields" {
    const auction = Auction.init(runar.ALICE.pubKey, runar.BOB.pubKey, 100, 500);

    try std.testing.expectEqualSlices(u8, runar.ALICE.pubKey, auction.auctioneer);
    try std.testing.expectEqualSlices(u8, runar.BOB.pubKey, auction.highestBidder);
    try std.testing.expectEqual(@as(i64, 100), auction.highestBid);
    try std.testing.expectEqual(@as(i64, 500), auction.deadline);
}

test "auction accepts a higher bid through the real contract" {
    var runtime = runar.StatefulSmartContract.init(std.testing.allocator);
    defer runtime.deinit();
    var auction = Auction.init(runar.ALICE.pubKey, runar.ALICE.pubKey, 100, 500);
    const ctx = try runar.StatefulContext.init(&runtime, runar.mockPreimage(.{ .locktime = 499 }));

    // N-027: the continuation carries the prior pot (extractAmount is 10000
    // off-chain) plus the bid.
    const prev = runar.setMockContinuationAmount(10000 + 150);
    defer _ = runar.setMockContinuationAmount(prev);
    auction.bid(ctx, runar.signTestMessage(runar.BOB), runar.BOB.pubKey, 150);
    try std.testing.expectEqualSlices(u8, runar.BOB.pubKey, auction.highestBidder);
    try std.testing.expectEqual(@as(i64, 150), auction.highestBid);
}

test "auction closes at or after the deadline through the real contract" {
    var runtime = runar.StatefulSmartContract.init(std.testing.allocator);
    defer runtime.deinit();
    const auction = Auction.init(runar.ALICE.pubKey, runar.BOB.pubKey, 150, 500);
    const ctx = try runar.StatefulContext.init(&runtime, runar.mockPreimage(.{ .locktime = 500 }));

    auction.close(ctx, runar.signTestMessage(runar.ALICE));
}

// W7: there is no "bid too late" negative any more, and adding one back would
// be vacuous. bid() reads no preimage field: nLockTime is a spender-chosen
// NOT-BEFORE, so no on-chain assert can prove the deadline has NOT passed.
// The close() finality guard that replaced it cannot be exercised here either
// — this tier's mock extractSequence returns a constant — so it is proved
// where it can be: on the real @bsv/sdk Spend engine, in
// conformance/witnesses/real-crypto/auction.json and
// packages/runar-testing/src/__tests__/w7-auction-locktime-polarity.test.ts.
test "auction rejects low bids" {
    try root.expectAssertFailure("auction-bid-too-low");
}

// N-027: carrying the pot forward unpaid passes F-024's `>= input` floor but not
// bid's own rule.
test "auction rejects a bid that is not paid into the pot" {
    try root.expectAssertFailure("auction-bid-unpaid");
    try root.expectAssertFailure("auction-bid-short");
}

test "auction rejects early close and wrong closing signature" {
    try root.expectAssertFailure("auction-close-too-early");
    try root.expectAssertFailure("auction-close-wrong-sig");
}
