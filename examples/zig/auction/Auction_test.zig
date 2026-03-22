const std = @import("std");

const root = @import("../examples_test.zig");
const runar = @import("runar");
const Auction = @import("Auction.runar.zig").Auction;

const contract_source = @embedFile("Auction.runar.zig");

test "compile-check Auction.runar.zig" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.writeFile(.{ .sub_path = "Auction.runar.zig", .data = contract_source });

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

test "auction accepts a higher bid before deadline through the real contract" {
    var runtime = runar.StatefulSmartContract.init(std.testing.allocator);
    defer runtime.deinit();
    var auction = Auction.init(runar.ALICE.pubKey, runar.ALICE.pubKey, 100, 500);
    const ctx = try runar.StatefulContext.init(&runtime, runar.mockPreimage(.{ .locktime = 499 }));

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

test "auction rejects low or late bids" {
    try root.expectAssertFailure("auction-bid-too-low");
    try root.expectAssertFailure("auction-bid-too-late");
}

test "auction rejects early close and wrong closing signature" {
    try root.expectAssertFailure("auction-close-too-early");
    try root.expectAssertFailure("auction-close-wrong-sig");
}
