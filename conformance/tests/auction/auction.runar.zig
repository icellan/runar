const runar = @import("runar");

pub const Auction = struct {
    pub const Contract = runar.StatefulSmartContract;

    auctioneer: runar.PubKey,
    highestBidder: runar.PubKey = "000000000000000000000000000000000000000000000000000000000000000000",
    highestBid: i64 = 0,
    deadline: i64,

    pub fn init(
        auctioneer: runar.PubKey,
        highestBidder: runar.PubKey,
        highestBid: i64,
        deadline: i64,
    ) Auction {
        return .{
            .auctioneer = auctioneer,
            .highestBidder = highestBidder,
            .highestBid = highestBid,
            .deadline = deadline,
        };
    }

    pub fn bid(self: *Auction, ctx: runar.StatefulContext, sig: runar.Sig, bidder: runar.PubKey, bidAmount: i64) void {
        runar.assert(runar.checkSig(sig, bidder));
        runar.assert(bidAmount > self.highestBid);
        runar.assert(runar.extractLocktime(ctx.txPreimage) < self.deadline);
        self.highestBidder = bidder;
        self.highestBid = bidAmount;
    }

    pub fn close(self: *const Auction, ctx: runar.StatefulContext, sig: runar.Sig) void {
        runar.assert(runar.checkSig(sig, self.auctioneer));
        runar.assert(runar.extractLocktime(ctx.txPreimage) >= self.deadline);
    }
};
