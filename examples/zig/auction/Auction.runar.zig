const runar = @import("runar");

// On-chain English auction.
//
// Time enforcement — read this before copying the pattern. nLockTime is chosen
// by the SPENDER and enforced by consensus as a NOT-BEFORE: the transaction
// becomes mineable once the chain has reached it. Nothing about it bounds the
// chain from above. A script can therefore assert "not before T" and can NEVER
// assert "before T" — a bidder at height T+1 simply stamps a stale nLockTime of
// T-1 and the node mines it.
//
// So bid carries no deadline check at all: bidding is open until the auctioneer
// closes. close uses the direction that does work, nLockTime >= deadline,
// paired with extractSequence != 0xffffffff. That second assert is
// load-bearing, not decoration: consensus ignores nLockTime entirely when every
// input is final, so without it the auctioneer could stamp
// nLockTime = deadline on an all-final transaction and close at any height,
// before anyone had a chance to bid.
//
// A trustless "bids only before T" window needs a time source the contract can
// read as state — an oracle or a tick — not the spending transaction's own
// locktime. v1 does not ship one.

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
        // bid reads no preimage field of its own (W7 removed the deadline
        // check); the compiler still injects the stateful context.
        _ = ctx;
        runar.assert(runar.checkSig(sig, bidder));
        runar.assert(bidAmount > self.highestBid);
        self.highestBidder = bidder;
        self.highestBid = bidAmount;
    }

    pub fn close(self: *const Auction, ctx: runar.StatefulContext, sig: runar.Sig) void {
        runar.assert(runar.checkSig(sig, self.auctioneer));
        runar.assert(runar.extractLocktime(ctx.txPreimage) >= self.deadline);
        // ...and that consensus actually enforces that nLockTime. A transaction
        // whose inputs are all final (nSequence 0xffffffff) is mineable at any height
        // with nLockTime ignored, so without this the assert above is script-only
        // theatre and the auctioneer can close immediately.
        runar.assert(runar.extractSequence(ctx.txPreimage) != 4294967295);
    }
};
