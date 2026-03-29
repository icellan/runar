from runar import StatefulSmartContract, PubKey, Sig, Bigint, Readonly, public, assert_, check_sig, extract_locktime

class Auction(StatefulSmartContract):
    auctioneer: Readonly[PubKey]
    highest_bidder: PubKey
    highest_bid: Bigint
    deadline: Readonly[Bigint]

    def __init__(self, auctioneer: PubKey, highest_bidder: PubKey, highest_bid: Bigint, deadline: Bigint):
        super().__init__(auctioneer, highest_bidder, highest_bid, deadline)
        self.auctioneer = auctioneer
        self.highest_bidder = highest_bidder
        self.highest_bid = highest_bid
        self.deadline = deadline

    @public
    def bid(self, sig: Sig, bidder: PubKey, bid_amount: Bigint):
        assert_(check_sig(sig, bidder))
        assert_(bid_amount > self.highest_bid)
        assert_(extract_locktime(self.tx_preimage) < self.deadline)
        self.highest_bidder = bidder
        self.highest_bid = bid_amount

    @public
    def close(self, sig: Sig):
        assert_(check_sig(sig, self.auctioneer))
        assert_(extract_locktime(self.tx_preimage) >= self.deadline)
