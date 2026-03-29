use runar::prelude::*;

#[runar::contract]
struct Auction {
    #[readonly]
    auctioneer: PubKey,
    highest_bidder: PubKey,
    highest_bid: Bigint,
    #[readonly]
    deadline: Bigint,
}

#[runar::methods(Auction)]
impl Auction {
    #[public]
    fn bid(&mut self, sig: Sig, bidder: PubKey, bid_amount: Bigint) {
        assert!(check_sig(sig, bidder));
        assert!(bid_amount > self.highest_bid);
        assert!(extract_locktime(self.tx_preimage) < self.deadline);
        self.highest_bidder = bidder;
        self.highest_bid = bid_amount;
    }

    #[public]
    fn close(&mut self, sig: Sig) {
        assert!(check_sig(sig, self.auctioneer));
        assert!(extract_locktime(self.tx_preimage) >= self.deadline);
    }
}
