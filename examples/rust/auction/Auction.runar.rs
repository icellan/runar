use runar::prelude::*;

#[runar::contract]
pub struct Auction {
    #[readonly]
    pub auctioneer: PubKey,
    pub highest_bidder: PubKey, // stateful
    pub highest_bid: Bigint,    // stateful
    #[readonly]
    pub deadline: Bigint, // block height deadline
    pub tx_preimage: SigHashPreimage,
}

#[runar::methods(Auction)]
impl Auction {
    /// State-mutating: compiler auto-injects checkPreimage + state continuation
    #[public]
    pub fn bid(&mut self, bidder: PubKey, bid_amount: Bigint) {
        assert!(bid_amount > self.highest_bid);
        assert!(extract_locktime(&self.tx_preimage) < self.deadline);
        self.highest_bidder = bidder;
        self.highest_bid = bid_amount;
    }

    /// Non-mutating: compiler auto-injects checkPreimage only
    #[public]
    pub fn close(&self, sig: &Sig) {
        assert!(check_sig(sig, &self.auctioneer));
        assert!(extract_locktime(&self.tx_preimage) >= self.deadline);
    }
}
