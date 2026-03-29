module Auction {
    use runar::types::{PubKey, Sig};
    use runar::crypto::{check_sig, extract_locktime};

    resource struct Auction {
        auctioneer: PubKey,
        highest_bidder: &mut PubKey,
        highest_bid: &mut bigint,
        deadline: bigint,
    }

    public fun bid(contract: &mut Auction, sig: Sig, bidder: PubKey, bid_amount: bigint) {
        assert!(check_sig(sig, bidder), 0);
        assert!(bid_amount > contract.highest_bid, 0);
        assert!(extract_locktime(contract.tx_preimage) < contract.deadline, 0);
        contract.highest_bidder = bidder;
        contract.highest_bid = bid_amount;
    }

    public fun close(contract: &mut Auction, sig: Sig) {
        assert!(check_sig(sig, contract.auctioneer), 0);
        assert!(extract_locktime(contract.tx_preimage) >= contract.deadline, 0);
    }
}
