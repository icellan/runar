module Auction {
    use runar::types::{PubKey, Sig};
    use runar::crypto::{check_sig, extract_locktime};

    resource struct Auction {
        auctioneer: PubKey,
        highest_bidder: PubKey,
        highest_bid: bigint,
        deadline: bigint,
    }

    public fun bid(contract: &mut Auction, bidder: PubKey, bid_amount: bigint) {
        // Bid must be higher than current highest
        assert!(bid_amount > contract.highest_bid, 0);

        // Auction must not have ended
        assert!(extract_locktime(contract.tx_preimage) < contract.deadline, 0);

        // Update state
        contract.highest_bidder = bidder;
        contract.highest_bid = bid_amount;
    }

    public fun close(contract: &mut Auction, sig: Sig) {
        // Only auctioneer can close
        assert!(check_sig(sig, contract.auctioneer), 0);

        // Auction must have ended
        assert!(extract_locktime(contract.tx_preimage) >= contract.deadline, 0);
    }
}
