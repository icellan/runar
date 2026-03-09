// On-chain English auction contract.
//
// Bidders compete by submitting progressively higher bids until a block-height
// deadline. After the deadline, only the auctioneer can close the auction.
//
// Lifecycle:
//   1. The auctioneer deploys the contract with themselves as the initial
//      highest bidder, a highest bid of 0, and a block-height deadline.
//   2. Anyone calls `bid` to outbid the current leader. Each successful bid
//      creates a new UTXO carrying the updated state.
//   3. Once the deadline has passed, the auctioneer calls `close` to finalize
//      the auction and spend the UTXO.
//
// Stateful mechanics:
//   Uses `resource struct` with StatefulSmartContract semantics. The compiler
//   auto-injects checkPreimage at method entry and a state-continuation output
//   at method exit for state-mutating methods. Each continuation UTXO encodes
//   state as:
//     OP_RETURN <auctioneer> <highest_bidder> <highest_bid> <deadline>
//
// Time enforcement:
//   Uses Bitcoin's native nLockTime mechanism via `extract_locktime`. Miners
//   will not include a transaction whose locktime is in the future, so the
//   deadline is enforced at the consensus level.
module Auction {
    use runar::types::{PubKey, Sig};
    use runar::crypto::{check_sig, extract_locktime};

    resource struct Auction {
        auctioneer: PubKey,         // Auction creator's public key. Immutable — baked into script.
        highest_bidder: PubKey,     // Current highest bidder. Mutable state across transactions.
        highest_bid: bigint,        // Current highest bid in satoshis. Mutable state.
        deadline: bigint,           // Block height cutoff. Immutable.
    }

    // Submit a new bid that outbids the current highest.
    //
    // State-mutating: the compiler auto-injects checkPreimage at entry and
    // appends a state-continuation output at exit, creating a new UTXO with
    // the updated highest_bidder and highest_bid.
    //
    // Parameters:
    //   sig        - Bidder's signature proving they authorized this bid.
    //   bidder     - Public key of the new bidder.
    //   bid_amount - Bid in satoshis; must exceed the current highest bid.
    public fun bid(contract: &mut Auction, sig: Sig, bidder: PubKey, bid_amount: bigint) {
        // Verify the bidder authorized this bid (prevents griefing)
        assert!(check_sig(sig, bidder), 0);

        // Reject bids that do not exceed the current highest
        assert!(bid_amount > contract.highest_bid, 0);

        // Enforce that the auction is still open: nLockTime must be before the deadline
        assert!(extract_locktime(contract.tx_preimage) < contract.deadline, 0);

        // Persist new leader into on-chain state
        contract.highest_bidder = bidder;
        contract.highest_bid = bid_amount;
    }

    // Close the auction after the deadline has passed.
    //
    // Non-mutating: the compiler auto-injects checkPreimage but does NOT append
    // a state-continuation output, so the UTXO is fully spent (no successor).
    // Only the auctioneer may call this.
    //
    // Parameters:
    //   sig - Signature from the auctioneer proving ownership.
    public fun close(contract: &mut Auction, sig: Sig) {
        // Verify the caller is the auctioneer
        assert!(check_sig(sig, contract.auctioneer), 0);

        // Enforce that the deadline has passed: nLockTime must be >= deadline
        assert!(extract_locktime(contract.tx_preimage) >= contract.deadline, 0);
    }
}
