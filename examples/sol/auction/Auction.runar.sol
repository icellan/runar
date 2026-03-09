pragma runar ^0.1.0;

/// @title Auction
/// @notice On-chain English auction contract.
/// Bidders compete by submitting progressively higher bids until a block-height
/// deadline. After the deadline, only the auctioneer can close the auction.
///
/// Lifecycle:
///   1. The auctioneer deploys the contract with themselves as the initial
///      highest bidder, a highest bid of 0, and a block-height deadline.
///   2. Anyone calls `bid()` to outbid the current leader. Each successful bid
///      creates a new UTXO carrying the updated state.
///   3. Once the deadline has passed, the auctioneer calls `close()` to
///      finalize the auction and spend the UTXO.
///
/// Stateful mechanics:
///   Extends StatefulSmartContract. The compiler auto-injects checkPreimage at
///   method entry and a state-continuation output at method exit for
///   state-mutating methods. Each continuation UTXO encodes state as:
///     OP_RETURN <auctioneer> <highestBidder> <highestBid> <deadline>
///
/// Time enforcement:
///   Uses Bitcoin's native nLockTime mechanism via extractLocktime(). Miners
///   will not include a transaction whose locktime is in the future, so the
///   deadline is enforced at the consensus level.
contract Auction is StatefulSmartContract {
    PubKey immutable auctioneer;    /// @dev Auction creator's public key. Immutable — baked into script at deploy time.
    PubKey highestBidder;           /// @dev Current highest bidder. Mutable state persisted across transactions.
    bigint highestBid;              /// @dev Current highest bid in satoshis. Mutable state persisted across transactions.
    bigint immutable deadline;      /// @dev Block height after which no more bids are accepted. Immutable.

    constructor(PubKey _auctioneer, PubKey _highestBidder, bigint _highestBid, bigint _deadline) {
        auctioneer = _auctioneer;
        highestBidder = _highestBidder;
        highestBid = _highestBid;
        deadline = _deadline;
    }

    /// @notice Submit a new bid that outbids the current highest.
    /// @dev State-mutating: the compiler auto-injects checkPreimage at entry and
    /// appends a state-continuation output at exit, creating a new UTXO with
    /// the updated highestBidder and highestBid.
    /// @param sig Bidder's signature proving they authorized this bid.
    /// @param bidder Public key of the new bidder.
    /// @param bidAmount Bid in satoshis; must exceed the current highest bid.
    function bid(Sig sig, PubKey bidder, bigint bidAmount) public {
        // Verify the bidder authorized this bid (prevents griefing)
        require(checkSig(sig, bidder));

        // Reject bids that do not exceed the current highest
        require(bidAmount > this.highestBid);

        // Enforce that the auction is still open: nLockTime must be before the deadline
        require(extractLocktime(this.txPreimage) < this.deadline);

        // Persist new leader into on-chain state
        this.highestBidder = bidder;
        this.highestBid = bidAmount;
    }

    /// @notice Close the auction after the deadline has passed.
    /// @dev Non-mutating: the compiler auto-injects checkPreimage but does NOT
    /// append a state-continuation output, so the UTXO is fully spent (no
    /// successor). Only the auctioneer may call this.
    /// @param sig Signature from the auctioneer proving ownership.
    function close(Sig sig) public {
        // Verify the caller is the auctioneer
        require(checkSig(sig, this.auctioneer));

        // Enforce that the deadline has passed: nLockTime must be >= deadline
        require(extractLocktime(this.txPreimage) >= this.deadline);
    }
}
