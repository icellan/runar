use runar::prelude::*;

/// On-chain English auction contract.
///
/// Bidders compete by submitting progressively higher bids until a block-height
/// deadline. After the deadline, only the auctioneer can close the auction.
///
/// # Lifecycle
///
/// 1. The auctioneer deploys the contract with themselves as the initial highest
///    bidder, a highest bid of 0, and a block-height deadline.
/// 2. Anyone calls [`bid`](Auction::bid) to outbid the current leader. Each
///    successful bid creates a new UTXO carrying the updated state.
/// 3. Once the deadline has passed, the auctioneer calls [`close`](Auction::close)
///    to finalize the auction and spend the UTXO.
///
/// # Stateful mechanics
///
/// Uses `#[runar::contract]` with `StatefulSmartContract` semantics. The compiler
/// auto-injects `checkPreimage` at method entry and a state-continuation output at
/// method exit for state-mutating methods. Each continuation UTXO encodes state as:
///
/// ```text
/// OP_RETURN <auctioneer> <highest_bidder> <highest_bid> <deadline>
/// ```
///
/// # Time enforcement
///
/// Uses Bitcoin's native nLockTime mechanism via [`extract_locktime`]. Miners will
/// not include a transaction whose locktime is in the future, so the deadline is
/// enforced at the consensus level.
#[runar::contract]
pub struct Auction {
    /// Auction creator's public key. Immutable — baked into the script at deploy time.
    #[readonly]
    pub auctioneer: PubKey,
    /// Current highest bidder's public key. Mutable state persisted across transactions.
    pub highest_bidder: PubKey,
    /// Current highest bid in satoshis. Mutable state persisted across transactions.
    pub highest_bid: Bigint,
    /// Block height after which no more bids are accepted. Immutable.
    #[readonly]
    pub deadline: Bigint,
    /// Sighash preimage injected by the compiler for `checkPreimage` verification.
    pub tx_preimage: SigHashPreimage,
}

#[runar::methods(Auction)]
impl Auction {
    /// Submit a new bid that outbids the current highest.
    ///
    /// State-mutating: the compiler auto-injects `checkPreimage` at entry and
    /// appends a state-continuation output at exit, creating a new UTXO with
    /// the updated `highest_bidder` and `highest_bid`.
    ///
    /// # Arguments
    ///
    /// * `sig`        - Bidder's signature proving they authorized this bid.
    /// * `bidder`     - Public key of the new bidder.
    /// * `bid_amount` - Bid in satoshis; must exceed the current highest bid.
    #[public]
    pub fn bid(&mut self, sig: &Sig, bidder: PubKey, bid_amount: Bigint) {
        // Verify the bidder authorized this bid (prevents griefing)
        assert!(check_sig(sig, &bidder));

        // Reject bids that do not exceed the current highest
        assert!(bid_amount > self.highest_bid);
        // Enforce that the auction is still open: nLockTime must be before the deadline
        assert!(extract_locktime(&self.tx_preimage) < self.deadline);
        // Persist new leader into on-chain state
        self.highest_bidder = bidder;
        self.highest_bid = bid_amount;
    }

    /// Close the auction after the deadline has passed.
    ///
    /// Non-mutating: the compiler auto-injects `checkPreimage` but does NOT
    /// append a state-continuation output, so the UTXO is fully spent (no
    /// successor). Only the auctioneer may call this.
    ///
    /// # Arguments
    ///
    /// * `sig` - Signature from the auctioneer proving ownership.
    #[public]
    pub fn close(&self, sig: &Sig) {
        // Verify the caller is the auctioneer
        assert!(check_sig(sig, &self.auctioneer));
        // Enforce that the deadline has passed: nLockTime must be >= deadline
        assert!(extract_locktime(&self.tx_preimage) >= self.deadline);
    }
}
