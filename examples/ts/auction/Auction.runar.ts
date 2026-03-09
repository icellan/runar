import { StatefulSmartContract, assert, checkSig, extractLocktime } from 'runar-lang';
import type { PubKey, Sig } from 'runar-lang';

/**
 * On-chain English auction contract.
 *
 * Bidders compete by submitting progressively higher bids until a block-height
 * deadline. After the deadline, only the auctioneer can close the auction.
 *
 * **Lifecycle:**
 * 1. The auctioneer deploys the contract with themselves as the initial highest
 *    bidder, a highest bid of 0, and a block-height deadline.
 * 2. Anyone calls {@link bid} to outbid the current leader. Each successful bid
 *    creates a new UTXO carrying the updated state.
 * 3. Once the deadline has passed, the auctioneer calls {@link close} to
 *    finalize the auction and spend the UTXO.
 *
 * **Stateful mechanics:**
 * Extends {@link StatefulSmartContract}. The compiler auto-injects
 * `checkPreimage` at method entry and a state-continuation output at method
 * exit for state-mutating methods. Each continuation UTXO encodes state as:
 * `OP_RETURN <auctioneer> <highestBidder> <highestBid> <deadline>`
 *
 * **Time enforcement:**
 * Uses Bitcoin's native nLockTime mechanism via {@link extractLocktime}.
 * Miners will not include a transaction whose locktime is in the future, so the
 * deadline is enforced at the consensus level.
 */
class Auction extends StatefulSmartContract {
  /** The public key of the auction creator. Immutable — baked into the script at deploy time. */
  readonly auctioneer: PubKey;
  /** Public key of the current highest bidder. Mutable state that persists across transactions. */
  highestBidder: PubKey;
  /** Current highest bid amount in satoshis. Mutable state that persists across transactions. */
  highestBid: bigint;
  /** Block height after which no more bids are accepted. Immutable — baked into the script. */
  readonly deadline: bigint;

  constructor(auctioneer: PubKey, highestBidder: PubKey, highestBid: bigint, deadline: bigint) {
    super(auctioneer, highestBidder, highestBid, deadline);
    this.auctioneer = auctioneer;
    this.highestBidder = highestBidder;
    this.highestBid = highestBid;
    this.deadline = deadline;
  }

  /**
   * Submit a new bid that outbids the current highest.
   *
   * State-mutating: the compiler auto-injects `checkPreimage` at entry and
   * appends a state-continuation output at exit, creating a new UTXO with
   * the updated `highestBidder` and `highestBid`.
   *
   * @param sig       - Bidder's signature proving they authorized this bid.
   * @param bidder    - Public key of the new bidder.
   * @param bidAmount - Bid in satoshis; must exceed the current highest bid.
   */
  public bid(sig: Sig, bidder: PubKey, bidAmount: bigint) {
    // Verify the bidder authorized this bid (prevents griefing by bidding on others' behalf)
    assert(checkSig(sig, bidder));

    // Reject bids that do not exceed the current highest
    assert(bidAmount > this.highestBid);

    // Enforce that the auction is still open: the spending transaction's
    // nLockTime (extracted from the sighash preimage) must be before the deadline
    assert(extractLocktime(this.txPreimage) < this.deadline);

    // Persist new leader into on-chain state
    this.highestBidder = bidder;
    this.highestBid = bidAmount;
  }

  /**
   * Close the auction after the deadline has passed.
   *
   * Non-mutating: the compiler auto-injects `checkPreimage` but does NOT
   * append a state-continuation output, so the UTXO is fully spent (no
   * successor). Only the auctioneer may call this.
   *
   * @param sig - Signature from the auctioneer proving ownership.
   */
  public close(sig: Sig) {
    // Verify the caller is the auctioneer
    assert(checkSig(sig, this.auctioneer));

    // Enforce that the deadline has passed: nLockTime must be >= deadline
    assert(extractLocktime(this.txPreimage) >= this.deadline);
  }
}
