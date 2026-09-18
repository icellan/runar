import {
  StatefulSmartContract,
  assert,
  checkSig,
  extractLocktime,
  extractSequence,
} from 'runar-lang';
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
 *    creates a new UTXO carrying the updated state. Bidding stays open for as
 *    long as that UTXO is unspent — see **Time enforcement** below.
 * 3. Once the deadline has passed, the auctioneer calls {@link close} to
 *    finalize the auction and spend the UTXO.
 *
 * **Stateful mechanics:**
 * Extends {@link StatefulSmartContract}. The compiler auto-injects
 * `checkPreimage` at method entry and a state-continuation output at method
 * exit for state-mutating methods. Each continuation UTXO encodes state as:
 * `OP_RETURN <auctioneer> <highestBidder> <highestBid> <deadline>`
 *
 * **Time enforcement — read this before copying the pattern:**
 * `nLockTime` is chosen by the *spender* and enforced by consensus as a
 * NOT-BEFORE: the transaction becomes mineable once the chain has reached it.
 * Nothing about it bounds the chain from above. A script can therefore assert
 * "not before T" and can NEVER assert "before T" — a bidder at height T+1
 * simply stamps a stale `nLockTime` of T-1 and the node mines it happily.
 *
 * So {@link bid} carries no deadline check at all: bidding is open until the
 * auctioneer closes. {@link close} uses the direction that does work,
 * `nLockTime >= deadline`, paired with `extractSequence !== 0xffffffff`.
 * That second assert is load-bearing, not decoration: consensus ignores
 * `nLockTime` entirely when every input is final, so without it the auctioneer
 * could stamp `nLockTime = deadline` on an all-final transaction and close at
 * any height, before anyone had a chance to bid.
 *
 * A trustless "bids only before T" window needs a time source the contract can
 * read as state — an oracle or a tick — not the spending transaction's own
 * locktime. v1 does not ship one.
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
   * There is deliberately no deadline check here — see **Time enforcement** on
   * the class. A bid lands whenever the contract's UTXO is still unspent.
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

    // ...and that consensus actually enforces that nLockTime. A transaction
    // whose inputs are all final (nSequence 0xffffffff) is mineable at any
    // height with nLockTime ignored, so without this the assert above is
    // script-only theatre and the auctioneer can close immediately.
    assert(extractSequence(this.txPreimage) !== 0xffffffffn);
  }
}
