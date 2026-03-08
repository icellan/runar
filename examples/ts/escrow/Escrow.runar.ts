import { SmartContract, assert, PubKey, Sig, checkSig } from 'runar-lang';

/**
 * Three-party escrow contract for marketplace payment protection.
 *
 * Holds funds in a UTXO until the buyer, seller, or arbiter authorizes release.
 * The buyer deposits funds by sending to this contract's locking script. Four
 * spending paths allow either party to move funds depending on the outcome:
 *
 * - {@link releaseBySeller} — seller confirms delivery, releases funds to themselves.
 * - {@link releaseByArbiter} — arbiter resolves a dispute in the seller's favor.
 * - {@link refundToBuyer} — buyer cancels before delivery (self-authorized).
 * - {@link refundByArbiter} — arbiter resolves a dispute in the buyer's favor.
 *
 * This is a stateless contract (SmartContract). The three public keys are readonly
 * constructor parameters baked into the locking script at deploy time.
 *
 * Script layout:
 *   Unlocking: <methodIndex> <sig>
 *   Locking:   OP_IF <release paths> OP_ELSE <refund paths> OP_ENDIF
 *
 * Each public method becomes an OP_IF branch selected by the method index in the
 * unlocking script.
 *
 * Design note: Each path requires only one signature. A production escrow might
 * use 2-of-3 multisig for stronger guarantees, but this contract demonstrates the
 * multi-method spending pattern clearly.
 *
 * @param buyer  — buyer's compressed public key (33 bytes)
 * @param seller — seller's compressed public key (33 bytes)
 * @param arbiter — arbiter's compressed public key (33 bytes)
 */
class Escrow extends SmartContract {
  readonly buyer: PubKey;
  readonly seller: PubKey;
  readonly arbiter: PubKey;

  constructor(buyer: PubKey, seller: PubKey, arbiter: PubKey) {
    super(buyer, seller, arbiter);
    this.buyer = buyer;
    this.seller = seller;
    this.arbiter = arbiter;
  }

  /**
   * Seller confirms delivery and releases the escrowed funds.
   * Requires the seller's signature (~72 bytes).
   */
  public releaseBySeller(sig: Sig) {
    assert(checkSig(sig, this.seller));
  }

  /**
   * Arbiter resolves a dispute in the seller's favor, releasing funds.
   * Requires the arbiter's signature (~72 bytes).
   */
  public releaseByArbiter(sig: Sig) {
    assert(checkSig(sig, this.arbiter));
  }

  /**
   * Buyer cancels the transaction before delivery and reclaims funds.
   * Requires the buyer's own signature (~72 bytes).
   */
  public refundToBuyer(sig: Sig) {
    assert(checkSig(sig, this.buyer));
  }

  /**
   * Arbiter resolves a dispute in the buyer's favor, refunding funds.
   * Requires the arbiter's signature (~72 bytes).
   */
  public refundByArbiter(sig: Sig) {
    assert(checkSig(sig, this.arbiter));
  }
}
