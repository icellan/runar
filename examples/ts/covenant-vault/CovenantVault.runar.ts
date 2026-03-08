import { SmartContract, assert, PubKey, Sig, Addr, ByteString, SigHashPreimage, checkSig, checkPreimage, hash160, extractOutputHash, hash256 } from 'runar-lang';

/**
 * CovenantVault -- a stateless Bitcoin covenant contract.
 *
 * A covenant is a self-enforcing spending constraint: the locking script
 * dictates not just *who* can spend the funds, but *how* they may be spent.
 * This contract demonstrates the pattern by combining three verification
 * layers in its single public method:
 *
 *   1. Owner authorization  -- the owner's ECDSA signature must be valid
 *      (proves who is spending).
 *   2. Preimage verification -- `checkPreimage` (OP_PUSH_TX) proves the
 *      contract is inspecting the real spending transaction, enabling
 *      on-chain introspection of its fields.
 *   3. Covenant rule -- the output amount must be >= `minAmount`, which
 *      constrains the transaction structure itself.
 *
 * Script layout (simplified):
 *   Unlocking: <sig> <amount> <txPreimage>
 *   Locking:   <pubKey> OP_CHECKSIG OP_VERIFY <checkPreimage>
 *              <amount >= minAmount> OP_VERIFY
 *
 * Use cases for this pattern include withdrawal limits, time-locked vaults,
 * rate-limited spending, and enforced change addresses.
 *
 * Contract model: Stateless (`SmartContract`). All constructor parameters
 * are `readonly` and baked into the locking script at deploy time.
 *
 * @param owner     - Owner's compressed public key (33 bytes). Only the
 *                    corresponding private key can produce a valid `sig`.
 * @param recipient - Recipient address hash (20 bytes, hash160 of pubkey).
 * @param minAmount - Minimum satoshi value the spending transaction must
 *                    include in its output, enforced by the covenant rule.
 */
class CovenantVault extends SmartContract {
  /** Owner's compressed ECDSA public key (33 bytes). */
  readonly owner: PubKey;
  /** Recipient address (20-byte hash160 of the recipient's public key). */
  readonly recipient: Addr;
  /** Minimum output amount in satoshis enforced by the covenant. */
  readonly minAmount: bigint;

  constructor(owner: PubKey, recipient: Addr, minAmount: bigint) {
    super(owner, recipient, minAmount);
    this.owner = owner;
    this.recipient = recipient;
    this.minAmount = minAmount;
  }

  /**
   * Spend funds held by this covenant.
   *
   * The caller must supply three pieces of evidence:
   *
   * @param sig        - ECDSA signature from the owner (~72 bytes DER).
   * @param amount     - Declared output amount; must be >= `minAmount`.
   * @param txPreimage - Sighash preimage (variable length) used by
   *                     `checkPreimage` to verify the spending transaction.
   */
  public spend(sig: Sig, amount: bigint, txPreimage: SigHashPreimage) {
    // Layer 1: Owner authorization -- verify the ECDSA signature against
    // the owner's public key. This proves the rightful owner is spending.
    assert(checkSig(sig, this.owner));

    // Layer 2: Preimage verification -- OP_PUSH_TX proves the contract is
    // inspecting the actual spending transaction, not a forgery. Without
    // this, the covenant rule below could be trivially bypassed.
    assert(checkPreimage(txPreimage));

    // Layer 3: Covenant rule -- enforce a minimum output amount. This is
    // the core covenant constraint: it restricts *how* funds are spent,
    // not just *who* can spend them.
    assert(amount >= this.minAmount);
  }
}
