import { SmartContract, assert, PubKey, Sig, Addr, ByteString, SigHashPreimage, checkSig, checkPreimage, extractOutputHash, hash256, num2bin, cat } from 'runar-lang';

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
 *   3. Covenant rule -- the contract constructs the expected P2PKH output
 *      on-chain (recipient address + `minAmount` satoshis) and verifies its
 *      hash against the transaction's `hashOutputs` field. This constrains
 *      both the destination and the amount at the consensus level.
 *
 * Script layout (simplified):
 *   Unlocking: <opPushTxSig> <sig> <txPreimage>
 *   Locking:   <pubKey> OP_CHECKSIG OP_VERIFY <checkPreimage>
 *              <buildP2PKH(recipient)> <num2bin(minAmount,8)> OP_CAT
 *              OP_HASH256 <extractOutputHash(preimage)> OP_EQUAL OP_VERIFY
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
   * Enforces that the spending transaction creates a P2PKH output to
   * the designated recipient with at least `minAmount` satoshis. The
   * output is constructed on-chain and verified against the sighash
   * preimage's hashOutputs field, ensuring the covenant is enforced
   * at the consensus level.
   *
   * @param sig        - ECDSA signature from the owner (~72 bytes DER).
   * @param txPreimage - Sighash preimage (variable length) used by
   *                     `checkPreimage` to verify the spending transaction.
   */
  public spend(sig: Sig, txPreimage: SigHashPreimage) {
    assert(checkSig(sig, this.owner));
    assert(checkPreimage(txPreimage));

    // Construct the expected P2PKH output on-chain:
    // <8-byte LE amount> <varint(25)> <OP_DUP OP_HASH160 OP_PUSH(20) recipient OP_EQUALVERIFY OP_CHECKSIG>
    const p2pkhScript = cat(cat('1976a914', this.recipient), '88ac');
    const expectedOutput = cat(num2bin(this.minAmount, 8n), p2pkhScript);

    // Verify the transaction's outputs match exactly
    assert(hash256(expectedOutput) === extractOutputHash(txPreimage));
  }
}
