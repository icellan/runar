import { SmartContract, assert, PubKey, Sig, Addr, hash160, checkSig } from 'runar-lang';

/**
 * P2PKH — Pay-to-Public-Key-Hash.
 *
 * The most fundamental Bitcoin spending pattern. Funds are locked to the
 * HASH160 (SHA-256 → RIPEMD-160) of a public key. To spend, the recipient
 * must provide their full public key (which must hash to the stored hash)
 * and a valid ECDSA signature over the transaction.
 *
 * ## How It Works: Two-Step Verification
 *
 *  1. **Hash check** — `hash160(pubKey) === pubKeyHash` proves the provided
 *     public key matches the one committed to when the output was created.
 *  2. **Signature check** — `checkSig(sig, pubKey)` proves the spender
 *     holds the private key corresponding to that public key.
 *
 * This is the same pattern as standard Bitcoin P2PKH transactions, but
 * expressed in the Rúnar smart contract language.
 *
 * ## Script Layout
 *
 *   Unlocking: `<sig> <pubKey>`
 *   Locking:   `OP_DUP OP_HASH160 <pubKeyHash> OP_EQUALVERIFY OP_CHECKSIG`
 *
 * ## Parameter Sizes
 *
 *   - pubKeyHash: 20 bytes (HASH160 of compressed public key)
 *   - sig: ~72 bytes (DER-encoded ECDSA signature + sighash flag)
 *   - pubKey: 33 bytes (compressed secp256k1 public key)
 */
class P2PKH extends SmartContract {
  readonly pubKeyHash: Addr;

  constructor(pubKeyHash: Addr) {
    super(pubKeyHash);
    this.pubKeyHash = pubKeyHash;
  }

  /** Unlock verifies the pubKey hashes to the committed hash, then checks the signature. */
  public unlock(sig: Sig, pubKey: PubKey) {
    // Step 1: Verify pubKey matches the committed hash
    assert(hash160(pubKey) === this.pubKeyHash);
    // Step 2: Verify ECDSA signature proves ownership of the private key
    assert(checkSig(sig, pubKey));
  }
}
