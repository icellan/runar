import { SmartContract, assert, Sig, PubKey, Addr, hash160, checkSig } from 'runar-lang';

/**
 * OrdinalNFT -- Pay-to-Public-Key-Hash lock for a 1sat ordinal inscription.
 *
 * This is a stateless P2PKH contract used to lock an ordinal NFT. The owner
 * (holder of the private key whose public key hashes to `pubKeyHash`) can
 * unlock and transfer the ordinal by providing a valid signature and public key.
 *
 * ## Ordinal Inscriptions
 *
 * A 1sat ordinal NFT is a UTXO carrying exactly 1 satoshi with an inscription
 * envelope embedded in the locking script. The inscription is a no-op
 * (OP_FALSE OP_IF ... OP_ENDIF) that doesn't affect script execution but
 * permanently records content (image, text, JSON, etc.) on-chain.
 *
 * The inscription envelope is injected by the SDK's `withInscription()` method
 * at deployment time -- the contract logic itself is just standard P2PKH.
 *
 * ## Script Layout
 *
 *   Unlocking: `<sig> <pubKey>`
 *   Locking:   `OP_DUP OP_HASH160 <pubKeyHash> OP_EQUALVERIFY OP_CHECKSIG [inscription envelope]`
 */
class OrdinalNFT extends SmartContract {
  readonly pubKeyHash: Addr;

  constructor(pubKeyHash: Addr) {
    super(pubKeyHash);
    this.pubKeyHash = pubKeyHash;
  }

  /** Unlock by proving ownership of the private key corresponding to pubKeyHash. */
  public unlock(sig: Sig, pubKey: PubKey) {
    assert(hash160(pubKey) === this.pubKeyHash);
    assert(checkSig(sig, pubKey));
  }
}
