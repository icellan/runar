import { SmartContract, assert, Sig, PubKey, Addr, hash160, checkSig } from 'runar-lang';

/**
 * BSV21Token -- Pay-to-Public-Key-Hash lock for a BSV-21 fungible token.
 *
 * BSV-21 (v2) is an improvement over BSV-20 that uses ID-based tokens instead
 * of tick-based. The token ID is derived from the deploy transaction
 * (`<txid>_<vout>`), eliminating ticker squatting and enabling admin-controlled
 * distribution.
 *
 * ## BSV-21 Token Lifecycle
 *
 * 1. **Deploy+Mint** -- A single inscription deploys the token and mints the
 *    initial supply in one atomic operation. The token ID is the outpoint of the
 *    output containing this inscription.
 * 2. **Transfer** -- Inscribe a transfer JSON referencing the token ID and amount.
 *
 * The SDK helpers `BSV21.deployMint()` and `BSV21.transfer()` build the correct
 * inscription payloads for each operation.
 */
class BSV21Token extends SmartContract {
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
