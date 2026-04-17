import { SmartContract, assert, Sig, PubKey, Addr, hash160, checkSig } from 'runar-lang';

/**
 * BSV20Token -- Pay-to-Public-Key-Hash lock for a BSV-20 fungible token.
 *
 * BSV-20 is a 1sat ordinals token standard where fungible tokens are represented
 * as inscriptions on P2PKH UTXOs. The contract logic is standard P2PKH -- the
 * token semantics (deploy, mint, transfer) are encoded in the inscription
 * envelope and interpreted by indexers, not by the script itself.
 *
 * ## BSV-20 Token Lifecycle
 *
 * 1. **Deploy** -- Inscribe a deploy JSON (`{"p":"bsv-20","op":"deploy","tick":"RUNAR","max":"21000000"}`)
 *    onto a UTXO to register a new ticker. First deployer wins.
 * 2. **Mint** -- Inscribe a mint JSON (`{"p":"bsv-20","op":"mint","tick":"RUNAR","amt":"1000"}`)
 *    to claim tokens up to the per-mint limit.
 * 3. **Transfer** -- Inscribe a transfer JSON (`{"p":"bsv-20","op":"transfer","tick":"RUNAR","amt":"50"}`)
 *    to move tokens between addresses.
 *
 * The SDK helpers `BSV20.deploy()`, `BSV20.mint()`, and `BSV20.transfer()`
 * build the correct inscription payloads for each operation.
 */
class BSV20Token extends SmartContract {
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
