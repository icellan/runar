import {
  SmartContract, ByteString, Sig, PubKey, Addr,
  assert, len, hash160, checkSig, extractPrevOutputScript,
} from 'runar-lang';

/**
 * StatelessWitness — a STATELESS contract whose public methods take the
 * auto-injected intent witness `_prevOutScript_0` (N-412).
 *
 * `extractPrevOutputScript(0n, expectedHash)` adds a hidden ByteString
 * parameter after the declared ones and asserts hash256(witness) ===
 * expectedHash. The spending unlock must therefore push
 * `<declared args> <witness> [<method selector>]`.
 *
 * `spend` carries a Sig (the SDKs' stateless signing branch); `peek` carries
 * none, and as the second public method its unlock ends with selector 1, so
 * it pins the witness's position BEFORE the selector.
 */
class StatelessWitness extends SmartContract {
  readonly pubKeyHash: Addr;
  readonly expectedHash: ByteString;

  constructor(pubKeyHash: Addr, expectedHash: ByteString) {
    super(pubKeyHash, expectedHash);
    this.pubKeyHash = pubKeyHash;
    this.expectedHash = expectedHash;
  }

  public spend(sig: Sig, pubKey: PubKey) {
    const s = extractPrevOutputScript(0n, this.expectedHash);
    assert(len(s) > 0n);
    assert(hash160(pubKey) === this.pubKeyHash);
    assert(checkSig(sig, pubKey));
  }

  public peek(x: bigint) {
    const s = extractPrevOutputScript(0n, this.expectedHash);
    assert(len(s) > x);
  }
}
