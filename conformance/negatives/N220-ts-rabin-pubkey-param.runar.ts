// F-286: verifyRabinSig's modulus (4th argument) is a spending-method parameter,
// so the spender picks n and forges any message (n = 1, sig = 0 passes real
// Spend). Every tier must refuse:
//   verifyRabinSig public key (4th argument) must be a contract property or a literal; a spender-supplied Rabin modulus lets anyone forge a signature
// Shape: TS surface, public-method parameter.
import { SmartContract, assert, ByteString, RabinSig, RabinPubKey, verifyRabinSig } from 'runar-lang';

class RabinParam extends SmartContract {
  readonly pk: RabinPubKey;

  constructor(pk: RabinPubKey) {
    super(pk);
    this.pk = pk;
  }

  public settle(msg: ByteString, sig: RabinSig, padding: ByteString, n: RabinPubKey) {
    assert(verifyRabinSig(msg, sig, padding, n));
  }
}
