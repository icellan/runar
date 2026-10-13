// N-205 (a): a stateful method writes a spending-method parameter into the
// MUTABLE property verifyRabinSig uses as its public key. The spender sets the
// next UTXO's modulus to 1, then forges any message against it one spend later
// (n = 1, sig = 0 — the F-286 attack). Every tier must refuse:
//   verifyRabinSig public key property 'key' may only be assigned a contract property or a literal outside the constructor; a spender-supplied Rabin modulus lets anyone forge a signature
// Shape: TS surface, `this.key = newKey`.
import { StatefulSmartContract, assert, ByteString, RabinSig, RabinPubKey, verifyRabinSig } from 'runar-lang';

class RabinKeyWrite extends StatefulSmartContract {
  key: RabinPubKey;

  constructor(key: RabinPubKey) {
    super(key);
    this.key = key;
  }

  public settle(msg: ByteString, sig: RabinSig, padding: ByteString) {
    assert(verifyRabinSig(msg, sig, padding, this.key));
  }

  public rotate(newKey: RabinPubKey) {
    this.key = newKey;
    assert(true);
  }
}
