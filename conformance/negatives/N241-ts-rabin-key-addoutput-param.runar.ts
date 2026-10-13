// N-205 (a): a stateful method passes a spending-method parameter in the
// addOutput slot of the MUTABLE property verifyRabinSig uses as its public
// key, so the next output carries a spender-chosen modulus. Every tier must
// refuse:
//   verifyRabinSig public key property 'key' may only be assigned a contract property or a literal outside the constructor; a spender-supplied Rabin modulus lets anyone forge a signature
// Shape: TS surface, `this.addOutput(sats, newKey, this.count)`.
import { StatefulSmartContract, assert, ByteString, RabinSig, RabinPubKey, verifyRabinSig } from 'runar-lang';

class RabinKeyCarry extends StatefulSmartContract {
  key: RabinPubKey;
  count: bigint;

  constructor(key: RabinPubKey, count: bigint) {
    super(key, count);
    this.key = key;
    this.count = count;
  }

  public settle(msg: ByteString, sig: RabinSig, padding: ByteString) {
    assert(verifyRabinSig(msg, sig, padding, this.key));
  }

  public carry(newKey: RabinPubKey) {
    this.addOutput(1000n, newKey, this.count);
    assert(true);
  }
}
