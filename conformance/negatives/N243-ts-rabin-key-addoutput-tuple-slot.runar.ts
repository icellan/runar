// N-205 (a): the addOutput value list is a single array literal
// (`addOutput(sats, [a, b])`, the shape the Zig tuple form parses to), and the
// spending-method parameter sits in the SECOND slot — the slot of the MUTABLE
// property verifyRabinSig uses as its public key. ANF lowering unpacks the
// list, so the validator must too, or the key slot goes unchecked. Every tier
// must refuse:
//   verifyRabinSig public key property 'key' may only be assigned a contract property or a literal outside the constructor; a spender-supplied Rabin modulus lets anyone forge a signature
import { StatefulSmartContract, assert, ByteString, RabinSig, RabinPubKey, verifyRabinSig } from 'runar-lang';

class RabinKeyTuple extends StatefulSmartContract {
  count: bigint;
  key: RabinPubKey;

  constructor(count: bigint, key: RabinPubKey) {
    super(count, key);
    this.count = count;
    this.key = key;
  }

  public settle(msg: ByteString, sig: RabinSig, padding: ByteString) {
    assert(verifyRabinSig(msg, sig, padding, this.key));
  }

  public carry(newKey: RabinPubKey) {
    this.addOutput(1000n, [this.count, newKey]);
    assert(true);
  }
}
