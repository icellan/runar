import { SmartContract, assert, checkSig, hash160, verifyECDSA_P256 } from 'runar-lang';
import type { ByteString, Addr, Sig, PubKey } from 'runar-lang';

class P256Wallet extends SmartContract {
  readonly ecdsaPubKeyHash: Addr;
  readonly p256PubKeyHash: ByteString;

  constructor(ecdsaPubKeyHash: Addr, p256PubKeyHash: ByteString) {
    super(ecdsaPubKeyHash, p256PubKeyHash);
    this.ecdsaPubKeyHash = ecdsaPubKeyHash;
    this.p256PubKeyHash = p256PubKeyHash;
  }

  public spend(p256Sig: ByteString, p256PubKey: ByteString, sig: Sig, pubKey: PubKey) {
    assert(hash160(pubKey) == this.ecdsaPubKeyHash);
    assert(checkSig(sig, pubKey));
    assert(hash160(p256PubKey) == this.p256PubKeyHash);
    assert(verifyECDSA_P256(sig, p256Sig, p256PubKey));
  }
}
