import { SmartContract, assert, checkSig, hash160, verifyECDSA_P384 } from 'runar-lang';
import type { ByteString, Addr, Sig, PubKey } from 'runar-lang';

class P384Wallet extends SmartContract {
  readonly ecdsaPubKeyHash: Addr;
  readonly p384PubKeyHash: ByteString;

  constructor(ecdsaPubKeyHash: Addr, p384PubKeyHash: ByteString) {
    super(ecdsaPubKeyHash, p384PubKeyHash);
    this.ecdsaPubKeyHash = ecdsaPubKeyHash;
    this.p384PubKeyHash = p384PubKeyHash;
  }

  public spend(p384Sig: ByteString, p384PubKey: ByteString, sig: Sig, pubKey: PubKey) {
    assert(hash160(pubKey) == this.ecdsaPubKeyHash);
    assert(checkSig(sig, pubKey));
    assert(hash160(p384PubKey) == this.p384PubKeyHash);
    assert(verifyECDSA_P384(sig, p384Sig, p384PubKey));
  }
}
