import { SmartContract, assert, verifySLHDSA_SHA2_128s } from 'runar-lang';
import type { ByteString } from 'runar-lang';

class PostQuantumSLHDSA extends SmartContract {
  readonly pubkey: ByteString;

  constructor(pubkey: ByteString) {
    super(pubkey);
    this.pubkey = pubkey;
  }

  public spend(msg: ByteString, sig: ByteString) {
    assert(verifySLHDSA_SHA2_128s(msg, sig, this.pubkey));
  }
}
