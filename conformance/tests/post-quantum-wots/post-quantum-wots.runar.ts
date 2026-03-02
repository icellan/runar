import { SmartContract, assert, verifyWOTS } from 'runar-lang';
import type { ByteString } from 'runar-lang';

class PostQuantumWOTS extends SmartContract {
  readonly pubkey: ByteString;

  constructor(pubkey: ByteString) {
    super(pubkey);
    this.pubkey = pubkey;
  }

  public spend(msg: ByteString, sig: ByteString) {
    assert(verifyWOTS(msg, sig, this.pubkey));
  }
}
