import { SmartContract, PubKey, Sig, assert, checkSig } from 'runar-lang';

class SighashSingle extends SmartContract {
  readonly owner: PubKey;

  constructor(owner: PubKey) {
    super(owner);
    this.owner = owner;
  }

  /** @sighash SINGLE|FORKID */
  public unlock(sig: Sig): void {
    assert(checkSig(sig, this.owner));
  }
}
