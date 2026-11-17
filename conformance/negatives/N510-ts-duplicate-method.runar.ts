// GK-BUG-015 — two methods with one name. Every name-keyed pass assumed one
// body per name; the duplicate public became a second spend entry whose body
// is `assert(x == x)`. Every tier refuses:
//   method 'withdraw' is already declared in this contract and cannot be re-declared
import { SmartContract, assert, checkSig, PubKey, Sig } from 'runar-lang';

class N510 extends SmartContract {
  readonly pk: PubKey;

  constructor(pk: PubKey) {
    super(pk);
    this.pk = pk;
  }

  public withdraw(sig: Sig) {
    assert(checkSig(sig, this.pk));
  }

  public withdraw(x: bigint) {
    assert(x == x);
  }
}
