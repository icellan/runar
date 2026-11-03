// F-222: the then and else arms of an if are mutually exclusive, so a Sig
// consumed once in each arm is legal. This one is not: `sig` is consumed in a
// nested then arm, then again after the outer if: the flag=true path consumes
// it twice.
// Every tier must refuse with:
//   affine value 'sig' has already been consumed
import { SmartContract, assert, checkSig, PubKey, Sig } from 'runar-lang';

class AffineSigNestedArmAndAfterIf extends SmartContract {
  readonly pk: PubKey;

  constructor(pk: PubKey) {
    super(pk);
    this.pk = pk;
  }

  public unlock(sig: Sig, flag: boolean) {
    if (flag) {
      if (flag) {
        assert(checkSig(sig, this.pk));
      }
    } else {
      assert(true);
    }
    assert(checkSig(sig, this.pk));
  }
}
