// F-222: the then and else arms of an if are mutually exclusive, so a Sig
// consumed once in each arm is legal. This one is not: `sig` is consumed
// through an alias in the then arm, then as the original after the if: the
// flag=true path consumes it twice.
// Every tier must refuse with:
//   affine value 'sig' has already been consumed
import { SmartContract, assert, checkSig, PubKey, Sig } from 'runar-lang';

class AffineSigAliasArmAndAfterIf extends SmartContract {
  readonly pk: PubKey;

  constructor(pk: PubKey) {
    super(pk);
    this.pk = pk;
  }

  public unlock(sig: Sig, flag: boolean) {
    const a: Sig = sig;
    if (flag) {
      assert(checkSig(a, this.pk));
    } else {
      assert(true);
    }
    assert(checkSig(sig, this.pk));
  }
}
