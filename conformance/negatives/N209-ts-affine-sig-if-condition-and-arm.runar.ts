// F-222: the then and else arms of an if are mutually exclusive, so a Sig
// consumed once in each arm is legal. This one is not: `sig` is consumed in
// the if condition, which runs on every path, then again in the else arm: the
// false path consumes it twice.
// Every tier must refuse with:
//   affine value 'sig' has already been consumed
import { SmartContract, assert, checkSig, PubKey, Sig } from 'runar-lang';

class AffineSigIfConditionAndArm extends SmartContract {
  readonly pk: PubKey;

  constructor(pk: PubKey) {
    super(pk);
    this.pk = pk;
  }

  public unlock(sig: Sig) {
    if (checkSig(sig, this.pk)) {
      assert(true);
    } else {
      assert(checkSig(sig, this.pk));
    }
  }
}
