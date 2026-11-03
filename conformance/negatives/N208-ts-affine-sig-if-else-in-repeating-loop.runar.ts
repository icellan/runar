// F-222: the then and else arms of an if are mutually exclusive, so a Sig
// consumed once in each arm is legal. This one is not: `sig` is consumed once
// per arm of an if/else inside a 2-iteration loop: the loop is unrolled, so
// every path consumes it twice.
// Every tier must refuse with:
//   affine value 'sig' has already been consumed
import { SmartContract, assert, checkSig, PubKey, Sig } from 'runar-lang';

class AffineSigIfElseInRepeatingLoop extends SmartContract {
  readonly pk: PubKey;

  constructor(pk: PubKey) {
    super(pk);
    this.pk = pk;
  }

  public unlock(sig: Sig, flag: boolean) {
    for (let i = 0n; i < 2n; i++) {
      if (flag) {
        assert(checkSig(sig, this.pk));
      } else {
        assert(checkSig(sig, this.pk));
      }
    }
    assert(true);
  }
}
