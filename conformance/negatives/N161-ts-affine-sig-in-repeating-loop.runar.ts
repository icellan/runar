// F-110: a bounded loop is unrolled `count` times, so `checkSig(sig, ...)` written
// once in the body of a 2-iteration loop consumes the same Sig twice. Every tier
// must refuse with:
//   affine value 'sig' has already been consumed
// (the same diagnostic the two consumptions written sequentially get). A loop
// that runs once stays legal.
import { SmartContract, assert, checkSig, PubKey, Sig } from 'runar-lang';

class AffineSigInLoop extends SmartContract {
  readonly pk: PubKey;

  constructor(pk: PubKey) {
    super(pk);
    this.pk = pk;
  }

  public unlock(sig: Sig) {
    for (let i = 0n; i < 2n; i++) {
      assert(checkSig(sig, this.pk));
    }
    assert(true);
  }
}
