// N-109 + F-110: a bounded loop is unrolled and private helpers are inlined, so
// `this.h(sig)` written once in the body of a 2-iteration loop consumes the same
// Sig twice. Every tier must refuse with:
//   affine value 'sig' has already been consumed
import { SmartContract, assert, checkSig, PubKey, Sig } from 'runar-lang';

class AffineSigViaHelperInLoop extends SmartContract {
  readonly pk: PubKey;

  constructor(pk: PubKey) {
    super(pk);
    this.pk = pk;
  }

  private h(s: Sig) {
    assert(checkSig(s, this.pk));
  }

  public unlock(sig: Sig) {
    for (let i = 0n; i < 2n; i++) {
      this.h(sig);
    }
    assert(true);
  }
}
