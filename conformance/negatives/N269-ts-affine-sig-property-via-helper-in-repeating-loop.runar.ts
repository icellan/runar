// N-288 + F-110: a bounded loop is unrolled and private helpers are inlined, so
// a helper that runs `checkSig(this.sig, ..)`, called once in the body of a
// 2-iteration loop, consumes the same Sig property twice. Every tier must refuse
// with:
//   affine value 'this.sig' has already been consumed
import { SmartContract, assert, checkSig, PubKey, Sig } from 'runar-lang';

class AffineSigPropertyViaHelperInLoop extends SmartContract {
  readonly pk: PubKey;
  readonly sig: Sig;

  constructor(pk: PubKey, sig: Sig) {
    super(pk, sig);
    this.pk = pk;
    this.sig = sig;
  }

  private h() {
    assert(checkSig(this.sig, this.pk));
  }

  public unlock() {
    for (let i = 0n; i < 2n; i++) {
      this.h();
    }
    assert(true);
  }
}
