// N-109: private helpers are inlined, so `this.h(sig)` twice consumes the same
// Sig twice in the emitted script even though the checkSig is written once, in
// the helper. Every tier must refuse with the diagnostic a sequential double use
// gets:
//   affine value 'sig' has already been consumed
// A single `this.h(sig)` stays legal.
import { SmartContract, assert, checkSig, PubKey, Sig } from 'runar-lang';

class AffineSigViaHelperTwice extends SmartContract {
  readonly pk: PubKey;

  constructor(pk: PubKey) {
    super(pk);
    this.pk = pk;
  }

  private h(s: Sig) {
    assert(checkSig(s, this.pk));
  }

  public unlock(sig: Sig) {
    this.h(sig);
    this.h(sig);
    assert(true);
  }
}
