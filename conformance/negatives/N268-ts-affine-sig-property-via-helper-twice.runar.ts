// N-288: private helpers are inlined, so a helper that runs
// `checkSig(this.sig, ..)` and is called twice consumes the same Sig PROPERTY
// twice in the emitted script, although the checkSig is written once. N-109
// tracked helper consumption of PARAMETERS only. Every tier must refuse with the
// diagnostic a sequential double use of the property gets:
//   affine value 'this.sig' has already been consumed
// A single `this.h()` stays legal.
import { SmartContract, assert, checkSig, PubKey, Sig } from 'runar-lang';

class AffineSigPropertyViaHelperTwice extends SmartContract {
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
    this.h();
    this.h();
    assert(true);
  }
}
