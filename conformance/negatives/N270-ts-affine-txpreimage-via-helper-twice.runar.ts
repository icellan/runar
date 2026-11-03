// N-288: in a StatefulSmartContract a private helper that runs
// `checkPreimage(this.txPreimage)` is inlined at every call site, so calling it
// twice consumes the implicit txPreimage property twice. Every tier must refuse
// with the diagnostic a direct double use of the property gets:
//   affine value 'this.txPreimage' has already been consumed
import { StatefulSmartContract, assert, checkPreimage } from 'runar-lang';

class AffineTxPreimageViaHelperTwice extends StatefulSmartContract {
  count: bigint;

  constructor(count: bigint) {
    super(count);
    this.count = count;
  }

  private h() {
    assert(checkPreimage(this.txPreimage));
  }

  public increment() {
    this.h();
    this.h();
    this.count = this.count + 1n;
  }
}
