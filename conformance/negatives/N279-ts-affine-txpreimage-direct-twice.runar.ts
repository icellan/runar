// N-297: a StatefulSmartContract method that calls `checkPreimage(this.txPreimage)`
// twice DIRECTLY (no private helper in between — contrast N270, which routes the
// second call through a helper). N-288 fixed the affine checker's cross-helper
// tracking, but no cross-tier negative pinned this simpler direct case, and Zig
// had accepted it before N-288 created an origin key for the implicit txPreimage
// property. Every tier must refuse with:
//   affine value 'this.txPreimage' has already been consumed
import { StatefulSmartContract, assert, checkPreimage } from 'runar-lang';

class AffineTxPreimageDirectTwice extends StatefulSmartContract {
  count: bigint;

  constructor(count: bigint) {
    super(count);
    this.count = count;
  }

  public increment() {
    assert(checkPreimage(this.txPreimage));
    assert(checkPreimage(this.txPreimage));
    this.count = this.count + 1n;
  }
}
