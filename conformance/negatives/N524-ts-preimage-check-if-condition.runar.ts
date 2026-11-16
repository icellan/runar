// R2-GK010-ASSERT (GK-GAP-010) -- checkPreimage(txPreimage) is an if condition; both arms spend, so the
// check decides nothing.
// Every tier refuses:
//   public method 'spend' must pass its SigHashPreimage parameter 'txPreimage'
//   to checkPreimage() on every path
import { SmartContract, assert, ByteString, SigHashPreimage, checkPreimage, extractAmount } from 'runar-lang';

class N524 extends SmartContract {
  readonly minAmount: bigint;

  constructor(minAmount: bigint) {
    super(minAmount);
    this.minAmount = minAmount;
  }

  public spend(txPreimage: SigHashPreimage, flag: boolean) {
    if (checkPreimage(txPreimage)) {
      assert(flag);
    } else {
      assert(!flag);
    }
    assert(extractAmount(txPreimage) >= this.minAmount);
  }
}
