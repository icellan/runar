// R2-GK010-ASSERT (GK-GAP-010) -- checkPreimage(txPreimage) is a ternary condition inside assert; the
// spender picks flag to match whichever arm runs.
// Every tier refuses:
//   public method 'spend' must pass its SigHashPreimage parameter 'txPreimage'
//   to checkPreimage() on every path
import { SmartContract, assert, ByteString, SigHashPreimage, checkPreimage, extractAmount } from 'runar-lang';

class N525 extends SmartContract {
  readonly minAmount: bigint;

  constructor(minAmount: bigint) {
    super(minAmount);
    this.minAmount = minAmount;
  }

  public spend(txPreimage: SigHashPreimage, flag: boolean) {
    assert(checkPreimage(txPreimage) ? flag : !flag);
    assert(extractAmount(txPreimage) >= this.minAmount);
  }
}
