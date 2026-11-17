// R2-GK010-ASSERT (GK-GAP-010) -- assert(checkPreimage(txPreimage) || flag) passes with flag = true and
// any preimage.
// Every tier refuses:
//   public method 'spend' must assert checkPreimage(txPreimage) on every path
import { SmartContract, assert, ByteString, SigHashPreimage, checkPreimage, extractAmount } from 'runar-lang';

class N523 extends SmartContract {
  readonly minAmount: bigint;

  constructor(minAmount: bigint) {
    super(minAmount);
    this.minAmount = minAmount;
  }

  public spend(txPreimage: SigHashPreimage, flag: boolean) {
    assert(checkPreimage(txPreimage) || flag);
    assert(extractAmount(txPreimage) >= this.minAmount);
  }
}
