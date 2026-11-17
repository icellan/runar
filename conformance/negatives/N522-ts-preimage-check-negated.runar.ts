// R2-GK010-ASSERT (GK-GAP-010) -- assert(!checkPreimage(txPreimage)) passes only when the check FAILS.
// Every tier refuses:
//   public method 'spend' must assert checkPreimage(txPreimage) on every path
import { SmartContract, assert, ByteString, SigHashPreimage, checkPreimage, extractAmount } from 'runar-lang';

class N522 extends SmartContract {
  readonly minAmount: bigint;

  constructor(minAmount: bigint) {
    super(minAmount);
    this.minAmount = minAmount;
  }

  public spend(txPreimage: SigHashPreimage, flag: boolean) {
    assert(!checkPreimage(txPreimage));
    assert(extractAmount(txPreimage) >= this.minAmount);
  }
}
