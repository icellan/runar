// R2-GK010-ASSERT (GK-GAP-010) -- a private helper returns checkPreimage(p) and the caller asserts the
// helper's result; the check must be asserted where it is made (fail closed).
// Every tier refuses:
//   public method 'spend' must assert checkPreimage(txPreimage) on every path
import { SmartContract, assert, ByteString, SigHashPreimage, checkPreimage, extractAmount } from 'runar-lang';

class N528 extends SmartContract {
  readonly minAmount: bigint;

  constructor(minAmount: bigint) {
    super(minAmount);
    this.minAmount = minAmount;
  }

  public spend(txPreimage: SigHashPreimage, flag: boolean) {
    assert(this.check(txPreimage));
    assert(extractAmount(txPreimage) >= this.minAmount);
  }

  private check(p: SigHashPreimage): boolean {
    return checkPreimage(p);
  }
}
