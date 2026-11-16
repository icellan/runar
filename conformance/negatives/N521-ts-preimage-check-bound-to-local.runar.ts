// R2-GK010-ASSERT (GK-GAP-010) -- checkPreimage(txPreimage) is bound to a local first; only a call that
// is itself the asserted condition counts.
// Every tier refuses:
//   public method 'spend' must assert checkPreimage(txPreimage) on every path
import { SmartContract, assert, ByteString, SigHashPreimage, checkPreimage, extractAmount } from 'runar-lang';

class N521 extends SmartContract {
  readonly minAmount: bigint;

  constructor(minAmount: bigint) {
    super(minAmount);
    this.minAmount = minAmount;
  }

  public spend(txPreimage: SigHashPreimage, flag: boolean) {
    const ok: boolean = checkPreimage(txPreimage);
    assert(ok);
    assert(extractAmount(txPreimage) >= this.minAmount);
  }
}
