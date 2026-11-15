// R2-GK010-ASSERT (GK-GAP-010) -- checkPreimage(txPreimage) is called as a statement; its result is
// discarded, so a preimage that is not the transaction's still spends.
// Every tier refuses:
//   public method 'spend' must pass its SigHashPreimage parameter 'txPreimage'
//   to checkPreimage() on every path
import { SmartContract, assert, ByteString, SigHashPreimage, checkPreimage, extractAmount } from 'runar-lang';

class N520 extends SmartContract {
  readonly minAmount: bigint;

  constructor(minAmount: bigint) {
    super(minAmount);
    this.minAmount = minAmount;
  }

  public spend(txPreimage: SigHashPreimage, flag: boolean) {
    checkPreimage(txPreimage);
    assert(extractAmount(txPreimage) >= this.minAmount);
  }
}
