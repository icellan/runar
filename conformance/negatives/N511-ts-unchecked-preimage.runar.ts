// GK-GAP-010 — a public method reads a SigHashPreimage parameter that never
// reaches checkPreimage(), so every extracted field is chosen by the spender.
// Every tier refuses:
//   public method 'spend' must pass its SigHashPreimage parameter 'txPreimage'
//   to checkPreimage() on every path
import { SmartContract, assert, SigHashPreimage, extractAmount } from 'runar-lang';

class N511 extends SmartContract {
  readonly minAmount: bigint;

  constructor(minAmount: bigint) {
    super(minAmount);
    this.minAmount = minAmount;
  }

  public spend(txPreimage: SigHashPreimage) {
    assert(extractAmount(txPreimage) >= this.minAmount);
  }
}
