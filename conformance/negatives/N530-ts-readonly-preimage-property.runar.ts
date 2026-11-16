// R3-GK010-GAPS — a readonly property holds a SigHashPreimage. It is a
// constant in the locking script, and a preimage commits to the scriptCode and
// outpoint of the very output carrying that script, so checkPreimage() on it
// can never pass and every field an extractor reads from it is unverified.
// Every tier refuses at the declaration:
//   readonly property 'pre' cannot hold a SigHashPreimage: a preimage fixed in the locking script can never pass checkPreimage(), so every field an extractor reads from it is unverified
import { SmartContract, assert, SigHashPreimage, extractAmount } from 'runar-lang';

class N530 extends SmartContract {
  readonly pre: SigHashPreimage;

  constructor(pre: SigHashPreimage) {
    super(pre);
    this.pre = pre;
  }

  public spend(x: bigint) {
    assert(extractAmount(this.pre) >= x);
  }
}
