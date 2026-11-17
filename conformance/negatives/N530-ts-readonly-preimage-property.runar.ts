// R3-GK010-GAPS — a readonly property holds a SigHashPreimage. It is a
// constant in the locking script, and a preimage commits to the scriptCode and
// outpoint of the very output carrying that script, so checkPreimage() on it
// can never pass and every field an extractor reads from it is unverified.
// Every tier refuses at the declaration (D9 generalised the rule to every
// property, mutable ones included; see N531):
//   property 'pre' cannot hold a SigHashPreimage: a preimage stored in a property was fixed before the spending transaction existed, so it can never pass checkPreimage() and every field an extractor reads from it is unverified
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
