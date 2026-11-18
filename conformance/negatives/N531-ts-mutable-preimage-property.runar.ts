// D9 — a MUTABLE state field holds a SigHashPreimage. Its value was written
// by an earlier spend, so it describes that earlier transaction, never the one
// spending this output: checkPreimage() on it can never pass, and nothing ties
// what an extractor reads from it to the current transaction. The compiler's
// own txPreimage (auto-injected and checked at every public method's entry) is
// not a declared property and is unaffected. Every tier refuses at the
// declaration:
//   property 'pre' cannot hold a SigHashPreimage: a preimage stored in a property was fixed before the spending transaction existed, so it can never pass checkPreimage() and every field an extractor reads from it is unverified
import { StatefulSmartContract, assert, SigHashPreimage, extractAmount } from 'runar-lang';

class N531 extends StatefulSmartContract {
  pre: SigHashPreimage;
  count: bigint;

  constructor(pre: SigHashPreimage, count: bigint) {
    super(pre, count);
    this.pre = pre;
    this.count = count;
  }

  public bump(x: bigint) {
    assert(extractAmount(this.pre) >= x);
    this.count = this.count + 1n;
  }
}
