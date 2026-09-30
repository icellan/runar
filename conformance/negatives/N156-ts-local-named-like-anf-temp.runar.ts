// N-065: a local spelled like an ANF temp. `0n` lowers to the temp `t2`, so before
// the fix the final guard read the temp (0) when c = false and the script accepted
// unlock(1, false), which the source rejects (@bsv/sdk Spend, folding OFF). Every
// tier must refuse with:
//   't2' is reserved for compiler-generated names and cannot be used as an identifier
import { SmartContract, assert } from 'runar-lang';

class RTsLocalT2Ifstale extends SmartContract {
  constructor() {
    super();
  }

  public unlock(p: bigint, c: boolean) {
    let t2: bigint = p;
    assert(p > 0n);
    if (c) {
      t2 = p;
    }
    assert(t2 + 1n === 1n);
  }
}
