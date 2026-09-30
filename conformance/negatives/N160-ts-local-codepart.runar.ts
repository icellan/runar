// N-060 / N-065: a local named like stack lowering's `_codePart` slot. Every tier
// must refuse with:
//   '_codePart' is reserved for compiler-generated names and cannot be used as an identifier
import { SmartContract, assert } from 'runar-lang';

class RLocalCodepart extends SmartContract {
  constructor() {
    super();
  }

  public unlock(p: bigint) {
    let _codePart: bigint = p + 1n;
    assert(_codePart > 1n);
  }
}
