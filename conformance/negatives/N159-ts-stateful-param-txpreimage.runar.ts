// N-065: a StatefulSmartContract method parameter named `txPreimage`, the parameter
// the compiler auto-injects. Before the fix the ABI listed `txPreimage` twice. (A
// stateless contract declares its own `txPreimage`, which stays legal.) Every tier
// must refuse with:
//   'txPreimage' is reserved for compiler-generated names and cannot be used as an identifier
import { StatefulSmartContract, assert } from 'runar-lang';

class RTsStatefulParamTxpreimage extends StatefulSmartContract {
  count: bigint;

  constructor(count: bigint) {
    super(count);
    this.count = count;
  }

  public inc(txPreimage: bigint) {
    assert(txPreimage > 0n);
    this.count = this.count + txPreimage;
  }
}
