// N-488: addOutput state-value diagnostic anchor parity. The state value is a mistyped literal (no location; falls back to the statement).
// Every tier must anchor the refusal where the TypeScript reference does
// (see n233-diagnostic-anchor-parity.test.ts).
import { StatefulSmartContract, ByteString, assert } from 'runar-lang';

export class Anchor extends StatefulSmartContract {
  count: bigint;

  constructor(count: bigint) {
    super(count);
    this.count = count;
  }

  public go(payload: ByteString, flag: boolean, x: bigint) {
    assert(x > 0n);
    this.addOutput(1000n, true);
  }
}
