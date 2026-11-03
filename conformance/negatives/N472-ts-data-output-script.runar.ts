// N-472: typecheck diagnostic anchor parity. addDataOutput scriptBytes argument is a composite.
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
    this.addDataOutput(0n, x + 1n);
  }
}
