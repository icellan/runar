// N-508: method-anchored validation diagnostic parity. A FixedArray method
// parameter. Every tier must anchor the refusal where the TypeScript
// reference does: at the method (see n233-diagnostic-anchor-parity.test.ts).
import { SmartContract, FixedArray, assert } from 'runar-lang';

export class Anchor extends SmartContract {
  readonly x: bigint;

  constructor(x: bigint) {
    super(x);
    this.x = x;
  }

  public go(a: FixedArray<bigint, 2>) {
    assert(this.x > 0n);
  }
}
