// N-508: method-anchored validation diagnostic parity. A method parameter
// whose type is not a Runar type. Every tier must anchor the refusal where
// the TypeScript reference does: at the method (see
// n233-diagnostic-anchor-parity.test.ts).
import { SmartContract, assert } from 'runar-lang';

export class Anchor extends SmartContract {
  readonly x: bigint;

  constructor(x: bigint) {
    super(x);
    this.x = x;
  }

  public go(a: Wibble) {
    assert(this.x > 0n);
  }
}
