// N-508: method-anchored validation diagnostic parity. A public method of a
// stateless contract that does not end with assert(). Every tier must anchor
// the refusal where the TypeScript reference does: at the method
// (see n233-diagnostic-anchor-parity.test.ts).
import { SmartContract, assert } from 'runar-lang';

export class Anchor extends SmartContract {
  readonly x: bigint;

  constructor(x: bigint) {
    super(x);
    this.x = x;
  }

  public go(y: bigint) {
    const z = y + this.x;
  }
}
