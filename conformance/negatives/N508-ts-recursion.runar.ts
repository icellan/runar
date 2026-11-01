// N-508: method-anchored validation diagnostic parity. A private method that
// calls itself. Every tier must anchor the refusal where the TypeScript
// reference does: at the recursive method (see n233-diagnostic-anchor-parity.test.ts).
import { SmartContract, assert } from 'runar-lang';

export class Anchor extends SmartContract {
  readonly x: bigint;

  constructor(x: bigint) {
    super(x);
    this.x = x;
  }

  private loop(n: bigint): bigint {
    return this.loop(n);
  }

  public go(y: bigint) {
    assert(this.loop(y) > this.x);
  }
}
