// N-489: typecheck diagnostic anchor parity. A unary `-` applied to a boolean identifier.
// Every tier must anchor the refusal where the TypeScript reference does
// (see n233-diagnostic-anchor-parity.test.ts).
import { SmartContract, assert, abs } from 'runar-lang';

export class Anchor extends SmartContract {
  readonly t: bigint;

  constructor(t: bigint) {
    super(t);
    this.t = t;
  }

  public go(x: bigint, flag: boolean) {
    assert(-flag);
  }
}
