// N-489: typecheck diagnostic anchor parity. A bigint composite whose first token is a literal, as the left operand of `&&`.
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
    assert(5n + 1n && flag);
  }
}
