// N-472: typecheck diagnostic anchor parity. A parenthesised operand: the
// refused node is the expression INSIDE the parentheses, so the anchor is the
// first token after the `(`.
// Every tier must anchor the refusal where the TypeScript reference does
// (see n233-diagnostic-anchor-parity.test.ts).
import { SmartContract, assert, PubKey, Sig, checkSig } from 'runar-lang';

export class Anchor extends SmartContract {
  readonly pk: PubKey;

  constructor(pk: PubKey) {
    super(pk);
    this.pk = pk;
  }

  public go(s: Sig, x: bigint) {
    assert(checkSig(s, this.pk));
    assert((this.pk + this.pk) * x > x);
  }
}
