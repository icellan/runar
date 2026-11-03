// N-472: typecheck diagnostic anchor parity. Unary '-' on a non-bigint operand.
// Every tier must anchor the refusal where the TypeScript reference does
// (see n233-diagnostic-anchor-parity.test.ts).
import { SmartContract, assert, PubKey, Sig, checkSig } from 'runar-lang';

export class Anchor extends SmartContract {
  readonly pk: PubKey;

  constructor(pk: PubKey) {
    super(pk);
    this.pk = pk;
  }

  private hp(): PubKey {
    return this.pk;
  }

  public go(s: Sig, x: bigint, flag: boolean) {
    assert(checkSig(s, this.hp()));
    assert(-this.hp() > x);
  }
}
