// N-472: typecheck diagnostic anchor parity. The second call of a helper that
// consumes a Sig PROPERTY carries no argument, so the refusal is anchored at
// the statement of that second call.
// Every tier must anchor the refusal where the TypeScript reference does
// (see n233-diagnostic-anchor-parity.test.ts).
import { SmartContract, assert, checkSig, PubKey, Sig } from 'runar-lang';

export class Anchor extends SmartContract {
  readonly pk: PubKey;
  readonly sig: Sig;

  constructor(pk: PubKey, sig: Sig) {
    super(pk, sig);
    this.pk = pk;
    this.sig = sig;
  }

  private h() {
    assert(checkSig(this.sig, this.pk));
  }

  public unlock() {
    this.h();
    this.h();
    assert(true);
  }
}
