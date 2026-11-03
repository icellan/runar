// N-472: typecheck diagnostic anchor parity. The second call of a helper that
// consumes a Sig PROPERTY passes an argument, so the refusal is anchored at
// that first argument.
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

  private h(n: bigint) {
    assert(checkSig(this.sig, this.pk));
    assert(n > 0n);
  }

  public unlock(n: bigint) {
    this.h(n);
    this.h(n);
    assert(true);
  }
}
