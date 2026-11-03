import { SmartContract, assert, checkMultiSig } from 'runar-lang';
import type { Sig, PubKey } from 'runar-lang';
// F-063: a self-call hidden inside an array literal. Six tiers' recursion
// detection did not walk array-literal elements, so the cycle escaped the
// validator: Go hung forever, Rust/Zig crashed (stack overflow / segfault),
// and TS/Python/Ruby died with a host-language recursion error. Only Java
// refused it cleanly. Every tier must report "recursion detected".
export class N100 extends SmartContract {
  readonly pk: PubKey;
  constructor(pk: PubKey) { super(pk); this.pk = pk; }
  private h(s: Sig): PubKey { assert(checkMultiSig([s], [this.h(s)])); return this.pk; }
  public unlock(s: Sig) { assert(checkMultiSig([s], [this.h(s)])); }
}
