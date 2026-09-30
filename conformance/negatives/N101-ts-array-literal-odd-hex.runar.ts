import { SmartContract, assert, checkMultiSig, toByteString } from 'runar-lang';
import type { Sig, PubKey } from 'runar-lang';
// F-063: an odd-length ByteString literal inside an array literal. The
// validator's hex check did not walk array-literal elements in TS, Go, Python
// or Ruby, so the literal surfaced later as a stack-lowering / emit error.
// Every tier must refuse it (TS, Go, Rust, Python, Ruby, Java in the validator).
export class N101 extends SmartContract {
  readonly pk: PubKey;
  constructor(pk: PubKey) { super(pk); this.pk = pk; }
  public unlock(s: Sig) { assert(checkMultiSig([s], [this.pk, toByteString('abc')])); }
}
