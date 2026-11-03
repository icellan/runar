import { SmartContract, assert, checkMultiSig } from 'runar-lang';
import type { Sig, PubKey } from 'runar-lang';
// F-063: an unknown function nested inside an array literal. Go, Rust, Python
// and Ruby never visited array-literal elements in the typechecker, so the
// "only Rúnar built-ins" rule did not fire and the call reached stack lowering
// (which refused it late, bypassing every frontend-only CompileCheck). Every
// tier must refuse it in the typechecker, as it does the un-nested call.
export class N99 extends SmartContract {
  readonly pk: PubKey;
  constructor(pk: PubKey) { super(pk); this.pk = pk; }
  public unlock(s: Sig) { assert(checkMultiSig([s], [this.pk, totallyBogusFunction(1n)])); }
}
