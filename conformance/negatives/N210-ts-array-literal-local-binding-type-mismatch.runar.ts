import { SmartContract, assert, checkMultiSig } from 'runar-lang';
import type { Sig, PubKey } from 'runar-lang';
// F-216: a heterogeneous array literal bound to a local `const` BEFORE it
// reaches checkMultiSig(), rather than written inline at the call site.
//
// N102 already covers a bigint in checkMultiSig's inline PubKey[] literal.
// This fixture targets a different path: checkMultiSig's own per-position
// validation only runs against a LITERAL array at the call site, so binding
// `[s, 1n]` to `sigs` first and passing the identifier moves the array out
// from under that special case entirely. Six tiers still catch it, because
// their generic array-literal inference compares every element to the
// first regardless of where the literal appears (F-063) -- it fires at the
// `const sigs = ...` statement itself. The Zig tier's generic arm walked
// elements for side effects only and returned "<unknown>" unconditionally,
// so the local-binding form compiled a locking script for an array no
// other tier accepts.
export class N210 extends SmartContract {
  readonly pk: PubKey;
  readonly pk2: PubKey;
  constructor(pk: PubKey, pk2: PubKey) { super(pk, pk2); this.pk = pk; this.pk2 = pk2; }
  public unlock(s: Sig) {
    const sigs = [s, 1n];
    assert(checkMultiSig(sigs, [this.pk, this.pk2]));
  }
}
