import { SmartContract, assert, checkMultiSig } from 'runar-lang';
import type { Sig, PubKey } from 'runar-lang';
// F-063: a bigint element in checkMultiSig's PubKey[] argument. Go, Python and
// Ruby typed every array literal as "<unknown>" (compatible with anything) and
// Rust typed only its first element, so all four COMPILED this to a locking
// script. The reference refuses it with:
//   Array element type mismatch: expected 'PubKey', got 'bigint'
export class N102 extends SmartContract {
  readonly pk: PubKey;
  constructor(pk: PubKey) { super(pk); this.pk = pk; }
  public unlock(s: Sig) { assert(checkMultiSig([s], [this.pk, 1n])); }
}
