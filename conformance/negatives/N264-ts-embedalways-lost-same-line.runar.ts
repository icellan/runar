import { SmartContract, assert } from 'runar-lang';
// N-199 (user decision R75): an embed-always directive sharing a line with the
// preceding property is that property's trailing trivia, so it attaches to no
// member. Every tier must refuse it; before N-199 `tag` was silently dropped
// by DCE although the author asked to keep it.
export class N264 extends SmartContract {
  readonly owner: bigint; // @embedAlways
  readonly tag: bigint;
  constructor(owner: bigint, tag: bigint) { super(owner, tag); this.owner = owner; this.tag = tag; }
  public unlock(x: bigint): void {
    assert(x === this.owner);
  }
}
