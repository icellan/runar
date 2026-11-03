import { SmartContract, assert } from 'runar-lang';

/**
 * N-397 — an alias the folder sees through but that stays LIVE.
 *
 * `seven` feeds a folded division (`seven / 2n` becomes 3) and also a runtime
 * comparison with the parameter, so its binding must survive the fold and
 * still push 7.
 *
 * Spendable with p in {3, 4, 5, 6}; rejected for p <= 2 and p >= 7.
 */
export class FoldRefAliasLive extends SmartContract {
  constructor() {
    super();
  }

  public unlock(p: bigint): void {
    const seven = 7n;
    assert(p >= seven / 2n);
    assert(p < seven);
  }
}
