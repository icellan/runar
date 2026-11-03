import { SmartContract, assert } from 'runar-lang';

/**
 * N-397 — an alias the folder sees through inside an `if` arm, where the
 * aliased local is one of the `if`'s merged `results`.
 *
 * In the then arm `x = 5n` lowers to `t = 5; x = @ref:t`, so `x + 1n` folds
 * to 6; `x` itself must still reach the merge block, because it is read after
 * the `if`.
 *
 * Spendable with p in {1 … 5} (x = 5) and p in {-2 … 0} (x = 1); rejected for
 * p >= 6 and p <= -3.
 */
export class FoldRefAliasInArm extends SmartContract {
  constructor() {
    super();
  }

  public unlock(p: bigint): void {
    let x = 1n;
    if (p > 0n) {
      x = 5n;
      assert(p < x + 1n);
    }
    assert(p + x > -2n);
  }
}
