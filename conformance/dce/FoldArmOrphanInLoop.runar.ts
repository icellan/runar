import { SmartContract, assert } from 'runar-lang';

/**
 * N-446 — the FoldArmOrphan shape one level deeper: the `if` whose else arm
 * holds the folded `-5n` sits inside a loop body, so the prune has to descend
 * through `loop.body` before it reaches the arm.
 *
 * Same spend set as FoldArmOrphan: p in {8, 10, …} or {-4 … 0} succeed;
 * p in {1 … 7}, p <= -5 and p = 9 fail.
 */
export class FoldArmOrphanInLoop extends SmartContract {
  constructor() {
    super();
  }

  public unlock(p: bigint): void {
    for (let i: bigint = 0n; i < 2n; i++) {
      if (p > 0n) {
        assert(p > 7n);
      } else {
        assert(p > -5n);
      }
    }
    assert(p !== 9n);
  }
}
