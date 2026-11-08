import { SmartContract, assert } from 'runar-lang';

/**
 * Same defect as FoldOrphanPartialAnd, for division: `100n / p` aborts the
 * script when `p === 0n`, so the contract is unspendable with `p = 0`. The
 * fold-ON prune used to delete the division once `q === 1n` folded away,
 * making `p = 0` spendable.
 */
export class FoldOrphanPartialDiv extends SmartContract {
  constructor() {
    super();
  }

  public unlock(p: bigint): void {
    let q: bigint = 100n / p;
    q = 1n;
    assert(q === 1n);
  }
}
