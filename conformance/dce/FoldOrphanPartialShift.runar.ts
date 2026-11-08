import { SmartContract, assert } from 'runar-lang';

/**
 * Same defect as FoldOrphanPartialAnd, for shifts: OP_LSHIFT aborts on a
 * negative shift count, so the contract is unspendable with `p < 0`. The
 * fold-ON prune used to delete the shift once `s === 1n` folded away.
 */
export class FoldOrphanPartialShift extends SmartContract {
  constructor() {
    super();
  }

  public unlock(p: bigint): void {
    let s: bigint = 1n << p;
    s = 1n;
    assert(s === 1n);
  }
}
