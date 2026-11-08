import { SmartContract, assert } from 'runar-lang';

class FoldOrphanPartialAnd extends SmartContract {
  constructor() {
    super();
  }

  public unlock(p: bigint): void {
    let m: bigint = 41n & p;
    m = 5n;
    assert(m === 5n);
  }
}
