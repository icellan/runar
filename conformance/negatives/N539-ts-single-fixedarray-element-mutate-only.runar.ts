// PR C (FixedArray element writes are state writes): under @sighash SINGLE a
// mutate-only method takes the auto-continuation sized by the spender's
// _newAmount, and SINGLE pins only the same-index output without its value,
// so the spender can skim the contract (sighash-validate refuses it). Before
// PR C a write to a FixedArray ELEMENT was not counted as a state write before
// pass 3b, so this shape compiled in all seven tiers. Every tier refuses:
//   @sighash SINGLE|FORKID: this stateful method's state continuation is sized
//   by the caller-chosen _newAmount ... a mutate-only SINGLE continuation is
//   unsound
import { StatefulSmartContract, assert } from 'runar-lang';
import type { FixedArray } from 'runar-lang';

class N539 extends StatefulSmartContract {
  table: FixedArray<bigint, 4> = [0n, 0n, 0n, 0n];

  constructor() {
    super();
  }

  /** @sighash SINGLE|FORKID */
  public bump(i: bigint) {
    this.table[i]++;
    assert(true);
  }
}
