import { SmartContract, assert } from 'runar-lang';

/**
 * N-397 — fold-ON used to be LONGER than fold-OFF for a folded literal
 * division: `7n / 2n` became the constant 3 but its operand bindings `7` and
 * `2` survived (N-003 measured fold-ON `57 52 53 53 7a 7c 9c 77 77` against
 * fold-OFF `57 52 96 9c`).
 * The N-138 prune removes them; this fixture keeps it that way.
 *
 * Spendable with p = 3 only.
 */
export class FoldDivLiteral extends SmartContract {
  constructor() {
    super();
  }

  public unlock(p: bigint): void {
    assert(p === 7n / 2n);
  }
}
