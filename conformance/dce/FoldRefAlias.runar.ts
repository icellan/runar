import { SmartContract, assert } from 'runar-lang';

/**
 * N-397 — a named `const` local defeated constant folding.
 *
 * `const seven = 7n` lowers to `t0 = 7; seven = @ref:t0`. The folder skipped
 * every `@ref:` value, so `seven` was never known to be 7 and `seven / 2n`
 * was emitted as a runtime OP_DIV: fold-ON produced the same bytes as
 * fold-OFF (`57 52 96 9c`) where the literal `7n / 2n` folds to
 * `53 9c`.
 *
 * Spendable with p = 3 only.
 */
export class FoldRefAlias extends SmartContract {
  constructor() {
    super();
  }

  public unlock(p: bigint): void {
    const seven = 7n;
    const half = seven / 2n;
    assert(p === half);
  }
}
