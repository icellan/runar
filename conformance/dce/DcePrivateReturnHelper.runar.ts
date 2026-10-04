import { SmartContract, assert, ecMulGen, Point } from 'runar-lang';

/**
 * F-108 — a private helper's return value must survive dead-code elimination
 * when the EC rewrite that arms DCE fires INSIDE the helper itself.
 *
 * Here every tier DCEs `add1` (it is the method that was rewritten), so a DCE
 * without a "last binding of a private method is live" root deletes `n + 1n` —
 * the value stack lowering returns to the caller — on all seven tiers.
 */
export class DcePrivateReturnHelper extends SmartContract {
  readonly target: bigint = 6n;

  constructor() {
    super();
  }

  public go(n: bigint): void {
    assert(this.add1(n) === this.target);
  }

  private add1(n: bigint): bigint {
    const p: Point = ecMulGen(0n);
    assert(p === p);
    return n + 1n;
  }
}
