import { SmartContract, assert, ecMulGen, Point } from 'runar-lang';

/**
 * F-108 — a private helper's return value must survive dead-code elimination
 * when the EC rewrite that arms DCE fires in the CALLER.
 *
 * `add1` is not ANF-inlined (it has no output side effect), so it stays its own
 * ANF method and the call site stays a `method_call`. Stack lowering inlines it
 * later and takes the helper's LAST binding (`n + 1n`) as its result. Nothing
 * inside `add1` references that binding and a `bin_op` is pure, so a DCE that
 * does not treat a private method's last binding as a root empties the helper.
 *
 * `ecMulGen(0n)` (EC rule 5) is what arms DCE. Tiers that DCE every method once
 * any rewrite fires lose `add1` here; a tier that DCEs only the rewritten method
 * (Go) does not — see DcePrivateReturnHelper.runar.ts for the shape that
 * reaches that tier too.
 */
export class DcePrivateReturnCaller extends SmartContract {
  readonly target: bigint = 6n;

  constructor() {
    super();
  }

  public go(n: bigint): void {
    const p: Point = ecMulGen(0n);
    assert(p === p);
    assert(this.add1(n) === this.target);
  }

  private add1(n: bigint): bigint {
    return n + 1n;
  }
}
