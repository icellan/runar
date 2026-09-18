import { SmartContract, assert, ecMulGen, Point } from 'runar-lang';

/**
 * N-140 — the branch below is LIVE and must survive dead-code elimination.
 *
 * `a` and `b` are branch-merged locals: the `if` is an ANF binding named
 * `t<n>` carrying `results: ['a','b']`, and nothing anywhere references `t<n>`.
 * `assert(a + b > this.zero)` references `a` and `b`, which the `if` DEFINES.
 *
 * `ecMulGen(0n)` is what makes this file a gate rather than a curiosity: EC
 * rule 5 rewrites it to the infinity constant, so `optimizeEC` reports
 * `anyChanged` and actually invokes DCE. Without a firing EC rewrite DCE never
 * runs at all and the bug is invisible.
 *
 * Both arms leave `a + b` strictly positive (3 in the then-arm, 7 in the else),
 * so a correct compile is spendable for EVERY `k`. A compile that drops the
 * `if` leaves `a = b = 0`, `0 + 0 > 0` is false, and the locking script is
 * unspendable with no signal — identical bytes on all seven tiers, so no
 * parity gate can see it.
 */
export class DceLiveIf extends SmartContract {
  readonly zero: bigint = 0n;

  constructor() {
    super();
  }

  public go(k: bigint): void {
    let a: bigint = 0n;
    let b: bigint = 0n;
    if (k > 1n) {
      a = 1n;
      b = 2n;
    } else {
      a = 3n;
      b = 4n;
    }
    const p: Point = ecMulGen(0n);
    assert(p === p);
    assert(a + b > this.zero);
  }
}
