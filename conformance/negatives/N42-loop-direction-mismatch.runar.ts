// W4, third shape — the comparison direction disagrees with the update.
//
// `i++` under `i > 1n` counts UP while the comparison counts DOWN. The unroll
// model is `start + k*step` with a single step sign, so there is no trip count
// that means what this says; `extractLoopStep` takes the sign from the update
// (`+1` here) and `extractLoopShape` then has no arm for `>` under a positive
// step.
//
// Unlike N40 and N41 this is NOT a new rule: every tier already refuses it
// inside loop-shape extraction. The fixture exists because that refusal had
// never been measured across the seven tiers, and W4 is a lesson about a guard
// whose invariant was asserted in a comment rather than checked -- so the
// direction rule is gated here rather than duplicated into each validator,
// where it would be a second copy nobody runs. If a tier ever stops refusing
// this, the rejection-parity gate says so.
//
// The loop must be LIVE (`acc` feeds the assert) or DCE removes it before ANF
// lowering ever looks at the shape.

import { SmartContract, assert } from 'runar-lang';

class DirectionMismatch extends SmartContract {
  readonly tag: bigint;

  constructor(tag: bigint) {
    super(tag);
    this.tag = tag;
  }

  public verify(expected: bigint) {
    let acc: bigint = 0n;
    for (let i = 0n; i > 1n; i++) {
      acc = acc + i;
    }
    assert(acc === expected);
  }
}
