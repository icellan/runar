// N-049 (EXT-2 "TernaryToll") — an output intrinsic inside a ternary arm.
//
// Each arm of a ternary lowers into its own sub-context, which starts with a
// fresh empty add-output ref list, and nothing propagates that list back to the
// method context — unlike the if-statement lowering, which concatenates each
// arm's outputs into a single ref so the parent sees them. Measured on this
// exact shape before the rule existed, on all seven tiers: the continuation
// hash committed to the state output and the change only, so a spend that
// DROPS the payee output (its value moved into change) was ACCEPTED by
// Spend.validate, and the honest three-output spend was REJECTED. With the
// top-level addOutput removed, the method died on the internal
// "_newAmount is not on the stack" invariant error instead.
//
// Every tier must refuse this with the shared N-049 diagnostic. The control in
// the other direction — a ternary that selects VALUES for one addRawOutput —
// stays accepted (conformance/negatives/ternary-output-control.test.ts).

import { StatefulSmartContract, ByteString } from 'runar-lang';

class ConditionalPayout extends StatefulSmartContract {
  count: bigint;
  readonly payee: ByteString;
  readonly refund: ByteString;

  constructor(count: bigint, payee: ByteString, refund: ByteString) {
    super(count, payee, refund);
    this.count = count;
    this.payee = payee;
    this.refund = refund;
  }

  public release() {
    this.addOutput(1000n, this.count);
    this.count > 0n ? this.addRawOutput(50000n, this.payee)
                    : this.addRawOutput(50000n, this.refund);
  }
}
