// R-127 — an output intrinsic inside a loop body.
//
// `lowerForStatement` lowers the body into its own sub-context, which starts
// with a fresh empty add-output ref list, and nothing propagates that list back
// to the method context — unlike the if-statement lowering, which concatenates
// each arm's outputs into a single ref precisely so the parent sees them. The
// continuation hash is therefore built from whatever `addOutput` calls sit at
// the method's TOP level, while the loop's outputs are still emitted into the
// transaction.
//
// Measured on this exact shape (two loop outputs, one top-level) before the
// rule existed:
//
//   * the ANF continuation hashed exactly ONE leaf while THREE outputs were
//     built. The hand-unrolled three-output equivalent hashes three:
//         Three    hashLeaves = t12[add_output], t17, t22, t33[if]
//         this     hashLeaves = t12[add_output],           t29[if]
//     An earlier probe counted `OP_8 OP_NUM2BIN` groups instead and read 7 for
//     both, concluding the shape was fine. Group count measures output bytes
//     BUILT, not bytes HASHED.
//   * with the top-level call removed, ts/go/rust/python blew up inside stack
//     lowering ("method parameter '_newAmount' is not on the stack at a
//     post-consumption reference"), zig and ruby COMPILED a covenant over the
//     wrong output set, and java compiled with no output groups at all. Two
//     tiers shipping the wrong covenant, four an internal invariant error, one
//     something else again — seven tiers, four different answers.
//
// A continuation committing to fewer outputs than the transaction creates is
// spendable only by a hand-crafted transaction, is rejected by every shipped
// SDK, and the successor it produces is permanently unspendable (CL-BUG-164).
//
// Every tier must refuse this. `conformance/tests/loop-if-merged-locals/` is
// the control in the other direction: an `addOutput` AFTER a loop, which stays
// accepted and byte-identical.

import { StatefulSmartContract, assert } from 'runar-lang';

class OutputInLoop extends StatefulSmartContract {
  count: bigint;

  constructor(count: bigint) {
    super(count);
    this.count = count;
  }

  public fan(n: bigint) {
    this.addOutput(1000n, this.count);
    for (let i = 0n; i < 2n; i++) {
      this.addOutput(1000n, this.count + i);
    }
    assert(n > 0n);
  }
}
