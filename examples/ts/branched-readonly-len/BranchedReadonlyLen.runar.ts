import { StatefulSmartContract, ByteString, len } from 'runar-lang';

/**
 * BranchedReadonlyLen exercises a state-mutating if/else branched on a
 * read-only intrinsic value (`len`). The hand-off section 3
 * affine-checker concern: branching on a `bigint`-returning intrinsic
 * with state mutations on both arms must pass the affine type checker.
 * If this contract compiles cleanly across all 7 tiers, the
 * AdvanceState fold-in (BSVM-side) is unblocked.
 */
class BranchedReadonlyLen extends StatefulSmartContract {
  count: bigint;
  tag: ByteString;

  constructor(count: bigint, tag: ByteString) {
    super(count, tag);
    this.count = count;
    this.tag = tag;
  }

  public spend(scratch: ByteString) {
    if (len(scratch) > 0n) {
      this.count = this.count + 1n;
      this.tag = scratch;
    } else {
      this.count = this.count - 1n;
      this.tag = '3030';
    }
    this.addOutput(1000n, this.count, this.tag);
  }
}
