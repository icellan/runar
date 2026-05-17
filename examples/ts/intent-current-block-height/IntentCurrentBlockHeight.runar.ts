import { StatefulSmartContract, assert, currentBlockHeight } from 'runar-lang';

/**
 * IntentCurrentBlockHeight exercises the `currentBlockHeight`
 * shorthand, which is pure source-level sugar for
 * `extractLocktime(this.txPreimage)`. The desugar happens at ANF
 * lowering time -- no new ANF kind or stack codegen is needed.
 */
class IntentCurrentBlockHeight extends StatefulSmartContract {
  readonly deadline: bigint;
  count: bigint;

  constructor(deadline: bigint, count: bigint) {
    super(deadline, count);
    this.deadline = deadline;
    this.count = count;
  }

  public spend() {
    const h = currentBlockHeight();
    assert(h <= this.deadline);
    this.count = this.count + 1n;
  }
}
