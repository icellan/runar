import { SmartContract, assert } from 'runar-lang';
import type { ByteString } from 'runar-lang';

/**
 * TernaryExpression -- a well-typed conditional expression `c ? a : b` in each
 * of the three shapes a surface can write it (GK-GAP-003): both arms bigint,
 * both arms ByteString, and a ternary nested in another ternary's else arm.
 * The condition is a comparison on a spender-supplied value, so constant
 * folding cannot remove either arm and the golden keeps the OP_IF / OP_ELSE.
 *
 * Only the surfaces with ternary syntax carry this fixture: .runar.ts,
 * .runar.sol, .runar.py (`a if c else b`), .runar.rb and .runar.java.
 */
class TernaryExpression extends SmartContract {
  readonly threshold: bigint;
  readonly highTag: ByteString;
  readonly lowTag: ByteString;

  constructor(threshold: bigint, highTag: ByteString, lowTag: ByteString) {
    super(threshold, highTag, lowTag);
    this.threshold = threshold;
    this.highTag = highTag;
    this.lowTag = lowTag;
  }

  public check(x: bigint, distance: bigint, tag: ByteString, band: bigint) {
    // bigint arms: |x - threshold| without abs()
    const d = x > this.threshold ? x - this.threshold : this.threshold - x;
    assert(d === distance);

    // ByteString arms
    const t = x > this.threshold ? this.highTag : this.lowTag;
    assert(t === tag);

    // nested: 2 above, 1 at, 0 below the threshold
    const b = x > this.threshold ? 2n : (x === this.threshold ? 1n : 0n);
    assert(b === band);
  }
}
