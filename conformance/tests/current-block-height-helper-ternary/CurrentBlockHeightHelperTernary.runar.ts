import { StatefulSmartContract, assert, currentBlockHeight } from 'runar-lang';

/**
 * CurrentBlockHeightHelperTernary -- `currentBlockHeight()` in the two
 * positions that used to fail: inside a private helper (inlined; the
 * preimage read there lowers as `this.txPreimage` does, so it does not
 * consume the caller's preimage) and in a ternary arm (the height-domain pin
 * runs in that arm only, exactly where the height is read). Both compares are
 * lower bounds, so the --ir path's locktime-domain rule (D26) sees them.
 *
 * Only the surfaces with ternary syntax carry this fixture: .runar.ts,
 * .runar.sol, .runar.py (`a if c else b`), .runar.rb and .runar.java.
 */
class CurrentBlockHeightHelperTernary extends StatefulSmartContract {
  readonly start: bigint;
  count: bigint;

  constructor(start: bigint, count: bigint) {
    super(start, count);
    this.start = start;
    this.count = count;
  }

  private height(): bigint {
    return currentBlockHeight();
  }

  public spend() {
    assert(this.height() >= this.start);
    const h = this.count > 5n ? currentBlockHeight() : this.start;
    assert(h >= this.start);
    this.count = this.count + 1n;
  }
}
