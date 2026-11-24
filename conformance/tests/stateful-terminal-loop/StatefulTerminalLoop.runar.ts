import { StatefulSmartContract, assert } from 'runar-lang';

/**
 * StatefulTerminalLoop -- a TERMINAL stateful method (no state write, so no
 * injected continuation assert) whose bounded loop of asserts is followed by
 * a final assert. The final assert is the script result. Without it the
 * method is refused in every tier (conformance/negatives N547): the loop's
 * asserts all VERIFY and the leftover stack value would decide the spend.
 */
class StatefulTerminalLoop extends StatefulSmartContract {
  floor: bigint;
  count: bigint;

  constructor(floor: bigint, count: bigint) {
    super(floor, count);
    this.floor = floor;
    this.count = count;
  }

  public close(x: bigint) {
    for (let i = 0n; i < 2n; i++) {
      assert(x >= this.floor + i);
    }
    assert(x > this.count);
  }
}
