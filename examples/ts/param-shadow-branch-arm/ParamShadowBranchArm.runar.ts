import { StatefulSmartContract, assert } from 'runar-lang';

/**
 * ParamShadowBranchArm — N-007 conformance fixture.
 *
 * The public method's parameter `count` shares its name with the mutable
 * property `count`, and is read inside an `if` arm. Inside the arm `count`
 * must still mean the PARAMETER (the caller's argument). Before N-007 the TS,
 * Go, Rust, Zig and Ruby tiers lowered the arm in a fresh context that lost
 * the parameter's reserved stack slot, so the arm read the deserialized
 * on-chain state instead: with state count = 5, `set(7n, true)` passed the
 * guard below.
 */
class ParamShadowBranchArm extends StatefulSmartContract {
  count: bigint;

  constructor(count: bigint) {
    super(count);
    this.count = count;
  }

  public set(count: bigint, flag: boolean) {
    if (flag) {
      assert(count == 5n);
    }
    this.count = count;
  }
}
