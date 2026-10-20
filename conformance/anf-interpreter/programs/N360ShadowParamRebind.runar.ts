import { StatefulSmartContract } from 'runar-lang';

/**
 * N-360 — a public parameter named like the mutable property, reassigned in
 * both arms of an if/else and read after it. The compiler binds the parameter
 * under its `count@local` slot (so its branch-merged result cannot collide with
 * the property's), which the ANF's `params` list carries; the ABI and the
 * interpreter's `args` map keep the source name `count`.
 */
class N360ShadowParamRebind extends StatefulSmartContract {
  count: bigint;

  constructor(count: bigint) {
    super(count);
    this.count = count;
  }

  public m(count: bigint, c: boolean) {
    if (c) {
      count = count + 1n;
    } else {
      count = count + 2n;
    }
    this.count = count * 10n + this.count;
  }
}
