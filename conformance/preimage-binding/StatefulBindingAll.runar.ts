// R-105 companion — same contract as StatefulBinding.runar.ts with the
// compact `@bindingVariant all` blob. Every tier must emit
// CHECK_PREIMAGE_BINDING_ALL_HEX verbatim.
import { StatefulSmartContract, assert } from 'runar-lang';

export class StatefulBindingAll extends StatefulSmartContract {
  count: bigint;
  constructor(count: bigint) { super(count); this.count = count; }
  /** @bindingVariant all */
  public bump() {
    const old = this.count++;
    assert(old >= 0n);
  }
}
