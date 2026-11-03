// R-105 companion (ports #170): the same contract as StatefulBinding.runar.ts
// with `@bindingVariant all`, so every tier must emit the compact
// CHECK_PREIMAGE_BINDING_ALL_HEX blob verbatim and not the default one.
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
