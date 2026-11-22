// R-105 / D25 companion: the same counter as StatefulBinding.runar.ts, but its
// continuation is an explicit addOutput, so the contract is NOT mutate-only and
// keeps the default ALL|FORKID (0x41) binding. Since D25 the mutate-only probes
// carry the 0x43 blob; this one keeps the 0x41 blob pinned in all seven tiers.
import { StatefulSmartContract, assert } from 'runar-lang';

export class StatefulBindingExplicit extends StatefulSmartContract {
  count: bigint;
  constructor(count: bigint) { super(count); this.count = count; }
  public bump(amount: bigint) {
    assert(this.count >= 0n);
    this.addOutput(amount, this.count + 1n);
  }
}
