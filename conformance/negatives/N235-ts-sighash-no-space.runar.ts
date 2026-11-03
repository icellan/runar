import { StatefulSmartContract } from 'runar-lang';
// N-039 (user decision R85): the sighash marker glued to its flag list (no space).
// A comment token that starts with the sighash marker but is not exactly the
// marker, a space and a flag list is a compile error in every tier.
// Before N-039 every tier read it as prose and compiled the default ALL|FORKID.
export class N235 extends StatefulSmartContract {
  count: bigint;
  constructor(count: bigint) { super(count); this.count = count; }
  /** @sighashSINGLE|FORKID */
  public bump() {
    this.addOutput(1000n, this.count);
  }
}
