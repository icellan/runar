import { StatefulSmartContract } from 'runar-lang';
// N-039 (user decision R85): an underscore glued to the sighash marker.
// A comment token that starts with the sighash marker but is not exactly the
// marker, a space and a flag list is a compile error in every tier.
// Before N-039 every tier read it as prose and compiled the default ALL|FORKID.
export class N238 extends StatefulSmartContract {
  count: bigint;
  constructor(count: bigint) { super(count); this.count = count; }
  /** @sighash_SINGLE|FORKID */
  public bump() {
    this.addOutput(1000n, this.count);
  }
}
