import { StatefulSmartContract } from 'runar-lang';
// N-039 (user decision R85): a word glued to the sighash marker (sighashType)
// is refused too, not read as prose. A comment token that starts with the marker
// but is not exactly the marker, a space and a flag list is a compile error.
// Before N-039 every tier read it as prose and compiled the default ALL|FORKID.
export class N237 extends StatefulSmartContract {
  count: bigint;
  constructor(count: bigint) { super(count); this.count = count; }
  /** see the @sighashType docs */
  public bump() {
    this.addOutput(1000n, this.count);
  }
}
