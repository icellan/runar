import { StatefulSmartContract } from 'runar-lang';
// N-039 (user decision R85): the same missing space, in a line comment.
// A comment token that starts with the sighash marker but is not exactly the
// marker, a space and a flag list is a compile error in every tier.
// Before N-039 every tier read it as prose and compiled the default ALL|FORKID.
export class N236 extends StatefulSmartContract {
  count: bigint;
  constructor(count: bigint) { super(count); this.count = count; }
  // @sighashNONE|FORKID
  public bump() {
    this.addOutput(1000n, this.count);
  }
}
