import { StatefulSmartContract, extractScriptCode, len } from 'runar-lang';

class ScLen extends StatefulSmartContract {
  n: bigint;

  constructor(n: bigint) {
    super(n);
    this.n = n;
  }

  public rec(): void {
    this.n = len(extractScriptCode(this.txPreimage));
  }
}
