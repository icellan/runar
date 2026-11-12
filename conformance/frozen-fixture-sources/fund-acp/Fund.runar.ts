
class Fund extends StatefulSmartContract {
  raised: bigint;
  constructor(raised: bigint) { super(raised); this.raised = raised; }
  /** @sighash ALL|ANYONECANPAY|FORKID */
  public pledge(amount: bigint): void { this.raised = this.raised + amount; }
}
