class Tip extends StatefulSmartContract {
  lastDeposit: bigint;
  constructor(lastDeposit: bigint) { super(lastDeposit); this.lastDeposit = lastDeposit; }
  public deposit() {
    this.lastDeposit = continuationAmount() - extractAmount(this.txPreimage);
  }
}
