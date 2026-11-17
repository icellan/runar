// D14 — a preimage extractor reads a plain ByteString parameter. Nothing ties
// x to the spending transaction, so the amount it "reads" is whatever the
// spender chose, and the >= check guards nothing. The subtype rules let a
// ByteString stand where a SigHashPreimage is expected, so every tier refuses
// on provenance instead: an extractor's argument must be a SigHashPreimage
// parameter (which GK-GAP-010 forces through assert(checkPreimage(...)) on
// every path) or the implicit txPreimage of a StatefulSmartContract.
//   extractAmount() needs a checked SigHashPreimage: its argument must be a SigHashPreimage parameter (one a public method must assert with checkPreimage()) or the implicit txPreimage of a StatefulSmartContract; any other value is not bound to the spending transaction, so every field an extractor reads from it is unverified
import { SmartContract, assert, ByteString, extractAmount } from 'runar-lang';

class N533 extends SmartContract {
  readonly minAmount: bigint;

  constructor(minAmount: bigint) {
    super(minAmount);
    this.minAmount = minAmount;
  }

  public spend(x: ByteString) {
    assert(extractAmount(x) >= this.minAmount);
  }
}
