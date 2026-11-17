// D14 — a ByteString laundered into a SigHashPreimage-typed local, then
// extracted from. The declared type proves nothing (ByteString and
// SigHashPreimage are mutually assignable); only a local DECLARED FROM a
// checked preimage counts as one. Every tier refuses:
//   extractAmount() needs a checked SigHashPreimage: its argument must be a SigHashPreimage parameter (one a public method must assert with checkPreimage()) or the implicit txPreimage of a StatefulSmartContract; any other value is not bound to the spending transaction, so every field an extractor reads from it is unverified
import { SmartContract, assert, ByteString, SigHashPreimage, extractAmount } from 'runar-lang';

class N535 extends SmartContract {
  readonly minAmount: bigint;

  constructor(minAmount: bigint) {
    super(minAmount);
    this.minAmount = minAmount;
  }

  public spend(x: ByteString) {
    const p: SigHashPreimage = x;
    assert(extractAmount(p) >= this.minAmount);
  }
}
