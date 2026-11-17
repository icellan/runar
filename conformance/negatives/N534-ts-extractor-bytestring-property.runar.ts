// D14 — a preimage extractor reads a ByteString PROPERTY. D9 refuses a
// property typed SigHashPreimage; typing it ByteString used to slip past that
// rule, though the value is just as fixed before the spending transaction
// existed. The method's own preimage is checked, but the extractor never
// reads it. Every tier refuses:
//   extractLocktime() needs a checked SigHashPreimage: its argument must be a SigHashPreimage parameter (one a public method must assert with checkPreimage()) or the implicit txPreimage of a StatefulSmartContract; any other value is not bound to the spending transaction, so every field an extractor reads from it is unverified
import { SmartContract, assert, ByteString, SigHashPreimage, checkPreimage, extractLocktime } from 'runar-lang';

class N534 extends SmartContract {
  readonly minLocktime: bigint;
  readonly pre: ByteString;

  constructor(minLocktime: bigint, pre: ByteString) {
    super(minLocktime, pre);
    this.minLocktime = minLocktime;
    this.pre = pre;
  }

  public spend(txPreimage: SigHashPreimage) {
    assert(checkPreimage(txPreimage));
    assert(extractLocktime(this.pre) >= this.minLocktime);
  }
}
