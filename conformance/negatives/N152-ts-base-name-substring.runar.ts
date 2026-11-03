// N-011: the only class extends `NotSmartContract`, which is not a valid base. The TS
// reference compares the `extends` expression exactly and refuses the file with "No class
// extending SmartContract, StatefulSmartContract, or UnsafeSmartContract found". Pre-fix
// the Go tier matched the base by substring and compiled it as a SmartContract.
import { SmartContract, assert, ByteString, Sha256, sha256 } from 'runar-lang';

class Helper extends NotSmartContract {
  readonly hashValue: Sha256;

  constructor(hashValue: Sha256) {
    super(hashValue);
    this.hashValue = hashValue;
  }

  public unlock(preimage: ByteString) {
    assert(sha256(preimage) !== this.hashValue);
  }
}
