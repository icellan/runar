// N-011: the only class in the file extends nothing. The TS reference refuses it with
// "No class extending SmartContract, StatefulSmartContract, or UnsafeSmartContract found".
// Pre-fix Zig, Ruby and Java defaulted the missing `extends` to SmartContract and
// compiled it (a8008791: any preimage EXCEPT the real one spends).
import { SmartContract, assert, ByteString, Sha256, sha256 } from 'runar-lang';

class Helper {
  readonly hashValue: Sha256;

  constructor(hashValue: Sha256) {
    super(hashValue);
    this.hashValue = hashValue;
  }

  public unlock(preimage: ByteString) {
    assert(sha256(preimage) !== this.hashValue);
  }
}
