// N-011: two classes extend SmartContract. The TS reference refuses the file with
// "Only one SmartContract subclass is allowed per file". Pre-fix Zig, Ruby and Java
// silently compiled the FIRST class (`assert(true)`: anyone can spend).
import { SmartContract, assert, ByteString, Sha256, sha256 } from 'runar-lang';

export class First extends SmartContract {
  constructor() {
    super();
  }

  public unlock(preimage: ByteString) {
    assert(true);
  }
}

export class HashLock extends SmartContract {
  readonly hashValue: Sha256;

  constructor(hashValue: Sha256) {
    super(hashValue);
    this.hashValue = hashValue;
  }

  public unlock(preimage: ByteString) {
    assert(sha256(preimage) === this.hashValue);
  }
}
