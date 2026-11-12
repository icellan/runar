import { StatefulSmartContract, ByteString, len, assert } from 'runar-lang';

class TaggedLog extends StatefulSmartContract {
  readonly cap: bigint;
  log: ByteString;

  constructor(cap: bigint, log: ByteString) {
    super(cap, log);
    this.cap = cap;
    this.log = log;
  }

  public append(entry: ByteString) {
    this.log = this.log + entry;
    assert(len(this.log) <= this.cap);
  }

  public reset(n: bigint) {
    assert(n < this.cap);
    this.log = '00';
  }
}
